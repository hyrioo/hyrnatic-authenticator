<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Exception;
use Hyrioo\HyrnaticAuthenticator\Exceptions\FailedToDeleteTokenFamilyException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenFamilyNotFoundException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Hyrioo\HyrnaticAuthenticator\Traits\HasApiTokens;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Plain;
use RuntimeException;

class Guard implements \Illuminate\Contracts\Auth\Guard
{
    /**
     * The authentication factory implementation.
     *
     * @var AuthFactory
     */
    protected AuthFactory $auth;

    /**
     * The currently authenticated user.
     *
     * @var Authenticatable|null
     */
    protected ?Authenticatable $user = null;

    /**
     * The provider instance.
     *
     * @var UserProvider|null
     */
    protected ?UserProvider $provider;

    /**
     * The provider name.
     */
    protected string $providerName;

    /**
     * The request instance.
     */
    protected Request $request;

    private JWT $jwt;

    /**
     * The current token.
     */
    protected ?PersonalAccessToken $token = null;

    /**
     * Create a new guard instance.
     *
     * @param AuthFactory $auth
     * @param Request $request
     * @param string $providerName
     * @param UserProvider|null $provider
     */
    public function __construct(AuthFactory $auth, Request $request, string $providerName, UserProvider $provider = null)
    {
        $this->auth = $auth;
        $this->provider = $provider;
        $this->providerName = $providerName;
        $this->request = $request;

        $this->jwt = new JWT();
    }

    public function user(): Contracts\HasApiTokens|Authenticatable|null
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if ($this->hasUser()) {
            return $this->user;
        }

        try {
            return $this->user = $this->retrieveUser($this->request);
        } catch (Exception) {
            return null;
        }
    }

    /**
     * Determine if the guard has a token instance
     * @return bool
     */
    public function hasToken(): bool
    {
        return !is_null($this->token);
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function token(): PersonalAccessToken|null
    {
        if ($this->hasToken()) {
            return $this->token;
        }

        return $this->token = $this->retrieveToken($this->request);
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function retrieveUser(Request $request): ?Contracts\HasApiTokens
    {
        $this->request = $request;
        $personalAccessToken = $this->token();
        if (!$personalAccessToken) {
            return null;
        }

        /** @var Contracts\HasApiTokens $authable */
        $authable = $this->retrieveAuthable($personalAccessToken->accessToken);
        if (!$this->supportsTokens($authable)) {
            return null;
        }

        $authable->withAccessToken(
            $personalAccessToken
        );

        $tokenFamily = $personalAccessToken->tokenFamily;

        if (method_exists($tokenFamily->getConnection(), 'hasModifiedRecords') &&
            method_exists($tokenFamily->getConnection(), 'setRecordModificationState')) {
            tap($tokenFamily->getConnection()->hasModifiedRecords(), static function ($hasModifiedRecords) use ($tokenFamily) {
                $tokenFamily->forceFill(['last_used_at' => now()])->save();

                $tokenFamily->getConnection()->setRecordModificationState($hasModifiedRecords);
            });
        } else {
            $tokenFamily->forceFill(['last_used_at' => now()])->save();
        }

        return $authable;
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function retrieveToken(Request $request): PersonalAccessToken|null
    {
        if ($accessToken = $this->getTokenFromRequest($request)) {
            $this->setToken($accessToken);
            return $this->token;
        }
        return null;
    }

    /**
     * Determine if the authable model supports API tokens.
     *
     * @param mixed|null $authable
     * @return bool
     */
    protected function supportsTokens(mixed $authable): bool
    {
        return $authable && in_array(HasApiTokens::class, class_uses_recursive(
            get_class($authable)
        ), true);
    }

    public function create(Contracts\HasApiTokens $authable): NewTokenBuilder
    {
        return new NewTokenBuilder($authable);
    }

    /**
     * @throws TokenFamilyNotFoundException
     * @throws RefreshTokenReuseException
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     * @throws FailedToDeleteTokenFamilyException
     */
    public function refresh(string $jwtToken): RefreshTokenBuilder
    {
        $token = $this->jwt->decode($jwtToken);

        $family = $token->claims()->get('fam');
        $sequence = (int)$token->claims()->get('seq');

        $tokenFamily = TokenFamily::findTokenFamily($family);
        if (!$tokenFamily) {
            throw new TokenFamilyNotFoundException();
        }
        if (!$tokenFamily->isMostRecentRefresh($sequence)) {
            $tokenFamily->revoke();
            $this->forget();
            throw new RefreshTokenReuseException();
        }
        if ($tokenFamily->expires_at && $tokenFamily->expires_at->isBefore(now())) {
            throw new TokenExpiredException();
        }

        $authable = $tokenFamily->authable;
        return new RefreshTokenBuilder($authable, $tokenFamily);
    }

    /**
     * Get the token from the request.
     *
     * @param Request $request
     * @return string|null
     */
    protected function getTokenFromRequest(Request $request): ?string
    {
        if (is_callable(HyrnaticAuthenticator::$accessTokenRetrievalCallback)) {
            return (string)(HyrnaticAuthenticator::$accessTokenRetrievalCallback)($request);
        }

        $token = $request->bearerToken();

        return $this->isValidBearerToken($token) ? $token : null;
    }

    /**
     * Determine if the bearer token is in the correct format.
     *
     * @param string|null $token
     * @return bool
     */
    protected function isValidBearerToken(string $token = null): bool
    {
        return !empty($token);
    }


    /**
     * Determine if the authable model matches the provider's model type.
     *
     * @param Authenticatable $authable
     * @return bool
     */
    protected function hasValidProvider(Authenticatable $authable): bool
    {
        $model = config("auth.providers.$this->providerName.model");

        return $authable instanceof $model;
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param Token $token
     * @return Authenticatable|null
     */
    protected function retrieveAuthable(Token $token): ?Authenticatable
    {
        $subject = $token->claims()->get('sub');
        [$id, $type] = explode('|', $subject, 2);
        $authable = $this->provider->retrieveById($id);
        $class = Relation::getMorphedModel($type) ?? $type;

        if (!$authable instanceof $class) {
            return null;
        }

        return $this->hasValidProvider($authable) ? $authable : null;
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param Plain $token
     * @return ?TokenFamily
     */
    protected function retrieveTokenFamily(Token\Plain $token): ?TokenFamily
    {
        $family = $token->claims()->get('fam');
        return TokenFamily::findTokenFamily($family);
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = []): bool
    {
        return (bool)$this->provider->retrieveByCredentials($credentials);
    }

    /**
     * Set the current request instance.
     *
     * @param Request $request
     * @return $this
     */
    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * @throws Exception
     */
    public function setUser(Authenticatable $user): void
    {
        throw new RuntimeException('It is not supported to set the user directly. Used the setToken method instead');
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function setToken(string $accessToken): void
    {
        $this->forget();

        $parsedToken = $this->jwt->decode($accessToken);

        $tokenFamily = $this->retrieveTokenFamily($parsedToken);
        if (!$tokenFamily) {
            throw new TokenInvalidException();
        }

        if ($tokenFamily->expires_at && $tokenFamily->expires_at->isBefore(now())) {
            throw new TokenExpiredException();
        }

        $this->token = new HyrnaticAuthenticator::$personalAccessTokenModel($parsedToken, $tokenFamily);
    }

    /**
     * Logs out the user, and revokes the family
     * @return void
     */
    public function logout(): void
    {
        try {
            $personalAccessToken = $this->token();
            $personalAccessToken?->tokenFamily->revoke();
        } catch (Exception) {
        }

        $this->forget();
    }

    /**
     * Forget the current user and token.
     *
     * @return $this
     */
    public function forget(): static
    {
        $this->user = null;
        $this->token = null;

        return $this;
    }


    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check(): bool
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id(): int|string|null
    {
        if ($this->user()) {
            return $this->user()->getAuthIdentifier();
        }
        return null;
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @return bool
     */
    public function hasUser(): bool
    {
        return !is_null($this->user);
    }
}
