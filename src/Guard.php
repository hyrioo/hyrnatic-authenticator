<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Carbon\CarbonInterface;
use Exception;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;

class Guard implements \Illuminate\Contracts\Auth\Guard
{
    use GuardHelpers;

    /**
     * The authentication factory implementation.
     *
     * @var AuthFactory
     */
    protected $auth;

    /**
     * The provider instance.
     *
     * @var UserProvider
     */
    protected $provider;

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
    protected ?PersonalAccessToken $token;

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
        if (!is_null($this->user)) {
            return $this->user;
        }

        try {
            return $this->user = $this->retrieveUser($this->request);
        } catch (Exception) {
            return null;
        }
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function token(): PersonalAccessToken|null
    {
        if (!is_null($this->token)) {
            return $this->token;
        }

        return $this->token = $this->retrieveToken($this->request);
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function retrieveUser(Request $request)
    {
        $personalAccessToken = $this->retrieveToken($request);

        /** @var \Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens $authable */
        $authable = $this->retrieveAuthable($personalAccessToken->accessToken);
        if (!$this->supportsTokens($authable)) {
            return;
        }

        $authable->withAccessToken(
            $personalAccessToken
        );

        $tokenFamily = $personalAccessToken->tokenFamily;

        if (method_exists($tokenFamily->getConnection(), 'hasModifiedRecords') &&
            method_exists($tokenFamily->getConnection(), 'setRecordModificationState')) {
            tap($tokenFamily->getConnection()->hasModifiedRecords(), function ($hasModifiedRecords) use ($tokenFamily) {
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
            $parsedToken = $this->jwt->decode($accessToken);

            $tokenFamily = $this->retrieveTokenFamily($parsedToken);
            if (!$tokenFamily) {
                throw new TokenInvalidException();
            }

            if ($tokenFamily->expires_at && $tokenFamily->expires_at->isBefore(now())) {
                throw new TokenExpiredException();
            }

            return new HyrnaticAuthenticator::$personalAccessTokenModel($parsedToken, $tokenFamily);
        }
        return null;
    }

    /**
     * Determine if the authable model supports API tokens.
     *
     * @param mixed $authable
     * @return bool
     */
    protected function supportsTokens($authable = null): bool
    {
        return $authable && in_array(HasApiTokens::class, class_uses_recursive(
                get_class($authable)
            ));
    }

    public function create(\Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens $authable): NewTokenBuilder
    {
        return new NewTokenBuilder($authable);
    }

    public function refresh(string $jwtToken): RefreshTokenBuilder
    {
        $token = $this->jwt->decode($jwtToken);

        $family = $token->claims()->get('fam');
        $sequence = (int)$token->claims()->get('seq');

        $tokenFamily = TokenFamily::findTokenFamily($family);

        if (!$tokenFamily->isMostRecentRefresh($sequence)) {
            $tokenFamily->revoke();
            $this->user = null;
            throw new RefreshTokenReuseException();
        } else if ($tokenFamily->expires_at && $tokenFamily->expires_at->isBefore(now())) {
            throw new TokenExpiredException();
        } else {
            $authable = $tokenFamily->authable;
            $builder = new RefreshTokenBuilder($authable, $tokenFamily);
            return $builder;
        }
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
     * Determine if the provided access token is valid.
     *
     * @param Token $token
     * @return bool
     */
    protected function isValidAccessToken(Token $token): bool
    {
        return !$token->isExpired(now());
    }

    /**
     * Determine if the authable model matches the provider's model type.
     *
     * @param Model $authable
     * @return bool
     */
    protected function hasValidProvider($authable): bool
    {
        if (is_null($this->providerName)) {
            return true;
        }

        $model = config("auth.providers.{$this->providerName}.model");

        return $authable instanceof $model;
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param Token $token
     * @return Authenticatable
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

        return $this->hasValidProvider($authable,) ? $authable : null;
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param Token $token
     * @return ?TokenFamily
     */
    protected function retrieveTokenFamily(Token $token): ?TokenFamily
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
     * Logs out the user, and revokes the family
     * @return void
     * @throws Exceptions\FailedToDeleteTokenFamilyException
     * @throws TokenInvalidException
     */
    public function logout(): void
    {
        if ($accessToken = $this->getTokenFromRequest($this->request)) {
            $parser = new Parser(new JoseEncoder());
            try {
                $parsedToken = $parser->parse($accessToken);
            } catch (Exception $e) {
                throw new TokenInvalidException();
            }

            $validator = new Validator();
//            $validator->validate($parsedToken, new SignedWith());

            if (!$this->isValidAccessToken($parsedToken)) {
                return;
            }

            $authable = $this->retrieveAuthable($parsedToken);
            if (!$this->supportsTokens($authable)) {
                return;
            }

            $tokenFamily = $this->retrieveTokenFamily($parsedToken);
            if (!$tokenFamily) {
                return;
            }

            $tokenFamily->revoke();
        }

        $this->user = null;
    }
}
