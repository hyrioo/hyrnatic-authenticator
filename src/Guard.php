<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Events\TokenAuthenticated;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;

class Guard implements \Illuminate\Contracts\Auth\Guard
{
    use GuardHelpers;

    /**
     * The authentication factory implementation.
     *
     * @var \Illuminate\Contracts\Auth\Factory
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
     * @var string
     */
    protected string $providerName;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Create a new guard instance.
     *
     * @param \Illuminate\Contracts\Auth\Factory $auth
     * @param int $expiration
     * @param UserProvider $provider
     * @return void
     */
    public function __construct(AuthFactory $auth, Request $request, string $providerName, UserProvider $provider = null)
    {
        $this->auth = $auth;
        $this->provider = $provider;
        $this->providerName = $providerName;
        $this->request = $request;
    }

    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        return $this->user = $this->retrieveUser($this->request);
    }

    public function retrieveUser(Request $request)
    {
        if ($accessToken = $this->getTokenFromRequest($request)) {

            $parser = new Parser(new JoseEncoder());
            try {
                $parsedToken = $parser->parse($accessToken);
            } catch (\Exception $e) {
                throw new TokenInvalidException();
            }

            if(!$this->isValidAccessToken($parsedToken)) {
                return;
            }

            $authable = $this->retrieveAuthable($parsedToken);
            if (!$this->supportsTokens($authable)) {
                return;
            }

            $tokenFamily = $this->retrieveTokenFamily($parsedToken);
            if(!$tokenFamily) {
                return;
            }

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
    }

    /**
     * Determine if the authable model supports API tokens.
     *
     * @param mixed $authable
     * @return bool
     */
    protected function supportsTokens($authable = null)
    {
        return $authable && in_array(HasApiTokens::class, class_uses_recursive(
                get_class($authable)
            ));
    }

    /**
     * Get the token from the request.
     *
     * @param \Illuminate\Http\Request $request
     * @return string|null
     */
    protected function getTokenFromRequest(Request $request)
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
    protected function isValidBearerToken(string $token = null)
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
     * @param  \Illuminate\Database\Eloquent\Model  $authable
     * @return bool
     */
    protected function hasValidProvider($authable)
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
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function retrieveAuthable(Token $token)
    {
        $subject = $token->claims()->get('sub');
        [$id] = explode('|', $subject, 2);
        $authable = $this->provider->retrieveById($id);

        return $this->hasValidProvider($authable) ? $authable : null;
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param Token $token
     * @return TokenFamily
     */
    protected function retrieveTokenFamily(Token $token)
    {
        $family = $token->claims()->get('fam');
        return TokenFamily::findTokenFamily($family);
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return (bool) $this->provider->retrieveByCredentials($credentials);
    }

    /**
     * Set the current request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    public function logout()
    {
        if ($accessToken = $this->getTokenFromRequest($this->request)) {
            $parser = new Parser(new JoseEncoder());
            try {
                $parsedToken = $parser->parse($accessToken);
            } catch (\Exception $e) {
                throw new TokenInvalidException();
            }

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

            $tokenFamily->invalidate();
        }

        $this->user = null;
    }
}
