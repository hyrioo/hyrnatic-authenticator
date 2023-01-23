<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Events\TokenAuthenticated;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\Request;

class Guard
{

    /**
     * The authentication factory implementation.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * The number of minutes tokens should be allowed to remain valid.
     *
     * @var int
     */
    protected $expiration;

    /**
     * The provider name.
     *
     * @var string
     */
    protected $provider;

    /**
     * Create a new guard instance.
     *
     * @param \Illuminate\Contracts\Auth\Factory $auth
     * @param int $expiration
     * @param string $provider
     * @return void
     */
    public function __construct(AuthFactory $auth, $expiration = null, $provider = null)
    {
        $this->auth = $auth;
        $this->expiration = $expiration;
        $this->provider = $provider;
    }

    public function __invoke(Request $request)
    {
        if ($token = $this->getTokenFromRequest($request)) {
            /** @var PersonalAccessToken $model */
            $model = HyrnaticAuthenticator::$personalAccessTokenModel;

            $accessToken = $model::findToken($token);

            if (!$this->isValidAccessToken($accessToken) ||
                !$this->supportsTokens($accessToken->authable)) {
                return;
            }

            $authable = $accessToken->authable->withAccessToken(
                $accessToken
            );

            event(new TokenAuthenticated($accessToken));

            if (method_exists($accessToken->getConnection(), 'hasModifiedRecords') &&
                method_exists($accessToken->getConnection(), 'setRecordModificationState')) {
                tap($accessToken->getConnection()->hasModifiedRecords(), function ($hasModifiedRecords) use ($accessToken) {
                    $accessToken->forceFill(['last_used_at' => now()])->save();

                    $accessToken->getConnection()->setRecordModificationState($hasModifiedRecords);
                });
            } else {
                $accessToken->forceFill(['last_used_at' => now()])->save();
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
        if (!is_null($token) && str_contains($token, '|')) {
            $model = new HyrnaticAuthenticator::$personalAccessTokenModel;

            if ($model->getKeyType() === 'int') {
                [$id, $token] = explode('|', $token, 2);

                return ctype_digit($id) && !empty($token);
            }
        }

        return !empty($token);
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param mixed $accessToken
     * @return bool
     */
    protected function isValidAccessToken($accessToken): bool
    {
        if (!$accessToken) {
            return false;
        }

        $isValid =
            (!$this->expiration || $accessToken->created_at->gt(now()->subMinutes($this->expiration)))
            && (!$accessToken->expires_at || !$accessToken->expires_at->isPast())
            && $this->hasValidProvider($accessToken->authable);

        if (is_callable(HyrnaticAuthenticator::$accessTokenAuthenticationCallback)) {
            $isValid = (bool)(HyrnaticAuthenticator::$accessTokenAuthenticationCallback)($accessToken, $isValid);
        }

        return $isValid;
    }

    /**
     * Determine if the authable model matches the provider's model type.
     *
     * @param \Illuminate\Database\Eloquent\Model $authable
     * @return bool
     */
    protected function hasValidProvider($authable)
    {
        if (is_null($this->provider)) {
            return true;
        }

        $model = config("auth.providers.{$this->provider}.model");

        return $authable instanceof $model;
    }
}
