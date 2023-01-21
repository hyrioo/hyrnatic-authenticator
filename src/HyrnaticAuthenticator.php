<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Mockery;

class HyrnaticAuthenticator
{
    /**
     * The personal access client model class name.
     *
     * @var string
     */
    public static $personalAccessTokenModel = 'Hyrioo\\HyrnaticAuthenticator\\PersonalAccessToken';

    /**
     * A callback that can get the token from the request.
     *
     * @var callable|null
     */
    public static $accessTokenRetrievalCallback;

    /**
     * A callback that can add to the validation of the access token.
     *
     * @var callable|null
     */
    public static $accessTokenAuthenticationCallback;

    /**
     * Indicates if HyrnaticAuthenticator's migrations will be run.
     *
     * @var bool
     */
    public static $runsMigrations = true;

    /**
     * Set the current user for the application with the given scopes.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable|\Hyrioo\HyrnaticAuthenticator\HasApiTokens $user
     * @param array $scopes
     * @param string $guard
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public static function actingAs($user, $scopes = [], $guard = 'hyrnatic-authenticator')
    {
        $token = Mockery::mock(self::personalAccessTokenModel())->shouldIgnoreMissing(false);

        if (in_array('*', $scopes)) {
            $token->shouldReceive('can')->withAnyArgs()->andReturn(true);
        } else {
            foreach ($scopes as $scope) {
                $token->shouldReceive('can')->with($scope)->andReturn(true);
            }
        }

        $user->withAccessToken($token);

        if (isset($user->wasRecentlyCreated) && $user->wasRecentlyCreated) {
            $user->wasRecentlyCreated = false;
        }

        app('auth')->guard($guard)->setUser($user);

        app('auth')->shouldUse($guard);

        return $user;
    }

    /**
     * Set the personal access token model name.
     *
     * @param string $model
     * @return void
     */
    public static function usePersonalAccessTokenModel($model)
    {
        static::$personalAccessTokenModel = $model;
    }

    /**
     * Specify a callback that should be used to fetch the access token from the request.
     *
     * @param callable $callback
     * @return void
     */
    public static function getAccessTokenFromRequestUsing(callable $callback)
    {
        static::$accessTokenRetrievalCallback = $callback;
    }

    /**
     * Specify a callback that should be used to authenticate access tokens.
     *
     * @param callable $callback
     * @return void
     */
    public static function authenticateAccessTokensUsing(callable $callback)
    {
        static::$accessTokenAuthenticationCallback = $callback;
    }

    /**
     * Determine if HyrnaticAuthenticator's migrations should be run.
     *
     * @return bool
     */
    public static function shouldRunMigrations()
    {
        return static::$runsMigrations;
    }

    /**
     * Configure HyrnaticAuthenticator to not register its migrations.
     *
     * @return static
     */
    public static function ignoreMigrations()
    {
        static::$runsMigrations = false;

        return new static;
    }

    /**
     * Get the token model class name.
     *
     * @return string
     */
    public static function personalAccessTokenModel()
    {
        return static::$personalAccessTokenModel;
    }
}
