<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Illuminate\Contracts\Auth\Authenticatable;
use Mockery;

class HyrnaticAuthenticator
{
    /**
     * The personal access client model class name.
     *
     * @var string
     */
    public static string $personalAccessTokenModel = 'Hyrioo\\HyrnaticAuthenticator\\PersonalAccessToken';

    /**
     * The personal refresh client model class name.
     *
     * @var string
     */
    public static string $tokenFamilyModel = 'Hyrioo\\HyrnaticAuthenticator\\TokenFamily';

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
    public static bool $runsMigrations = true;

    /**
     * Set the current user for the application with the given scopes.
     *
     * @param Authenticatable|HasApiTokens $user
     * @param array $scopes
     * @param string $guard
     * @return Authenticatable
     */
    public static function actingAs($user, array $scopes = [], string $guard = 'hyrnatic-authenticator')
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
    public static function usePersonalAccessTokenModel(string $model): void
    {
        static::$personalAccessTokenModel = $model;
    }

    /**
     * Set the token family model name.
     *
     * @param string $model
     * @return void
     */
    public static function useTokenFamilyModel(string $model): void
    {
        static::$tokenFamilyModel = $model;
    }

    /**
     * Specify a callback that should be used to fetch the access token from the request.
     *
     * @param callable $callback
     * @return void
     */
    public static function getAccessTokenFromRequestUsing(callable $callback): void
    {
        static::$accessTokenRetrievalCallback = $callback;
    }

    /**
     * Specify a callback that should be used to authenticate access tokens.
     *
     * @param callable $callback
     * @return void
     */
    public static function authenticateAccessTokensUsing(callable $callback): void
    {
        static::$accessTokenAuthenticationCallback = $callback;
    }

    /**
     * Determine if HyrnaticAuthenticator's migrations should be run.
     *
     * @return bool
     */
    public static function shouldRunMigrations(): bool
    {
        return static::$runsMigrations;
    }

    /**
     * Configure HyrnaticAuthenticator to not register its migrations.
     *
     * @return static
     */
    public static function ignoreMigrations(): static
    {
        static::$runsMigrations = false;

        return new static;
    }

    /**
     * Get the access token model class name.
     *
     * @return string
     */
    public static function personalAccessTokenModel(): string
    {
        return static::$personalAccessTokenModel;
    }
}
