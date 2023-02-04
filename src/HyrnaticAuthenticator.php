<?php

namespace Hyrioo\HyrnaticAuthenticator;

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
    public static string $tokenFamilyModel = 'Hyrioo\\HyrnaticAuthenticator\\Models\\TokenFamily';

    /**
     * A callback that can get the token from the request.
     *
     * @var callable|null
     */
    public static $accessTokenRetrievalCallback;

    /**
     * Indicates if HyrnaticAuthenticator's migrations will be run.
     *
     * @var bool
     */
    public static bool $runsMigrations = true;

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
     * @param  callable  $callback
     * @return void
     */
    public static function getAccessTokenFromRequestUsing(callable $callback)
    {
        static::$accessTokenRetrievalCallback = $callback;
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

    /**
     * Get the token family model class name.
     *
     * @return string
     */
    public static function tokenFamilyModel(): string
    {
        return static::$tokenFamilyModel;
    }
}
