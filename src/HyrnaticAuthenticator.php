<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Exceptions\DuplicateScopeKeyException;
use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;

class HyrnaticAuthenticator
{
    public static string $personalAccessTokenModel = 'Hyrioo\\HyrnaticAuthenticator\\PersonalAccessToken';

    public static string $tokenFamilyModel = 'Hyrioo\\HyrnaticAuthenticator\\Models\\TokenFamily';

    public static string $scopeModel = 'Hyrioo\\HyrnaticAuthenticator\\Models\\Scope';

    public static $accessTokenRetrievalCallback;

    public static bool $runsMigrations = true;

    public static $scopesByKey;

    public static $scopeKeysByClass;

    public static function registerScopes(array $scopes): void
    {
        self::$scopesByKey ??= collect();
        self::$scopeKeysByClass ??= collect();

        foreach ($scopes as $scope) {
            if (!is_a($scope, Scope::class, true)) {
                throw new \InvalidArgumentException("Scope [{$scope}] must extend [".Scope::class.'].');
            }

            $key = $scope::scopeKey();
            $existingClass = self::$scopesByKey->get($key);
            $existingKey = self::$scopeKeysByClass->get($scope);

            if ($existingClass !== null && $existingClass !== $scope) {
                throw new DuplicateScopeKeyException("Scope key [{$key}] is already registered by [{$existingClass}].");
            }

            if ($existingKey !== null && $existingKey !== $key) {
                throw new DuplicateScopeKeyException("Scope class [{$scope}] is already registered with key [{$existingKey}].");
            }

            self::$scopesByKey->put($key, $scope);
            self::$scopeKeysByClass->put($scope, $key);
        }
    }

    public static function clearRegisteredScopes(): void
    {
        self::$scopesByKey = collect();
        self::$scopeKeysByClass = collect();
    }

    public static function scopeClassForKey(string $key): ?string
    {
        return self::$scopesByKey?->get($key);
    }

    public static function scopeKeyForClass(string $scopeClass): ?string
    {
        return self::$scopeKeysByClass?->get($scopeClass);
    }

    public static function usePersonalAccessTokenModel(string $model): void
    {
        static::$personalAccessTokenModel = $model;
    }

    public static function useTokenFamilyModel(string $model): void
    {
        static::$tokenFamilyModel = $model;
    }

    public static function useScopeModel(string $model): void
    {
        static::$scopeModel = $model;
    }

    public static function getAccessTokenFromRequestUsing(callable $callback)
    {
        static::$accessTokenRetrievalCallback = $callback;
    }

    public static function shouldRunMigrations(): bool
    {
        return static::$runsMigrations;
    }

    public static function ignoreMigrations(): self
    {
        static::$runsMigrations = false;

        return new self();
    }

    public static function personalAccessTokenModel(): string
    {
        return static::$personalAccessTokenModel;
    }

    public static function tokenFamilyModel(): string
    {
        return static::$tokenFamilyModel;
    }

    public static function scopeModel(): string
    {
        return static::$scopeModel;
    }

    public static function actingAs(\Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens $authable, ?array $scopes = null, string $guard = 'api'): Contracts\HasApiTokens
    {
        $builder = new NewTokenBuilder($authable);
        if ($scopes !== null) {
            $builder->setScopes($scopes);
        }
        $token = $builder->getToken();

        self::actingAsToken($token->accessToken, $guard);

        return $authable;
    }

    public static function actingAsToken(string $token, string $guard = 'api'): void
    {
        app('auth')->guard($guard)->setToken($token);
        app('auth')->shouldUse($guard);
    }
}
