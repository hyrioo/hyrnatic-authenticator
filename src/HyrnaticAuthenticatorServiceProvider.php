<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Commands\GenerateSecretCommand;
use Hyrioo\HyrnaticAuthenticator\Commands\PruneExpired;
use Hyrioo\HyrnaticAuthenticator\Scopes\ScopeResolver;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class HyrnaticAuthenticatorServiceProvider extends ServiceProvider
{
    public function register()
    {
        if (!app()->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__.'/../config/hyrnatic-authenticator.php', 'hyrnatic-authenticator');
        }

        $this->app->singleton(ScopeResolver::class);
        $this->app->singleton('hyrnatic-authenticator', fn () => new HyrnaticAuthenticator());
    }

    public function boot()
    {
        if (app()->runningInConsole()) {
            $this->registerMigrations();

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'hyrnatic-authenticator-migrations');

            $this->publishes([
                __DIR__.'/../config/hyrnatic-authenticator.php' => config_path('hyrnatic-authenticator.php'),
            ], 'hyrnatic-authenticator-config');

            $this->commands([
                GenerateSecretCommand::class,
                PruneExpired::class,
            ]);
        }

        $this->configureGuard();
    }

    protected function registerMigrations()
    {
        if (HyrnaticAuthenticator::shouldRunMigrations()) {
            $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        }
    }

    protected function configureGuard()
    {
        Auth::resolved(function ($auth) {
            $createGuard = fn (array $config): Guard => $this->createGuard($auth, $config);

            $auth->extend('hyrnatic-authenticator', static function ($app, $name, array $config) use ($createGuard) {
                return tap($createGuard($config), static function ($guard) {
                    app()->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }

    protected function createGuard($auth, $config): Guard
    {
        return new Guard(
            $auth,
            request(),
            $config['provider'] ?? null,
            $auth->createUserProvider($config['provider'] ?? null),
        );
    }
}
