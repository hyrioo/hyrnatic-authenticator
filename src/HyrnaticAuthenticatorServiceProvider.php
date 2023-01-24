<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Hyrioo\HyrnaticAuthenticator\Commands\GenerateSecretCommand;

class HyrnaticAuthenticatorServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        if (!app()->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__ . '/../config/hyrnatic-authenticator.php', 'hyrnatic-authenticator');
        }
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        if (app()->runningInConsole()) {
            $this->registerMigrations();

            $this->publishes([
                __DIR__ . '/../database/migrations' => database_path('migrations'),
            ], 'hyrnatic-authenticator-migrations');

            $this->publishes([
                __DIR__ . '/../config/hyrnatic-authenticator.php' => config_path('hyrnatic-authenticator.php'),
            ], 'hyrnatic-authenticator-config');

            $this->commands([
                GenerateSecretCommand::class,
            ]);
        }

        $this->configureGuard();
    }

    /**
     * Register Sanctum's migration files.
     *
     * @return void
     */
    protected function registerMigrations()
    {
        if (HyrnaticAuthenticator::shouldRunMigrations()) {
            $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        }
    }

    protected function configureGuard()
    {
        Auth::resolved(function ($auth) {
            $auth->extend('hyrnatic-authenticator', function ($app, $name, array $config) use ($auth) {
                return tap($this->createGuard($auth, $config), function ($guard) {
                    app()->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }


    /**
     * Register the guard.
     *
     * @param \Illuminate\Contracts\Auth\Factory $auth
     * @param array $config
     * @return Guard
     */
    protected function createGuard($auth, $config)
    {
        return new Guard($auth, $config['provider'], $auth->createUserProvider($config['provider'] ?? null));
    }
}
