<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Hyrioo\HyrnaticAuthenticator\Commands\GenerateSecretCommand;

class HyrnaticAuthenticatorServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        /*
         * This class is a Package Service Provider
         *
         * More info: https://github.com/spatie/laravel-package-tools
         */
        $package
            ->name('hyrnatic-authenticator')
            ->hasConfigFile()
            ->hasMigrations('create_authenticator_table', 'create_permissions_table')
            ->hasCommand(GenerateSecretCommand::class);

        $this->configureGuard();
    }

    protected function configureGuard()
    {
        info('configureGuard');
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
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @param  array  $config
     * @return RequestGuard
     */
    protected function createGuard($auth, $config)
    {
        return new RequestGuard(
            new Guard($auth, config('hyrnatic-authenticator.expiration'), $config['provider']),
            request(),
            $auth->createUserProvider($config['provider'] ?? null)
        );
    }
}
