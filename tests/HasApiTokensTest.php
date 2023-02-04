<?php

use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Traits\HasApiTokens;
use Illuminate\Foundation\Auth\User;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Orchestra\Testbench\TestCase;
use function Orchestra\Testbench\artisan;

class HasApiTokensTest extends TestCase
{
    use \Illuminate\Foundation\Testing\RefreshDatabase;

    /**
     * Define database migrations.
     *
     * @return void
     */
    protected function defineDatabaseMigrations()
    {
        $this->loadMigrationsFrom(__DIR__ . '/database/migrations');
    }

    protected function getPackageProviders($app)
    {
        return [\Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticatorServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app)
    {
        $key = \Illuminate\Support\Str::random(32);
        $app['config']->set('hyrnatic-authenticator.secret', $key);

        $app['config']->set('database.default', 'testbench');

        $app['config']->set('database.connections.testbench', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }
}

