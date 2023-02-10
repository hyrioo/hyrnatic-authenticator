<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\SecretMissingException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Hyrioo\HyrnaticAuthenticator\Guard;
use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthUser;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use function Orchestra\Testbench\artisan;

class ActingAsTest extends TestCase
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

    public function test_acting_as_when_route_is_protected_by_auth_middleware()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        Route::get('/foo', function () {
            return 'bar';
        })->middleware('auth:api');

        $user = AuthUser::createTestUser();
        HyrnaticAuthenticator::actingAs($user);

        $response = $this->get('/foo');

        $response->assertStatus(200);
        $response->assertSee('bar');
    }
}
