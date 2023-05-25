<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\SecretMissingException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Hyrioo\HyrnaticAuthenticator\Guard;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthUser;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use function Orchestra\Testbench\artisan;

class PruneExpiredTest extends TestCase
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

    public function test_can_delete_expired_token_families()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();

        $token1 = $requestGuard->create($user)->setName('test_1')->setFamilyExpiresAt(now()->addMinutes(15))->getToken();
        $token2 = $requestGuard->create($user)->setName('test_2')->setFamilyExpiresAt(now()->addMinutes(2))->getToken();

        $this->travelTo(now()->addMinutes(5));

        $this->artisan('authenticator:prune-expired')
            ->expectsOutputToContain('Tokens pruned successfully.');

        $this->assertDatabaseHas('token_families', ['name' => 'test_1']);
        $this->assertDatabaseMissing('token_families', ['name' => 'test_2']);
    }

    public function test_can_delete_expired_refresh_tokens()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();

        $token1 = $requestGuard->create($user)->setName('test_1')->setRefreshExpiresAt(now()->addMinutes(15))->getToken();
        $token2 = $requestGuard->create($user)->setName('test_2')->setRefreshExpiresAt(now()->addMinutes(2))->getToken();
        $token3 = $requestGuard->create($user)->setName('test_3')->setRefreshExpiresAt(now()->addMinutes(2))->getToken();

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token3->accessToken);

        $requestGuard->setRequest($request);

        $token3 = $requestGuard->refresh($token3->refreshToken)->setRefreshExpiresAt(now()->addMinutes(10))->refreshToken();

        $this->travelTo(now()->addMinutes(5));

        $this->artisan('authenticator:prune-expired')
            ->expectsOutputToContain('Tokens pruned successfully.');

        $this->assertDatabaseHas('token_families', ['name' => 'test_1']);
        $this->assertDatabaseMissing('token_families', ['name' => 'test_2']);
        $this->assertDatabaseHas('token_families', ['name' => 'test_3']);
    }

}
