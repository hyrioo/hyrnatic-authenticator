<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Guard;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthUser;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use function Orchestra\Testbench\artisan;

class GuardTest extends TestCase
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

    public function test_tokens_can_be_created()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();

        $newToken = $requestGuard->create($user)->getToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $parsedRefreshToken = $parser->parse($newToken->refreshToken);
        $expectedSubject = $user->id.'|'.$user->getMorphClass();

        $this->assertTrue($parsedAccessToken->isRelatedTo($expectedSubject));
        $this->assertEquals($newToken->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));

        $this->assertEquals($newToken->tokenFamily->family, $parsedRefreshToken->claims()->get('fam'));
    }

    public function test_authentication_succeeds()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();
        $expire = \Carbon\Carbon::now()->addMinute();

        $newToken = $requestGuard->create($user)->setAccessExpiresAt($expire)->getToken();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$newToken->accessToken);

        $requestGuard->setRequest($request);
        $requestGuard->user();

        $this->assertAuthenticated('api');
    }

    public function test_authentication_fails_if_access_token_expired()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();
        $expire = \Carbon\Carbon::now()->addMinute();

        $newToken = $requestGuard->create($user)->setAccessExpiresAt($expire)->getToken();

        $this->travel(5)->minutes();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$newToken->accessToken);

        $requestGuard->setRequest($request);

        $requestUser = $requestGuard->user();
        $this->assertNull($requestUser);
    }

    public function test_authentication_fails_if_family_expired()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();
        $expire = \Carbon\Carbon::now()->addMinute();

        $newToken = $requestGuard->create($user)->setFamilyExpiresAt($expire)->getToken();

        $this->travel(5)->minutes();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$newToken->accessToken);

        $requestGuard->setRequest($request);

        $this->assertException(TokenExpiredException::class, fn() => $requestGuard->user());
    }

    public function test_token_can_be_refreshed()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();

        $token = $requestGuard->create($user)->getToken();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);

        $requestGuard->setRequest($request);

        $newToken = $requestGuard->refresh($token->refreshToken)->refreshToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $expectedSubject = $user->id.'|'.$user->getMorphClass();

        $this->assertTrue($parsedAccessToken->isRelatedTo($expectedSubject));
        $this->assertEquals($token->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));
        $this->assertEquals($newToken->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));
    }

    public function test_refresh_fails_if_expired()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();
        $expire = \Carbon\Carbon::now()->addMinute();

        $token = $requestGuard->create($user)->setRefreshExpiresAt($expire)->getToken();

        $this->travel(5)->minutes();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);

        $requestGuard->setRequest($request);

        $this->assertException(TokenExpiredException::class, fn() => $requestGuard->refresh($token->refreshToken)->refreshToken());
    }

    public function test_refresh_fails_if_family_expired()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();
        $expire = \Carbon\Carbon::now()->addMinute();

        $token = $requestGuard->create($user)->setFamilyExpiresAt($expire)->getToken();

        $this->travel(5)->minutes();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);

        $requestGuard->setRequest($request);

        $this->assertException(TokenExpiredException::class, fn() => $requestGuard->refresh($token->refreshToken)->refreshToken());
    }

    public function test_refresh_reuse_detection()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();

        $token = $requestGuard->create($user)->getToken();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);

        $requestGuard->setRequest($request);

        $requestGuard->refresh($token->refreshToken)->refreshToken();

        $this->assertException(RefreshTokenReuseException::class, fn() => $requestGuard->refresh($token->refreshToken)->refreshToken());
        $this->assertException(ModelNotFoundException::class, fn() => $token->tokenFamily->refresh());

        $requestUser = $requestGuard->user();
        $this->assertNull($requestUser);
    }

    public function test_tokens_has_custom_claims()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();

        $token = $requestGuard->create($user)->setAccessClaims(['foo' => 1])->setRefreshClaims(['bar' => 2])->getToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($token->accessToken);
        $parsedRefreshToken = $parser->parse($token->refreshToken);

        $this->assertEquals(1, $parsedAccessToken->claims()->get('foo'));
        $this->assertEquals(2, $parsedRefreshToken->claims()->get('bar'));
    }

    public function test_tokens_has_custom_claims_after_refresh()
    {
        config(['auth.guards.api.provider' => 'users']);
        config(['auth.guards.api.driver' => 'hyrnatic-authenticator']);
        config(['auth.providers.users.model' => AuthUser::class]);

        $factory = $this->app->make(AuthFactory::class);
        /** @var Guard $requestGuard */
        $requestGuard = $factory->guard('api');

        $user = AuthUser::createTestUser();

        $token = $requestGuard->create($user)->setAccessClaims(['foo' => 1])->setRefreshClaims(['bar' => 2])->getToken();

        $newToken = $requestGuard->refresh($token->refreshToken)->refreshToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $parsedRefreshToken = $parser->parse($newToken->refreshToken);

        $this->assertNotEquals($token->accessToken, $newToken->accessToken);
        $this->assertNotEquals($token->refreshToken, $newToken->refreshToken);
        $this->assertEquals(1, $parsedAccessToken->claims()->get('foo'));
        $this->assertEquals(2, $parsedRefreshToken->claims()->get('bar'));
    }

}
