<?php

use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens as HasApiTokensContract;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\HasApiTokens;
use Illuminate\Foundation\Auth\User;
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
        $app['config']->set('database.default', 'testbench');

        $app['config']->set('database.connections.testbench', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
    }

    public function test_tokens_can_be_created()
    {
        $user = AuthUser::createTestUser();
        $accessExpire = \Carbon\Carbon::now();
        $refreshExpire = \Carbon\Carbon::now();

        $newToken = $user->createToken('test', ['foo'], $accessExpire, $refreshExpire);

        // Assert accessToken
        [$id, $token] = explode('|', $newToken->plainTextAccessToken);

        $this->assertEquals(
            $newToken->accessToken->token,
            hash('sha256', $token)
        );
        $this->assertEquals(
            $newToken->accessToken->id,
            $id
        );
        $this->assertEquals(
            $accessExpire->toDateTimeString(),
            $newToken->accessToken->expires_at->toDateTimeString(),
        );

        // Assert refreshToken
        [$id, $token] = explode('|', $newToken->plainTextRefreshToken);

        $this->assertEquals(
            $newToken->refreshToken->token,
            hash('sha256', $token)
        );
        $this->assertEquals(
            $newToken->refreshToken->id,
            $id
        );
        $this->assertEquals(
            $refreshExpire->toDateTimeString(),
            $newToken->refreshToken->expires_at->toDateTimeString(),
        );
    }

    public function test_token_can_be_refreshed()
    {
        $user = AuthUser::createTestUser();
        $newToken = $user->createToken('test', ['foo']);

        $refreshedToken = $user->refreshToken($newToken->plainTextRefreshToken);

        [$id, $token] = explode('|', $refreshedToken->plainTextAccessToken);
        $this->assertNotEquals(
            $newToken->accessToken->token,
            hash('sha256', $token)
        );
    }

    public function test_refresh_token_can_detect_reuse()
    {
        $user = AuthUser::createTestUser();
        $newToken = $user->createToken('test', ['foo']);

        $refreshedToken = $user->refreshToken($newToken->plainTextRefreshToken);

        $this->expectException(RefreshTokenReuseException::class);
        $refreshedToken2 = $user->refreshToken($newToken->plainTextRefreshToken);
    }
}
