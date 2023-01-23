<?php

use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens as HasApiTokensContract;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\HasApiTokens;
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

    public function test_tokens_can_be_created()
    {
        $user = AuthUser::createTestUser();
        $expire = \Carbon\Carbon::now();

        $newToken = $user->createToken('test', ['foo'], $expire);


        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $parsedRefreshToken = $parser->parse($newToken->refreshToken);
        $expectedSubject = $user->id.'|'.$user->getMorphClass();

        $this->assertTrue($parsedAccessToken->isRelatedTo($expectedSubject));
        $this->assertEquals($newToken->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));

        $this->assertEquals($newToken->tokenFamily->family, $parsedRefreshToken->claims()->get('fam'));
    }

    public function test_token_can_be_refreshed()
    {
        $user = AuthUser::createTestUser();
        $newToken = $user->createToken('test', ['foo']);

        $refreshedToken = $user->refreshToken($newToken->refreshToken);

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $expectedSubject = $user->id.'|'.$user->getMorphClass();

        $this->assertTrue($parsedAccessToken->isRelatedTo($expectedSubject));
        $this->assertEquals($newToken->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));
        $this->assertEquals($refreshedToken->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));
    }

    public function test_refresh_token_can_detect_reuse()
    {
        $user = AuthUser::createTestUser();
        $newToken = $user->createToken('test', ['foo']);

        $refreshedToken = $user->refreshToken($newToken->refreshToken);

        $this->expectException(RefreshTokenReuseException::class);
        $refreshedToken2 = $user->refreshToken($newToken->refreshToken);
    }
}

class AuthUser extends User implements HasApiTokensContract
{
    use HasApiTokens;

    protected $table = 'users';

    public static function createTestUser()
    {
        $user = new self();
        $user->id = 1;
        $user->name = 'John Doe';
        $user->email = 'user@example.com';
        $user->password = 'password';
        $user->save();

        return $user;
    }
}
