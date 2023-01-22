<?php

use Illuminate\Foundation\Auth\User;
use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens as HasApiTokensContract;
use Hyrioo\HyrnaticAuthenticator\HasApiTokens;
use Illuminate\Support\Facades\Route;

class ActingAsTest extends \Orchestra\Testbench\TestCase
{
    protected function getPackageProviders($app)
    {
        return [\Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticatorServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app)
    {
//        $app['config']->set('database.default', 'testbench');
//
//        $app['config']->set('database.connections.testbench', [
//            'driver'   => 'sqlite',
//            'database' => ':memory:',
//            'prefix'   => '',
//        ]);
    }

    public function ActingAsWhenTheRouteIsProtectedByAuthMiddleware()
    {
        $this->withoutExceptionHandling();

        Route::get('/foo', function () {
            return 'bar';
        })->middleware('auth:hyrnatic-authenticator');

        \Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator::actingAs($user = new AuthUser);
        $user->id = 1;

        $response = $this->get('/foo');

        $response->assertStatus(200);
        $response->assertSee('bar');
    }
}

class AuthUser extends User implements HasApiTokensContract
{
    use HasApiTokens;

    protected $table = 'users';

    public static function createTestUser()
    {
        $user = new self();
        $user->name = 'John Doe';
        $user->email = 'user@example.com';
        $user->password = 'password';
        $user->save();

        return $user;
    }
}
