<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthUser;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectRead;
use Illuminate\Support\Facades\Route;

class ActingAsTest extends TestCase
{
    use \Illuminate\Foundation\Testing\RefreshDatabase;

    protected function defineDatabaseMigrations()
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
    }

    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);

        $key = \Illuminate\Support\Str::random(32);
        $app['config']->set('hyrnatic-authenticator.secret', $key);
        $app['config']->set('auth.guards.api.provider', 'users');
        $app['config']->set('auth.guards.api.driver', 'hyrnatic-authenticator');
        $app['config']->set('auth.providers.users.driver', 'eloquent');
        $app['config']->set('auth.providers.users.model', AuthUser::class);

        HyrnaticAuthenticator::registerScopes([
            ProjectRead::class,
        ]);
    }

    public function test_acting_as_uses_the_authable_scopes_when_no_token_scopes_are_provided()
    {
        Route::get('/foo', fn () => 'bar')->middleware('auth:api');

        $user = AuthUser::createTestUser();
        $user->scope(ProjectRead::class);

        HyrnaticAuthenticator::actingAs($user);

        $response = $this->get('/foo');

        $response->assertOk();
        $response->assertSee('bar');
    }

    public function test_acting_as_accepts_an_explicitly_empty_scope_list()
    {
        $user = AuthUser::createTestUser();
        $user->scope(ProjectRead::class);

        HyrnaticAuthenticator::actingAs($user, []);

        /** @var AuthUser $resolved */
        $resolved = auth('api')->user();

        $this->assertTrue($resolved->modelHasScope(ProjectRead::class));
        $this->assertFalse($resolved->tokenHasScope(ProjectRead::class));
        $this->assertFalse($resolved->hasScope(ProjectRead::class));
    }
}
