<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Models\ModelScope;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthClient;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthProject;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthUser;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectRead;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class SchemaHardeningTest extends TestCase
{
    use RefreshDatabase;

    protected function defineDatabaseMigrations()
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
    }

    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('hyrnatic-authenticator.secret', Str::random(32));

        HyrnaticAuthenticator::registerScopes([ProjectRead::class]);
    }

    public function test_global_scope_assignments_are_unique(): void
    {
        $user = AuthUser::createTestUser();
        $user->scope(ProjectRead::class);

        $duplicate = new ModelScope([
            'scope_key' => ProjectRead::scopeKey(),
            'resource_type' => null,
            'resource_id' => null,
        ]);

        $this->expectException(QueryException::class);

        DB::transaction(fn () => $user->modelScopes()->save($duplicate));
    }

    public function test_resource_bound_scope_assignments_are_unique(): void
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $scope = ProjectRead::for($project);
        $user->scope($scope);

        $duplicate = new ModelScope([
            'scope_key' => $scope->key(),
            'resource_type' => $scope->boundResourceType(),
            'resource_id' => $scope->boundResourceId(),
        ]);

        $this->expectException(QueryException::class);

        DB::transaction(fn () => $user->modelScopes()->save($duplicate));
    }

    public function test_token_family_identifiers_are_unique(): void
    {
        $user = AuthUser::createTestUser();
        $family = str_repeat('f', 48);
        $this->saveTokenFamily($user, $family);

        $this->expectException(QueryException::class);

        DB::transaction(fn () => $this->saveTokenFamily($user, $family));
    }

    public function test_uuid_models_can_own_scopes_and_token_families(): void
    {
        $client = AuthClient::query()->create([
            'id' => (string) Str::uuid(),
            'name' => 'Deployment client',
        ]);

        $client->scope(ProjectRead::class);
        $this->saveTokenFamily($client, Str::random(48));

        $this->assertSame($client->getKey(), $client->modelScopes()->sole()->authable_id);
        $this->assertSame($client->getKey(), $client->tokenFamilies()->sole()->authable_id);
    }

    private function saveTokenFamily(AuthUser|AuthClient $authable, string $family): void
    {
        $tokenFamily = new TokenFamily();
        $tokenFamily->family = $family;
        $tokenFamily->scopes = [];
        $tokenFamily->access_claims = [];
        $tokenFamily->refresh_claims = [];
        $tokenFamily->last_refresh_sequence = 1;

        $authable->tokenFamilies()->save($tokenFamily);
    }
}
