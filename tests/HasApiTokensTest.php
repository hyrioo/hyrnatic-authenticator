<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\Enums\ScopeDenialReason;
use Hyrioo\HyrnaticAuthenticator\Exceptions\InvalidScopeException;
use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Models\Scope as PersistedScope;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthProject;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthUser;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\DuplicateProjectRead;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectEdit;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectManager;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectRead;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectWildcard;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Database\Eloquent\MassAssignmentException;

class HasApiTokensTest extends TestCase
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

        HyrnaticAuthenticator::registerScopes([
            ProjectRead::class,
            ProjectEdit::class,
            ProjectManager::class,
            ProjectWildcard::class,
        ]);
    }

    public function test_model_can_resolve_resource_scoped_and_composite_scopes()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $otherProject = AuthProject::createTestProject(2);

        $user->scope(ProjectManager::for($project));

        $this->assertTrue($user->modelHasScope(ProjectRead::for($project)));
        $this->assertTrue($user->modelHasScope(ProjectEdit::for($project)));
        $this->assertFalse($user->modelHasScope(ProjectRead::for($otherProject)));
    }

    public function test_model_can_match_resource_bound_wildcards()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $otherProject = AuthProject::createTestProject(2);

        $user->scope(ProjectWildcard::for($project));

        $this->assertTrue($user->modelHasScope(ProjectRead::for($project)));
        $this->assertTrue($user->modelHasScope(ProjectEdit::for($project)));
        $this->assertFalse($user->modelHasScope(ProjectRead::for($otherProject)));
        $this->assertFalse($user->modelHasScope(ProjectRead::class));
    }

    public function test_code_scopes_reject_resources_of_the_wrong_type()
    {
        $this->expectException(InvalidScopeException::class);

        ProjectRead::for(AuthUser::createTestUser());
    }

    public function test_code_scopes_require_persisted_resources()
    {
        $this->expectException(InvalidScopeException::class);

        ProjectRead::for(new AuthProject());
    }

    public function test_persisted_scopes_reject_resources_of_the_wrong_type()
    {
        $scope = PersistedScope::create(
            name: 'Project viewer',
            resourceType: AuthProject::class,
        );

        $this->expectException(InvalidScopeException::class);

        $scope->for(AuthUser::createTestUser());
    }

    public function test_unregistered_code_scopes_are_rejected()
    {
        $user = AuthUser::createTestUser();

        $this->expectException(InvalidScopeException::class);

        $user->scope(DuplicateProjectRead::class);
    }

    public function test_custom_db_scopes_expand_their_sub_scopes()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();

        $customScope = PersistedScope::create(
            name: 'Custom Project Manager',
            subScopes: [ProjectRead::class, ProjectEdit::class],
            resourceType: AuthProject::class,
        );

        $user->scope($customScope->for($project));

        $this->assertTrue($user->modelHasScope($customScope->for($project)));
        $this->assertTrue($user->modelHasScope(ProjectRead::for($project)));
        $this->assertTrue($user->modelHasScope(ProjectEdit::for($project)));
    }

    public function test_persisted_scopes_generate_internal_keys_and_accept_persisted_sub_scopes()
    {
        $child = PersistedScope::create(
            name: 'Project viewer',
            subScopes: [ProjectRead::class],
            resourceType: AuthProject::class,
        );

        $parent = PersistedScope::create(
            name: 'Project team member',
            subScopes: [$child, ProjectEdit::class, ProjectEdit::class],
            resourceType: AuthProject::class,
            metadata: ['managed_by' => 'customer'],
        );

        $this->assertStringStartsWith('custom.', $parent->key());
        $this->assertSame([$child->key(), 'project.edit'], $parent->subScopeKeys());
        $this->assertSame(AuthProject::class, $parent->allowedResourceType());
        $this->assertSame(['managed_by' => 'customer'], $parent->metadata);
    }

    public function test_persisted_scopes_reject_raw_sub_scope_keys()
    {
        $this->expectException(\Hyrioo\HyrnaticAuthenticator\Exceptions\InvalidScopeException::class);

        PersistedScope::create(
            name: 'Unsafe role',
            subScopes: ['project.read'],
            resourceType: AuthProject::class,
        );
    }

    public function test_persisted_scopes_cannot_be_mass_assigned()
    {
        $this->expectException(MassAssignmentException::class);

        PersistedScope::query()->create([
            'key' => 'raw.scope',
            'name' => 'Raw scope',
            'source' => 'custom',
            'sub_scopes' => [],
        ]);
    }

    public function test_laravel_gate_checks_are_not_intercepted_by_scope_checks()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();

        app(Gate::class)->define(
            'edit-project',
            fn (AuthUser $candidate, AuthProject $candidateProject) => $candidate->is($user)
                && $candidateProject->is($project),
        );

        $this->assertTrue($user->can('edit-project', $project));
        $this->assertFalse($user->can('edit-project', AuthProject::createTestProject(2)));
    }

    public function test_scope_decisions_can_be_inspected_and_authorized()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $otherProject = AuthProject::createTestProject(2);
        $user->scope(ProjectRead::for($project));

        $allowed = $user->inspectScope(ProjectRead::for($project));

        $this->assertTrue($allowed->allowed());
        $this->assertTrue($user->authorizeScope(ProjectRead::for($project))->allowed());

        $denied = $user->inspectScope(ProjectRead::for($otherProject));

        $this->assertTrue($denied->denied());
        $this->assertSame(ScopeDenialReason::MissingModelScope->value, $denied->code());
        $this->assertSame('The required scope is not assigned.', $denied->message());

        try {
            $user->authorizeScope(ProjectRead::for($otherProject));
            $this->fail('A missing model scope was authorized.');
        } catch (AuthorizationException $exception) {
            $this->assertSame(ScopeDenialReason::MissingModelScope->value, $exception->response()->code());
        }
    }
}
