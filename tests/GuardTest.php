<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\Enums\ScopeDenialReason;
use Hyrioo\HyrnaticAuthenticator\Exceptions\AuthableProviderMismatchException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\FailedToDeleteTokenFamilyException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\FailedToSaveTokenFamilyException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\InvalidGuardConfigurationException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenBuilderConsumedException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenTransactionException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\ReservedTokenClaimException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\SecretMissingException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\SecretTooShortException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\ScopeEscalationException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenFamilyNotFoundException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Hyrioo\HyrnaticAuthenticator\Guard;
use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\JWT;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Hyrioo\HyrnaticAuthenticator\Scopes\ScopeClaim;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthProject;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthUser;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\CustomTokenFamily;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectEdit;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectManager;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectRead;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use PHPUnit\Framework\Attributes\DataProvider;

class GuardTest extends TestCase
{
    use \Illuminate\Foundation\Testing\DatabaseMigrations;

    protected function defineDatabaseMigrations()
    {
        $this->app->make('migrator')->path(__DIR__.'/database/migrations');
    }

    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);

        $key = \Illuminate\Support\Str::random(32);
        $app['config']->set('hyrnatic-authenticator.secret', $key);
        $app['config']->set('auth.guards.api.provider', 'users');
        $app['config']->set('auth.guards.api.driver', 'hyrnatic-authenticator');
        $app['config']->set('auth.guards.project-api.provider', 'projects');
        $app['config']->set('auth.guards.project-api.driver', 'hyrnatic-authenticator');
        $app['config']->set('auth.providers.users.driver', 'eloquent');
        $app['config']->set('auth.providers.users.model', AuthUser::class);
        $app['config']->set('auth.providers.projects.driver', 'eloquent');
        $app['config']->set('auth.providers.projects.model', AuthProject::class);

        HyrnaticAuthenticator::registerScopes([
            ProjectRead::class,
            ProjectEdit::class,
            ProjectManager::class,
        ]);
    }

    public function test_project_tokens_are_rejected_on_the_users_guard()
    {
        $project = AuthProject::createTestProject();
        $project->scope(ProjectRead::class);

        $token = $this->guard('project-api')->create($project)->getToken();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);

        $guard = $this->guard('api');
        $guard->setRequest($request);

        $this->assertNull($guard->user());
    }

    public function test_users_guard_cannot_create_project_tokens()
    {
        $project = AuthProject::createTestProject();

        $this->expectException(AuthableProviderMismatchException::class);

        $this->guard()->create($project);
    }

    public function test_users_guard_cannot_refresh_project_tokens()
    {
        $project = AuthProject::createTestProject();
        $token = $this->guard('project-api')->create($project)->getToken();

        try {
            $this->guard()->refresh($token->refreshToken);
            $this->fail('The users guard refreshed a project token.');
        } catch (AuthableProviderMismatchException) {
            $this->assertDatabaseHas('token_families', ['family' => $token->tokenFamily->family]);
        }

        $refreshed = $this->guard('project-api')->refresh($token->refreshToken)->refreshToken();

        $this->assertSame($token->tokenFamily->family, $refreshed->tokenFamily->family);
    }

    public function test_project_tokens_can_authenticate_on_a_project_guard()
    {
        $project = AuthProject::createTestProject();
        $project->scope(ProjectRead::class);

        $guard = $this->guard('project-api');
        $token = $guard->create($project)->getToken();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);
        $guard->setRequest($request);

        $resolved = $guard->user();

        $this->assertInstanceOf(AuthProject::class, $resolved);
        $this->assertTrue($resolved->hasScope(ProjectRead::class));
    }

    public function test_token_scopes_can_only_downscope_the_owner()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $user->scope(ProjectRead::for($project));

        $guard = $this->guard();

        $this->expectException(ScopeEscalationException::class);

        $guard->create($user)
            ->setScopes([ProjectEdit::for($project)])
            ->getToken();
    }

    public function test_token_downscoping_applies_resource_specific_limits()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $otherProject = AuthProject::createTestProject(2);

        $user->scope(ProjectManager::for($project));
        $user->scope(ProjectManager::for($otherProject));

        $guard = $this->guard();
        $token = $guard->create($user)
            ->setScopes([ProjectRead::for($project)])
            ->getToken();
        $parser = new Parser(new JoseEncoder());
        $digest = $parser->parse($token->accessToken)->claims()->get('scp');
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $digest);
        $this->assertSame($digest, $parser->parse($token->refreshToken)->claims()->get('scp'));

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);
        $guard->setRequest($request);

        /** @var AuthUser $resolved */
        $resolved = $guard->user();

        $this->assertTrue($resolved->hasScope(ProjectRead::for($project)));
        $this->assertFalse($resolved->hasScope(ProjectEdit::for($project)));
        $this->assertFalse($resolved->hasScope(ProjectRead::for($otherProject)));
        $this->assertTrue($resolved->tokenHasScope(ProjectRead::for($project)));
        $this->assertFalse($resolved->tokenHasScope(ProjectEdit::for($project)));
        $this->assertTrue($resolved->currentAccessToken()->hasScope(ProjectRead::for($project)));
    }

    public function test_default_token_follows_the_owners_current_scopes()
    {
        $user = AuthUser::createTestUser();
        $user->scope(ProjectRead::class);

        $guard = $this->guard();
        $token = $guard->create($user)->getToken();
        $parser = new Parser(new JoseEncoder());
        $this->assertFalse($parser->parse($token->accessToken)->claims()->has('scp'));
        $this->assertFalse($parser->parse($token->refreshToken)->claims()->has('scp'));
        $this->assertNull($token->tokenFamily->fresh()->scopes);

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);
        $guard->setRequest($request);
        $this->assertTrue($guard->user()->hasScope(ProjectRead::class));
        $this->assertFalse($guard->token()->hasScopeRestrictions());

        $user->unscope(ProjectRead::class);
        $user->scope(ProjectEdit::class);
        $guard->setRequest(clone $request);
        $this->assertFalse($guard->user()->hasScope(ProjectRead::class));
        $this->assertTrue($guard->user()->tokenHasScope(ProjectEdit::class));

        $refreshed = $guard->refresh($token->refreshToken)->refreshToken();
        $this->assertFalse($parser->parse($refreshed->accessToken)->claims()->has('scp'));
        $this->assertFalse($parser->parse($refreshed->refreshToken)->claims()->has('scp'));
        $guard->setToken($refreshed->accessToken);
        $this->assertTrue($guard->user()->hasScope(ProjectEdit::class));
    }

    public function test_explicitly_empty_token_scopes_grant_no_scopes()
    {
        $user = AuthUser::createTestUser();
        $user->scope(ProjectRead::class);

        $guard = $this->guard();
        $token = $guard->create($user)->setScopes([])->getToken();
        $guard->setToken($token->accessToken);

        /** @var AuthUser $resolved */
        $resolved = $guard->user();

        $parser = new Parser(new JoseEncoder());
        $digest = $parser->parse($token->accessToken)->claims()->get('scp');
        $this->assertSame(ScopeClaim::digest([]), $digest);
        $this->assertSame([], $token->tokenFamily->fresh()->scopes);
        $this->assertTrue($guard->token()->hasScopeRestrictions());
        $this->assertTrue($resolved->modelHasScope(ProjectRead::class));
        $this->assertFalse($resolved->tokenHasScope(ProjectRead::class));
        $this->assertFalse($resolved->hasScope(ProjectRead::class));

        $refreshed = $guard->refresh($token->refreshToken)->refreshToken();
        $this->assertSame($digest, $parser->parse($refreshed->accessToken)->claims()->get('scp'));
        $this->assertSame($digest, $parser->parse($refreshed->refreshToken)->claims()->get('scp'));
        $guard->setToken($refreshed->accessToken);
        $this->assertFalse($guard->user()->hasScope(ProjectRead::class));
    }

    public function test_scope_authorization_explains_token_limits()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $user->scope(ProjectManager::for($project));

        $token = $this->guard()->create($user)
            ->setScopes([ProjectRead::for($project)])
            ->getToken();

        $guard = $this->guard();
        $guard->setToken($token->accessToken);
        $resolved = $guard->user();
        $denied = $resolved->inspectScope(ProjectEdit::for($project));

        $this->assertTrue($denied->denied());
        $this->assertSame(ScopeDenialReason::MissingTokenScope->value, $denied->code());
        $this->assertSame(
            'The current access token does not include the required scope.',
            $denied->message(),
        );

        try {
            $resolved->authorizeScope(ProjectEdit::for($project));
            $this->fail('A scope excluded by the token was authorized.');
        } catch (AuthorizationException $exception) {
            $this->assertSame(ScopeDenialReason::MissingTokenScope->value, $exception->response()->code());
        }
    }

    public function test_refresh_preserves_the_original_scope_restrictions()
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $user->scope(ProjectManager::for($project));

        $guard = $this->guard();
        $token = $guard->create($user)
            ->setScopes([ProjectManager::for($project)])
            ->getToken();

        $user->unscope(ProjectManager::for($project));
        $refreshed = $guard->refresh($token->refreshToken)->refreshToken();

        $this->assertSame($token->tokenFamily->scopes, $refreshed->tokenFamily->scopes);
        $parser = new Parser(new JoseEncoder());
        $this->assertSame(
            $parser->parse($token->accessToken)->claims()->get('scp'),
            $parser->parse($refreshed->accessToken)->claims()->get('scp'),
        );
        $guard->setToken($refreshed->accessToken);
        $this->assertFalse($guard->user()->hasScope(ProjectRead::for($project)));
    }

    public function test_scope_digest_is_order_independent_and_distinguishes_resource_bindings(): void
    {
        $global = ['key' => 'key$type$id', 'resource_type' => null, 'resource_id' => null];
        $bound = ['key' => 'key', 'resource_type' => 'type', 'resource_id' => 'id'];
        $scopes = [$global, $bound];
        $this->assertSame(
            ScopeClaim::digest($scopes),
            ScopeClaim::digest(array_reverse($scopes)),
        );
        $this->assertNotSame(ScopeClaim::digest([$global]), ScopeClaim::digest([$bound]));
        $differentResource = array_replace($bound, ['resource_id' => 'other-id']);
        $this->assertNotSame(ScopeClaim::digest([$bound]), ScopeClaim::digest([$differentResource]));
        $this->assertNotSame(ScopeClaim::digest(null), ScopeClaim::digest([]));
    }

    public function test_tokens_can_be_created()
    {
        $user = AuthUser::createTestUser();

        $newToken = $this->guard()->create($user)->getToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $parsedRefreshToken = $parser->parse($newToken->refreshToken);
        $expectedSubject = $user->id.'|'.$user->getMorphClass();

        $this->assertTrue($parsedAccessToken->isRelatedTo($expectedSubject));
        $this->assertSame('at+jwt', $parsedAccessToken->headers()->get('typ'));
        $this->assertSame('rt+jwt', $parsedRefreshToken->headers()->get('typ'));
        $this->assertEquals($newToken->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));
        $this->assertEquals($newToken->tokenFamily->family, $parsedRefreshToken->claims()->get('fam'));
    }

    public function test_access_tokens_cannot_be_used_as_refresh_tokens()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        $this->expectException(TokenInvalidException::class);

        $this->guard()->refresh($token->accessToken);
    }

    public function test_refresh_tokens_cannot_be_used_as_access_tokens()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        $this->expectException(TokenInvalidException::class);

        $this->guard()->setToken($token->refreshToken);
    }

    public function test_access_token_can_use_matching_legacy_scope_claims(): void
    {
        $user = AuthUser::createTestUser();
        $project = AuthProject::createTestProject();
        $user->scope(ProjectRead::for($project));
        $guard = $this->guard();
        $token = $guard->create($user)->setScopes([ProjectRead::for($project)])->getToken();

        $jwt = new JWT();
        $builder = $jwt->create()
            ->withHeader('typ', 'at+jwt')
            ->relatedTo($user->getKey().'|'.$user->getMorphClass())
            ->withClaim('fam', $token->tokenFamily->family);
        $compactClaim = ['project.read$'.rawurlencode($project->getMorphClass()).'$'.$project->getKey()];

        foreach ([$token->tokenFamily->scopes, $compactClaim] as $claim) {
            $guard->setToken($jwt->encode($builder->withClaim('scp', $claim)));
            $this->assertTrue($guard->user()->hasScope(ProjectRead::for($project)));
            $this->assertSame($token->tokenFamily->scopes, $guard->token()->scopes);
        }
    }

    public function test_token_family_scope_restrictions_cannot_be_updated(): void
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->setScopes([])->getToken();
        $family = $token->tokenFamily;
        $family->scopes = null;

        $this->assertException(\LogicException::class, fn () => $family->saveQuietly());
        $this->assertSame([], $family->fresh()->scopes);

        $family->refresh();
        $family->name = 'renamed';
        TokenFamily::updating(static function (TokenFamily $family): void {
            $family->scopes = null;
        });

        try {
            $this->assertException(\LogicException::class, fn () => $family->save());
            $this->assertSame([], $family->fresh()->scopes);
        } finally {
            TokenFamily::flushEventListeners();
        }
    }

    public function test_unrestricted_access_token_rejects_a_restriction_added_to_its_family(): void
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        DB::table('token_families')->where('id', $token->tokenFamily->getKey())->update(['scopes' => '[]']);

        $this->expectException(TokenInvalidException::class);

        $this->guard()->setToken($token->accessToken);
    }

    public function test_restricted_access_and_refresh_tokens_reject_family_changes(): void
    {
        $user = AuthUser::createTestUser();
        $user->scope(ProjectRead::class);
        $guard = $this->guard();
        $token = $guard->create($user)->setScopes([ProjectRead::class])->getToken();
        $refresh = $guard->refresh($token->refreshToken);

        DB::table('token_families')->where('id', $token->tokenFamily->getKey())->update(['scopes' => 'null']);

        $this->assertException(TokenInvalidException::class, fn () => $guard->setToken($token->accessToken));
        $this->assertException(TokenInvalidException::class, fn () => $refresh->refreshToken());
        $this->assertSame(1, $token->tokenFamily->fresh()->last_refresh_sequence);
    }

    public function test_restricted_family_requires_a_digest_on_the_refresh_token(): void
    {
        $user = AuthUser::createTestUser();
        $guard = $this->guard();
        $token = $guard->create($user)->setScopes([])->getToken();
        $jwt = new JWT();
        $legacyToken = $jwt->encode($jwt->create()
            ->withHeader('typ', 'rt+jwt')
            ->withClaim('fam', $token->tokenFamily->family)
            ->withClaim('seq', $token->tokenFamily->last_refresh_sequence));

        $this->expectException(TokenInvalidException::class);

        $guard->refresh($legacyToken)->refreshToken();
    }

    public function test_restricted_family_rejects_invalid_scope_claims(): void
    {
        $user = AuthUser::createTestUser();
        $user->scope(ProjectRead::class);
        $guard = $this->guard();
        $token = $guard->create($user)->setScopes([ProjectRead::class])->getToken();
        $jwt = new JWT();
        $builder = $jwt->create()
            ->withHeader('typ', 'at+jwt')
            ->relatedTo($user->getKey().'|'.$user->getMorphClass())
            ->withClaim('fam', $token->tokenFamily->family);

        $this->assertException(TokenInvalidException::class, fn () => $guard->setToken($jwt->encode($builder)));

        foreach ([null, 'project.read', ScopeClaim::digest([]), [], ['project.read$project'], ['project.edit']] as $claim) {
            $this->assertException(
                TokenInvalidException::class,
                fn () => $guard->setToken($jwt->encode($builder->withClaim('scp', $claim))),
            );
        }
    }

    public function test_tokens_can_override_configured_expirations_with_null()
    {
        config(['hyrnatic-authenticator.family_expiration' => 120]);
        config(['hyrnatic-authenticator.access_expiration' => 60]);
        config(['hyrnatic-authenticator.refresh_expiration' => 30]);

        $user = AuthUser::createTestUser();

        $token = $this->guard()->create($user)
            ->setFamilyExpiresAt(null)
            ->setAccessExpiresAt(null)
            ->setRefreshExpiresAt(null)
            ->getToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($token->accessToken);
        $parsedRefreshToken = $parser->parse($token->refreshToken);

        $this->assertFalse($parsedAccessToken->claims()->has('exp'));
        $this->assertFalse($parsedRefreshToken->claims()->has('exp'));
        $this->assertNull($token->tokenFamily->expires_at);
        $this->assertNull($token->tokenFamily->prune_at);
    }

    public function test_config_expiration_is_anchored_when_new_token_builder_is_created()
    {
        config(['hyrnatic-authenticator.access_expiration' => 60]);
        config(['hyrnatic-authenticator.refresh_expiration' => 30]);

        $user = AuthUser::createTestUser();
        $anchor = now()->copy();
        $builder = $this->guard()->create($user);
        $this->travel(10)->minutes();

        $token = $builder->getToken();
        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($token->accessToken);
        $parsedRefreshToken = $parser->parse($token->refreshToken);

        $this->assertEquals($anchor->copy()->addMinutes(60)->getTimestamp(), $parsedAccessToken->claims()->get('exp')->getTimestamp());
        $this->assertEquals($anchor->copy()->addMinutes(30)->getTimestamp(), $parsedRefreshToken->claims()->get('exp')->getTimestamp());
    }

    public function test_authentication_succeeds()
    {
        $user = AuthUser::createTestUser();
        $expire = now()->addMinute();

        $newToken = $this->guard()->create($user)->setAccessExpiresAt($expire)->getToken();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$newToken->accessToken);

        $guard = $this->guard();
        $guard->setRequest($request);
        $guard->user();

        $this->assertAuthenticated('api');
    }

    public function test_authentication_fails_if_access_token_expired()
    {
        $user = AuthUser::createTestUser();
        $expire = now()->addMinute();

        $newToken = $this->guard()->create($user)->setAccessExpiresAt($expire)->getToken();
        $this->travel(5)->minutes();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$newToken->accessToken);

        $guard = $this->guard();
        $guard->setRequest($request);

        $this->assertException(TokenExpiredException::class, fn () => $guard->retrieveUser($request));
        $this->assertNull($guard->user());
    }

    public function test_guard_requires_a_configured_provider()
    {
        config([
            'auth.guards.broken-api.driver' => 'hyrnatic-authenticator',
            'auth.guards.broken-api.provider' => 'missing-provider',
        ]);

        $this->expectException(InvalidGuardConfigurationException::class);

        $this->guard('broken-api')->validate([]);
    }

    public function test_authentication_fails_if_family_expired()
    {
        $user = AuthUser::createTestUser();
        $expire = now()->addMinute();

        $newToken = $this->guard()->create($user)->setFamilyExpiresAt($expire)->getToken();
        $this->travel(5)->minutes();

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$newToken->accessToken);

        $guard = $this->guard();
        $guard->setRequest($request);

        $this->assertException(TokenExpiredException::class, fn () => $guard->retrieveUser($request));
        $this->assertNull($guard->user());
    }

    public function test_token_can_be_refreshed()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        $guard = $this->guard();
        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);
        $guard->setRequest($request);

        $newToken = $guard->refresh($token->refreshToken)->refreshToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $expectedSubject = $user->id.'|'.$user->getMorphClass();

        $this->assertTrue($parsedAccessToken->isRelatedTo($expectedSubject));
        $this->assertEquals($token->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));
        $this->assertEquals($newToken->tokenFamily->family, $parsedAccessToken->claims()->get('fam'));
    }

    public function test_refresh_can_override_configured_expirations_with_null()
    {
        config(['hyrnatic-authenticator.family_expiration' => null]);
        config(['hyrnatic-authenticator.access_expiration' => 60]);
        config(['hyrnatic-authenticator.refresh_expiration' => 30]);

        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        $newToken = $this->guard()->refresh($token->refreshToken)
            ->setAccessExpiresAt(null)
            ->setRefreshExpiresAt(null)
            ->refreshToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $parsedRefreshToken = $parser->parse($newToken->refreshToken);

        $this->assertFalse($parsedAccessToken->claims()->has('exp'));
        $this->assertFalse($parsedRefreshToken->claims()->has('exp'));
        $this->assertNull($newToken->tokenFamily->prune_at);
    }

    public function test_config_expiration_is_anchored_when_refresh_builder_is_created()
    {
        config(['hyrnatic-authenticator.access_expiration' => 60]);
        config(['hyrnatic-authenticator.refresh_expiration' => 30]);

        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        $anchor = now()->copy();
        $builder = $this->guard()->refresh($token->refreshToken);
        $this->travel(10)->minutes();

        $newToken = $builder->refreshToken();
        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $parsedRefreshToken = $parser->parse($newToken->refreshToken);

        $this->assertEquals($anchor->copy()->addMinutes(60)->getTimestamp(), $parsedAccessToken->claims()->get('exp')->getTimestamp());
        $this->assertEquals($anchor->copy()->addMinutes(30)->getTimestamp(), $parsedRefreshToken->claims()->get('exp')->getTimestamp());
    }

    public function test_refresh_fails_if_expired()
    {
        $user = AuthUser::createTestUser();
        $expire = now()->addMinute();

        $token = $this->guard()->create($user)->setRefreshExpiresAt($expire)->getToken();
        $this->travel(5)->minutes();

        $this->assertException(TokenExpiredException::class, fn () => $this->guard()->refresh($token->refreshToken)->refreshToken());
    }

    public function test_refresh_fails_if_family_expired()
    {
        $user = AuthUser::createTestUser();
        $expire = now()->addMinute();

        $token = $this->guard()->create($user)->setFamilyExpiresAt($expire)->getToken();
        $this->travel(5)->minutes();

        $this->assertException(TokenExpiredException::class, fn () => $this->guard()->refresh($token->refreshToken)->refreshToken());
    }

    public function test_refresh_reuse_detection()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        $guard = $this->guard();
        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);
        $guard->setRequest($request);

        $guard->refresh($token->refreshToken)->refreshToken();

        $this->assertException(RefreshTokenReuseException::class, fn () => $guard->refresh($token->refreshToken)->refreshToken());
        $this->assertException(ModelNotFoundException::class, fn () => $token->tokenFamily->refresh());
        $this->assertNull($guard->user());
    }

    #[DataProvider('refreshTransactionStates')]
    public function test_refresh_rejects_an_outer_transaction_before_changing_the_family(bool $reused): void
    {
        $guard = $this->guard();
        $token = $guard->create(AuthUser::createTestUser())->getToken();
        if ($reused) {
            $guard->refresh($token->refreshToken)->refreshToken();
        }

        $builder = $guard->refresh($token->refreshToken);
        $this->assertException(RefreshTokenTransactionException::class, fn () => DB::transaction(
            fn () => $builder->refreshToken(),
        ));

        $this->assertSame(0, DB::transactionLevel());
        $this->assertSame($reused ? 2 : 1, $token->tokenFamily->fresh()->last_refresh_sequence);

        if ($reused) {
            $this->assertException(RefreshTokenReuseException::class, fn () => $builder->refreshToken());
            $this->assertDatabaseMissing('token_families', ['family' => $token->tokenFamily->family]);
        } else {
            $this->assertSame(2, $builder->refreshToken()->tokenFamily->last_refresh_sequence);
        }
    }

    public static function refreshTransactionStates(): array
    {
        return [
            'current token' => [false],
            'reused token' => [true],
        ];
    }

    public function test_canceled_refresh_save_throws_and_preserves_the_original_refresh_token(): void
    {
        $guard = $this->guard();
        $token = $guard->create(AuthUser::createTestUser())->getToken();
        TokenFamily::updating(fn () => false);

        try {
            $this->assertException(FailedToSaveTokenFamilyException::class, fn () => $guard->refresh($token->refreshToken)->refreshToken());
            $this->assertSame(1, $token->tokenFamily->fresh()->last_refresh_sequence);
        } finally {
            TokenFamily::flushEventListeners();
        }

        $this->assertSame(2, $guard->refresh($token->refreshToken)->refreshToken()->tokenFamily->last_refresh_sequence);
        $this->assertException(RefreshTokenReuseException::class, fn () => $guard->refresh($token->refreshToken)->refreshToken());
        $this->assertDatabaseMissing('token_families', ['family' => $token->tokenFamily->family]);
    }

    public function test_canceled_new_family_save_does_not_return_tokens(): void
    {
        $user = AuthUser::createTestUser();
        TokenFamily::creating(fn () => false);

        try {
            $this->assertException(FailedToSaveTokenFamilyException::class, fn () => $this->guard()->create($user)->getToken());
            $this->assertDatabaseCount('token_families', 0);
        } finally {
            TokenFamily::flushEventListeners();
        }
    }

    public function test_refresh_sequence_is_checked_when_the_builder_is_consumed()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();
        $guard = $this->guard();
        $firstBuilder = $guard->refresh($token->refreshToken);
        $racingBuilder = $guard->refresh($token->refreshToken);

        $firstBuilder->refreshToken();

        try {
            $racingBuilder->refreshToken();
            $this->fail('A consumed refresh sequence was accepted.');
        } catch (RefreshTokenReuseException) {
            $this->assertDatabaseMissing('token_families', ['family' => $token->tokenFamily->family]);
        }
    }

    public function test_refresh_builder_can_only_be_consumed_once()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();
        $builder = $this->guard()->refresh($token->refreshToken);

        $builder->refreshToken();

        $this->expectException(RefreshTokenBuilderConsumedException::class);

        $builder->refreshToken();
    }

    public function test_tokens_has_custom_claims()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)
            ->setAccessClaims(['foo' => 1])
            ->setRefreshClaims(['bar' => 2])
            ->getToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($token->accessToken);
        $parsedRefreshToken = $parser->parse($token->refreshToken);

        $this->assertEquals(1, $parsedAccessToken->claims()->get('foo'));
        $this->assertEquals(2, $parsedRefreshToken->claims()->get('bar'));
    }

    public function test_access_claims_cannot_override_the_token_family()
    {
        $user = AuthUser::createTestUser();

        $this->expectException(ReservedTokenClaimException::class);

        $this->guard()->create($user)->setAccessClaims(['fam' => 'overridden']);
    }

    public function test_access_claims_cannot_override_the_scope_claim()
    {
        $user = AuthUser::createTestUser();

        $this->expectException(ReservedTokenClaimException::class);

        $this->guard()->create($user)->setAccessClaims(['scp' => [['key' => '*']]]);
    }

    public function test_refresh_claims_cannot_override_refresh_sequence()
    {
        $user = AuthUser::createTestUser();

        $this->expectException(ReservedTokenClaimException::class);

        $this->guard()->create($user)->setRefreshClaims(['seq' => 100]);
    }

    public function test_tokens_has_custom_claims_after_refresh()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)
            ->setAccessClaims(['foo' => 1])
            ->setRefreshClaims(['bar' => 2])
            ->getToken();

        $newToken = $this->guard()->refresh($token->refreshToken)->refreshToken();

        $parser = new Parser(new JoseEncoder());
        $parsedAccessToken = $parser->parse($newToken->accessToken);
        $parsedRefreshToken = $parser->parse($newToken->refreshToken);

        $this->assertNotEquals($token->accessToken, $newToken->accessToken);
        $this->assertNotEquals($token->refreshToken, $newToken->refreshToken);
        $this->assertEquals(1, $parsedAccessToken->claims()->get('foo'));
        $this->assertEquals(2, $parsedRefreshToken->claims()->get('bar'));
    }

    public function test_secret_is_required()
    {
        config(['hyrnatic-authenticator.secret' => null]);

        $user = AuthUser::createTestUser();

        $this->assertException(SecretMissingException::class, function () use ($user) {
            $this->guard()->create($user)->getToken();
        });
    }

    public function test_secret_must_contain_at_least_32_bytes()
    {
        config(['hyrnatic-authenticator.secret' => str_repeat('a', 31)]);

        $user = AuthUser::createTestUser();

        $this->expectException(SecretTooShortException::class);

        $this->guard()->create($user)->getToken();
    }

    public function test_tokens_expire_by_default()
    {
        $user = AuthUser::createTestUser();
        $issuedAt = now();

        $token = $this->guard()->create($user)->getToken();
        $parser = new Parser(new JoseEncoder());
        $accessToken = $parser->parse($token->accessToken);
        $refreshToken = $parser->parse($token->refreshToken);

        $this->assertEqualsWithDelta(
            $issuedAt->copy()->addMinutes(15)->timestamp,
            $accessToken->claims()->get('exp')->getTimestamp(),
            2,
        );
        $this->assertEqualsWithDelta(
            $issuedAt->copy()->addDays(30)->timestamp,
            $refreshToken->claims()->get('exp')->getTimestamp(),
            2,
        );
        $this->assertEqualsWithDelta(
            $issuedAt->copy()->addDays(30)->timestamp,
            $token->tokenFamily->expires_at->timestamp,
            2,
        );
    }

    public function test_subject_cannot_be_manipulated()
    {
        $user = AuthUser::createTestUser();
        AuthUser::createTestUser(2);

        $token = $this->guard()->create($user)->getToken();
        $manipulatedToken = $this->tamperSubject($token->accessToken, '2|'.$user->getMorphClass());

        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$manipulatedToken);

        $this->assertException(TokenInvalidException::class, fn () => $this->guard()->retrieveUser($request));
    }

    public function test_guard_can_logout()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        $guard = $this->guard();
        $request = Request::create('/', 'GET');
        $request->headers->set('Authorization', 'Bearer '.$token->accessToken);
        $guard->setRequest($request);

        $this->assertNotNull($guard->user());

        $guard->logout();

        $this->assertNull($guard->user());
        $this->assertException(TokenInvalidException::class, fn () => $guard->retrieveUser($request));
    }

    #[DataProvider('logoutFailures')]
    public function test_logout_propagates_revocation_failures_and_clears_authentication(?string $exceptionClass): void
    {
        $guard = $this->guard();
        $token = $guard->create(AuthUser::createTestUser())->getToken();
        $guard->setToken($token->accessToken);
        $this->assertNotNull($guard->user());

        TokenFamily::deleting(static function () use ($exceptionClass) {
            if ($exceptionClass !== null) {
                throw new $exceptionClass();
            }

            return false;
        });

        try {
            $this->assertException($exceptionClass ?? FailedToDeleteTokenFamilyException::class, fn () => $guard->logout());
            $this->assertFalse($guard->hasUser());
            $this->assertFalse($guard->hasToken());
            $this->assertDatabaseHas('token_families', ['family' => $token->tokenFamily->family]);
        } finally {
            TokenFamily::flushEventListeners();
        }
    }

    public static function logoutFailures(): array
    {
        return [
            'deletion vetoed' => [null],
            'operational failure' => [\RuntimeException::class],
            'invalid token exception during revocation' => [TokenInvalidException::class],
            'expired token exception during revocation' => [TokenExpiredException::class],
        ];
    }

    #[DataProvider('unauthenticatedLogoutStates')]
    public function test_logout_without_a_valid_token_is_a_no_op(string $state): void
    {
        $guard = $this->guard();
        $token = $guard->create(AuthUser::createTestUser())->getToken();
        $request = Request::create('/', 'GET');

        if ($state !== 'missing') {
            $request->headers->set('Authorization', 'Bearer '.($state === 'malformed' ? 'invalid' : $token->accessToken));
        }

        if ($state === 'expired') {
            $this->travel(16)->minutes();
        } elseif ($state === 'revoked') {
            $token->tokenFamily->revoke();
        }

        $guard->setRequest($request);
        $guard->logout();

        $this->assertFalse($guard->hasUser());
        $this->assertFalse($guard->hasToken());
        $this->assertDatabaseCount('token_families', $state === 'revoked' ? 0 : 1);
    }

    public static function unauthenticatedLogoutStates(): array
    {
        return [
            'missing' => ['missing'],
            'malformed' => ['malformed'],
            'expired' => ['expired'],
            'revoked' => ['revoked'],
        ];
    }

    public function test_guard_can_set_token()
    {
        $user = AuthUser::createTestUser();
        $token = $this->guard()->create($user)->getToken();

        $guard = $this->guard();
        $this->assertNull($guard->user());

        $guard->setToken($token->accessToken);

        $this->assertNotNull($guard->user());
    }

    public function test_validate_checks_the_password_without_authenticating(): void
    {
        $user = AuthUser::createTestUser();
        $user->password = Hash::make('correct-password');
        $user->save();
        $guard = $this->guard();

        $this->assertFalse($guard->validate(['email' => $user->email, 'password' => 'wrong-password']));
        $this->assertFalse($guard->validate(['email' => $user->email]));
        $this->assertFalse($guard->validate(['email' => $user->email, 'password' => null]));
        $this->assertFalse($guard->validate(['email' => 'missing@example.com', 'password' => 'correct-password']));
        $this->assertFalse($guard->validate([]));
        $this->assertTrue($guard->validate(['email' => $user->email, 'password' => 'correct-password']));
        $this->assertFalse($guard->hasUser());
        $this->assertFalse($guard->hasToken());
    }

    public function test_custom_token_family_model_is_used_throughout_the_token_lifecycle(): void
    {
        $originalModel = HyrnaticAuthenticator::tokenFamilyModel();
        HyrnaticAuthenticator::useTokenFamilyModel(CustomTokenFamily::class);

        try {
            $user = AuthUser::createTestUser();
            $guard = $this->guard();
            $token = $guard->create($user)->setName('visible')->getToken();

            $this->assertInstanceOf(CustomTokenFamily::class, $token->tokenFamily);
            $this->assertInstanceOf(CustomTokenFamily::class, $user->tokenFamilies()->sole());

            $guard->setToken($token->accessToken);
            $this->assertSame($user->id, $guard->id());
            $this->assertInstanceOf(CustomTokenFamily::class, $guard->token()->tokenFamily);

            $refreshed = $guard->refresh($token->refreshToken)->refreshToken();
            $this->assertInstanceOf(CustomTokenFamily::class, $refreshed->tokenFamily);
            $this->assertSame(2, $refreshed->tokenFamily->last_refresh_sequence);

            $guard->setToken($refreshed->accessToken);
            $guard->logout();
            $this->assertDatabaseMissing('token_families', ['family' => $token->tokenFamily->family]);
        } finally {
            HyrnaticAuthenticator::useTokenFamilyModel($originalModel);
        }
    }

    public function test_custom_token_family_scopes_apply_to_authentication_and_refresh(): void
    {
        $originalModel = HyrnaticAuthenticator::tokenFamilyModel();
        HyrnaticAuthenticator::useTokenFamilyModel(CustomTokenFamily::class);

        try {
            $guard = $this->guard();
            $token = $guard->create(AuthUser::createTestUser())->setName('hidden')->getToken();

            $this->assertDatabaseHas('token_families', ['family' => $token->tokenFamily->family]);
            $this->assertException(TokenInvalidException::class, fn () => $guard->setToken($token->accessToken));
            $this->assertException(TokenFamilyNotFoundException::class, fn () => $guard->refresh($token->refreshToken));
        } finally {
            HyrnaticAuthenticator::useTokenFamilyModel($originalModel);
        }
    }

    #[DataProvider('expirationSettings')]
    public function test_configured_expiration_values(mixed $minutes, bool $valid): void
    {
        $user = AuthUser::createTestUser();
        $parser = new Parser(new JoseEncoder());
        $this->travelTo(now()->startOfSecond());

        foreach (['access', 'refresh', 'family'] as $kind) {
            $configKey = "hyrnatic-authenticator.{$kind}_expiration";
            $originalValue = config($configKey);
            config([$configKey => $minutes]);

            try {
                if (!$valid) {
                    $this->assertException(\InvalidArgumentException::class, fn () => $this->guard()->create($user));
                    $this->assertDatabaseCount('token_families', 0);
                    continue;
                }

                $token = $this->guard()->create($user)->getToken();
                $expiresAt = match ($kind) {
                    'access' => $parser->parse($token->accessToken)->claims()->get('exp'),
                    'refresh' => $parser->parse($token->refreshToken)->claims()->get('exp'),
                    'family' => $token->tokenFamily->fresh()->expires_at,
                };

                if ($minutes === null) {
                    $this->assertNull($expiresAt);
                } else {
                    $this->assertSame(now()->addMinutes((float) $minutes)->getTimestamp(), $expiresAt->getTimestamp());
                }
            } finally {
                config([$configKey => $originalValue]);
            }
        }
    }

    public static function expirationSettings(): array
    {
        return [
            'null disables expiry' => [null, true],
            'integer zero' => [0, false],
            'string zero' => ['0', false],
            'float zero' => [0.0, false],
            'string decimal zero' => ['0.0', false],
            'integer minutes' => [15, true],
            'string minutes' => ['15', true],
            'fractional minutes' => [0.5, true],
            'string fractional minutes' => ['0.5', true],
            'false' => [false, false],
            'true' => [true, false],
            'empty string' => ['', false],
            'nonnumeric string' => ['invalid', false],
            'negative minutes' => [-1, false],
            'negative string minutes' => ['-1', false],
            'infinity' => [INF, false],
            'not a number' => [NAN, false],
        ];
    }

    private function guard(string $name = 'api'): Guard
    {
        /** @var Guard $guard */
        $guard = $this->app->make(AuthFactory::class)->guard($name);

        return $guard;
    }

    private function tamperSubject(string $jwt, string $subject): string
    {
        [$header, $payload, $signature] = explode('.', $jwt);
        $decodedPayload = json_decode(base64_decode(strtr($payload, '-_', '+/')), true, 512, JSON_THROW_ON_ERROR);
        $decodedPayload['sub'] = $subject;

        $tamperedPayload = rtrim(strtr(base64_encode(json_encode($decodedPayload, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        return implode('.', [$header, $tamperedPayload, $signature]);
    }
}
