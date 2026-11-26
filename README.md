[![Latest Version on Packagist](https://img.shields.io/packagist/v/hyrioo/hyrnatic-authenticator.svg?style=flat-square)](https://packagist.org/packages/hyrioo/hyrnatic-authenticator)
[![Tests](https://github.com/hyrioo/hyrnatic-authenticator/actions/workflows/tests.yml/badge.svg)](https://github.com/hyrioo/hyrnatic-authenticator/actions/workflows/tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/hyrioo/hyrnatic-authenticator.svg?style=flat-square)](https://packagist.org/packages/hyrioo/hyrnatic-authenticator)

**JWT based authentication for Laravel**  
With refresh tokens, token downscoping, and a flexible scope system.

## Installation

```bash
composer require hyrioo/hyrnatic-authenticator
php artisan vendor:publish --tag="hyrnatic-authenticator-config"
php artisan vendor:publish --tag="hyrnatic-authenticator-migrations"
php artisan authenticator:secret
php artisan migrate
```

`JWT_SECRET` is required and must contain at least 32 bytes. The generator writes a cryptographically random 64-character value. Do not reuse this value between applications or commit it to source control.

The generator updates Laravel's configured environment file, supports quoted values, and reports failure if it cannot safely replace the file. After rotating a secret, rebuild any configuration cache and restart long-running workers.

Tokens expire by default: access tokens after 15 minutes, refresh tokens after 30 days, and token families after 30 days. Override these limits with `JWT_ACCESS_EXPIRATION`, `JWT_REFRESH_EXPIRATION`, and `JWT_FAMILY_EXPIRATION`, expressed in minutes. Setting an expiration to `null` explicitly disables it and should only be done deliberately.

Expiration values must be positive numbers of minutes; numeric strings from environment variables are accepted. Zero, boolean, nonnumeric, negative, and non-finite values throw `InvalidArgumentException`.

## Usage

Add the `Hyrioo\HyrnaticAuthenticator\Traits\HasApiTokens` trait to any model that should own tokens and scopes.

```php
use Hyrioo\HyrnaticAuthenticator\Traits\HasApiTokens;
use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens as HasApiTokensContract;

class User extends Authenticatable implements HasApiTokensContract
{
    use HasApiTokens;
}
```

Configure the guard:

```php
'guards' => [
    'api' => [
        'driver' => 'hyrnatic-authenticator',
        'provider' => 'users',
    ],
    'project-api' => [
        'driver' => 'hyrnatic-authenticator',
        'provider' => 'projects',
    ],
],

'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model' => App\Models\User::class,
    ],
    'projects' => [
        'driver' => 'eloquent',
        'model' => App\Models\Project::class,
    ],
],
```

Each `hyrnatic-authenticator` guard is bound to exactly one provider model. A `Project` token must be created, refreshed, and authenticated through a guard backed by the `projects` provider; it will be rejected on a `users` guard.

## Scopes

Define scopes in code by extending `Hyrioo\HyrnaticAuthenticator\Scopes\Scope`.

```php
use App\Models\Project;
use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;

final class ProjectRead extends Scope
{
    public static function scopeKey(): string
    {
        return 'project.read';
    }

    public static function allowedResourceType(): ?string
    {
        return Project::class;
    }
}

final class ProjectManager extends Scope
{
    public static function scopeKey(): string
    {
        return 'project.manager';
    }

    public static function allowedResourceType(): ?string
    {
        return Project::class;
    }

    public static function subScopes(): array
    {
        return [
            ProjectRead::class,
            ProjectEdit::class,
        ];
    }
}
```

Register code-defined scopes once at boot time:

```php
HyrnaticAuthenticator::registerScopes([
    ProjectRead::class,
    ProjectEdit::class,
    ProjectManager::class,
]);
```

Scope keys must be unique across all registered scope classes. Registering two different classes with the same `scopeKey()` now fails immediately.

Assign scopes:

```php
$user->scope(ProjectRead::class);
$user->scope(ProjectEdit::for($project));
$user->scope(ProjectManager::for($project));
```

Check scopes:

```php
$user->hasScope(ProjectRead::class);
$user->hasScope(ProjectEdit::for($project));
```

Inspect a decision or authorize and throw with a denial reason:

```php
$response = $user->inspectScope(ProjectEdit::for($project));
$user->authorizeScope(ProjectEdit::for($project));
```

Scope checks use their own API and do not override Laravel's `can()` method. Policies and gates continue to work normally:

```php
$user->can('update', $project);
```

Create end-user-defined scopes without handling database columns or raw scope keys:

```php
$manager = \Hyrioo\HyrnaticAuthenticator\Models\Scope::create(
    name: 'Project manager',
    subScopes: [ProjectRead::class, ProjectEdit::class],
    resourceType: Project::class,
);

$user->scope($manager->for($project));
```

The package generates the internal key. `subScopes` accepts registered code-scope classes or existing unbound persisted scope objects. Bound children are rejected; bind the parent scope with `for($resource)` instead.

## Issuing tokens

Tokens may only downscope the owner. Any requested token scope must already be allowed for the authable model.

```php
$token = auth('api')->create($user)
    ->setScopes([
        ProjectRead::for($project),
        ProjectEdit::for($project),
    ])
    ->getToken();
```

Omit `setScopes()` for a token that follows the owner's current scopes. Scope checks use the owner's assignments at request time, so grants and removals apply to existing default tokens. Call `setScopes([...])` to limit a token, such as an API key, to specific scopes. Calling `setScopes([])` explicitly denies all scope checks for that token.

Default tokens omit `scp`. Restricted access and refresh tokens carry a 43-character SHA-256 digest of the restrictions stored on their token family. The guard rejects a digest that differs from the stored restrictions. Family restrictions are fixed at issuance. Revoke the old family and issue a new one to change an API key's access.

Custom JWT claims cannot use registered JWT claim names or the package-owned `fam`, `scp`, and `seq` names.

## Refresh tokens

Refreshing a token verifies the digest against the locked token family before issuing new tokens. Existing access tokens with scope lists in `scp` remain valid when those lists match the family's restrictions. Restricted families with older refresh tokens that lack a digest require reissuance.

Refresh tokens are single-use. Reusing one, including through concurrent duplicate requests, revokes the entire token family.

Call `refreshToken()` outside any existing database transaction on the token-family connection. It throws `RefreshTokenTransactionException` otherwise, so a caller's rollback cannot undo replay-triggered revocation. Tests that refresh tokens should use Laravel's `DatabaseMigrations` rather than the transaction-wrapping `RefreshDatabase` or `DatabaseTransactions` traits.

Token creation and refresh throw `FailedToSaveTokenFamilyException` if a model event cancels persistence; no token pair is returned.

```php
$token = auth('api')->refresh($request->refresh_token)
    ->setAccessExpiresAt(now()->addMinutes(5))
    ->setRefreshExpiresAt(now()->addMonth())
    ->refreshToken();
```

## Logout

`auth('api')->logout()` revokes the current token family and always clears the guard's cached authentication. Missing, invalid, expired, or already-revoked tokens are treated as a no-op. Failures while resolving a token other than validation errors, and all failures while revoking its family, propagate to the caller so logout is not reported as successful when revocation fails.

## Testing

```bash
composer check
```

The test suite selects its database through the standard `DB_CONNECTION`, `DB_HOST`, `DB_PORT`, `DB_DATABASE`, `DB_USERNAME`, and `DB_PASSWORD` variables. CI runs every test against SQLite, MySQL 8, and PostgreSQL 16 on Laravel 10, 11, 12, and 13.

Laravel 10 and 11 are retained as compatibility targets but are end-of-life upstream. Their CI jobs permit Composer to resolve the final releases despite known framework advisories; the release quality gate and dependency audit remain strict on the supported Laravel 12 and 13 stacks.

Local Docker examples:

```bash
docker compose run --rm php composer test
docker compose run --rm -e DB_CONNECTION=mysql php composer test
docker compose run --rm -e DB_CONNECTION=pgsql php composer test
```

## Releases

Push an annotated semantic-version tag such as `v1.0.0`. The release workflow runs the complete quality and compatibility matrix, then creates a GitHub release with generated notes. Invalid or lightweight tags are rejected.
