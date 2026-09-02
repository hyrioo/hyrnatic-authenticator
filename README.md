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

Tokens expire by default: access tokens after 15 minutes, refresh tokens after 30 days, and token families after 30 days. Override these limits with `JWT_ACCESS_EXPIRATION`, `JWT_REFRESH_EXPIRATION`, and `JWT_FAMILY_EXPIRATION`, expressed in minutes. Setting an expiration to `null` explicitly disables it and should only be done deliberately.

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

The package generates the internal key. `subScopes` accepts registered code-scope classes or existing persisted scope objects.

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

If `setScopes()` is not called, the token inherits the authable model's effective scopes as a snapshot. Calling `setScopes([])` explicitly issues a token with no scopes.

Custom JWT claims cannot use registered JWT claim names or the package-owned `fam`, `scp`, and `seq` names.

## Refresh tokens

Refreshing a token preserves the original token scope snapshot.

Refresh tokens are single-use. Reusing one, including through concurrent duplicate requests, revokes the entire token family.

```php
$token = auth('api')->refresh($request->refresh_token)
    ->setAccessExpiresAt(now()->addMinutes(5))
    ->setRefreshExpiresAt(now()->addMonth())
    ->refreshToken();
```

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
