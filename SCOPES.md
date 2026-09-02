# Scopes

Everything in the authorization model is a scope.

- Leaf scopes represent a single capability.
- Composite scopes define `sub_scopes`.
- Custom scopes created by end users are stored in the `scopes` table.
- Tokens may only downscope their owner's effective scopes.

## Code-defined scopes

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

Register them:

```php
HyrnaticAuthenticator::registerScopes([
    ProjectRead::class,
    ProjectEdit::class,
    ProjectManager::class,
]);
```

Scope keys must be globally unique across code-defined scopes. Duplicate keys are rejected at registration time.
Code-defined scopes must be registered before they can be assigned, checked, or issued in a token.

## Assigning and checking scopes

```php
$user->scope(ProjectRead::class);
$user->scope(ProjectEdit::for($project));
$user->scope(ProjectManager::for($project));

$user->hasScope(ProjectRead::class);
$user->hasScope(ProjectEdit::for($project));
```

Use `inspectScope()` when the denial reason is needed, or `authorizeScope()` to throw Laravel's `AuthorizationException` with that response:

```php
$response = $user->inspectScope(ProjectEdit::for($project));
$user->authorizeScope(ProjectEdit::for($project));
```

`hasScope()` checks the model's effective scopes and applies the current token's limits when the model was authenticated by a token. Use `modelHasScope()` to check only the model or `tokenHasScope()` to explicitly require a current token.

Laravel's `can()` method is not overridden, so policy and gate checks remain unchanged:

```php
$user->can('update', $project);
```

## Wildcards

Wildcard scopes are supported in v1.

- `*`
- `project.*`
- resource-bound `project.*`

Example:

```php
final class ProjectWildcard extends Scope
{
    public static function scopeKey(): string
    {
        return 'project.*';
    }

    public static function allowedResourceType(): ?string
    {
        return Project::class;
    }
}
```

## Custom scopes

Create custom scopes through the typed model API. Internal keys and database fields are managed by the package:

```php
$manager = \Hyrioo\HyrnaticAuthenticator\Models\Scope::create(
    name: 'Project manager',
    subScopes: [ProjectRead::class, ProjectEdit::class],
    resourceType: Project::class,
    metadata: ['created_by' => $user->getKey()],
);
```

`subScopes` accepts registered code-scope classes and existing persisted scope objects. Raw scope-key strings and raw mass assignment are rejected.

## Token downscoping

```php
$token = auth('api')->create($user)
    ->setScopes([
        ProjectRead::for($project),
        ProjectEdit::for($project),
    ])
    ->getToken();
```

The token receives only those scopes, and they must already be allowed for the authable owner.
If `setScopes()` is omitted, the token inherits the owner's effective scopes. Calling `setScopes([])` explicitly issues a token with no scopes.
