# Scopes

### Create permission

```php
use Hyrioo\HyrnaticAuthenticator\Models\Permission;
 
class ProjectCreate extends Permission
{
    public static string $key = 'project.create';
}

class ProjectEdit extends Permission
{
    public static string $key = 'project.edit';
}
```

### Create permission group
  
```php
use App\Permissions\ProjectCreate;
use Hyrioo\HyrnaticAuthenticator\Models\PermissionGroup;

class DefaultUser extends PermissionGroup
{
    public static string $key = 'default_user';

    public static array $permissions = [
        ProjectCreate::class,
        ProjectEdit::class,
    ];
}
```

### Register them
Register your permissions and groups in the `AuthServiceProvider.php`
```php
public function boot()
{
    // ...
    
    HyrnaticAuthenticator::registerPermissions([
        ProjectCreate::class,
        ProjectEdit::class,
    ]);
    
    HyrnaticAuthenticator::registerPermissionGroups([
        DefaultUser::class,
    ]);
}
```

### Assign scope to user
```php
$user = auth()->user();
$user->assignScope(new DefaultUser);
```

### Check for scopes

```php
$user = auth()->user();

// Check if the user has the permission globally assigned.
if(!$user->modelCan(new ProjectCreate)) {
    return Response::deny(__('auth.you_dont_have_sufficient_permissions_for_this'));
}
// Check if the user is assigned a permission for a specific model.
if(!$user->modelCan(new ProjectEdit, $project)) {
    return Response::deny(__('auth.you_dont_have_sufficient_permissions_for_this'));
}

// Check if the current token has the permission.
if(!$user->tokenCan(new ProjectCreate)) {
    return Response::deny(__('auth.your_access_token_dont_have_sufficient_permissions_for_this'));
}
// Check if the current token has permission for a specific model.
if(!$user->tokenCan(new ProjectEdit, $project)) {
    return Response::deny(__('auth.your_access_token_dont_have_sufficient_permissions_for_this'));
}
```
