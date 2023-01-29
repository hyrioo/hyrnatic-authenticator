[![Latest Version on Packagist](https://img.shields.io/packagist/v/hyrioo/hyrnatic-authenticator.svg?style=flat-square)](https://packagist.org/packages/hyrioo/hyrnatic-authenticator)
[![GitHub Tests Action Status](https://img.shields.io/github/workflow/status/hyrioo/hyrnatic-authenticator/run-tests?label=tests)](https://github.com/hyrioo/hyrnatic-authenticator/actions?query=workflow%3Arun-tests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/workflow/status/hyrioo/hyrnatic-authenticator/Check%20&%20fix%20styling?label=code%20style)](https://github.com/hyrioo/hyrnatic-authenticator/actions?query=workflow%3A"Check+%26+fix+styling"+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/hyrioo/hyrnatic-authenticator.svg?style=flat-square)](https://packagist.org/packages/hyrioo/hyrnatic-authenticator)

## Installation

You can install the package via composer:

```bash
composer require hyrioo/hyrnatic-authenticator
```

```bash
php artisan vendor:publish --provider="Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticatorServiceProvider"
```

You can publish and run the migrations with:

```bash
php artisan vendor:publish --tag="hyrnatic-authenticator-migrations"
php artisan migrate
```

You can publish the config file with:

```bash
php artisan vendor:publish --tag="hyrnatic-authenticator-config"
```

## Usage

### Update user model
Add the `Hyrioo\HyrnaticAuthenticator\HasApiTokens` trait to your user model.
```php
use Hyrioo\HyrnaticAuthenticator\HasApiTokens;
 
class User extends Authenticatable
{
    use HasApiTokens;
}
```

### Configure auth guard
Add `hyrnatic-authenticator` as the driver to your api guard.  
*Example:*
```php
'guards' => [
        'api' => [
            'driver' => 'hyrnatic-authenticator',
            'provider' => 'users',
        ],
    ],
```

### Issuing tokens
```php
$builder = auth('api')->create($user) // NewTokenBuilder
$builder->setName('Phone');
$builder->setScopes(['photo.*']);
$builder->setFamilyExpiresAt(now()->addYear());
$builder->setAccessExpiresAt(now()->addMinutes(5));
$builder->setRefreshExpiresAt(now()->addMonth());

$token = $builder->getToken();
$token->accessToken;
$token->refreshToken;
```

### Refresh token
```php
$builder = auth('api')->refresh($request->refresh_token); // RefreshTokenBuilder
$builder->setAccessExpiresAt(now()->addMinutes(5));
$builder->setRefreshExpiresAt(now()->addMonth());

$token = $builder->refreshToken();
$token->accessToken;
$token->refreshToken;
```

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](https://github.com/spatie/.github/blob/main/CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Hyrioo](https://github.com/msp@hyrioo.com)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
