<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests\Models;

use Hyrioo\HyrnaticAuthenticator\HasApiTokens;
use Illuminate\Foundation\Auth\User;
use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens as HasApiTokensContract;

class AuthUser extends User implements HasApiTokensContract
{
    use HasApiTokens;

    protected $table = 'users';

    public static function createTestUser()
    {
        $user = new self();
        $user->id = 1;
        $user->name = 'John Doe';
        $user->email = 'user@example.com';
        $user->password = 'password';
        $user->save();

        return $user;
    }
}
