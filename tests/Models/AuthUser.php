<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests\Models;

use Hyrioo\HyrnaticAuthenticator\HasApiTokens;
use Illuminate\Foundation\Auth\User;
use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens as HasApiTokensContract;

class AuthUser extends User implements HasApiTokensContract
{
    use HasApiTokens;

    protected $table = 'users';

    public static function createTestUser($id = 1)
    {
        $user = new self();
        $user->id = $id;
        $user->name = 'John Doe';
        $user->email = "user+{$id}@example.com";
        $user->password = 'password';
        $user->save();

        return $user;
    }
}
