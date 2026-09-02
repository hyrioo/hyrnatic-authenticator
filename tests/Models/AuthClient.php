<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests\Models;

use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens as HasApiTokensContract;
use Hyrioo\HyrnaticAuthenticator\Traits\HasApiTokens;
use Illuminate\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

class AuthClient extends Model implements HasApiTokensContract
{
    use Authenticatable;
    use HasApiTokens;

    protected $table = 'api_clients';

    protected $guarded = [];

    public $incrementing = false;

    protected $keyType = 'string';
}
