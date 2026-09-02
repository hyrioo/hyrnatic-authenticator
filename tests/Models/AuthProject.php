<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests\Models;

use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens as HasApiTokensContract;
use Hyrioo\HyrnaticAuthenticator\Traits\HasApiTokens;
use Illuminate\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

class AuthProject extends Model implements HasApiTokensContract
{
    use Authenticatable;
    use HasApiTokens;

    protected $table = 'projects';

    protected $guarded = [];

    public static function createTestProject(int $id = 1): self
    {
        $project = new self();
        $project->id = $id;
        $project->name = "Project {$id}";
        $project->save();

        return $project;
    }
}
