<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

abstract class PermissionGroup extends Scope
{
    public static array $permissions;

    public static function getKey() {
        return '$'.static::$key;
    }
}
