<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

abstract class PermissionGroup
{
    protected static string $key;

    public static array $permissions;

    public static function getKey() {
        return '$'.static::$key;
    }
}
