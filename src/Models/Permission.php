<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

abstract class Permission
{
    protected static string $key;

    public static function getKey() {
        return static::$key;
    }
}
