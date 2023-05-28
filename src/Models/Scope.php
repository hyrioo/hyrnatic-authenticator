<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

abstract class Scope
{
    protected static string $key;

    public static function getKey() {
        return static::$key;
    }
}
