<?php

namespace Hyrioo\HyrnaticAuthenticator\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator
 */
class HyrnaticAuthenticator extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'hyrnatic-authenticator';
    }
}
