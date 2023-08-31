<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

abstract class Permission extends Scope
{
    public function can(): bool
    {
        return true;
    }
}
