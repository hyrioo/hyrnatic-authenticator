<?php

namespace Hyrioo\HyrnaticAuthenticator\Exceptions;

use RuntimeException;

class SecretTooShortException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('JWT_SECRET must contain at least 32 bytes.');
    }
}
