<?php

namespace Hyrioo\HyrnaticAuthenticator\Enums;

enum ScopeDenialReason: string
{
    case MissingModelScope = 'missing_model_scope';

    case MissingTokenScope = 'missing_token_scope';
}
