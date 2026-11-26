<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests\Models;

use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Illuminate\Database\Eloquent\Builder;

class CustomTokenFamily extends TokenFamily
{
    protected $table = 'token_families';

    protected static function booted(): void
    {
        static::addGlobalScope('visible', fn (Builder $query) => $query->where('name', 'visible'));
    }
}
