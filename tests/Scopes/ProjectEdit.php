<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests\Scopes;

use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthProject;

final class ProjectEdit extends Scope
{
    public static function scopeKey(): string
    {
        return 'project.edit';
    }

    public static function allowedResourceType(): ?string
    {
        return AuthProject::class;
    }
}
