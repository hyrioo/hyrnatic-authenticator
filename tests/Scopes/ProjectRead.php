<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests\Scopes;

use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthProject;

final class ProjectRead extends Scope
{
    public static function scopeKey(): string
    {
        return 'project.read';
    }

    public static function allowedResourceType(): ?string
    {
        return AuthProject::class;
    }
}
