<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests\Scopes;

use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;
use Hyrioo\HyrnaticAuthenticator\Tests\Models\AuthProject;

final class ProjectManager extends Scope
{
    public static function scopeKey(): string
    {
        return 'project.manager';
    }

    public static function allowedResourceType(): ?string
    {
        return AuthProject::class;
    }

    public static function subScopes(): array
    {
        return [
            ProjectRead::class,
            ProjectEdit::class,
        ];
    }
}
