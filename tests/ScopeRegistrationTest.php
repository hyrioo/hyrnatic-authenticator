<?php

namespace Hyrioo\HyrnaticAuthenticator\Tests;

use Hyrioo\HyrnaticAuthenticator\Exceptions\DuplicateScopeKeyException;
use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\DuplicateProjectRead;
use Hyrioo\HyrnaticAuthenticator\Tests\Scopes\ProjectRead;

class ScopeRegistrationTest extends TestCase
{
    public function test_registering_the_same_scope_class_twice_is_idempotent()
    {
        HyrnaticAuthenticator::registerScopes([ProjectRead::class]);
        HyrnaticAuthenticator::registerScopes([ProjectRead::class]);

        $this->assertSame(ProjectRead::class, HyrnaticAuthenticator::scopeClassForKey('project.read'));
        $this->assertSame('project.read', HyrnaticAuthenticator::scopeKeyForClass(ProjectRead::class));
    }

    public function test_registering_two_scope_classes_with_the_same_key_fails()
    {
        HyrnaticAuthenticator::registerScopes([ProjectRead::class]);

        $this->expectException(DuplicateScopeKeyException::class);

        HyrnaticAuthenticator::registerScopes([DuplicateProjectRead::class]);
    }
}
