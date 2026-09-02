<?php

namespace Hyrioo\HyrnaticAuthenticator\Contracts;

use Hyrioo\HyrnaticAuthenticator\PersonalAccessToken;
use Illuminate\Auth\Access\Response;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Relations\MorphMany;

interface HasApiTokens extends Authenticatable
{
    public function tokenFamilies(): MorphMany;

    public function modelScopes(): MorphMany;

    /**
     * @param class-string<\Hyrioo\HyrnaticAuthenticator\Scopes\Scope>|Scopeable $scope
     */
    public function hasScope(string|Scopeable $scope): bool;

    /**
     * @param class-string<\Hyrioo\HyrnaticAuthenticator\Scopes\Scope>|Scopeable $scope
     */
    public function inspectScope(string|Scopeable $scope): Response;

    /**
     * @param class-string<\Hyrioo\HyrnaticAuthenticator\Scopes\Scope>|Scopeable $scope
     */
    public function authorizeScope(string|Scopeable $scope): Response;

    /**
     * @param class-string<\Hyrioo\HyrnaticAuthenticator\Scopes\Scope>|Scopeable $scope
     */
    public function modelHasScope(string|Scopeable $scope): bool;

    /**
     * @param class-string<\Hyrioo\HyrnaticAuthenticator\Scopes\Scope>|Scopeable $scope
     */
    public function tokenHasScope(string|Scopeable $scope): bool;

    /**
     * @param class-string<\Hyrioo\HyrnaticAuthenticator\Scopes\Scope>|Scopeable $scope
     */
    public function scope(string|Scopeable $scope): void;

    /**
     * @param class-string<\Hyrioo\HyrnaticAuthenticator\Scopes\Scope>|Scopeable $scope
     */
    public function unscope(string|Scopeable $scope): void;

    public function currentAccessToken(): ?PersonalAccessToken;

    public function withAccessToken(PersonalAccessToken $accessToken): HasApiTokens;
}
