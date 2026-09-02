<?php

namespace Hyrioo\HyrnaticAuthenticator\Traits;

use Hyrioo\HyrnaticAuthenticator\Contracts\Scopeable;
use Hyrioo\HyrnaticAuthenticator\Models\ModelScope;
use Hyrioo\HyrnaticAuthenticator\PersonalAccessToken;
use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;
use Hyrioo\HyrnaticAuthenticator\Scopes\ScopeResolver;
use Illuminate\Auth\Access\Response;
use Illuminate\Database\Eloquent\Relations\MorphMany;

trait HasApiTokens
{
    protected ?PersonalAccessToken $accessToken = null;

    public function tokenFamilies(): MorphMany
    {
        return $this->morphMany(\Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator::$tokenFamilyModel, 'authable');
    }

    public function modelScopes(): MorphMany
    {
        return $this->morphMany(ModelScope::class, 'authable');
    }

    public function currentAccessToken(): ?PersonalAccessToken
    {
        return $this->accessToken;
    }

    public function withAccessToken(PersonalAccessToken $accessToken): \Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function hasScope(string|Scopeable $scope): bool
    {
        return $this->inspectScope($scope)->allowed();
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function inspectScope(string|Scopeable $scope): Response
    {
        return $this->scopeResolver()->inspectScope($this, $scope, $this->currentAccessToken());
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function authorizeScope(string|Scopeable $scope): Response
    {
        return $this->inspectScope($scope)->authorize();
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function modelHasScope(string|Scopeable $scope): bool
    {
        return $this->scopeResolver()->hasScope($this, $scope);
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function tokenHasScope(string|Scopeable $scope): bool
    {
        if ($this->accessToken === null) {
            return false;
        }

        return $this->scopeResolver()->hasScope($this, $scope, $this->accessToken);
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function scope(string|Scopeable $scope): void
    {
        $this->scopeResolver()->scope($this, $scope);
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function unscope(string|Scopeable $scope): void
    {
        $this->scopeResolver()->unscope($this, $scope);
    }

    private function scopeResolver(): ScopeResolver
    {
        return app(ScopeResolver::class);
    }

}
