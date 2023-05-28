<?php

namespace Hyrioo\HyrnaticAuthenticator\Traits;

use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Models\ModelHasScope;
use Hyrioo\HyrnaticAuthenticator\PersonalAccessToken;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Collection;

trait HasApiTokens
{
    /**
     * The access token the user is using for the current request.
     *
     * @var ?PersonalAccessToken
     */
    protected ?PersonalAccessToken $accessToken = null;

    /**
     * Get the access tokens that belong to model.
     *
     * @return MorphMany
     */
    public function tokenFamilies(): MorphMany
    {
        return $this->morphMany(HyrnaticAuthenticator::$tokenFamilyModel, 'authable');
    }

    /**
     * Get the access token currently associated with the user.
     *
     * @return ?PersonalAccessToken
     */
    public function currentAccessToken(): ?PersonalAccessToken
    {
        return $this->accessToken;
    }

    /**
     * Set the current access token for the user.
     *
     * @param PersonalAccessToken $accessToken
     * @return \Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens
     */
    public function withAccessToken(PersonalAccessToken $accessToken): \Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * Determine if the authable has a given permission
     * @param string $permission
     * @param $model
     * @return bool
     */
    public function modelCan(string $permission, $model = null): bool
    {
        $scopes = ModelHasScope::query()->whereMorphedTo('authable', $this)->where(function(Builder $q) use ($model) {
            if($model === null) {
                $q->whereNull('model_id')->whereNull('model_type');
            } else {
                $q->whereMorphedTo('model', $model)->orWhere(function(Builder $q) {
                    $q->whereNull('model_id')->whereNull('model_type');
                });
            }
        })->get();
        $compilePermissions = self::compilePermissions($scopes->pluck('scope')->values()->all());

        return $compilePermissions->has($permission);
    }

    /**
     * Determine if the current API token has a given permission.
     *
     * @param string $permission
     * @param $model
     * @return bool
     */
    public function tokenCan(string $permission, $model = null): bool
    {
        $compilePermissions = self::compilePermissionsFromToken($this->accessToken->scopes);
        $matchingScope = $compilePermissions->get($permission);

        return !($matchingScope === null || ($model !== null && !self::matchingIdentifier($matchingScope, $model->getKey())));
    }

    private static function compilePermissions(array $scopes): Collection
    {
        $permissions = collect();

        foreach ($scopes as $scope) {
            self::expandScope($scope, $permissions);
        }

        return $permissions->flip();
    }

    private static function expandScope($scope, &$permissions): void
    {
        if ($scope[0] === '$') {
            $class = HyrnaticAuthenticator::$permissionGroups[$scope];
            foreach ($class::$permissions as $permission) {
                $key = $permission::$key;
                self::expandScope($key, $permissions);
            }
        } else {
            $permissions->push($scope);
        }
    }

    private static function compilePermissionsFromToken(array $scopes): Collection
    {
        $permissions = collect();

        foreach ($scopes as $scope) {
            self::expandScope($scope, $permissions);
        }

        return $permissions->mapWithKeys(function ($item) {
            preg_match('/([\w.]+?)(\[(.*)])?$/', $item, $matches);
            $key = $matches[1];
            $ids = isset($matches[3]) ? explode(',', $matches[3]) : null;
            return [$key => $ids];
        });
    }

    private static function matchingIdentifier(array $ids, mixed $key): bool
    {
        if(in_array('ALL', $ids, true)) {
            return true;
        }

        return in_array((string) $key, $ids, true);
    }
}
