<?php

namespace Hyrioo\HyrnaticAuthenticator\Contracts;

use Hyrioo\HyrnaticAuthenticator\Models\Permission;
use Hyrioo\HyrnaticAuthenticator\PersonalAccessToken;
use Illuminate\Database\Eloquent\Relations\MorphMany;

interface HasApiTokens
{
    /**
     * Get the access tokens that belong to model.
     *
     * @return MorphMany
     */
    public function tokenFamilies(): MorphMany;

    /**
     * Determine if the current API token has a given scope.
     *
     * @param Permission $permission
     * @param null $model
     * @return bool
     */
    public function tokenCan(Permission $permission, $model = null): bool;

    /**
     * Get the access token currently associated with the user.
     *
     * @return ?PersonalAccessToken
     */
    public function currentAccessToken(): ?PersonalAccessToken;

    /**
     * Set the current access token for the user.
     *
     * @param PersonalAccessToken $accessToken
     * @return HasApiTokens
     */
    public function withAccessToken(PersonalAccessToken $accessToken): HasApiTokens;
}
