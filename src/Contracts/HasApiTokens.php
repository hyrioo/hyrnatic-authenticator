<?php

namespace Hyrioo\HyrnaticAuthenticator\Contracts;

use Carbon\CarbonInterface;
use DateTimeInterface;

interface HasApiTokens
{
    /**
     * Get the access tokens that belong to model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany
     */
    public function tokenFamilies();


    /**
     * Determine if the current API token has a given scope.
     *
     * @param  string  $ability
     * @return bool
     */
    public function tokenCan(string $ability);

    /**
     * Create a new personal access token for the user.
     *
     * @param  string  $name
     * @param  array  $abilities
     * @return \Hyrioo\HyrnaticAuthenticator\NewToken
     */
    public function createToken(string $name = null, array $scopes = ['*'], CarbonInterface $familyExpiresAt = null, CarbonInterface $accessExpiresAt = null, CarbonInterface $refreshExpiresAt = null);

    /**
     * Get the access token currently associated with the user.
     *
     * @return \Hyrioo\HyrnaticAuthenticator\Contracts\HasAbilities
     */
    public function currentAccessToken();

    /**
     * Set the current access token for the user.
     *
     * @param  \Hyrioo\HyrnaticAuthenticator\Contracts\HasAbilities  $accessToken
     * @return \Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens
     */
    public function withAccessToken($accessToken);
}
