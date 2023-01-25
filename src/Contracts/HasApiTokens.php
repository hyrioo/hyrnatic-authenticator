<?php

namespace Hyrioo\HyrnaticAuthenticator\Contracts;

use Carbon\CarbonInterface;
use Hyrioo\HyrnaticAuthenticator\NewToken;
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
     * @param  string  $scope
     * @return bool
     */
    public function tokenCan(string $scope): bool;

    /**
     * Create a new tokens for the user.
     *
     * @param string|null $name
     * @param array $scopes
     * @param CarbonInterface|null $familyExpiresAt
     * @param CarbonInterface|null $accessExpiresAt
     * @param CarbonInterface|null $refreshExpiresAt
     * @return NewToken
     */
    public function createToken(string $name = null, array $scopes = ['*'], CarbonInterface $familyExpiresAt = null, CarbonInterface $accessExpiresAt = null, CarbonInterface $refreshExpiresAt = null): NewToken;

    /**
     * Refreshes the access token and rotates the refresh token
     * @param string $jwtToken
     * @param CarbonInterface|null $accessExpiresAt
     * @param CarbonInterface|null $refreshExpiresAt
     * @return NewToken
     */
    public static function refreshToken(string $jwtToken, CarbonInterface $accessExpiresAt = null, CarbonInterface $refreshExpiresAt = null): NewToken;

    /**
     * Get the access token currently associated with the user.
     *
     * @return PersonalAccessToken
     */
    public function currentAccessToken(): PersonalAccessToken;

    /**
     * Set the current access token for the user.
     *
     * @param PersonalAccessToken $accessToken
     * @return HasApiTokens
     */
    public function withAccessToken(PersonalAccessToken $accessToken): HasApiTokens;
}
