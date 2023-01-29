<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Carbon\CarbonInterface;
use Exception;
use Hyrioo\HyrnaticAuthenticator\Exceptions\FailedToDeleteTokenFamilyException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;

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
     * Determine if the current API token has a given scope.
     *
     * @param string $scope
     * @return bool
     */
    public function tokenCan(string $scope): bool
    {
        return $this->accessToken && $this->accessToken->can($scope);
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
     * @return $this
     */
    public function withAccessToken(PersonalAccessToken $accessToken): \Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens
    {
        $this->accessToken = $accessToken;

        return $this;
    }
}
