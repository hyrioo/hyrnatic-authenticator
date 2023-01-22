<?php

namespace Hyrioo\HyrnaticAuthenticator;

use DateTimeInterface;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Illuminate\Support\Str;

trait HasApiTokens
{
    /**
     * The access token the user is using for the current request.
     *
     * @var \Hyrioo\HyrnaticAuthenticator\Contracts\HasAbilities
     */
    protected $accessToken;

    /**
     * Get the access tokens that belong to model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany
     */
    public function accessTokens()
    {
        return $this->morphMany(HyrnaticAuthenticator::$personalAccessTokenModel, 'authable');
    }

    /**
     * Get the refresh tokens that belong to model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany
     */
    public function refreshTokens()
    {
        return $this->morphMany(HyrnaticAuthenticator::$personalRefreshTokenModel, 'authable');
    }

    /**
     * Determine if the current API token has a given scope.
     *
     * @param  string  $scope
     * @return bool
     */
    public function tokenCan(string $scope)
    {
        return $this->accessToken && $this->accessToken->can($scope);
    }

    /**
     * Create a new personal access token for the user.
     *
     * @param  string  $name
     * @param  array  $abilities
     * @param  \DateTimeInterface|null  $expiresAt
     * @return \Hyrioo\HyrnaticAuthenticator\NewToken
     */
    public function createToken(string $name = null, array $scopes = ['*'], DateTimeInterface $accessExpiresAt = null, DateTimeInterface $refreshExpiresAt = null)
    {
        $family = Str::random(40);

        [$accessToken, $plainTextAccessToken] = $this->createAccessToken($family, $name, $scopes, $accessExpiresAt);
        [$refreshToken, $plainTextRefreshToken] = $this->createRefreshToken($family, 1, $refreshExpiresAt);

        $this->accessTokens()->save($accessToken);
        $this->refreshTokens()->save($refreshToken);

        return new NewToken($accessToken, $refreshToken, $accessToken->getKey().'|'.$plainTextAccessToken, $refreshToken->getKey().'|'.$plainTextRefreshToken);
    }

    private function createAccessToken(string $family, string $name = null, array $scopes = ['*'], DateTimeInterface $expiresAt = null): array
    {
        $plainTextAccessToken = Str::random(40);

        /** @var PersonalAccessToken $accessToken */
        $accessToken = new HyrnaticAuthenticator::$personalAccessTokenModel();
        $accessToken->name = $name;
        $accessToken->family = $family;
        $accessToken->token = hash('sha256', $plainTextAccessToken);
        $accessToken->scopes = $scopes;
        $accessToken->expires_at = $expiresAt;

        return [$accessToken, $plainTextAccessToken];
    }

    private function createRefreshToken(string $family, int $order, DateTimeInterface $expiresAt = null): array
    {
        $plainTextRefreshToken = Str::random(40);

        /** @var PersonalRefreshToken $refreshToken */
        $refreshToken = new HyrnaticAuthenticator::$personalRefreshTokenModel();
        $refreshToken->family = $family;
        $refreshToken->token = hash('sha256', $plainTextRefreshToken);
        $refreshToken->order = $order;
        $refreshToken->expires_at = $expiresAt;

        return [$refreshToken, $plainTextRefreshToken];
    }

    public function refreshToken(string $token, DateTimeInterface $accessExpiresAt = null, DateTimeInterface $refreshExpiresAt = null)
    {
        $refreshToken = PersonalRefreshToken::findToken($token);

        if(!$refreshToken->isMostRecent()) {
            PersonalRefreshToken::invalidateFamily($refreshToken->family);
            throw new RefreshTokenReuseException();
        } else {
            $accessToken = PersonalAccessToken::findByFamily($refreshToken->family);

            $plainTextAccessToken = Str::random(40);
            $accessToken->token = hash('sha256', $plainTextAccessToken);
            $accessToken->expires_at = $accessExpiresAt;
            $accessToken->save();
            [$refreshToken, $plainTextRefreshToken] = $this->createRefreshToken($refreshToken->family, $refreshToken->order + 1, $refreshExpiresAt);

            $this->refreshTokens()->save($refreshToken);

            return new NewToken($accessToken, $refreshToken, $accessToken->getKey().'|'.$plainTextAccessToken, $refreshToken->getKey().'|'.$plainTextRefreshToken);
        }
    }

    /**
     * Get the access token currently associated with the user.
     *
     * @return \Hyrioo\HyrnaticAuthenticator\Contracts\HasAbilities
     */
    public function currentAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Set the current access token for the user.
     *
     * @param  \Hyrioo\HyrnaticAuthenticator\Contracts\HasAbilities  $accessToken
     * @return $this
     */
    public function withAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }
}
