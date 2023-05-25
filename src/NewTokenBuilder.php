<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Carbon\CarbonInterface;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;

class NewTokenBuilder extends TokenBuilderBase
{
    private ?string $name = null;

    private ?CarbonInterface $familyExpiresAt = null;

    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    public function setScopes(array $scopes): static
    {
        $this->scopes = $scopes;

        return $this;
    }

    public function setAccessClaims(array $claims): static
    {
        $this->accessClaims = $claims;

        return $this;
    }

    public function setRefreshClaims(array $claims): static
    {
        $this->refreshClaims = $claims;

        return $this;
    }

    public function setFamilyExpiresAt(CarbonInterface $expiresAt): static
    {
        $this->familyExpiresAt = $expiresAt;

        return $this;
    }

    public function getToken(): NewToken
    {
        $family = Str::random(48);

        $tokenFamily = new TokenFamily();
        $tokenFamily->name = $this->name;
        $tokenFamily->family = $family;
        $tokenFamily->scopes = $this->scopes;
        $tokenFamily->access_claims = $this->accessClaims;
        $tokenFamily->refresh_claims = $this->refreshClaims;
        $tokenFamily->expires_at = self::getFamilyTokenExpiration($this->familyExpiresAt);
        $tokenFamily->last_refresh_sequence = 1;
        $refreshExpiresAt = self::getRefreshTokenExpiration($this->refreshExpiresAt);
        $tokenFamily->prune_at = self::getPruneAt($tokenFamily->expires_at, Date::make($refreshExpiresAt));

        $accessToken = $this->createAccessToken($family, self::getAccessTokenExpiration($this->accessExpiresAt));
        $refreshToken = $this->createRefreshToken($family, $tokenFamily->last_refresh_sequence, $refreshExpiresAt);

        $this->model->tokenFamilies()->save($tokenFamily);

        return new NewToken($tokenFamily, $accessToken, $refreshToken);
    }
}
