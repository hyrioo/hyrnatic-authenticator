<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Carbon\CarbonInterface;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Illuminate\Support\Str;

class RefreshTokenBuilder extends TokenBuilderBase
{
    private TokenFamily $tokenFamily;

    public function __construct(Contracts\HasApiTokens $model, TokenFamily $tokenFamily)
    {
        parent::__construct($model);
        $this->tokenFamily = $tokenFamily;
        $this->scopes = $tokenFamily->scopes;
        $this->accessClaims = $tokenFamily->access_claims;
        $this->refreshClaims = $tokenFamily->refresh_claims;
    }

    public function refreshToken(): NewToken
    {
        $newSequence = $this->tokenFamily->last_refresh_sequence + 1;
        $family = $this->tokenFamily->family;

        $this->tokenFamily->last_refresh_sequence = $newSequence;
        $this->tokenFamily->prune_at = $refreshExpiresAt = self::getRefreshTokenExpiration($this->refreshExpiresAt);

        $accessToken = $this->createAccessToken($family, self::getAccessTokenExpiration($this->accessExpiresAt));
        $refreshToken = $this->createRefreshToken($family, $newSequence, $refreshExpiresAt);

        $this->tokenFamily->save();

        return new NewToken($this->tokenFamily, $accessToken, $refreshToken);
    }
}
