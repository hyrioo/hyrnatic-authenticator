<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Carbon\CarbonInterface;
use Hyrioo\HyrnaticAuthenticator\Contracts\Scopeable;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Str;

class NewTokenBuilder extends TokenBuilderBase
{
    private ?string $name = null;

    private ?CarbonInterface $familyExpiresAt = null;

    public function __construct(\Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens $model)
    {
        parent::__construct($model);
        $this->familyExpiresAt = $this->getConfigTokenExpiration('family');
    }

    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    /**
     * @param list<class-string<Scope>|Scopeable> $scopes
     */
    public function setScopes(array $scopes): static
    {
        $this->scopes = $scopes;

        return $this;
    }

    public function setAccessClaims(array $claims): static
    {
        $this->assertClaimsAreNotReserved($claims);
        $this->accessClaims = $claims;

        return $this;
    }

    public function setRefreshClaims(array $claims): static
    {
        $this->assertClaimsAreNotReserved($claims);
        $this->refreshClaims = $claims;

        return $this;
    }

    public function setFamilyExpiresAt(?CarbonInterface $expiresAt): static
    {
        $this->familyExpiresAt = $expiresAt;

        return $this;
    }

    public function getToken(): NewToken
    {
        $this->scopeResolver->assertScopesCanBeIssued($this->model, $this->scopes ?? []);

        $family = Str::random(48);
        $scopeSnapshot = $this->getScopeSnapshot();

        $tokenFamily = new TokenFamily();
        $tokenFamily->name = $this->name;
        $tokenFamily->family = $family;
        $tokenFamily->scopes = $scopeSnapshot;
        $tokenFamily->access_claims = $this->accessClaims;
        $tokenFamily->refresh_claims = $this->refreshClaims;
        $familyExpiresAt = self::getFamilyTokenExpiration($this->familyExpiresAt);
        $tokenFamily->setAttribute('expires_at', $familyExpiresAt);
        $tokenFamily->last_refresh_sequence = 1;
        $refreshExpiresAt = self::getRefreshTokenExpiration($this->refreshExpiresAt);
        $tokenFamily->setAttribute(
            'prune_at',
            self::getPruneAt(Date::make($familyExpiresAt), Date::make($refreshExpiresAt)),
        );

        $accessToken = $this->createAccessToken(
            $family,
            self::getAccessTokenExpiration($this->accessExpiresAt),
            $scopeSnapshot,
        );
        $refreshToken = $this->createRefreshToken($family, $tokenFamily->last_refresh_sequence, $refreshExpiresAt);

        $this->model->tokenFamilies()->save($tokenFamily);

        return new NewToken($tokenFamily, $accessToken, $refreshToken);
    }
}
