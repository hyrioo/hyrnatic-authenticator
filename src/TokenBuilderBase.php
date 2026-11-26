<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Carbon\CarbonInterface;
use DateTimeImmutable;
use Hyrioo\HyrnaticAuthenticator\Contracts\Scopeable;
use Hyrioo\HyrnaticAuthenticator\Exceptions\ReservedTokenClaimException;
use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;
use Hyrioo\HyrnaticAuthenticator\Scopes\ScopeResolver;
use Illuminate\Database\Eloquent\Model;

class TokenBuilderBase
{
    public const TOKEN_TYPE_ACCESS = 'at+jwt';

    public const TOKEN_TYPE_REFRESH = 'rt+jwt';

    private const RESERVED_CLAIMS = [
        'iss',
        'sub',
        'aud',
        'exp',
        'nbf',
        'iat',
        'jti',
        'fam',
        'scp',
        'seq',
    ];

    protected Contracts\HasApiTokens&Model $model;

    /**
     * @var list<class-string<Scope>|Scopeable>
     */
    protected ?array $scopes = null;

    protected array $accessClaims = [];
    protected array $refreshClaims = [];

    protected ?CarbonInterface $accessExpiresAt = null;
    protected ?CarbonInterface $refreshExpiresAt = null;

    protected JWT $jwt;

    protected ScopeResolver $scopeResolver;

    public function __construct(\Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens $model)
    {
        if (!$model instanceof Model) {
            throw new \InvalidArgumentException('Token authables must be Eloquent models.');
        }

        $this->model = $model;
        $this->accessExpiresAt = $this->getConfigTokenExpiration('access');
        $this->refreshExpiresAt = $this->getConfigTokenExpiration('refresh');
        $this->jwt = new JWT();
        $this->scopeResolver = app(ScopeResolver::class);
    }

    public function setAccessExpiresAt(?CarbonInterface $expiresAt): static
    {
        $this->accessExpiresAt = $expiresAt;

        return $this;
    }

    public function setRefreshExpiresAt(?CarbonInterface $expiresAt): static
    {
        $this->refreshExpiresAt = $expiresAt;

        return $this;
    }

    protected function getConfigTokenExpiration(string $key): ?CarbonInterface
    {
        $minutes = config("hyrnatic-authenticator.{$key}_expiration");

        if ($minutes === null) {
            return null;
        }

        if (!is_numeric($minutes) || !is_finite((float) $minutes) || $minutes <= 0) {
            throw new \InvalidArgumentException(
                "The hyrnatic-authenticator.{$key}_expiration setting must be a positive number of minutes or null."
            );
        }

        return now()->addMinutes((float) $minutes);
    }

    protected static function getTokenExpiration(CarbonInterface $expiresAt = null): ?DateTimeImmutable
    {
        return $expiresAt?->toDateTimeImmutable();
    }

    protected static function getFamilyTokenExpiration(CarbonInterface $expiresAt = null): ?DateTimeImmutable
    {
        return self::getTokenExpiration($expiresAt);
    }

    protected static function getAccessTokenExpiration(CarbonInterface $expiresAt = null): ?DateTimeImmutable
    {
        return self::getTokenExpiration($expiresAt);
    }

    protected static function getRefreshTokenExpiration(CarbonInterface $expiresAt = null): ?DateTimeImmutable
    {
        return self::getTokenExpiration($expiresAt);
    }

    protected static function getPruneAt(?CarbonInterface $familyExpiresAt, ?CarbonInterface $refreshExpiresAt): ?DateTimeImmutable
    {
        if ($familyExpiresAt === null && $refreshExpiresAt === null) {
            return null;
        }

        if ($familyExpiresAt === null) {
            return $refreshExpiresAt->toImmutable();
        }

        if ($refreshExpiresAt === null) {
            return $familyExpiresAt->toImmutable();
        }

        if ($familyExpiresAt->lt($refreshExpiresAt)) {
            return $familyExpiresAt->toImmutable();
        }

        return $refreshExpiresAt->toImmutable();
    }

    protected function createAccessToken(
        string $family,
        ?DateTimeImmutable $expiresAt,
        ?string $scopeDigest,
    ): string {
        $this->assertClaimsAreNotReserved($this->accessClaims);

        $subject = $this->model->getKey().'|'.$this->model->getMorphClass();
        $tokenBuilder = $this->jwt->create()
            ->withHeader('typ', self::TOKEN_TYPE_ACCESS)
            ->issuedAt(now()->toImmutable())
            ->relatedTo($subject)
            ->withClaim('fam', $family);

        if ($scopeDigest !== null) {
            $tokenBuilder = $tokenBuilder->withClaim('scp', $scopeDigest);
        }

        foreach ($this->accessClaims as $name => $claim) {
            $tokenBuilder = $tokenBuilder->withClaim($name, $claim);
        }

        if ($expiresAt) {
            $tokenBuilder = $tokenBuilder->expiresAt($expiresAt);
        }

        return $this->jwt->encode($tokenBuilder);
    }

    protected function createRefreshToken(
        string $family,
        int $sequence,
        ?DateTimeImmutable $expiresAt,
        ?string $scopeDigest,
    ): string {
        $this->assertClaimsAreNotReserved($this->refreshClaims);

        $tokenBuilder = $this->jwt->create()
            ->withHeader('typ', self::TOKEN_TYPE_REFRESH)
            ->issuedAt(now()->toImmutable())
            ->withClaim('fam', $family)
            ->withClaim('seq', $sequence);

        if ($scopeDigest !== null) {
            $tokenBuilder = $tokenBuilder->withClaim('scp', $scopeDigest);
        }

        foreach ($this->refreshClaims as $name => $claim) {
            $tokenBuilder = $tokenBuilder->withClaim($name, $claim);
        }

        if ($expiresAt) {
            $tokenBuilder = $tokenBuilder->expiresAt($expiresAt);
        }

        return $this->jwt->encode($tokenBuilder);
    }

    protected function assertClaimsAreNotReserved(array $claims): void
    {
        $reservedClaims = array_values(array_intersect(array_keys($claims), self::RESERVED_CLAIMS));

        if ($reservedClaims !== []) {
            throw new ReservedTokenClaimException(
                'The following token claims are reserved: '.implode(', ', $reservedClaims).'.'
            );
        }
    }
}
