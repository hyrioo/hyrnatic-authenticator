<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Carbon\CarbonInterface;
use DateTimeImmutable;
use Illuminate\Support\Str;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;

class TokenBuilder
{
    private Contracts\HasApiTokens $model;

    private ?string $name = null;

    private array $scopes = ['*'];

    private array $accessClaims = [];
    private array $refreshClaims = [];

    private ?CarbonInterface $familyExpiresAt = null;
    private ?CarbonInterface $accessExpiresAt = null;
    private ?CarbonInterface $refreshExpiresAt = null;

    public function __construct(\Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens $model)
    {
        $this->model = $model;
    }

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

    public function setFamilyExpiresAt(CarbonInterface $expiresAt): static
    {
        $this->familyExpiresAt = $expiresAt;

        return $this;
    }

    public function setAccessExpiresAt(CarbonInterface $expiresAt): static
    {
        $this->accessExpiresAt = $expiresAt;

        return $this;
    }
    public function setRefreshExpiresAt(CarbonInterface $expiresAt): static
    {
        $this->refreshExpiresAt = $expiresAt;

        return $this;
    }

    protected static function getTokenExpiration(string $key, CarbonInterface $expiresAt = null): ?DateTimeImmutable
    {
        if($expiresAt) {
            return $expiresAt->toDateTimeImmutable();
        } else {
            $minutes = config("hyrnatic-authenticator.{$key}_expiration");
            return $minutes ? now()->addMinutes($minutes)->toImmutable() : null;
        }
    }

    protected static function getFamilyTokenExpiration(CarbonInterface $expiresAt = null): ?DateTimeImmutable
    {
        return self::getTokenExpiration('family', $expiresAt);
    }

    protected static function getAccessTokenExpiration(CarbonInterface $expiresAt = null): ?DateTimeImmutable
    {
        return self::getTokenExpiration('access', $expiresAt);
    }

    protected static function getRefreshTokenExpiration(CarbonInterface $expiresAt = null): ?DateTimeImmutable
    {
        return self::getTokenExpiration('refresh', $expiresAt);
    }

    private function createAccessToken(string $family): string
    {
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
        $algorithm = new Sha256();
        $signingKey = InMemory::plainText(config('hyrnatic-authenticator.secret'));
        $now = now();
        $expiresAt = self::getAccessTokenExpiration($this->accessExpiresAt);

        $subject = $this->model->getKey().'|'.$this->model->getMorphClass();
        $token = $tokenBuilder
            ->issuedAt($now->toImmutable())
            ->relatedTo($subject)
            ->withClaim('fam', $family)
            ->withClaim('scp', $this->scopes);

        foreach ($this->accessClaims as $name => $claim) {
            $token->withClaim($name, $claim);
        }

        if($expiresAt) {
            $token->expiresAt($expiresAt);
        }
        $token = $token->getToken($algorithm, $signingKey);

        return $token->toString();
    }

    private function createRefreshToken(string $family, int $sequence): string
    {
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
        $algorithm = new Sha256();
        $signingKey = InMemory::plainText(config('hyrnatic-authenticator.secret'));
        $now = now();
        $expiresAt = self::getRefreshTokenExpiration($this->refreshExpiresAt);

        $token = $tokenBuilder
            ->issuedAt($now->toImmutable())
            ->withClaim('fam', $family)
            ->withClaim('seq', $sequence);

        foreach ($this->refreshClaims as $name => $claim) {
            $token->withClaim($name, $claim);
        }

        if($expiresAt) {
            $token->expiresAt($expiresAt);
        }
        $token = $token->getToken($algorithm, $signingKey);

        return $token->toString();
    }

    public function getToken(): NewToken
    {
        $family = Str::random(48);

        $tokenFamily = new TokenFamily();
        $tokenFamily->name = $this->name;
        $tokenFamily->family = $family;
        $tokenFamily->scopes = $this->scopes;
        $tokenFamily->expires_at = self::getFamilyTokenExpiration($this->familyExpiresAt);
        $tokenFamily->last_refresh_sequence = 1;

        $accessToken = $this->createAccessToken($family);
        $refreshToken = $this->createRefreshToken($family, $tokenFamily->last_refresh_sequence);

        $this->model->tokenFamilies()->save($tokenFamily);

        return new NewToken($tokenFamily, $accessToken, $refreshToken);
    }
}
