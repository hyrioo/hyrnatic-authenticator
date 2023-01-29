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

class TokenBuilderBase
{
    protected Contracts\HasApiTokens $model;

    protected array $scopes = ['*'];

    protected array $accessClaims = [];
    protected array $refreshClaims = [];

    protected ?CarbonInterface $accessExpiresAt = null;
    protected ?CarbonInterface $refreshExpiresAt = null;

    protected JWT $jwt;

    public function __construct(\Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens $model)
    {
        $this->model = $model;
        $this->jwt = new JWT();
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

    protected function createAccessToken(string $family, ?DateTimeImmutable $expiresAt): string
    {
        $subject = $this->model->getKey().'|'.$this->model->getMorphClass();
        $tokenBuilder = $this->jwt->create()
            ->issuedAt(now()->toImmutable())
            ->relatedTo($subject)
            ->withClaim('fam', $family)
            ->withClaim('scp', $this->scopes);

        foreach ($this->accessClaims as $name => $claim) {
            $tokenBuilder->withClaim($name, $claim);
        }

        if($expiresAt) {
            $tokenBuilder->expiresAt($expiresAt);
        }

        return $this->jwt->encode($tokenBuilder);
    }

    protected function createRefreshToken(string $family, int $sequence, ?DateTimeImmutable $expiresAt): string
    {
        $tokenBuilder = $this->jwt->create()
            ->issuedAt(now()->toImmutable())
            ->withClaim('fam', $family)
            ->withClaim('seq', $sequence);

        foreach ($this->refreshClaims as $name => $claim) {
            $tokenBuilder->withClaim($name, $claim);
        }

        if($expiresAt) {
            $tokenBuilder->expiresAt($expiresAt);
        }

        return $this->jwt->encode($tokenBuilder);
    }
}
