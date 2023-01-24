<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Carbon\CarbonInterface;
use DateTimeImmutable;
use DateTimeInterface;
use Hyrioo\HyrnaticAuthenticator\Exceptions\FailedToDeleteTokenFamilyException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Illuminate\Support\Str;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use PHPUnit\Util\Exception;

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
    public function tokenFamilies()
    {
        return $this->morphMany(HyrnaticAuthenticator::$personalAccessTokenModel, 'authable');
    }

    /**
     * Determine if the current API token has a given scope.
     *
     * @param string $scope
     * @return bool
     */
    public function tokenCan(string $scope)
    {
        return $this->accessToken && $this->accessToken->can($scope);
    }

    /**
     * Create a new personal access token for the user.
     *
     * @param string $name
     * @param array $abilities
     * @param \DateTimeInterface|null $expiresAt
     * @return \Hyrioo\HyrnaticAuthenticator\NewToken
     */
    public function createToken(string $name = null, array $scopes = ['*'], CarbonInterface $familyExpiresAt = null, CarbonInterface $accessExpiresAt = null, CarbonInterface $refreshExpiresAt = null)
    {
        $family = Str::random(48);

        $tokenFamily = new TokenFamily();
        $tokenFamily->name = $name;
        $tokenFamily->family = $family;
        $tokenFamily->scopes = $scopes;
        $tokenFamily->expires_at = self::getFamilyTokenExpiration($familyExpiresAt);
        $tokenFamily->last_refresh_sequence = 1;

        $accessToken = $this->createAccessToken($family, $scopes, self::getAccessTokenExpiration($accessExpiresAt));
        $refreshToken = $this->createRefreshToken($family, $tokenFamily->last_refresh_sequence, self::getRefreshTokenExpiration($refreshExpiresAt));

        $this->tokenFamilies()->save($tokenFamily);

        return new NewToken($tokenFamily, $accessToken, $refreshToken);
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

    private function createAccessToken(string $family, array $scopes = ['*'], DateTimeImmutable $expiresAt = null): string
    {
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
        $algorithm = new Sha256();
        $signingKey = InMemory::plainText(config('hyrnatic-authenticator.secret'));
        $now = now();

        $subject = $this->getKey().'|'.$this->getMorphClass();
        $token = $tokenBuilder
            ->issuedAt($now->toImmutable())
            ->relatedTo($subject)
            ->withClaim('fam', $family)
            ->withClaim('scp', $scopes);

        if($expiresAt) {
            $token->expiresAt($expiresAt);
        }
        $token = $token->getToken($algorithm, $signingKey);

        return $token->toString();
    }

    private function createRefreshToken(string $family, int $sequence, DateTimeImmutable $expiresAt = null): string
    {
        $tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
        $algorithm = new Sha256();
        $signingKey = InMemory::plainText(config('hyrnatic-authenticator.secret'));
        $now = now();

        $token = $tokenBuilder
            ->issuedAt($now->toImmutable())
            ->withClaim('fam', $family)
            ->withClaim('seq', $sequence);

        if($expiresAt) {
            $token->expiresAt($expiresAt);
        }
        $token = $token->getToken($algorithm, $signingKey);

        return $token->toString();
    }

    /**
     * @throws FailedToDeleteTokenFamilyException
     * @throws RefreshTokenReuseException
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public static function refreshToken(string $jwtToken, CarbonInterface $accessExpiresAt = null, CarbonInterface $refreshExpiresAt = null)
    {
        $parser = new Parser(new JoseEncoder());
        try {
            $token = $parser->parse($jwtToken);
        } catch (\Exception $e) {
            throw new TokenInvalidException();
        }

        if($token->isExpired(now())) {
            throw new TokenExpiredException();
        }

        $family = $token->claims()->get('fam');
        $sequence = (int) $token->claims()->get('seq');

        $tokenFamily = TokenFamily::findTokenFamily($family);

        if (!$tokenFamily->isMostRecentRefresh($sequence)) {
            $tokenFamily->invalidate();
            throw new RefreshTokenReuseException();
        } else {
            $newSequence = $tokenFamily->last_refresh_sequence + 1;

            $accessToken = $tokenFamily->authable->createAccessToken($family, $tokenFamily->scopes, self::getAccessTokenExpiration($accessExpiresAt));
            $refreshToken = $tokenFamily->authable->createRefreshToken($family, $newSequence, self::getRefreshTokenExpiration($refreshExpiresAt));

            $tokenFamily->last_refresh_sequence = $newSequence;
            $tokenFamily->save();

            return new NewToken($tokenFamily, $accessToken, $refreshToken);
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
     * @param \Hyrioo\HyrnaticAuthenticator\Contracts\HasAbilities $accessToken
     * @return $this
     */
    public function withAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }
}
