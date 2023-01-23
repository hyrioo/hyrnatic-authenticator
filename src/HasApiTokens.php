<?php

namespace Hyrioo\HyrnaticAuthenticator;

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
    public function createToken(string $name = null, array $scopes = ['*'], DateTimeInterface $expiresAt = null)
    {
        $family = Str::random(48);

        $tokenFamily = new TokenFamily();
        $tokenFamily->name = $name;
        $tokenFamily->family = $family;
        $tokenFamily->scopes = $scopes;
        $tokenFamily->expires_at = $expiresAt;
        $tokenFamily->last_refresh_sequence = 1;

        $accessToken = $this->createAccessToken($family, $scopes, now()->addMinutes(30)->toImmutable());
        $refreshToken = $this->createRefreshToken($family, $tokenFamily->last_refresh_sequence, now()->addYear()->toImmutable());

        $this->tokenFamilies()->save($tokenFamily);

        return new NewToken($tokenFamily, $accessToken, $refreshToken);
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
            ->expiresAt($expiresAt)
            ->relatedTo($subject)
            ->withClaim('fam', $family)
            ->withClaim('scp', $scopes)
            ->getToken($algorithm, $signingKey);

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
            ->expiresAt($expiresAt)
            ->withClaim('fam', $family)
            ->withClaim('seq', $sequence)
            ->getToken($algorithm, $signingKey);

        return $token->toString();
    }

    /**
     * @throws FailedToDeleteTokenFamilyException
     * @throws RefreshTokenReuseException
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function refreshToken(string $jwtToken)
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
        } else {
            $newSequence = $tokenFamily->last_refresh_sequence + 1;

            $accessToken = $this->createAccessToken($family, $tokenFamily->scopes, now()->addMinutes(30)->toImmutable());
            $refreshToken = $this->createRefreshToken($family, $newSequence, now()->addYear()->toImmutable());

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
