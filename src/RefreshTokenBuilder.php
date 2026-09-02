<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Closure;
use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenBuilderConsumedException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\RefreshTokenReuseException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenFamilyNotFoundException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Date;

class RefreshTokenBuilder extends TokenBuilderBase
{
    private TokenFamily $tokenFamily;

    private int $expectedSequence;

    private bool $consumed = false;

    private ?Closure $onReuse;

    public function __construct(
        HasApiTokens $model,
        TokenFamily $tokenFamily,
        int $expectedSequence,
        ?Closure $onReuse = null,
    )
    {
        parent::__construct($model);
        $this->tokenFamily = $tokenFamily;
        $this->expectedSequence = $expectedSequence;
        $this->onReuse = $onReuse;
        $this->accessClaims = $tokenFamily->access_claims;
        $this->refreshClaims = $tokenFamily->refresh_claims;
    }

    public function refreshToken(): NewToken
    {
        if ($this->consumed) {
            throw new RefreshTokenBuilderConsumedException('A refresh token builder may only be consumed once.');
        }

        $this->consumed = true;
        $reuseDetected = false;
        $connection = $this->tokenFamily->getConnection();
        $tokenFamilyClass = $this->tokenFamily::class;
        $tokenFamilyId = $this->tokenFamily->getKey();

        /** @var NewToken|null $newToken */
        $newToken = $connection->transaction(function () use (
            &$reuseDetected,
            $tokenFamilyClass,
            $tokenFamilyId,
        ): ?NewToken {
            /** @var TokenFamily|null $lockedFamily */
            $lockedFamily = $tokenFamilyClass::query()
                ->whereKey($tokenFamilyId)
                ->lockForUpdate()
                ->first();

            if ($lockedFamily === null) {
                throw new TokenFamilyNotFoundException();
            }

            if ($lockedFamily->family !== $this->tokenFamily->family) {
                throw new TokenInvalidException();
            }

            if (!$lockedFamily->isMostRecentRefresh($this->expectedSequence)) {
                $lockedFamily->revoke();
                $reuseDetected = true;

                return null;
            }

            if ($lockedFamily->expires_at && $lockedFamily->expires_at->isBefore(now())) {
                throw new TokenExpiredException();
            }

            $authable = $lockedFamily->authable;
            $expectedAuthableClass = $this->model::class;
            if (!$authable instanceof HasApiTokens
                || !$authable instanceof Model
                || $authable::class !== $expectedAuthableClass
                || !$authable->is($this->model)
            ) {
                throw new TokenInvalidException();
            }

            $this->model = $authable;
            $this->tokenFamily = $lockedFamily;
            $this->accessClaims = $lockedFamily->access_claims;
            $this->refreshClaims = $lockedFamily->refresh_claims;

            $newSequence = $this->expectedSequence + 1;
            $family = $lockedFamily->family;
            $lockedFamily->last_refresh_sequence = $newSequence;
            $refreshExpiresAt = self::getRefreshTokenExpiration($this->refreshExpiresAt);
            $lockedFamily->setAttribute(
                'prune_at',
                self::getPruneAt($lockedFamily->expires_at, Date::make($refreshExpiresAt)),
            );

            $accessToken = $this->createAccessToken(
                $family,
                self::getAccessTokenExpiration($this->accessExpiresAt),
                $lockedFamily->scopes,
            );
            $refreshToken = $this->createRefreshToken($family, $newSequence, $refreshExpiresAt);

            $lockedFamily->save();

            return new NewToken($lockedFamily, $accessToken, $refreshToken);
        }, 3);

        if ($reuseDetected) {
            if ($this->onReuse !== null) {
                ($this->onReuse)();
            }

            throw new RefreshTokenReuseException();
        }

        if ($newToken === null) {
            throw new TokenInvalidException();
        }

        return $newToken;
    }
}
