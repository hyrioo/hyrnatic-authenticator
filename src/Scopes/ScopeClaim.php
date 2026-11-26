<?php

namespace Hyrioo\HyrnaticAuthenticator\Scopes;

use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Lcobucci\JWT\Token;

/** @internal */
final class ScopeClaim
{
    /**
     * @param list<array{key:string,resource_type:?string,resource_id:string|int|null}>|null $scopes
     */
    public static function digest(?array $scopes): ?string
    {
        if ($scopes === null) {
            return null;
        }

        $entries = self::encode($scopes);
        sort($entries, SORT_STRING);
        $digest = hash('sha256', json_encode($entries, JSON_THROW_ON_ERROR), true);

        return rtrim(strtr(base64_encode($digest), '+/', '-_'), '=');
    }

    public static function readDigest(Token\Plain $token): ?string
    {
        $claims = $token->claims();
        if (!$claims->has('scp')) {
            return null;
        }

        $digest = $claims->get('scp');
        if (!is_string($digest)) {
            throw new TokenInvalidException();
        }

        return $digest;
    }

    /**
     * @param list<array{key:string,resource_type:?string,resource_id:string|int|null}>|null $scopes
     */
    public static function assertDigestMatches(?string $digest, ?array $scopes): void
    {
        if ($digest !== self::digest($scopes)) {
            throw new TokenInvalidException();
        }
    }

    /**
     * @param list<array{key:string,resource_type:?string,resource_id:string|int|null}> $scopes
     * @return list<string>
     */
    public static function encode(array $scopes): array
    {
        return array_map(static function (array $scope): string {
            $key = rawurlencode($scope['key']);
            if ($scope['resource_type'] === null) {
                return $key;
            }

            return $key.'$'.rawurlencode($scope['resource_type']).'$'.rawurlencode((string) $scope['resource_id']);
        }, self::normalize($scopes));
    }

    /**
     * @param list<array{key:string,resource_type:?string,resource_id:string|int|null}>|null $scopes
     */
    public static function assertMatches(Token\Plain $token, ?array $scopes): void
    {
        $claim = $token->claims()->get('scp');
        if (!is_array($claim)) {
            self::assertDigestMatches(self::readDigest($token), $scopes);

            return;
        }

        if ($scopes === null || !array_is_list($claim)) {
            throw new TokenInvalidException();
        }

        // Older access tokens carried either the encoded scope strings or the full entries.
        if ($claim === self::encode($scopes)) {
            return;
        }

        if (self::normalize($claim) !== self::normalize($scopes)) {
            throw new TokenInvalidException();
        }
    }

    /**
     * @param list<mixed> $scopes
     * @return list<array{key:string,resource_type:?string,resource_id:string|int|null}>
     */
    private static function normalize(array $scopes): array
    {
        $normalized = [];

        foreach ($scopes as $scope) {
            if (!is_array($scope) || !is_string($scope['key'] ?? null) || $scope['key'] === '') {
                throw new TokenInvalidException();
            }

            $resourceType = $scope['resource_type'] ?? null;
            $resourceId = $scope['resource_id'] ?? null;
            if (($resourceType !== null && !is_string($resourceType))
                || ($resourceId !== null && !is_string($resourceId) && !is_int($resourceId))
                || ($resourceType === null) !== ($resourceId === null)
            ) {
                throw new TokenInvalidException();
            }

            $normalized[] = (new ScopeEntry($scope['key'], $resourceType, $resourceId))->toArray();
        }

        return $normalized;
    }
}
