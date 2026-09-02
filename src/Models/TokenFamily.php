<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens;
use Hyrioo\HyrnaticAuthenticator\Exceptions\FailedToDeleteTokenFamilyException;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string|null $name
 * @property string $family
 * @property array $scopes
 * @property array $access_claims
 * @property array $refresh_claims
 * @property int $last_refresh_sequence
 * @property-read HasApiTokens $authable
 * @property \Illuminate\Support\Carbon|null $last_used_at
 * @property \Illuminate\Support\Carbon|null $expires_at
 * @property \Illuminate\Support\Carbon|null $prune_at
 */
class TokenFamily extends Model
{
    protected $casts = [
        'scopes' => 'json',
        'access_claims' => 'json',
        'refresh_claims' => 'json',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
        'prune_at' => 'datetime',
    ];

    protected $fillable = [
        'name',
        'last_used_at',
        'prune_at',
    ];

    protected $hidden = [
        'family',
        'access_claims',
        'refresh_claims',
    ];

    /**
     * @return list<array{key:string,resource_type:?string,resource_id:string|int|null}>
     */
    public function getScopesAttribute(string $value): array
    {
        /** @var list<array{key:string,resource_type?:string|null,resource_id?:string|int|null}> $scopes */
        $scopes = json_decode($value, true, 512, JSON_THROW_ON_ERROR);

        return array_map(static fn (array $scope): array => [
            'key' => $scope['key'],
            'resource_type' => $scope['resource_type'] ?? null,
            'resource_id' => $scope['resource_id'] ?? null,
        ], $scopes);
    }

    public function authable()
    {
        return $this->morphTo('authable');
    }

    public static function findTokenFamily(string $family)
    {
        return static::query()->where('family', $family)->first();
    }

    public function isMostRecentRefresh(int $sequence): bool
    {
        return $this->last_refresh_sequence === $sequence;
    }

    public function revoke(): void
    {
        if (!$this->delete()) {
            throw new FailedToDeleteTokenFamilyException();
        }
    }
}
