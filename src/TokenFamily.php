<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Contracts\HasAbilities;
use Hyrioo\HyrnaticAuthenticator\Exceptions\FailedToDeleteTokenFamilyException;
use Illuminate\Database\Eloquent\Model;

/**
 *
 * @property string|null $name
 * @property string $family
 * @property array $scopes
 * @property array $access_claims
 * @property array $refresh_claims
 * @property int $last_refresh_sequence
 * @property \Illuminate\Support\Carbon|null $last_used_at
 * @property \Illuminate\Support\Carbon|null $expires_at
 * @property \Illuminate\Support\Carbon|null $prune_at
 */
class TokenFamily extends Model implements HasAbilities
{
    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'scopes' => 'json',
        'access_claims' => 'json',
        'refresh_claims' => 'json',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
        'prune_at' => 'datetime',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'family',
        'scopes',
        'access_claims',
        'refresh_claims',
        'last_used_at',
        'expires_at',
        'prune_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array
     */
    protected $hidden = [
        'family',
    ];

    /**
     * Get the authable model that the access token belongs to.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo
     */
    public function authable()
    {
        return $this->morphTo('authable');
    }

    /**
     * Find the token instance matching the given token.
     *
     * @param string $token
     * @return static|null
     */
    public static function findTokenFamily(string $family)
    {
        return static::where('family', $family)->first();
    }

    /**
     * Determine if the token has a given scope.
     *
     * @param string $scope
     * @return bool
     */
    public function can(string $scope): bool
    {
        return in_array('*', $this->scopes) ||
            array_key_exists($scope, array_flip($this->scopes));
    }

    /**
     * Determine if the token is missing a given scope.
     *
     * @param string $scope
     * @return bool
     */
    public function cant(string $scope): bool
    {
        return !$this->can($scope);
    }

    public function isMostRecentRefresh(int $sequence)
    {
        return $this->last_refresh_sequence === $sequence;
    }

    public function invalidate()
    {
        if (!$this->delete()) {
            throw new FailedToDeleteTokenFamilyException();
        }
    }
}
