<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property string $scope_key
 * @property string|null $resource_type
 * @property string|null $resource_id
 * @property string $binding_key
 */
class ModelScope extends Model
{
    protected $table = 'model_scopes';

    protected $fillable = [
        'scope_key',
        'resource_type',
        'resource_id',
    ];

    protected static function booted(): void
    {
        static::saving(function (self $model): void {
            $model->binding_key = self::bindingKey(
                $model->resource_type,
                $model->resource_id,
            );
        });
    }

    public static function bindingKey(?string $resourceType, string|int|null $resourceId): string
    {
        return hash('sha256', json_encode(
            [$resourceType, $resourceId === null ? null : (string) $resourceId],
            JSON_THROW_ON_ERROR,
        ));
    }

    public function authable()
    {
        return $this->morphTo('authable');
    }
}
