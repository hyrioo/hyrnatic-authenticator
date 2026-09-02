<?php

namespace Hyrioo\HyrnaticAuthenticator\Models;

use Hyrioo\HyrnaticAuthenticator\Contracts\Scopeable;
use Hyrioo\HyrnaticAuthenticator\Exceptions\InvalidScopeException;
use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Scopes\Scope as CodeScope;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * @property string $key
 * @property string|null $resource_type
 * @property list<string>|null $sub_scopes
 */
class Scope extends Model implements Scopeable
{
    protected $guarded = ['*'];

    protected $casts = [
        'sub_scopes' => 'json',
        'metadata' => 'json',
    ];

    protected ?string $boundResourceType = null;

    protected string|int|null $boundResourceId = null;

    final public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);
    }

    /**
     * @param list<class-string<CodeScope>|self> $subScopes
     * @param class-string<Model>|null $resourceType
     * @param array<string, mixed> $metadata
     */
    public static function create(
        string $name,
        array $subScopes = [],
        ?string $resourceType = null,
        array $metadata = [],
    ): static {
        $name = trim($name);

        if ($name === '') {
            throw new InvalidScopeException('A persisted scope must have a name.');
        }

        if (strlen($name) > 255) {
            throw new InvalidScopeException('A persisted scope name may not exceed 255 bytes.');
        }

        if ($resourceType !== null && !is_a($resourceType, Model::class, true)) {
            throw new InvalidScopeException("Resource type [{$resourceType}] must be an Eloquent model class.");
        }

        $scope = new static();
        $scope->setAttribute('key', 'custom.'.Str::uuid());
        $scope->setAttribute('name', $name);
        $scope->setAttribute('source', 'custom');
        $scope->setAttribute('resource_type', $resourceType);
        $scope->setAttribute('sub_scopes', array_values(array_unique(array_map(
            static fn (mixed $subScope): string => self::subScopeKey($subScope),
            $subScopes,
        ))));
        $scope->setAttribute('metadata', $metadata);
        $scope->save();

        return $scope;
    }

    public function key(): string
    {
        return $this->key;
    }

    public function allowedResourceType(): ?string
    {
        return $this->resource_type;
    }

    /**
     * @return list<string>
     */
    public function subScopeKeys(): array
    {
        return array_values($this->sub_scopes ?? []);
    }

    public function boundResourceType(): ?string
    {
        return $this->boundResourceType;
    }

    public function boundResourceId(): string|int|null
    {
        return $this->boundResourceId;
    }

    public function for(Model $resource): static
    {
        return $this->bindTo($resource);
    }

    public function bindTo(Model $resource): static
    {
        $expectedType = $this->allowedResourceType();

        if ($expectedType === null) {
            throw new InvalidScopeException("Scope [{$this->key()}] does not support resource binding.");
        }

        if (!is_a($expectedType, Model::class, true)) {
            throw new InvalidScopeException("Scope [{$this->key()}] has an invalid resource type [{$expectedType}].");
        }

        if (!$resource instanceof $expectedType) {
            throw new InvalidScopeException("Scope [{$this->key()}] only supports resource type [{$expectedType}].");
        }

        if (!$resource->exists || $resource->getKey() === null) {
            throw new InvalidScopeException("Scope [{$this->key()}] requires a persisted resource.");
        }

        $clone = clone $this;
        $clone->boundResourceType = $resource->getMorphClass();
        $clone->boundResourceId = $resource->getKey();

        return $clone;
    }

    /**
     * @return array{key:string,resource_type:?string,resource_id:string|int|null}
     */
    public function toScopeArray(): array
    {
        return [
            'key' => $this->key(),
            'resource_type' => $this->boundResourceType(),
            'resource_id' => $this->boundResourceId(),
        ];
    }

    private static function subScopeKey(mixed $scope): string
    {
        if ($scope instanceof self) {
            if (!$scope->exists) {
                throw new InvalidScopeException('A persisted sub scope must be saved before it can be included.');
            }

            return $scope->key();
        }

        if (!is_string($scope) || !is_a($scope, CodeScope::class, true)) {
            throw new InvalidScopeException(
                'Sub scopes must be registered scope classes or persisted scope objects; raw scope keys are not supported.'
            );
        }

        $key = HyrnaticAuthenticator::scopeKeyForClass($scope);
        if ($key === null) {
            throw new InvalidScopeException("Scope class [{$scope}] has not been registered.");
        }

        return $key;
    }
}
