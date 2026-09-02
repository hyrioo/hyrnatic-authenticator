<?php

namespace Hyrioo\HyrnaticAuthenticator\Scopes;

use Hyrioo\HyrnaticAuthenticator\Contracts\Scopeable;
use Hyrioo\HyrnaticAuthenticator\Exceptions\InvalidScopeException;
use Illuminate\Database\Eloquent\Model;

abstract class Scope implements Scopeable
{
    protected ?string $resourceType = null;

    protected string|int|null $resourceId = null;

    final public function __construct()
    {
    }

    abstract public static function scopeKey(): string;

    public static function allowedResourceType(): ?string
    {
        return null;
    }

    /**
     * @return list<class-string<self>|string>
     */
    public static function subScopes(): array
    {
        return [];
    }

    public static function global(): static
    {
        return new static();
    }

    public static function for(Model $resource): static
    {
        return (new static())->bindTo($resource);
    }

    public function bindTo(Model $resource): static
    {
        $expectedType = static::allowedResourceType();

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

        $this->resourceType = $resource->getMorphClass();
        $this->resourceId = $resource->getKey();

        return $this;
    }

    public function key(): string
    {
        return static::scopeKey();
    }

    public function boundResourceType(): ?string
    {
        return $this->resourceType;
    }

    public function boundResourceId(): string|int|null
    {
        return $this->resourceId;
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
}
