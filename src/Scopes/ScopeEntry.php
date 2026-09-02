<?php

namespace Hyrioo\HyrnaticAuthenticator\Scopes;

final class ScopeEntry
{
    public function __construct(
        public readonly string $key,
        public readonly ?string $resourceType = null,
        public readonly string|int|null $resourceId = null,
        public readonly ?string $scopeClass = null,
    ) {
    }

    public static function fromArray(array $scope): self
    {
        return new self(
            $scope['key'],
            $scope['resource_type'] ?? null,
            $scope['resource_id'] ?? null,
        );
    }

    /**
     * @return array{key:string,resource_type:?string,resource_id:string|int|null}
     */
    public function toArray(): array
    {
        return [
            'key' => $this->key,
            'resource_type' => $this->resourceType,
            'resource_id' => $this->resourceId,
        ];
    }

    public function isGlobal(): bool
    {
        return $this->resourceType === null && $this->resourceId === null;
    }

    public function hash(): string
    {
        return implode('|', [
            $this->key,
            $this->resourceType ?? '*',
            (string) ($this->resourceId ?? '*'),
        ]);
    }

    public function withSameBinding(string $key, ?string $scopeClass = null): self
    {
        return new self($key, $this->resourceType, $this->resourceId, $scopeClass);
    }
}
