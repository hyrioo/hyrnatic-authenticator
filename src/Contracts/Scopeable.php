<?php

namespace Hyrioo\HyrnaticAuthenticator\Contracts;

interface Scopeable
{
    public function key(): string;

    public function boundResourceType(): ?string;

    public function boundResourceId(): string|int|null;

    /**
     * @return array{key:string,resource_type:?string,resource_id:string|int|null}
     */
    public function toScopeArray(): array;
}
