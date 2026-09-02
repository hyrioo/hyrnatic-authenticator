<?php

namespace Hyrioo\HyrnaticAuthenticator\Scopes;

use Hyrioo\HyrnaticAuthenticator\Contracts\HasApiTokens;
use Hyrioo\HyrnaticAuthenticator\Contracts\Scopeable;
use Hyrioo\HyrnaticAuthenticator\Enums\ScopeDenialReason;
use Hyrioo\HyrnaticAuthenticator\Exceptions\InvalidScopeException;
use Hyrioo\HyrnaticAuthenticator\HyrnaticAuthenticator;
use Hyrioo\HyrnaticAuthenticator\Models\ModelScope;
use Hyrioo\HyrnaticAuthenticator\PersonalAccessToken;
use Illuminate\Auth\Access\Response;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;

class ScopeResolver
{
    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function normalize(string|Scopeable $scope): ScopeEntry
    {
        if (is_string($scope)) {
            if (!is_a($scope, Scope::class, true)) {
                throw new InvalidScopeException("Unknown scope class [{$scope}].");
            }

            $this->assertScopeClassIsRegistered($scope);
            $instance = $scope::global();

            return new ScopeEntry(
                $instance->key(),
                $instance->boundResourceType(),
                $instance->boundResourceId(),
                $scope,
            );
        }

        if ($scope instanceof Scope) {
            $this->assertScopeClassIsRegistered($scope::class);
        }

        return new ScopeEntry(
            $scope->key(),
            $scope->boundResourceType(),
            $scope->boundResourceId(),
            $scope instanceof Scope ? $scope::class : null,
        );
    }

    /**
     * @param list<class-string<Scope>|Scopeable> $scopes
     * @return list<array{key:string,resource_type:?string,resource_id:string|int|null}>
     */
    public function snapshot(HasApiTokens $authable, ?array $scopes = null): array
    {
        $entries = $scopes === null
            ? $this->effectiveModelScopes($authable)
            : $this->expandEntries(array_map(fn ($scope) => $this->normalize($scope), $scopes));

        return array_values(array_map(
            fn (ScopeEntry $entry) => $entry->toArray(),
            $this->uniqueEntries($entries),
        ));
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function hasScope(HasApiTokens $authable, string|Scopeable $scope, ?PersonalAccessToken $token = null): bool
    {
        return $this->inspectScope($authable, $scope, $token)->allowed();
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function inspectScope(
        HasApiTokens $authable,
        string|Scopeable $scope,
        ?PersonalAccessToken $token = null,
    ): Response
    {
        $requested = $this->expandEntries([$this->normalize($scope)]);
        $ownerScopes = $this->effectiveModelScopes($authable);

        if (!$this->matchesAll($ownerScopes, $requested)) {
            return Response::deny(
                'The required scope is not assigned.',
                ScopeDenialReason::MissingModelScope->value,
            );
        }

        if ($token === null) {
            return Response::allow();
        }

        if (!$this->matchesAll($token->scopeEntries(), $requested)) {
            return Response::deny(
                'The current access token does not include the required scope.',
                ScopeDenialReason::MissingTokenScope->value,
            );
        }

        return Response::allow();
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function scope(HasApiTokens $authable, string|Scopeable $scope): ModelScope
    {
        $entry = $this->normalize($scope);

        /** @var ModelScope $modelScope */
        $modelScope = $authable->modelScopes()->firstOrCreate([
            'scope_key' => $entry->key,
            'resource_type' => $entry->resourceType,
            'resource_id' => $entry->resourceId === null ? null : (string) $entry->resourceId,
        ]);

        return $modelScope;
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function unscope(HasApiTokens $authable, string|Scopeable $scope): void
    {
        $entry = $this->normalize($scope);

        $authable->modelScopes()
            ->where('scope_key', $entry->key)
            ->where('resource_type', $entry->resourceType)
            ->where('resource_id', $entry->resourceId)
            ->delete();
    }

    /**
     * @param list<class-string<Scope>|Scopeable> $scopes
     */
    public function assertScopesCanBeIssued(HasApiTokens $authable, array $scopes): void
    {
        foreach ($scopes as $scope) {
            if (!$this->hasScope($authable, $scope)) {
                $entry = $this->normalize($scope);

                throw new \Hyrioo\HyrnaticAuthenticator\Exceptions\ScopeEscalationException(
                    "Cannot issue token scope [{$entry->key}] beyond the authable's own scopes."
                );
            }
        }
    }

    /**
     * @return list<ScopeEntry>
     */
    public function effectiveModelScopes(HasApiTokens $authable): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, ModelScope> $modelScopes */
        $modelScopes = $authable->modelScopes()->get();

        $entries = $modelScopes
            ->map(fn (ModelScope $scope) => new ScopeEntry(
                $scope->scope_key,
                $scope->resource_type,
                $scope->resource_id,
                HyrnaticAuthenticator::scopeClassForKey($scope->scope_key),
            ))
            ->all();

        return $this->expandEntries($entries);
    }

    /**
     * @param list<array{key:string,resource_type:?string,resource_id:string|int|null}> $scopes
     * @return list<ScopeEntry>
     */
    public function deserialize(array $scopes): array
    {
        return array_map(fn (array $scope) => ScopeEntry::fromArray($scope), $scopes);
    }

    /**
     * @param list<ScopeEntry> $entries
     * @return list<ScopeEntry>
     */
    public function expandEntries(array $entries): array
    {
        $expanded = [];
        $visited = [];

        foreach ($entries as $entry) {
            $this->expandEntry($entry, $expanded, $visited);
        }

        return $this->uniqueEntries($expanded);
    }

    /**
     * @param list<ScopeEntry> $candidates
     * @param list<ScopeEntry> $requested
     */
    private function matchesAll(array $candidates, array $requested): bool
    {
        foreach ($requested as $requestedEntry) {
            $matched = false;

            foreach ($candidates as $candidate) {
                if ($this->matches($candidate, $requestedEntry)) {
                    $matched = true;
                    break;
                }
            }

            if (!$matched) {
                return false;
            }
        }

        return true;
    }

    private function matches(ScopeEntry $candidate, ScopeEntry $requested): bool
    {
        if (!$this->resourceMatches($candidate, $requested)) {
            return false;
        }

        return $candidate->key === '*'
            || $candidate->key === $requested->key
            || $this->wildcardMatches($candidate->key, $requested->key);
    }

    private function resourceMatches(ScopeEntry $candidate, ScopeEntry $requested): bool
    {
        if ($requested->isGlobal()) {
            return $candidate->isGlobal();
        }

        if ($candidate->isGlobal()) {
            return true;
        }

        return $candidate->resourceType === $requested->resourceType
            && (string) $candidate->resourceId === (string) $requested->resourceId;
    }

    private function wildcardMatches(string $candidateKey, string $requestedKey): bool
    {
        if (!str_ends_with($candidateKey, '.*')) {
            return false;
        }

        $prefix = substr($candidateKey, 0, -1);

        return str_starts_with($requestedKey, $prefix);
    }

    /**
     * @param list<ScopeEntry> $expanded
     * @param array<string, true> $visited
     */
    private function expandEntry(ScopeEntry $entry, array &$expanded, array &$visited): void
    {
        $hash = $entry->hash();
        if (isset($visited[$hash])) {
            return;
        }

        $visited[$hash] = true;
        $expanded[] = $entry;

        foreach ($this->subScopeEntriesFor($entry) as $subScope) {
            $this->expandEntry($subScope, $expanded, $visited);
        }
    }

    /**
     * @return list<ScopeEntry>
     */
    private function subScopeEntriesFor(ScopeEntry $entry): array
    {
        $scopeClass = $entry->scopeClass ?? HyrnaticAuthenticator::scopeClassForKey($entry->key);
        if ($scopeClass !== null) {
            return $this->subScopeEntriesFromClass($scopeClass, $entry);
        }

        /** @var \Hyrioo\HyrnaticAuthenticator\Models\Scope|null $scopeModel */
        $scopeModel = HyrnaticAuthenticator::scopeModel()::query()
            ->where('key', $entry->key)
            ->first();

        if ($scopeModel === null) {
            return [];
        }

        return array_map(
            fn (string $childKey) => $this->normalizeChildKey($childKey, $entry),
            $scopeModel->subScopeKeys(),
        );
    }

    /**
     * @param class-string<Scope> $scopeClass
     * @return list<ScopeEntry>
     */
    private function subScopeEntriesFromClass(string $scopeClass, ScopeEntry $entry): array
    {
        $subScopes = [];

        foreach ($scopeClass::subScopes() as $subScope) {
            if (is_string($subScope) && is_a($subScope, Scope::class, true)) {
                $child = $subScope::global();
                $childClass = $subScope;
                $childKey = $child->key();
            } else {
                $childClass = HyrnaticAuthenticator::scopeClassForKey($subScope);
                $childKey = $subScope;
            }

            $subScopes[] = $this->inheritBinding(
                new ScopeEntry($childKey, null, null, $childClass),
                $entry,
            );
        }

        return $subScopes;
    }

    private function normalizeChildKey(string $childKey, ScopeEntry $entry): ScopeEntry
    {
        return $this->inheritBinding(
            new ScopeEntry($childKey, null, null, HyrnaticAuthenticator::scopeClassForKey($childKey)),
            $entry,
        );
    }

    private function inheritBinding(ScopeEntry $child, ScopeEntry $parent): ScopeEntry
    {
        if ($parent->isGlobal()) {
            return $child;
        }

        $allowedResourceType = $this->allowedResourceTypeFor($child);
        if ($allowedResourceType === null) {
            throw new InvalidScopeException("Scope [{$child->key}] cannot be used as a resource-bound sub scope.");
        }

        $resourceClass = Relation::getMorphedModel($parent->resourceType) ?? $parent->resourceType;
        if (!is_a($resourceClass, $allowedResourceType, true)) {
            throw new InvalidScopeException("Scope [{$child->key}] expects resource type [{$allowedResourceType}].");
        }

        return new ScopeEntry($child->key, $parent->resourceType, $parent->resourceId, $child->scopeClass);
    }

    private function allowedResourceTypeFor(ScopeEntry $entry): ?string
    {
        $scopeClass = $entry->scopeClass ?? HyrnaticAuthenticator::scopeClassForKey($entry->key);
        if ($scopeClass !== null) {
            return $scopeClass::allowedResourceType();
        }

        /** @var \Hyrioo\HyrnaticAuthenticator\Models\Scope|null $scopeModel */
        $scopeModel = HyrnaticAuthenticator::scopeModel()::query()
            ->where('key', $entry->key)
            ->first();

        return $scopeModel?->allowedResourceType();
    }

    /**
     * @param class-string<Scope> $scopeClass
     */
    private function assertScopeClassIsRegistered(string $scopeClass): void
    {
        if (HyrnaticAuthenticator::scopeKeyForClass($scopeClass) === null) {
            throw new InvalidScopeException("Scope class [{$scopeClass}] has not been registered.");
        }
    }

    /**
     * @param list<ScopeEntry> $entries
     * @return list<ScopeEntry>
     */
    private function uniqueEntries(array $entries): array
    {
        $unique = [];

        foreach ($entries as $entry) {
            $unique[$entry->hash()] = $entry;
        }

        return array_values($unique);
    }
}
