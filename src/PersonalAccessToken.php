<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Contracts\Scopeable;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Hyrioo\HyrnaticAuthenticator\Scopes\Scope;
use Hyrioo\HyrnaticAuthenticator\Scopes\ScopeEntry;
use Hyrioo\HyrnaticAuthenticator\Scopes\ScopeResolver;
use Lcobucci\JWT\Token;

class PersonalAccessToken
{
    public Token\Plain $accessToken;

    public TokenFamily $tokenFamily;

    /**
     * @var list<array{key:string,resource_type:?string,resource_id:string|int|null}>
     */
    public array $scopes;

    public function __construct(Token\Plain $accessToken, TokenFamily $tokenFamily)
    {
        $this->accessToken = $accessToken;
        $this->tokenFamily = $tokenFamily;
        $this->scopes = $this->accessToken->claims()->get('scp');
    }

    /**
     * @param class-string<Scope>|Scopeable $scope
     */
    public function hasScope(string|Scopeable $scope): bool
    {
        return app(ScopeResolver::class)->hasScope($this->tokenFamily->authable, $scope, $this);
    }

    /**
     * @return list<ScopeEntry>
     */
    public function scopeEntries(): array
    {
        return app(ScopeResolver::class)->deserialize($this->scopes);
    }
}
