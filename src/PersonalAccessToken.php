<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Lcobucci\JWT\Token;

class PersonalAccessToken
{
    public Token\Plain $accessToken;
    public TokenFamily $tokenFamily;

    public array $scopes;

    public function __construct(Token\Plain $accessToken, TokenFamily $tokenFamily)
    {
        $this->accessToken = $accessToken;
        $this->tokenFamily = $tokenFamily;
        $this->scopes = $this->accessToken->claims()->get('scp');
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
}
