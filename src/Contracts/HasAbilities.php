<?php

namespace Hyrioo\HyrnaticAuthenticator\Contracts;

interface HasAbilities
{
    /**
     * Determine if the token has a given ability.
     *
     * @param string $scope
     * @return bool
     */
    public function can(string $scope): bool;

    /**
     * Determine if the token is missing a given scope.
     *
     * @param string $scope
     * @return bool
     */
    public function cant(string $scope): bool;
}
