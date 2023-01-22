<?php

namespace Hyrioo\HyrnaticAuthenticator\Events;


class TokenAuthenticated
{
    /**
     * The personal access token that was authenticated.
     *
     * @var \Hyrioo\HyrnaticAuthenticator\PersonalAccessToken
     */
    public $token;

    /**
     * Create a new event instance.
     *
     * @param \Hyrioo\HyrnaticAuthenticator\PersonalAccessToken  $token
     * @return void
     */
    public function __construct($token)
    {
        $this->token = $token;
    }
}
