<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;

class NewToken implements Arrayable, Jsonable
{
    /**
     * The access token instance.
     *
     * @var \Hyrioo\HyrnaticAuthenticator\PersonalAccessToken
     */
    public $accessToken;

    /**
     * The refresh token instance.
     *
     * @var \Hyrioo\HyrnaticAuthenticator\PersonalRefreshToken
     */
    public $refreshToken;

    /**
     * The plain text version of the token.
     *
     * @var string
     */
    public $plainTextAccessToken;

    /**
     * The plain text version of the token.
     *
     * @var string
     */
    public $plainTextRefreshToken;

    /**
     * Create a new access token result.
     *
     * @param  \Hyrioo\HyrnaticAuthenticator\PersonalAccessToken  $accessToken
     * @param  \Hyrioo\HyrnaticAuthenticator\PersonalRefreshToken  $refreshToken
     * @param  string  $plainTextAccessToken
     * @param  string  $plainTextRefreshToken
     * @return void
     */
    public function __construct(PersonalAccessToken $accessToken, PersonalRefreshToken $refreshToken, string $plainTextAccessToken, string $plainTextRefreshToken)
    {
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
        $this->plainTextAccessToken = $plainTextAccessToken;
        $this->plainTextRefreshToken = $plainTextRefreshToken;
    }

    /**
     * Get the instance as an array.
     *
     * @return array
     */
    public function toArray()
    {
        return [
            'accessToken' => $this->accessToken,
            'refreshToken' => $this->refreshToken,
            'plainTextAccessToken' => $this->plainTextAccessToken,
            'plainTextRefreshToken' => $this->plainTextRefreshToken,
        ];
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @param  int  $options
     * @return string
     */
    public function toJson($options = 0)
    {
        return json_encode($this->toArray(), $options);
    }
}
