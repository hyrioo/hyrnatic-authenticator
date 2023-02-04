<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;

class NewToken implements Arrayable, Jsonable
{
    public string $accessToken;

    public string $refreshToken;

    /**
     * The refresh token instance.
     *
     * @var TokenFamily
     */
    public TokenFamily $tokenFamily;

    /**
     * Create a new access token result.
     *
     * @param TokenFamily $tokenFamily
     * @param string $accessToken
     * @param string $refreshToken
     */
    public function __construct(TokenFamily $tokenFamily, string $accessToken, string $refreshToken)
    {
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
        $this->tokenFamily = $tokenFamily;
    }

    /**
     * Get the instance as an array.
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'tokenFamily' => $this->tokenFamily,
            'accessToken' => $this->accessToken,
            'refreshToken' => $this->refreshToken,
        ];
    }

    /**
     * Convert the object to its JSON representation.
     *
     * @param  int  $options
     * @return string
     */
    public function toJson($options = 0): string
    {
        return json_encode($this->toArray(), $options);
    }
}
