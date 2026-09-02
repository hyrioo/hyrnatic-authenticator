<?php
// config for Hyrioo/HyrnaticAuthenticator
return [

    /*
    |--------------------------------------------------------------------------
    | Expiration Minutes
    |--------------------------------------------------------------------------
    |
    | These values control the number of minutes until an issued token or token
    | family expires. Set a value to null explicitly to disable that expiry.
    |
    */

    'secret' => env('JWT_SECRET'),

    'family_expiration' => env('JWT_FAMILY_EXPIRATION', 43200),

    'access_expiration' => env('JWT_ACCESS_EXPIRATION', 15),

    'refresh_expiration' => env('JWT_REFRESH_EXPIRATION', 43200),
];
