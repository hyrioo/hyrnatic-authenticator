<?php
// config for Hyrioo/HyrnaticAuthenticator
return [

    /*
    |--------------------------------------------------------------------------
    | Expiration Minutes
    |--------------------------------------------------------------------------
    |
    | This value controls the number of minutes until an issued token will be
    | considered expired. If this value is null, tokens do not expire.
    |
    */

    'secret' => env('JWT_SECRET'),

    'family_expiration' => null,

    'access_expiration' => null,

    'refresh_expiration' => null,
];
