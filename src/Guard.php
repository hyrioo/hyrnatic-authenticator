<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Hyrioo\HyrnaticAuthenticator\Events\TokenAuthenticated;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;

class Guard
{

    /**
     * The authentication factory implementation.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * The number of minutes tokens should be allowed to remain valid.
     *
     * @var int
     */
    protected $expiration;

    /**
     * The provider name.
     *
     * @var UserProvider
     */
    protected $provider;

    /**
     * Create a new guard instance.
     *
     * @param \Illuminate\Contracts\Auth\Factory $auth
     * @param int $expiration
     * @param UserProvider $provider
     * @return void
     */
    public function __construct(AuthFactory $auth, $expiration = null, UserProvider $provider = null)
    {
        $this->auth = $auth;
        $this->expiration = $expiration;
        $this->provider = $provider;
    }

    public function __invoke(Request $request)
    {
        if ($accessToken = $this->getTokenFromRequest($request)) {

            $parser = new Parser(new JoseEncoder());
            try {
                $parsedToken = $parser->parse($accessToken);
            } catch (\Exception $e) {
                throw new TokenInvalidException();
            }

            if($parsedToken->isExpired(now())) {
                return false;
            }

            $authable = $this->retrieveAuthable($parsedToken);
            if (!$this->supportsTokens($authable)) {
                return false;
            }

            $tokenFamily = $this->retrieveTokenFamily($parsedToken);
            if(!$tokenFamily) {
                return false;
            }

            if (method_exists($tokenFamily->getConnection(), 'hasModifiedRecords') &&
                method_exists($tokenFamily->getConnection(), 'setRecordModificationState')) {
                tap($tokenFamily->getConnection()->hasModifiedRecords(), function ($hasModifiedRecords) use ($tokenFamily) {
                    $tokenFamily->forceFill(['last_used_at' => now()])->save();

                    $tokenFamily->getConnection()->setRecordModificationState($hasModifiedRecords);
                });
            } else {
                $tokenFamily->forceFill(['last_used_at' => now()])->save();
            }

            return $authable;
        }
    }

    /**
     * Determine if the authable model supports API tokens.
     *
     * @param mixed $authable
     * @return bool
     */
    protected function supportsTokens($authable = null)
    {
        return $authable && in_array(HasApiTokens::class, class_uses_recursive(
                get_class($authable)
            ));
    }

    /**
     * Get the token from the request.
     *
     * @param \Illuminate\Http\Request $request
     * @return string|null
     */
    protected function getTokenFromRequest(Request $request)
    {
        if (is_callable(HyrnaticAuthenticator::$accessTokenRetrievalCallback)) {
            return (string)(HyrnaticAuthenticator::$accessTokenRetrievalCallback)($request);
        }

        $token = $request->bearerToken();

        return $this->isValidBearerToken($token) ? $token : null;
    }

    /**
     * Determine if the bearer token is in the correct format.
     *
     * @param string|null $token
     * @return bool
     */
    protected function isValidBearerToken(string $token = null)
    {
        return !empty($token);
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param Token $token
     * @return bool
     */
    protected function isValidAccessToken(Token $token): bool
    {
        return $token->isExpired(now());
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param Token $token
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function retrieveAuthable(Token $token)
    {
        $subject = $token->claims()->get('sub');
        [$id] = explode('|', $subject, 2);
        $authable = $this->provider->retrieveById($id);

        return $authable;
    }

    /**
     * Determine if the provided access token is valid.
     *
     * @param Token $token
     * @return TokenFamily
     */
    protected function retrieveTokenFamily(Token $token)
    {
        $family = $token->claims()->get('fam');
        return TokenFamily::findTokenFamily($family);
    }
}
