<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Exception;
use Hyrioo\HyrnaticAuthenticator\Exceptions\SecretMissingException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;

class JWT
{
    private Sha256 $signer;
    private InMemory $signingKey;

    /**
     * @throws SecretMissingException
     */
    public function __construct()
    {
        $this->signer = new Sha256();
        if (config('hyrnatic-authenticator.secret') === null) {
            throw new SecretMissingException();
        } else {
            $this->signingKey = InMemory::plainText(config('hyrnatic-authenticator.secret'));
        }
    }

    public function create(): Builder
    {
        return (new Builder(new JoseEncoder(), ChainedFormatter::default()));
    }

    public function encode(Builder $builder): string
    {
        $token = $builder->getToken($this->signer, $this->signingKey);
        return $token->toString();
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function decode(string $jwt): Token\Plain
    {
        $parser = new Parser(new JoseEncoder());
        try {
            $parsedToken = $parser->parse($jwt);
            $validator = new Validator();
            if(!$validator->validate($parsedToken, new SignedWith($this->signer, $this->signingKey))) {
                throw new TokenInvalidException();
            }
            if(!$validator->validate($parsedToken, new LooseValidAt(new FrozenClock(now()->toDateTimeImmutable())))) {
                throw new TokenExpiredException();
            }
            return $parsedToken;
        } catch (TokenInvalidException | TokenExpiredException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new TokenInvalidException();
        }
    }
}
