<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Exception;
use Hyrioo\HyrnaticAuthenticator\Exceptions\SecretMissingException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\SecretTooShortException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Builder as BuilderInterface;
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
     * @throws SecretTooShortException
     */
    public function __construct()
    {
        $this->signer = new Sha256();
        $secret = config('hyrnatic-authenticator.secret');

        if (!is_string($secret) || $secret === '') {
            throw new SecretMissingException();
        }

        if (strlen($secret) < 32) {
            throw new SecretTooShortException();
        }

        $this->signingKey = InMemory::plainText($secret);
    }

    public function create(): BuilderInterface
    {
        return (new Builder(new JoseEncoder(), ChainedFormatter::default()));
    }

    public function encode(BuilderInterface $builder): string
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
            if (!$parsedToken instanceof Token\Plain) {
                throw new TokenInvalidException();
            }

            return $parsedToken;
        } catch (TokenInvalidException | TokenExpiredException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new TokenInvalidException();
        }
    }
}
