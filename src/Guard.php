<?php

namespace Hyrioo\HyrnaticAuthenticator;

use Exception;
use Hyrioo\HyrnaticAuthenticator\Exceptions\AuthableProviderMismatchException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\InvalidGuardConfigurationException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenExpiredException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenFamilyNotFoundException;
use Hyrioo\HyrnaticAuthenticator\Exceptions\TokenInvalidException;
use Hyrioo\HyrnaticAuthenticator\Models\TokenFamily;
use Hyrioo\HyrnaticAuthenticator\Traits\HasApiTokens as HasApiTokensTrait;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use Lcobucci\JWT\Token;
use RuntimeException;

class Guard implements \Illuminate\Contracts\Auth\Guard
{
    protected AuthFactory $auth;

    protected ?Contracts\HasApiTokens $user = null;

    protected ?UserProvider $provider;

    protected ?string $providerName;

    protected Request $request;

    private JWT $jwt;

    protected ?PersonalAccessToken $token = null;

    public function __construct(AuthFactory $auth, Request $request, ?string $providerName = null, UserProvider $provider = null)
    {
        $this->auth = $auth;
        $this->provider = $provider;
        $this->providerName = $providerName;
        $this->request = $request;
        $this->jwt = new JWT();
    }

    public function user(): ?Contracts\HasApiTokens
    {
        if ($this->hasUser()) {
            return $this->user;
        }

        try {
            return $this->user = $this->retrieveUser($this->request);
        } catch (Exception) {
            return null;
        }
    }

    public function hasToken(): bool
    {
        return $this->token !== null;
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function token(): ?PersonalAccessToken
    {
        if ($this->hasToken()) {
            return $this->token;
        }

        return $this->token = $this->retrieveToken($this->request);
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function retrieveUser(Request $request): ?Contracts\HasApiTokens
    {
        $this->request = $request;
        $personalAccessToken = $this->token();
        if ($personalAccessToken === null) {
            return null;
        }

        $authable = $this->retrieveAuthable($personalAccessToken->accessToken);
        if (!$this->supportsTokens($authable)) {
            return null;
        }

        $familyAuthable = $personalAccessToken->tokenFamily->authable;
        if (!$familyAuthable instanceof Model || !$authable instanceof Model || !$familyAuthable->is($authable)) {
            return null;
        }

        $authable->withAccessToken($personalAccessToken);

        $tokenFamily = $personalAccessToken->tokenFamily;
        if (
            method_exists($tokenFamily->getConnection(), 'hasModifiedRecords')
            && method_exists($tokenFamily->getConnection(), 'setRecordModificationState')
        ) {
            tap($tokenFamily->getConnection()->hasModifiedRecords(), static function ($hasModifiedRecords) use ($tokenFamily) {
                $tokenFamily->forceFill(['last_used_at' => now()])->save();
                $tokenFamily->getConnection()->setRecordModificationState($hasModifiedRecords);
            });
        } else {
            $tokenFamily->forceFill(['last_used_at' => now()])->save();
        }

        return $authable;
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function retrieveToken(Request $request): ?PersonalAccessToken
    {
        if ($accessToken = $this->getTokenFromRequest($request)) {
            $this->setToken($accessToken);

            return $this->token;
        }

        return null;
    }

    protected function supportsTokens(mixed $authable): bool
    {
        return $authable instanceof Contracts\HasApiTokens
            && in_array(HasApiTokensTrait::class, class_uses_recursive(get_class($authable)), true);
    }

    public function create(Contracts\HasApiTokens $authable): NewTokenBuilder
    {
        $authable = $this->assertAuthableMatchesProvider($authable);

        return new NewTokenBuilder($authable);
    }

    /**
     * @throws TokenFamilyNotFoundException
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function refresh(string $jwtToken): RefreshTokenBuilder
    {
        $token = $this->jwt->decode($jwtToken);
        $this->assertTokenType($token, TokenBuilderBase::TOKEN_TYPE_REFRESH);

        $family = $this->requiredStringClaim($token, 'fam');
        $sequence = $this->requiredPositiveIntegerClaim($token, 'seq');

        $tokenFamily = TokenFamily::findTokenFamily($family);
        if ($tokenFamily === null) {
            throw new TokenFamilyNotFoundException();
        }

        $authable = $this->assertAuthableMatchesProvider($tokenFamily->authable);

        if ($tokenFamily->expires_at && $tokenFamily->expires_at->isBefore(now())) {
            throw new TokenExpiredException();
        }

        return new RefreshTokenBuilder(
            $authable,
            $tokenFamily,
            $sequence,
            fn () => $this->forget(),
        );
    }

    protected function getTokenFromRequest(Request $request): ?string
    {
        if (is_callable(HyrnaticAuthenticator::$accessTokenRetrievalCallback)) {
            return (string) (HyrnaticAuthenticator::$accessTokenRetrievalCallback)($request);
        }

        $token = $request->bearerToken();

        return $this->isValidBearerToken($token) ? $token : null;
    }

    protected function isValidBearerToken(string $token = null): bool
    {
        return !empty($token);
    }

    protected function retrieveAuthable(Token\Plain $token): ?Contracts\HasApiTokens
    {
        $subject = $token->claims()->get('sub');
        [$id, $type] = explode('|', $subject, 2);
        $class = Relation::getMorphedModel($type) ?? $type;
        $providerModel = $this->providerModelClass();

        if (!is_subclass_of($class, Model::class)) {
            return null;
        }

        if ($class !== $providerModel) {
            return null;
        }

        /** @var Model|null $authable */
        $authable = $this->provider?->retrieveById($id);

        if (!$authable instanceof $providerModel) {
            return null;
        }

        return $authable instanceof Contracts\HasApiTokens ? $authable : null;
    }

    protected function retrieveTokenFamily(string $family): ?TokenFamily
    {
        return TokenFamily::findTokenFamily($family);
    }

    public function validate(array $credentials = []): bool
    {
        $this->providerModelClass();

        return (bool) $this->provider->retrieveByCredentials($credentials);
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * @throws Exception
     */
    public function setUser(\Illuminate\Contracts\Auth\Authenticatable $user): static
    {
        throw new RuntimeException('It is not supported to set the user directly. Use the setToken method instead.');
    }

    /**
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     */
    public function setToken(string $accessToken): void
    {
        $this->forget();

        $parsedToken = $this->jwt->decode($accessToken);
        $this->assertTokenType($parsedToken, TokenBuilderBase::TOKEN_TYPE_ACCESS);
        $family = $this->requiredStringClaim($parsedToken, 'fam');
        $this->requiredSubjectClaim($parsedToken);
        $scopeSnapshot = $this->requiredScopeSnapshotClaim($parsedToken);

        $tokenFamily = $this->retrieveTokenFamily($family);
        if ($tokenFamily === null) {
            throw new TokenInvalidException();
        }

        if ($tokenFamily->expires_at && $tokenFamily->expires_at->isBefore(now())) {
            throw new TokenExpiredException();
        }

        if ($scopeSnapshot !== $this->normalizeScopeSnapshot($tokenFamily->scopes)) {
            throw new TokenInvalidException();
        }

        $this->token = new HyrnaticAuthenticator::$personalAccessTokenModel($parsedToken, $tokenFamily);
    }

    public function logout(): void
    {
        try {
            $this->token()?->tokenFamily->revoke();
        } catch (Exception) {
        }

        $this->forget();
    }

    public function forget(): static
    {
        $this->user = null;
        $this->token = null;

        return $this;
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function guest(): bool
    {
        return !$this->check();
    }

    public function id(): int|string|null
    {
        return $this->user()?->getAuthIdentifier();
    }

    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    /**
     * @return class-string<Model>
     */
    protected function providerModelClass(): string
    {
        if ($this->providerName === null) {
            throw new InvalidGuardConfigurationException('The hyrnatic-authenticator guard requires a configured auth provider.');
        }

        if ($this->provider === null) {
            throw new InvalidGuardConfigurationException("The auth provider [{$this->providerName}] could not be resolved.");
        }

        $model = config("auth.providers.{$this->providerName}.model");

        if (!is_string($model) || !is_subclass_of($model, Model::class)) {
            throw new InvalidGuardConfigurationException("The auth provider [{$this->providerName}] must define an Eloquent model.");
        }

        return $model;
    }

    protected function assertAuthableMatchesProvider(mixed $authable): Contracts\HasApiTokens
    {
        $providerModel = $this->providerModelClass();

        if (!$authable instanceof Contracts\HasApiTokens || $authable::class !== $providerModel) {
            $actualModel = is_object($authable) ? $authable::class : get_debug_type($authable);

            throw new AuthableProviderMismatchException(
                "Guard provider [{$this->providerName}] expects [{$providerModel}], [{$actualModel}] given."
            );
        }

        return $authable;
    }

    protected function assertTokenType(Token\Plain $token, string $expectedType): void
    {
        if (!$token->headers()->has('typ') || $token->headers()->get('typ') !== $expectedType) {
            throw new TokenInvalidException();
        }
    }

    protected function requiredStringClaim(Token\Plain $token, string $name): string
    {
        if (!$token->claims()->has($name)) {
            throw new TokenInvalidException();
        }

        $value = $token->claims()->get($name);
        if (!is_string($value) || $value === '') {
            throw new TokenInvalidException();
        }

        return $value;
    }

    protected function requiredPositiveIntegerClaim(Token\Plain $token, string $name): int
    {
        if (!$token->claims()->has($name)) {
            throw new TokenInvalidException();
        }

        $value = $token->claims()->get($name);
        if (!is_int($value) || $value < 1) {
            throw new TokenInvalidException();
        }

        return $value;
    }

    protected function requiredSubjectClaim(Token\Plain $token): string
    {
        $subject = $this->requiredStringClaim($token, 'sub');
        $parts = explode('|', $subject, 2);

        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new TokenInvalidException();
        }

        return $subject;
    }

    /**
     * @return list<array{key:string,resource_type:?string,resource_id:string|int|null}>
     */
    protected function requiredScopeSnapshotClaim(Token\Plain $token): array
    {
        if (!$token->claims()->has('scp')) {
            throw new TokenInvalidException();
        }

        $scopeSnapshot = $token->claims()->get('scp');
        if (!is_array($scopeSnapshot) || !array_is_list($scopeSnapshot)) {
            throw new TokenInvalidException();
        }

        foreach ($scopeSnapshot as $scope) {
            if (!is_array($scope)
                || !isset($scope['key'])
                || !is_string($scope['key'])
                || $scope['key'] === ''
                || (isset($scope['resource_type']) && !is_string($scope['resource_type']))
                || (isset($scope['resource_id']) && !is_string($scope['resource_id']) && !is_int($scope['resource_id']))
            ) {
                throw new TokenInvalidException();
            }

            $hasResourceType = array_key_exists('resource_type', $scope) && $scope['resource_type'] !== null;
            $hasResourceId = array_key_exists('resource_id', $scope) && $scope['resource_id'] !== null;
            if ($hasResourceType !== $hasResourceId) {
                throw new TokenInvalidException();
            }
        }

        return $this->normalizeScopeSnapshot($scopeSnapshot);
    }

    /**
     * @param list<array{key:string,resource_type?:string|null,resource_id?:string|int|null}> $scopeSnapshot
     * @return list<array{key:string,resource_type:?string,resource_id:string|int|null}>
     */
    private function normalizeScopeSnapshot(array $scopeSnapshot): array
    {
        return array_map(static fn (array $scope): array => [
            'key' => $scope['key'],
            'resource_type' => $scope['resource_type'] ?? null,
            'resource_id' => $scope['resource_id'] ?? null,
        ], $scopeSnapshot);
    }
}
