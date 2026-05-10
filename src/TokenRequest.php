<?php

declare(strict_types=1);

namespace Cbox\CboxIdTokens;

/**
 * Fluent builder for a service-token fetch. Each call returns a
 * new instance — safe to stash one and reuse with different scope
 * sets.
 */
final readonly class TokenRequest
{
    /**
     * @param  list<string>  $scopes
     */
    private function __construct(
        private CboxIdTokens $client,
        private string $audience,
        private array $scopes = [],
    ) {}

    /**
     * @internal Construction goes through CboxIdTokens::forAudience().
     */
    public static function forAudience(CboxIdTokens $client, string $audience): self
    {
        return new self($client, $audience);
    }

    /**
     * @param  list<string>  $scopes
     */
    public function withScopes(array $scopes): self
    {
        $normalized = array_values(array_map(static fn ($s): string => (string) $s, $scopes));

        return new self($this->client, $this->audience, $normalized);
    }

    public function fetch(): ServiceToken
    {
        return $this->client->fetchToken($this->audience, $this->scopes);
    }
}
