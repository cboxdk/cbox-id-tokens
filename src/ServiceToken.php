<?php

declare(strict_types=1);

namespace Cbox\CboxIdTokens;

use Carbon\CarbonImmutable;

/**
 * Result of a service-to-service token fetch via id's /oauth/token.
 * Immutable. Carries enough metadata for the receiver-side audit
 * (audience, scopes) plus the bearer string for outbound calls.
 *
 * Wire shape when serialized into the Redis cache uses ISO-8601 for
 * `expires_at` so cross-runtime decoding is trivial.
 */
final readonly class ServiceToken
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $bearer,
        public CarbonImmutable $expiresAt,
        public string $audience,
        public array $scopes,
    ) {}

    public function isExpired(?CarbonImmutable $now = null): bool
    {
        return ($now ?? CarbonImmutable::now())->greaterThanOrEqualTo($this->expiresAt);
    }

    /**
     * @return array{bearer: string, expires_at: string, audience: string, scopes: list<string>}
     */
    public function toArray(): array
    {
        return [
            'bearer' => $this->bearer,
            'expires_at' => $this->expiresAt->toIso8601String(),
            'audience' => $this->audience,
            'scopes' => $this->scopes,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $scopes = is_array($data['scopes'] ?? null) ? $data['scopes'] : [];

        return new self(
            bearer: (string) ($data['bearer'] ?? ''),
            expiresAt: CarbonImmutable::parse((string) ($data['expires_at'] ?? 'now')),
            audience: (string) ($data['audience'] ?? ''),
            scopes: array_values(array_map(static fn ($s): string => (string) $s, $scopes)),
        );
    }
}
