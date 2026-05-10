<?php

declare(strict_types=1);

namespace Cbox\CboxIdTokens;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Throwable;

/**
 * Service-to-service OAuth helper for callers of id-issued tokens.
 * Implements the contract in cbox-infra/docs/SERVICE_AUTH.md.
 *
 * Sister apps (webhooks, vault, future cortex/atlas) install this
 * package to talk to id and to each other. id itself rarely needs
 * it — id self-mints tokens for outbound calls when it's the issuer.
 *
 * Caches the fetched token under
 *   cbox:svc-token:{sha256(client_id|audience|sorted-deduped-scopes)}
 * with TTL = (token expires_in - 60s safety margin). Single-flight
 * via Cache::lock() so a thundering herd doesn't stampede the
 * /oauth/token endpoint after a deploy / cache flush.
 *
 * On 401 from upstream the caller should invalidate(...) and
 * refetch once. A second 401 is a hard failure.
 *
 * Usage (per SERVICE_AUTH.md):
 *   $token = $cboxIdTokens
 *       ->forAudience('notifications.cbox.systems')
 *       ->withScopes(['notifications.publish'])
 *       ->fetch();
 *
 *   Http::withToken($token->bearer)->post(...);
 */
final class CboxIdTokens
{
    /** Cache TTL safety margin so a cache hit can never serve a soon-to-expire token. */
    private const TTL_SAFETY_MARGIN_SECONDS = 60;

    /** Lock TTL — generous; the actual fetch is sub-second. */
    private const LOCK_TTL_SECONDS = 30;

    /** Time a competing worker waits for the leader to finish. */
    private const LOCK_BLOCK_SECONDS = 10;

    private CacheRepository $cache;

    public function __construct(
        private readonly string $tokenEndpoint,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly HttpFactory $http,
        CacheFactory $cacheFactory,
        ?string $cacheStore = null,
    ) {
        $this->cache = $cacheFactory->store($cacheStore);
    }

    public function forAudience(string $audience): TokenRequest
    {
        return TokenRequest::forAudience($this, $audience);
    }

    /**
     * @param  list<string>  $scopes
     *
     * @internal Called by TokenRequest::fetch().
     */
    public function fetchToken(string $audience, array $scopes): ServiceToken
    {
        $cacheKey = $this->cacheKey($audience, $scopes);

        $cached = $this->cache->get($cacheKey);
        if (is_array($cached)) {
            $token = ServiceToken::fromArray($cached);
            if (! $token->isExpired()) {
                return $token;
            }
        }

        $lock = $this->cache->lock($cacheKey.':lock', self::LOCK_TTL_SECONDS);

        try {
            return $lock->block(self::LOCK_BLOCK_SECONDS, function () use ($audience, $scopes, $cacheKey): ServiceToken {
                // Re-check the cache after acquiring the lock — a
                // concurrent worker may have populated it while we waited.
                $cached = $this->cache->get($cacheKey);
                if (is_array($cached)) {
                    $token = ServiceToken::fromArray($cached);
                    if (! $token->isExpired()) {
                        return $token;
                    }
                }

                $token = $this->fetchFromEndpoint($audience, $scopes);

                // Unix-timestamp arithmetic — Carbon's diffInSeconds is
                // signed in v3 so getting the operand order wrong silently
                // collapses the TTL to 1s. The straight subtraction is
                // unambiguous and faster.
                $secondsUntilExpiry = $token->expiresAt->getTimestamp() - CarbonImmutable::now()->getTimestamp();
                $ttl = max(1, $secondsUntilExpiry - self::TTL_SAFETY_MARGIN_SECONDS);
                $this->cache->put($cacheKey, $token->toArray(), $ttl);

                return $token;
            });
        } catch (LockTimeoutException $e) {
            // Another worker held the lock for >LOCK_BLOCK_SECONDS without
            // ever publishing a token — likely the leader is hung mid-fetch.
            // Surface as TokenFetchException so the caller's catch path
            // (per SERVICE_AUTH.md) sees a uniform contract instead of a
            // framework-specific exception.
            throw new TokenFetchException(
                message: 'Timed out waiting for concurrent token fetch (lock held >'.self::LOCK_BLOCK_SECONDS.'s).',
                audience: $audience,
                previous: $e,
            );
        }
    }

    /**
     * Forget the cached token for a given (audience, scopes) pair.
     * Call this after a 401 from upstream so the next fetch goes
     * back to id's /oauth/token instead of replaying a stale token.
     *
     * @param  list<string>  $scopes
     */
    public function invalidate(string $audience, array $scopes): void
    {
        $this->cache->forget($this->cacheKey($audience, $scopes));
    }

    /**
     * @param  list<string>  $scopes
     */
    private function fetchFromEndpoint(string $audience, array $scopes): ServiceToken
    {
        try {
            $response = $this->http
                ->asForm()
                ->acceptJson()
                ->timeout(10)
                ->connectTimeout(5)
                ->post($this->tokenEndpoint, [
                    'grant_type' => 'client_credentials',
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                    'scope' => implode(' ', $scopes),
                ]);
        } catch (ConnectionException $e) {
            throw new TokenFetchException(
                message: "Failed to reach id token endpoint: {$e->getMessage()}",
                audience: $audience,
                previous: $e,
            );
        } catch (Throwable $e) {
            throw new TokenFetchException(
                message: "Unexpected error fetching service token: {$e->getMessage()}",
                audience: $audience,
                previous: $e,
            );
        }

        if (! $response->successful()) {
            $body = (string) $response->body();
            $upstreamError = is_array($json = $response->json())
                ? (string) ($json['error'] ?? '')
                : '';

            throw new TokenFetchException(
                message: "Token endpoint returned HTTP {$response->status()}: ".substr($body, 0, 200),
                httpStatus: $response->status(),
                upstreamError: $upstreamError !== '' ? $upstreamError : null,
                audience: $audience,
            );
        }

        /** @var array<string, mixed> $body */
        $body = (array) $response->json();

        $accessToken = (string) ($body['access_token'] ?? '');
        $expiresIn = (int) ($body['expires_in'] ?? 0);

        if ($accessToken === '' || $expiresIn <= 0) {
            throw new TokenFetchException(
                message: 'Token endpoint returned a malformed response (missing access_token or expires_in).',
                httpStatus: $response->status(),
                audience: $audience,
            );
        }

        return new ServiceToken(
            bearer: $accessToken,
            expiresAt: CarbonImmutable::now()->addSeconds($expiresIn),
            audience: $audience,
            scopes: $scopes,
        );
    }

    /**
     * @param  list<string>  $scopes
     */
    private function cacheKey(string $audience, array $scopes): string
    {
        // Dedupe + sort — `['a','a','b']` and `['b','a']` both
        // produce identical issued tokens, so they should share a
        // cache slot. Without array_unique we'd burn an extra
        // /oauth/token round-trip per duplicate-permutation.
        $normalized = array_values(array_unique($scopes));
        sort($normalized);

        $material = $this->clientId.'|'.$audience.'|'.implode(',', $normalized);

        return 'cbox:svc-token:'.hash('sha256', $material);
    }
}
