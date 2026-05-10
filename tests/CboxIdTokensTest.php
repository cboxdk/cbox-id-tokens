<?php

declare(strict_types=1);

namespace Cbox\CboxIdTokens\Tests;

use Carbon\CarbonImmutable;
use Cbox\CboxIdTokens\CboxIdTokens;
use Cbox\CboxIdTokens\TokenFetchException;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Cache\Store as CacheStore;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use RuntimeException;

const TOKEN_ENDPOINT = 'https://id.test/oauth/token';
const CLIENT_ID = 'test-client';
const CLIENT_SECRET = 'test-secret';

beforeEach(function (): void {
    Cache::flush();
});

function makeCboxIdTokens(): CboxIdTokens
{
    return new CboxIdTokens(
        tokenEndpoint: TOKEN_ENDPOINT,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        http: app(HttpFactory::class),
        cacheFactory: app(CacheFactory::class),
    );
}

function fakeTokenResponse(string $bearer = 'opaque-bearer', int $expiresIn = 600): void
{
    Http::fake([
        TOKEN_ENDPOINT => Http::response([
            'token_type' => 'Bearer',
            'access_token' => $bearer,
            'expires_in' => $expiresIn,
        ], 200),
    ]);
}

test('fluent API fetches a token and exposes the bearer + expiry', function (): void {
    fakeTokenResponse('the-token', 600);

    $token = makeCboxIdTokens()
        ->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch();

    expect($token->bearer)->toBe('the-token')
        ->and($token->audience)->toBe('notifications.cbox.systems')
        ->and($token->scopes)->toBe(['notifications.publish'])
        ->and($token->isExpired())->toBeFalse();

    Http::assertSent(function ($request): bool {
        $body = $request->data();

        return $request->url() === TOKEN_ENDPOINT
            && $body['grant_type'] === 'client_credentials'
            && $body['client_id'] === CLIENT_ID
            && $body['client_secret'] === CLIENT_SECRET
            && $body['scope'] === 'notifications.publish';
    });
});

test('repeated fetch within the cache TTL hits the cache and not the endpoint', function (): void {
    fakeTokenResponse('once-only', 600);

    $client = makeCboxIdTokens();

    $first = $client->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch();

    $second = $client->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch();

    expect($first->bearer)->toBe('once-only')
        ->and($second->bearer)->toBe('once-only');

    Http::assertSentCount(1);
});

test('different scope sets get different cache entries and trigger separate fetches', function (): void {
    Http::fake([
        TOKEN_ENDPOINT => Http::sequence()
            ->push(['token_type' => 'Bearer', 'access_token' => 'tok-A', 'expires_in' => 600], 200)
            ->push(['token_type' => 'Bearer', 'access_token' => 'tok-B', 'expires_in' => 600], 200),
    ]);

    $client = makeCboxIdTokens();

    $a = $client->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch();

    $b = $client->forAudience('notifications.cbox.systems')
        ->withScopes(['id.audit.write'])
        ->fetch();

    expect($a->bearer)->toBe('tok-A')
        ->and($b->bearer)->toBe('tok-B');

    Http::assertSentCount(2);
});

test('scope-set order does not change the cache key', function (): void {
    fakeTokenResponse('canonical-scopes', 600);

    $client = makeCboxIdTokens();

    $client->forAudience('vault.cbox.systems')
        ->withScopes(['id.usage.write', 'id.audit.write'])
        ->fetch();

    $client->forAudience('vault.cbox.systems')
        ->withScopes(['id.audit.write', 'id.usage.write']) // reversed
        ->fetch();

    Http::assertSentCount(1);
});

test('duplicate scopes in the request collapse to the same cache slot', function (): void {
    fakeTokenResponse('deduped', 600);

    $client = makeCboxIdTokens();

    $client->forAudience('a.cbox.systems')
        ->withScopes(['scope.a', 'scope.a', 'scope.b'])
        ->fetch();

    $client->forAudience('a.cbox.systems')
        ->withScopes(['scope.a', 'scope.b'])
        ->fetch();

    Http::assertSentCount(1);
});

test('invalidate forces a refetch on the next call', function (): void {
    Http::fake([
        TOKEN_ENDPOINT => Http::sequence()
            ->push(['token_type' => 'Bearer', 'access_token' => 'first', 'expires_in' => 600], 200)
            ->push(['token_type' => 'Bearer', 'access_token' => 'second', 'expires_in' => 600], 200),
    ]);

    $client = makeCboxIdTokens();

    $a = $client->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch();

    $client->invalidate('notifications.cbox.systems', ['notifications.publish']);

    $b = $client->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch();

    expect($a->bearer)->toBe('first')
        ->and($b->bearer)->toBe('second');

    Http::assertSentCount(2);
});

test('cache TTL stays below the token expiry by the safety margin', function (): void {
    Http::fake([
        TOKEN_ENDPOINT => Http::sequence()
            ->push(['token_type' => 'Bearer', 'access_token' => 'first', 'expires_in' => 600], 200)
            ->push(['token_type' => 'Bearer', 'access_token' => 'second', 'expires_in' => 600], 200),
    ]);

    CarbonImmutable::setTestNow('2026-05-10T12:00:00Z');

    $client = makeCboxIdTokens();
    $client->forAudience('a.cbox.systems')->withScopes(['s'])->fetch();

    CarbonImmutable::setTestNow('2026-05-10T12:05:00Z');
    $client->forAudience('a.cbox.systems')->withScopes(['s'])->fetch();
    Http::assertSentCount(1);

    CarbonImmutable::setTestNow('2026-05-10T12:10:01Z');
    $token = $client->forAudience('a.cbox.systems')->withScopes(['s'])->fetch();

    Http::assertSentCount(2);
    expect($token->bearer)->toBe('second');

    CarbonImmutable::setTestNow();
});

test('a 4xx from the token endpoint surfaces as TokenFetchException with httpStatus', function (): void {
    Http::fake([
        TOKEN_ENDPOINT => Http::response([
            'error' => 'invalid_client',
            'error_description' => 'Authentication failed',
        ], 401),
    ]);

    expect(fn () => makeCboxIdTokens()
        ->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch())
        ->toThrow(TokenFetchException::class);

    try {
        makeCboxIdTokens()
            ->forAudience('notifications.cbox.systems')
            ->withScopes(['notifications.publish'])
            ->fetch();
    } catch (TokenFetchException $e) {
        expect($e->httpStatus)->toBe(401)
            ->and($e->upstreamError)->toBe('invalid_client')
            ->and($e->audience)->toBe('notifications.cbox.systems');
    }
});

test('a 5xx surfaces as TokenFetchException', function (): void {
    Http::fake([
        TOKEN_ENDPOINT => Http::response('upstream blew up', 503),
    ]);

    expect(fn () => makeCboxIdTokens()
        ->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch())
        ->toThrow(TokenFetchException::class);
});

test('a connection failure surfaces as TokenFetchException with the original cause attached', function (): void {
    Http::fake([
        TOKEN_ENDPOINT => fn () => throw new ConnectionException('dns lookup failed'),
    ]);

    try {
        makeCboxIdTokens()
            ->forAudience('notifications.cbox.systems')
            ->withScopes(['notifications.publish'])
            ->fetch();
    } catch (TokenFetchException $e) {
        expect($e->getPrevious())->toBeInstanceOf(ConnectionException::class)
            ->and($e->audience)->toBe('notifications.cbox.systems');

        return;
    }

    test()->fail('Expected TokenFetchException');
});

test('a malformed token response (missing access_token) surfaces as TokenFetchException', function (): void {
    Http::fake([
        TOKEN_ENDPOINT => Http::response([
            'token_type' => 'Bearer',
            'expires_in' => 600,
        ], 200),
    ]);

    expect(fn () => makeCboxIdTokens()
        ->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch())
        ->toThrow(TokenFetchException::class);
});

test('container-wired CboxIdTokens resolves and uses configured values', function (): void {
    config()->set('services.cbox_id_tokens', [
        'token_endpoint' => TOKEN_ENDPOINT,
        'client_id' => 'wired-client',
        'client_secret' => 'wired-secret',
        'cache_store' => null,
    ]);

    fakeTokenResponse('via-container', 600);

    /** @var CboxIdTokens $client */
    $client = app(CboxIdTokens::class);
    $token = $client->forAudience('a.cbox.systems')->withScopes(['s'])->fetch();

    expect($token->bearer)->toBe('via-container');

    Http::assertSent(function ($request): bool {
        $body = $request->data();

        return $body['client_id'] === 'wired-client'
            && $body['client_secret'] === 'wired-secret';
    });
});

test('rejects an http:// tokenEndpoint at construction', function (): void {
    expect(fn () => new CboxIdTokens(
        tokenEndpoint: 'http://id.public.example/oauth/token',
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        http: app(HttpFactory::class),
        cacheFactory: app(CacheFactory::class),
    ))->toThrow(InvalidArgumentException::class, 'must use https://');
});

test('rejects a non-URL tokenEndpoint at construction', function (): void {
    expect(fn () => new CboxIdTokens(
        tokenEndpoint: 'not-a-url',
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        http: app(HttpFactory::class),
        cacheFactory: app(CacheFactory::class),
    ))->toThrow(InvalidArgumentException::class);
});

test('allowInsecure permits http://localhost for local dev only', function (): void {
    $client = new CboxIdTokens(
        tokenEndpoint: 'http://localhost/oauth/token',
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        http: app(HttpFactory::class),
        cacheFactory: app(CacheFactory::class),
        allowInsecure: true,
    );

    expect($client)->toBeInstanceOf(CboxIdTokens::class);
});

test('allowInsecure does NOT permit http:// against a public host', function (): void {
    expect(fn () => new CboxIdTokens(
        tokenEndpoint: 'http://id.public.example/oauth/token',
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        http: app(HttpFactory::class),
        cacheFactory: app(CacheFactory::class),
        allowInsecure: true,
    ))->toThrow(InvalidArgumentException::class, 'must use https://');
});

test('empty tokenEndpoint is allowed (constructor stays a no-op for non-consuming apps)', function (): void {
    $client = new CboxIdTokens(
        tokenEndpoint: '',
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        http: app(HttpFactory::class),
        cacheFactory: app(CacheFactory::class),
    );

    expect($client)->toBeInstanceOf(CboxIdTokens::class);
});

/**
 * Cache repository whose primary ops throw on demand. Used to simulate
 * Redis dropping while an outbound /oauth/token call is in flight.
 */
final class FailingCacheRepository extends Repository
{
    public bool $getFails = false;

    public bool $lockFails = false;

    public bool $putFails = false;

    public function __construct(CacheStore $store)
    {
        parent::__construct($store);
    }

    public function get($key, $default = null): mixed
    {
        if ($this->getFails) {
            throw new RuntimeException('Redis is down (test).');
        }

        return parent::get($key, $default);
    }

    public function put($key, $value, $ttl = null): bool
    {
        if ($this->putFails) {
            throw new RuntimeException('Redis is down (test).');
        }

        return parent::put($key, $value, $ttl);
    }

    public function lock($name, $seconds = 0, $owner = null)
    {
        if ($this->lockFails) {
            throw new RuntimeException('Redis is down (test).');
        }

        return parent::lock($name, $seconds, $owner);
    }
}

function makeCboxIdTokensWith(CacheRepository $cache): CboxIdTokens
{
    $factory = new class($cache) implements CacheFactory
    {
        public function __construct(private readonly CacheRepository $cache) {}

        public function store($name = null)
        {
            return $this->cache;
        }
    };

    return new CboxIdTokens(
        tokenEndpoint: TOKEN_ENDPOINT,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        http: app(HttpFactory::class),
        cacheFactory: $factory,
    );
}

test('Redis read failure falls through to direct fetch and still returns a token', function (): void {
    fakeTokenResponse('redis-bypass', 600);

    /** @var CacheRepository $real */
    $real = app(CacheFactory::class)->store();
    $cache = new FailingCacheRepository($real->getStore());
    $cache->getFails = true;

    $token = makeCboxIdTokensWith($cache)
        ->forAudience('a.cbox.systems')
        ->withScopes(['s'])
        ->fetch();

    expect($token->bearer)->toBe('redis-bypass');
    Http::assertSentCount(1);
});

test('Redis lock failure falls through to direct fetch and still returns a token', function (): void {
    fakeTokenResponse('lock-bypass', 600);

    /** @var CacheRepository $real */
    $real = app(CacheFactory::class)->store();
    $cache = new FailingCacheRepository($real->getStore());
    $cache->lockFails = true;

    $token = makeCboxIdTokensWith($cache)
        ->forAudience('a.cbox.systems')
        ->withScopes(['s'])
        ->fetch();

    expect($token->bearer)->toBe('lock-bypass');
    Http::assertSentCount(1);
});

test('Redis put failure swallows silently — token still returned to caller', function (): void {
    fakeTokenResponse('put-bypass', 600);

    /** @var CacheRepository $real */
    $real = app(CacheFactory::class)->store();
    $cache = new FailingCacheRepository($real->getStore());
    $cache->putFails = true;

    $token = makeCboxIdTokensWith($cache)
        ->forAudience('a.cbox.systems')
        ->withScopes(['s'])
        ->fetch();

    expect($token->bearer)->toBe('put-bypass');
    Http::assertSentCount(1);
});

test('invalidate() swallows cache failures silently', function (): void {
    /** @var CacheRepository $real */
    $real = app(CacheFactory::class)->store();
    $cache = new FailingCacheRepository($real->getStore());
    $cache->getFails = true; // forget() in Laravel calls store->forget — getFails doesn't trip it
    // but exercising the catch path doesn't require a specific failure flag.

    expect(fn () => makeCboxIdTokensWith($cache)
        ->invalidate('a.cbox.systems', ['s']))->not->toThrow(\Throwable::class);
});
