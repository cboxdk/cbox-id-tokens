# cbox-id-tokens (PHP)

Service-to-service OAuth helper for callers of id-issued tokens. Implements
the contract in [`cbox-infra/docs/SERVICE_AUTH.md`](https://github.com/cboxdk/cbox-infra/blob/main/docs/SERVICE_AUTH.md).

Sister apps (webhooks, vault, cortex, atlas, …) install this package to talk
to id and to each other through id-issued bearer tokens.

## Install

```bash
composer require cboxdk/cbox-id-tokens
```

The package auto-registers via Laravel's package discovery — no manual
service-provider registration needed.

## Configure

Add a `cbox_id_tokens` block to `config/services.php`:

```php
'cbox_id_tokens' => [
    'token_endpoint' => env('CBOX_ID_TOKEN_ENDPOINT'),
    'client_id' => env('CBOX_ID_CLIENT_ID'),
    'client_secret' => env('CBOX_ID_CLIENT_SECRET'),
    'cache_store' => env('CBOX_ID_TOKEN_CACHE_STORE'),
],
```

Set the env vars in `.env`:

```
CBOX_ID_TOKEN_ENDPOINT=https://id.cbox.systems/oauth/token
CBOX_ID_CLIENT_ID=your-app-client-id
CBOX_ID_CLIENT_SECRET=your-app-client-secret
```

`CBOX_ID_TOKEN_CACHE_STORE` is optional — defaults to your app's default cache
store (Redis is strongly recommended in production).

## Use

```php
use Cbox\CboxIdTokens\CboxIdTokens;
use Illuminate\Support\Facades\Http;

public function publish(CboxIdTokens $tokens, array $payload): void
{
    $token = $tokens
        ->forAudience('notifications.cbox.systems')
        ->withScopes(['notifications.publish'])
        ->fetch();

    Http::withToken($token->bearer)
        ->post('https://notifications.cbox.systems/api/v1/events', $payload);
}
```

The helper handles caching, single-flight (so a thundering herd doesn't
stampede `/oauth/token`), and retry-friendly exception types.

### On a 401 from upstream

```php
use Cbox\CboxIdTokens\CboxIdTokens;

$audience = 'notifications.cbox.systems';
$scopes = ['notifications.publish'];

$token = $tokens->forAudience($audience)->withScopes($scopes)->fetch();
$response = Http::withToken($token->bearer)->post(/* ... */);

if ($response->status() === 401) {
    // Token may have been revoked — invalidate and retry once.
    $tokens->invalidate($audience, $scopes);
    $token = $tokens->forAudience($audience)->withScopes($scopes)->fetch();
    $response = Http::withToken($token->bearer)->post(/* ... */);
}
```

A second 401 after invalidate is a hard failure — let it propagate.

## Caching

Tokens are cached under
`cbox:svc-token:{sha256(client_id|audience|sorted-deduped-scopes)}` with TTL
= `expires_in - 60s`. Single-flight via `Cache::lock()`. Duplicate scopes in
a request collapse to the same cache slot.

## Errors

All recoverable errors throw `Cbox\CboxIdTokens\TokenFetchException` with
context fields:

- `httpStatus` — set when the token endpoint returned a 4xx/5xx
- `upstreamError` — OAuth `error` code from id when present (`invalid_client`,
  `invalid_scope`, …)
- `audience` — the audience the failed call was for
- `getPrevious()` — the underlying exception (`ConnectionException` for
  network errors, `LockTimeoutException` if a concurrent fetch hung)

## License

MIT
