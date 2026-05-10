<?php

declare(strict_types=1);

namespace Cbox\CboxIdTokens;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\ServiceProvider;

/**
 * Auto-discovered by Laravel via composer.json's
 * `extra.laravel.providers`. Reads its config from
 * `services.cbox_id_tokens` so the consumer app keeps a single
 * `config/services.php` file rather than publishing a separate
 * config from this package.
 *
 * Required env vars in the consumer app:
 *   CBOX_ID_TOKEN_ENDPOINT  full URL of id's /oauth/token
 *   CBOX_ID_CLIENT_ID       this app's OAuth client_id (registered in id)
 *   CBOX_ID_CLIENT_SECRET   the matching client secret
 * Optional:
 *   CBOX_ID_TOKEN_CACHE_STORE  cache store name (defaults to default)
 *
 * The consumer's `config/services.php` should contain:
 *
 *   'cbox_id_tokens' => [
 *       'token_endpoint' => env('CBOX_ID_TOKEN_ENDPOINT'),
 *       'client_id' => env('CBOX_ID_CLIENT_ID'),
 *       'client_secret' => env('CBOX_ID_CLIENT_SECRET'),
 *       'cache_store' => env('CBOX_ID_TOKEN_CACHE_STORE'),
 *   ],
 *
 * The provider doesn't validate config presence at boot — empty
 * values produce a CboxIdTokens that throws TokenFetchException on
 * first fetch, with a clear error. That's the right tradeoff for
 * apps that may legitimately not consume id-issued tokens.
 */
class CboxIdTokensServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(CboxIdTokens::class, function ($app): CboxIdTokens {
            /** @var array<string, mixed> $config */
            $config = (array) $app['config']->get('services.cbox_id_tokens', []);

            return new CboxIdTokens(
                tokenEndpoint: (string) ($config['token_endpoint'] ?? ''),
                clientId: (string) ($config['client_id'] ?? ''),
                clientSecret: (string) ($config['client_secret'] ?? ''),
                http: $app->make(HttpFactory::class),
                cacheFactory: $app->make(CacheFactory::class),
                cacheStore: is_string($config['cache_store'] ?? null) && $config['cache_store'] !== ''
                    ? (string) $config['cache_store']
                    : null,
            );
        });
    }
}
