<?php

declare(strict_types=1);

namespace Cbox\CboxIdTokens\Tests;

use Cbox\CboxIdTokens\CboxIdTokensServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            CboxIdTokensServiceProvider::class,
        ];
    }

    /**
     * @param  Application  $app
     */
    protected function defineEnvironment($app): void
    {
        // Tests construct CboxIdTokens directly with explicit deps;
        // the container-wired test sets its own config. Defaults are
        // intentionally empty so a misconfigured provider fails loud
        // rather than silently falling back to dev values.
        $app['config']->set('cache.default', 'array');
    }
}
