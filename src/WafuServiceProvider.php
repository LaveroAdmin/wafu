<?php

namespace LaveroAdmin\Admin\Wafu;

use Illuminate\Support\ServiceProvider;
use LaveroAdmin\Admin\Wafu\Middleware\WafuFirewallMiddleware;

class WafuServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'lavero-admin-wafu');
        $this->loadTranslationsFrom(__DIR__ . '/../resources/lang', 'lavero-admin-wafu');

        Wafu::boot();

        if ($this->app->bound('router')) {
            $this->app['router']->aliasMiddleware('wafu.firewall', WafuFirewallMiddleware::class);
        }
    }

    public function register(): void
    {
        // Service bindings if needed
    }
}
