<?php

namespace LaveroAdmin\Admin\Wafu;

use Illuminate\Routing\Router;
use LaveroAdmin\Admin\Admin;

trait BootExtension
{
    public static function boot()
    {
        static::registerRoutes();

        Admin::extend('wafu', __CLASS__);
    }

    protected static function registerRoutes()
    {
        parent::routes(function (Router $router) {
            $router->resource('wafu/events', 'LaveroAdmin\Admin\Wafu\Controllers\WafuEventController', ['as' => 'wafu']);
            $router->resource('wafu/blocks', 'LaveroAdmin\Admin\Wafu\Controllers\WafuBlockController', ['as' => 'wafu']);
            $router->get('wafu/settings', 'LaveroAdmin\Admin\Wafu\Controllers\WafuSettingsController@index')->name('wafu.settings');
            $router->post('wafu/settings', 'LaveroAdmin\Admin\Wafu\Controllers\WafuSettingsController@save')->name('wafu.settings.save');
            $router->post('wafu/ip/toggle', 'LaveroAdmin\Admin\Wafu\Controllers\WafuIpActionController@toggle')->name('wafu.ip.toggle');
        });
    }

    public static function import()
    {
        parent::createMenu('WAF Firewall', 'wafu', 'icon-shield-alt', 0, [
            [
                'title' => 'Security Events',
                'path'  => 'wafu/events',
                'uri'   => 'wafu/events',
                'icon'  => 'icon-list',
            ],
            [
                'title' => 'Blocked IPs',
                'path'  => 'wafu/blocks',
                'uri'   => 'wafu/blocks',
                'icon'  => 'icon-ban',
            ],
            [
                'title' => 'WAF Settings',
                'path'  => 'wafu/settings',
                'uri'   => 'wafu/settings',
                'icon'  => 'icon-cogs',
            ],
        ]);

        parent::createPermission('WAF Firewall', 'ext.wafu', 'wafu*');
    }
}
