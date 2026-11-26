<?php

namespace LaveroAdmin\Admin\Wafu\Actions;

use Illuminate\Database\Eloquent\Model;
use LaveroAdmin\Admin\Actions\Response;
use LaveroAdmin\Admin\Actions\RowAction;
use LaveroAdmin\Admin\Wafu\Services\WafuService;

class ExcludeRouteRowAction extends RowAction
{
    public $icon = 'icon-filter text-warning';

    public function render()
    {
        return (string) preg_replace("/class='([^']*)'/", "class='$1 d-none d-md-inline-flex'", parent::render(), 1);
    }

    public function name()
    {
        return trans('lavero-admin-wafu::wafu.exclude_route');
    }

    public function handle(Model $model): Response
    {
        $path = parse_url((string) $model->uri, PHP_URL_PATH);
        $route = is_string($path) && $path !== '' ? $path : '/';

        $added = WafuService::addExcludedRoute($route);
        $message = $added
            ? trans('lavero-admin-wafu::wafu.route_excluded_msg', ['route' => $route])
            : trans('lavero-admin-wafu::wafu.route_already_excluded_msg', ['route' => $route]);

        return $this->response()->success($message);
    }
}
