<?php

namespace LaveroAdmin\Admin\Wafu\Actions;

use Illuminate\Database\Eloquent\Model;
use LaveroAdmin\Admin\Actions\Response;
use LaveroAdmin\Admin\Actions\RowAction;
use LaveroAdmin\Admin\Wafu\Services\WafuService;

class WhitelistIpRowAction extends RowAction
{
    public function name()
    {
        return trans('lavero-admin-wafu::wafu.whitelist_ip');
    }

    public function handle(Model $model): Response
    {
        $ip = trim((string) $model->ip);
        if ($ip === '') {
            return $this->response()->error('IP address is empty.');
        }

        $added = WafuService::addWhitelistedIp($ip);
        $message = $added
            ? trans('lavero-admin-wafu::wafu.ip_whitelisted_msg', ['ip' => $ip])
            : trans('lavero-admin-wafu::wafu.ip_already_whitelisted_msg', ['ip' => $ip]);

        return $this->response()->success($message);
    }
}
