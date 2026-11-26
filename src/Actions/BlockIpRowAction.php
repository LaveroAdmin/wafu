<?php

namespace LaveroAdmin\Admin\Wafu\Actions;

use Illuminate\Database\Eloquent\Model;
use LaveroAdmin\Admin\Actions\Response;
use LaveroAdmin\Admin\Actions\RowAction;
use LaveroAdmin\Admin\Wafu\Models\WafuBlock;

class BlockIpRowAction extends RowAction
{
    public function name()
    {
        $ip = (string) $this->row->ip;

        return WafuBlock::isBlocked($ip)
            ? trans('lavero-admin-wafu::wafu.unblock_ip')
            : trans('lavero-admin-wafu::wafu.block_ip');
    }

    public function handle(Model $model): Response
    {
        $ip = (string) $model->ip;
        $record = WafuBlock::toggle($ip, 'Toggled from WAF Events grid');

        $message = $record->is_blocked
            ? trans('lavero-admin-wafu::wafu.ip_blocked_msg', ['ip' => $ip])
            : trans('lavero-admin-wafu::wafu.ip_unblocked_msg', ['ip' => $ip]);

        return $this->response()->success($message)->refresh();
    }
}
