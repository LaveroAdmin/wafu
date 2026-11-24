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
        $ip = (string)$this->row->ip;
        return WafuBlock::isBlocked($ip) ? 'Unblock IP' : 'Block IP';
    }

    public function handle(Model $model): Response
    {
        $ip = (string)$model->ip;
        $record = WafuBlock::toggle($ip, 'Toggled from WAF Events grid');

        $message = $record->is_blocked
            ? "IP [{$ip}] has been blocked."
            : "IP [{$ip}] has been unblocked.";

        return $this->response()->success($message)->refresh();
    }
}
