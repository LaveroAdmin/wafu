<?php

namespace LaveroAdmin\Admin\Wafu\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use LaveroAdmin\Admin\Wafu\Models\WafuEvent;

class LogWafuEventJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public array $data)
    {
    }

    public function handle(): void
    {
        try {
            WafuEvent::create($this->data);
        }
        catch (\Throwable) {
            // Fail silently so background logging never breaks anything
        }
    }
}
