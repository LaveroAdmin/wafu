<?php

namespace LaveroAdmin\Admin\Wafu\Models;

use Illuminate\Database\Eloquent\Model;

class WafuEvent extends Model
{
    protected $table = 'wafu_events';

    protected $fillable = [
        'ip',
        'method',
        'uri',
        'module',
        'action',
        'reason',
        'status_code',
        'user_agent',
        'payload',
        'blocked',
    ];

    protected $casts = [
        'payload'     => 'array',
        'blocked'     => 'boolean',
        'status_code' => 'integer',
    ];

    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $connection = config('admin.database.connection') ?: config('database.default');
        $this->setConnection($connection);
        $this->setTable(config('admin.extensions.wafu.events_table', 'wafu_events'));
    }

    public function blockRecord()
    {
        return $this->hasOne(WafuBlock::class, 'ip', 'ip');
    }

    public function isIpBlocked(): bool
    {
        return WafuBlock::isBlocked($this->ip);
    }
}
