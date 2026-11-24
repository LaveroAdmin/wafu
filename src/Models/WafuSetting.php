<?php

namespace LaveroAdmin\Admin\Wafu\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;

class WafuSetting extends Model
{
    protected $table = 'wafu_settings';

    protected $fillable = [
        'key',
        'value',
    ];

    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $connection = config('admin.database.connection') ?: config('database.default');
        $this->setConnection($connection);
        $this->setTable(config('admin.extensions.wafu.settings_table', 'wafu_settings'));
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        try {
            return Cache::remember("wafu_setting_{$key}", 300, function () use ($key, $default) {
                $record = static::where('key', $key)->first();
                if ($record === null) {
                    return $default;
                }

                $decoded = json_decode((string) $record->value, true);
                return json_last_error() === JSON_ERROR_NONE ? $decoded : $record->value;
            });
        } catch (\Throwable) {
            return $default;
        }
    }

    public static function set(string $key, mixed $value): void
    {
        $serialized = is_array($value) || is_object($value) ? json_encode($value) : (string) $value;

        static::updateOrCreate(
            ['key' => $key],
            ['value' => $serialized]
        );

        try {
            Cache::forget("wafu_setting_{$key}");
        } catch (\Throwable) {
        }
    }

    protected static function booted(): void
    {
        static::saved(function ($model) {
            try {
                Cache::forget("wafu_setting_{$model->key}");
            } catch (\Throwable) {
            }
        });

        static::deleted(function ($model) {
            try {
                Cache::forget("wafu_setting_{$model->key}");
            } catch (\Throwable) {
            }
        });
    }
}
