<?php

namespace LaveroAdmin\Admin\Wafu\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;

class WafuSetting extends Model
{
    public const CACHE_KEY = 'wafu_settings_all';

    protected static ?array $memoryCache = null;

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

    /**
     * Load all WAFU settings from memory/cache (cached forever until a setting changes).
     */
    public static function allCached(): array
    {
        if (static::$memoryCache !== null) {
            return static::$memoryCache;
        }

        try {
            $all = Cache::rememberForever(self::CACHE_KEY, function (): array {
                $rows = static::query()->pluck('value', 'key');
                $result = [];

                foreach ($rows as $key => $rawValue) {
                    $decoded = json_decode((string) $rawValue, true);
                    $result[(string) $key] = json_last_error() === JSON_ERROR_NONE ? $decoded : $rawValue;
                }

                return $result;
            });

            static::$memoryCache = is_array($all) ? $all : [];

            return static::$memoryCache;
        } catch (\Throwable) {
            return [];
        }
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        $all = static::allCached();

        return array_key_exists($key, $all) ? $all[$key] : $default;
    }

    public static function set(string $key, mixed $value): void
    {
        $serialized = (is_array($value) || is_object($value) || is_bool($value))
            ? json_encode($value)
            : (string) $value;

        static::updateOrCreate(
            ['key' => $key],
            ['value' => $serialized]
        );

        static::flushCache($key);
    }

    public static function flushCache(?string $key = null): void
    {
        static::$memoryCache = null;

        try {
            Cache::forget(self::CACHE_KEY);
            if ($key !== null) {
                Cache::forget("wafu_setting_{$key}");
            }
        } catch (\Throwable) {
        }
    }

    protected static function booted(): void
    {
        static::saved(function ($model) {
            static::flushCache($model->key);
        });

        static::deleted(function ($model) {
            static::flushCache($model->key);
        });
    }
}
