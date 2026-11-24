<?php

namespace LaveroAdmin\Admin\Wafu\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;

class WafuBlock extends Model
{
    protected $table = 'wafu_blocks';

    protected $fillable = [
        'ip',
        'reason',
        'is_blocked',
        'blocked_at',
        'unblocked_at',
    ];

    protected $casts = [
        'is_blocked' => 'boolean',
        'blocked_at' => 'datetime',
        'unblocked_at' => 'datetime',
    ];

    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $connection = config('admin.database.connection') ?: config('database.default');
        $this->setConnection($connection);
        $this->setTable(config('admin.extensions.wafu.blocks_table', 'wafu_blocks'));
    }

    public static function clearCache(): void
    {
        try {
            Cache::forget('wafu_blocked_ips');
        } catch (\Throwable) {
        }
    }

    public static function isBlocked(string $ip): bool
    {
        try {
            $blockedList = Cache::remember('wafu_blocked_ips', 300, function () {
                $connection = config('admin.database.connection') ?: config('database.default');
                $table = config('admin.extensions.wafu.blocks_table', 'wafu_blocks');

                if (!Schema::connection($connection)->hasTable($table)) {
                    return [];
                }

                return static::where('is_blocked', true)->pluck('ip')->toArray();
            });

            if (empty($blockedList)) {
                return false;
            }

            if (in_array($ip, $blockedList, true)) {
                return true;
            }

            foreach ($blockedList as $rule) {
                if (str_contains($rule, '/') && static::ipMatchesCidr($ip, $rule)) {
                    return true;
                }
            }

            return false;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function ipMatchesCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        // IPv4 CIDR check
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $mask = -1 << (32 - $bits);
            $subnetLong &= $mask;

            return ($ipLong & $mask) === $subnetLong;
        }

        // IPv6 CIDR check
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ipBin = inet_pton($ip);
            $subnetBin = inet_pton($subnet);

            if ($ipBin === false || $subnetBin === false) {
                return false;
            }

            $bytes = (int) ($bits / 8);
            $remainingBits = $bits % 8;

            if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
                return false;
            }

            if ($remainingBits > 0) {
                $mask = 0xFF << (8 - $remainingBits);
                if ((ord($ipBin[$bytes]) & $mask) !== (ord($subnetBin[$bytes]) & $mask)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    public static function block(string $ip, string $reason = ''): static
    {
        $record = static::updateOrCreate(
            ['ip' => $ip],
            [
                'reason' => $reason ?: 'Blocked via LaveroAdmin',
                'is_blocked' => true,
                'blocked_at' => now(),
                'unblocked_at' => null,
            ]
        );

        static::clearCache();

        return $record;
    }

    public static function unblock(string $ip): ?static
    {
        $record = static::where('ip', $ip)->first();
        if ($record) {
            $record->update([
                'is_blocked' => false,
                'unblocked_at' => now(),
            ]);
            static::clearCache();
        }

        return $record;
    }

    public static function toggle(string $ip, ?string $reason = null): static
    {
        $record = static::firstOrNew(['ip' => $ip]);

        if ($record->exists && $record->is_blocked) {
            $record->is_blocked = false;
            $record->unblocked_at = now();
        } else {
            $record->is_blocked = true;
            $record->blocked_at = now();
            $record->unblocked_at = null;
            if ($reason) {
                $record->reason = $reason;
            } elseif (!$record->reason) {
                $record->reason = 'Manual toggle via LaveroAdmin';
            }
        }

        $record->save();
        static::clearCache();

        return $record;
    }

    protected static function booted(): void
    {
        static::saved(fn () => static::clearCache());
        static::deleted(fn () => static::clearCache());
    }
}
