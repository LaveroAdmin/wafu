<?php

namespace LaveroAdmin\Admin\Wafu\Services;

use Bespredel\Wafu\Core\Context;
use Bespredel\Wafu\Core\ContextKeys;
use Bespredel\Wafu\Core\Decision;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use LaveroAdmin\Admin\Wafu\Jobs\LogWafuEventJob;
use LaveroAdmin\Admin\Wafu\Models\WafuBlock;
use LaveroAdmin\Admin\Wafu\Models\WafuEvent;
use LaveroAdmin\Admin\Wafu\Models\WafuSetting;

class WafuService
{
    public static function isEnabled(): bool
    {
        return (bool)WafuSetting::get('enabled', config('wafu.enabled', true));
    }

    public static function getMode(): string
    {
        return (string)WafuSetting::get('mode', config('wafu.mode', 'enforce'));
    }

    public static function getActiveBlockedIps(): array
    {
        return WafuBlock::isBlocked('0.0.0.0') ? [] : []; // cached through WafuBlock
    }

    /**
     * Non-blocking event logging.
     * Dispatches event writing via queue/afterResponse so the HTTP response is never delayed.
     */
    public static function logEvent(
        string  $ip,
        string  $method,
        string  $uri,
        string  $module,
        string  $action,
        ?string $reason = null,
        int     $statusCode = 403,
        ?string $userAgent = null,
        ?array  $payload = null,
        bool    $blocked = true
    ): void
    {
        $data = [
            'ip'          => $ip,
            'method'      => strtoupper($method),
            'uri'         => $uri,
            'module'      => $module,
            'action'      => $action,
            'reason'      => $reason,
            'status_code' => $statusCode,
            'user_agent'  => $userAgent,
            'payload'     => $payload,
            'blocked'     => $blocked,
            'created_at'  => now(),
            'updated_at'  => now(),
        ];

        // 1. Dispatch as an afterResponse background task so response returns immediately
        try {
            if (class_exists(LogWafuEventJob::class) && function_exists('dispatch')) {
                LogWafuEventJob::dispatch($data)->afterResponse();
                return;
            }
        }
        catch (\Throwable) {
        }

        // 2. Fallback to PHP shutdown handler (runs after connection closed)
        register_shutdown_function(function () use ($data) {
            try {
                WafuEvent::create($data);
            }
            catch (\Throwable) {
            }
        });
    }

    public static function recordDecision(
        Request  $request,
        Context  $context,
        Decision $decision,
        string   $module = 'firewall'
    ): void
    {
        $ip = $context->getIp() ?: (string)$request->ip();
        $isBlocked = $decision->isBlocked();
        $reason = $decision->getReason() ?: ($isBlocked ? 'Blocked by WAF' : 'Triggered rule');
        $status = $decision->getStatus() > 0 ? $decision->getStatus() : 403;
        $match = $context->getAttribute(ContextKeys::MATCH);

        $payload = [
            'query'   => Arr::except($request->query->all(), ['_pjax', '_token', '_method']),
            'body'    => $request->request->all(),
            'headers' => Arr::except($context->getHeaders(), ['cookie', 'authorization']),
            'match'   => $match,
            'meta'    => $decision->getMeta(),
        ];

        static::logEvent(
            ip: $ip,
            method: $request->method(),
            uri: $request->fullUrl(),
            module: $module,
            action: $isBlocked ? 'block' : 'report',
            reason: $reason,
            statusCode: $status,
            userAgent: $request->userAgent(),
            payload: $payload,
            blocked: $isBlocked
        );
    }
}
