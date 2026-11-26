<?php

namespace LaveroAdmin\Admin\Wafu\Services;

use Bespredel\Wafu\Core\Context;
use Bespredel\Wafu\Core\ContextKeys;
use Bespredel\Wafu\Core\Decision;
use Bespredel\Wafu\Core\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use LaveroAdmin\Admin\Wafu\Jobs\LogWafuEventJob;
use LaveroAdmin\Admin\Wafu\Models\WafuBlock;
use LaveroAdmin\Admin\Wafu\Models\WafuEvent;
use LaveroAdmin\Admin\Wafu\Models\WafuSetting;
use Symfony\Component\HttpFoundation\IpUtils;

class WafuService
{
    public const TOGGLEABLE_MODULES = [
        'sql_injection',
        'xss',
        'rce',
        'lfi',
        'path_traversal',
        'bad_bots',
        'rate_limit',
        'not_found_abuse',
        'ip_blocklist',
    ];

    protected static ?string $cachedKernelHash = null;
    protected static ?Kernel $cachedKernel = null;
    protected const INSPECTION_EXCLUDED_KEYS = [
        'password',
        'password_confirmation',
        'current_password',
        'new_password',
        'old_password',
        'passwd',
        'pwd',
        '_token',
        'csrf_token',
    ];

    protected const LOG_SENSITIVE_KEY_FRAGMENTS = [
        'password',
        'passwd',
        'pwd',
        'secret',
        'token',
        'api_key',
        'apikey',
        'authorization',
        'cookie',
        'cvv',
        'cvc',
        'credit_card',
        'card_number',
        'private_key',
    ];

    public static function isEnabled(): bool
    {
        return static::toBool(WafuSetting::get('enabled', config('wafu.enabled', true)), true);
    }

    public static function getMode(): string
    {
        $mode = (string) WafuSetting::get('mode', config('wafu.mode', 'enforce'));

        return $mode === 'report' ? 'report' : 'enforce';
    }

    public static function isModuleEnabled(string $module): bool
    {
        $module = trim($module);
        if (!in_array($module, self::TOGGLEABLE_MODULES, true)) {
            return true;
        }

        return static::toBool(WafuSetting::get("mod_{$module}", true), true);
    }

    public static function getTrustedProxies(): array
    {
        $default = implode("\n", (array) config('wafu.trusted_proxies', []));

        return static::parseList((string) WafuSetting::get('trusted_proxies', $default));
    }

    public static function getWhitelistedIps(): array
    {
        return static::parseList((string) WafuSetting::get('whitelisted_ips', ''));
    }

    public static function isIpWhitelisted(string $ip): bool
    {
        $whitelist = static::getWhitelistedIps();
        if (empty($whitelist) || $ip === '') {
            return false;
        }

        try {
            return IpUtils::checkIp($ip, $whitelist);
        } catch (\Throwable) {
            return in_array($ip, $whitelist, true);
        }
    }

    public static function getExcludedRoutes(): array
    {
        return static::parseList((string) WafuSetting::get('excluded_routes', ''));
    }

    public static function addWhitelistedIp(string $ip): bool
    {
        $ip = trim($ip);
        if ($ip === '') {
            return false;
        }

        $list = static::getWhitelistedIps();
        if (in_array($ip, $list, true)) {
            return false;
        }

        $list[] = $ip;
        WafuSetting::set('whitelisted_ips', implode("\n", $list));

        return true;
    }

    public static function addExcludedRoute(string $route): bool
    {
        $route = trim($route);
        if ($route === '') {
            return false;
        }

        $list = static::getExcludedRoutes();
        if (in_array($route, $list, true)) {
            return false;
        }

        $list[] = $route;
        WafuSetting::set('excluded_routes', implode("\n", $list));

        return true;
    }

    public static function isRouteExcluded(Request $request): bool
    {
        $patterns = static::getExcludedRoutes();
        if (empty($patterns)) {
            return false;
        }

        $path = '/' . ltrim($request->path(), '/');

        foreach ($patterns as $pattern) {
            $trimmed = ltrim($pattern, '/');
            if ($trimmed !== '' && $request->is($trimmed)) {
                return true;
            }
            if (Str::is($pattern, $path)) {
                return true;
            }
        }

        return false;
    }

    public static function parseList(string $raw): array
    {
        $lines = preg_split('/[\r\n,]+/', $raw) ?: [];
        $items = [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '') {
                $items[] = $line;
            }
        }

        return array_values(array_unique($items));
    }

    protected static function parseLines(string $raw): array
    {
        $lines = preg_split('/[\r\n]+/', $raw) ?: [];
        $items = [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '') {
                $items[] = $line;
            }
        }

        return $items;
    }

    public static function buildRuntimeConfig(?array $baseConfig = null): array
    {
        $config = $baseConfig ?? (array) config('wafu', []);

        $config['enabled'] = static::isEnabled();
        $config['mode'] = static::getMode();
        $config['trust_forwarded_headers'] = static::toBool(
            WafuSetting::get('trust_forwarded_headers', $config['trust_forwarded_headers'] ?? false)
        );
        $config['trusted_proxies'] = static::getTrustedProxies();

        $pipeline = (array) ($config['pipeline'] ?? []);
        $config['pipeline'] = array_values(array_filter(
            $pipeline,
            static fn ($module) => is_string($module) && static::isModuleEnabled($module)
        ));

        $modules = (array) ($config['modules'] ?? []);

        foreach (['sql_injection', 'xss', 'rce', 'lfi', 'path_traversal', 'bad_bots'] as $mod) {
            if (!isset($modules[$mod]) || !is_array($modules[$mod])) {
                continue;
            }

            $action = WafuSetting::get("mod_{$mod}_action");
            if (is_string($action) && in_array($action, ['block', 'challenge', 'log'], true)) {
                $modules[$mod]['on_match'] = $action;
            }

            if ($mod !== 'bad_bots') {
                $targets = WafuSetting::get("mod_{$mod}_targets");
                if (is_array($targets) && !empty($targets)) {
                    $modules[$mod]['targets'] = array_values(array_intersect(
                        $targets,
                        ['query', 'body', 'cookies', 'uri', 'headers']
                    ));
                }
            }

            $customPatterns = static::parseLines((string) WafuSetting::get("mod_{$mod}_custom_patterns", ''));
            if (!empty($customPatterns)) {
                $existing = (array) ($modules[$mod]['patterns'] ?? []);
                $modules[$mod]['patterns'] = array_values(array_unique(array_merge($existing, $customPatterns)));
            }
        }

        if (isset($modules['rate_limit']) && is_array($modules['rate_limit'])) {
            $limit = (int) WafuSetting::get('rate_limit_limit', $modules['rate_limit']['limit'] ?? 120);
            $interval = (int) WafuSetting::get('rate_limit_interval', $modules['rate_limit']['interval'] ?? 60);
            $keyBy = (string) WafuSetting::get('rate_limit_key_by', $modules['rate_limit']['key_by'] ?? 'ip');
            $action = (string) WafuSetting::get('rate_limit_action', $modules['rate_limit']['on_exceed'] ?? 'challenge');

            $modules['rate_limit']['limit'] = max(1, $limit);
            $modules['rate_limit']['interval'] = max(1, $interval);
            $modules['rate_limit']['key_by'] = in_array($keyBy, ['ip', 'ip+uri'], true) ? $keyBy : 'ip';
            $modules['rate_limit']['on_exceed'] = in_array($action, ['block', 'challenge', 'log'], true) ? $action : 'challenge';
        }

        if (isset($modules['not_found_abuse']) && is_array($modules['not_found_abuse'])) {
            $threshold = (int) WafuSetting::get('not_found_threshold', $modules['not_found_abuse']['threshold'] ?? 20);
            $interval = (int) WafuSetting::get('not_found_interval', $modules['not_found_abuse']['interval'] ?? 300);
            $keyBy = (string) WafuSetting::get('not_found_key_by', $modules['not_found_abuse']['key_by'] ?? 'ip');
            $action = (string) WafuSetting::get('not_found_action', $modules['not_found_abuse']['on_exceed'] ?? 'block');

            $modules['not_found_abuse']['threshold'] = max(1, $threshold);
            $modules['not_found_abuse']['interval'] = max(1, $interval);
            $modules['not_found_abuse']['key_by'] = in_array($keyBy, ['ip', 'ip+uri'], true) ? $keyBy : 'ip';
            $modules['not_found_abuse']['on_exceed'] = in_array($action, ['block', 'challenge', 'log'], true) ? $action : 'block';
        }

        $config['modules'] = $modules;

        return $config;
    }

    public static function resolveKernel(?Kernel $fallback = null): ?Kernel
    {
        if (!class_exists(Kernel::class)) {
            return $fallback;
        }

        $baseConfig = $fallback !== null ? $fallback->getConfig() : (array) config('wafu', []);
        $runtimeConfig = static::buildRuntimeConfig($baseConfig);
        $hash = md5(json_encode([
            'enabled'                 => $runtimeConfig['enabled'],
            'mode'                    => $runtimeConfig['mode'],
            'trust_forwarded_headers' => $runtimeConfig['trust_forwarded_headers'],
            'trusted_proxies'         => $runtimeConfig['trusted_proxies'],
            'pipeline'                => $runtimeConfig['pipeline'],
            'modules'                 => $runtimeConfig['modules'],
        ]));

        if (static::$cachedKernel !== null && static::$cachedKernelHash === $hash) {
            return static::$cachedKernel;
        }

        static::$cachedKernel = new Kernel($runtimeConfig);
        static::$cachedKernelHash = $hash;

        return static::$cachedKernel;
    }

    public static function toBool(mixed $value, bool $default = false): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value) || is_float($value)) {
            return (bool) $value;
        }

        if (is_string($value)) {
            $trimmed = strtolower(trim($value));
            if ($trimmed === '') {
                return false;
            }

            $parsed = filter_var($trimmed, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            return $parsed ?? $default;
        }

        return (bool) $value;
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
            'payload'     => $payload !== null ? static::sanitizePayload($payload) : null,
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

        $payload = static::sanitizePayload([
            'query'   => Arr::except($request->query->all(), ['_pjax', '_token', '_method']),
            'body'    => $request->request->all(),
            'headers' => Arr::except($context->getHeaders(), ['cookie', 'authorization']),
            'match'   => $match,
            'meta'    => $decision->getMeta(),
        ]);

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

    /**
     * Strip password/CSRF fields before passing request data to WAFU Kernel inspection,
     * preventing false positives (e.g. SQLi/XSS) on legitimate password characters.
     */
    public static function stripSensitiveForInspection(array $data): array
    {
        $dbIgnored = static::parseList((string) WafuSetting::get('ignored_fields', ''));
        $custom = array_map('strtolower', array_merge((array) config('wafu.ignored_fields', []), $dbIgnored));
        $result = [];

        foreach ($data as $key => $value) {
            $lowerKey = strtolower((string) $key);

            if (
                in_array($lowerKey, self::INSPECTION_EXCLUDED_KEYS, true)
                || in_array($lowerKey, $custom, true)
                || str_contains($lowerKey, 'password')
                || str_contains($lowerKey, 'passwd')
            ) {
                continue;
            }

            $result[$key] = is_array($value) ? static::stripSensitiveForInspection($value) : $value;
        }

        return $result;
    }

    /**
     * Recursively redact sensitive values (passwords, tokens, secrets) before persisting event logs.
     */
    public static function sanitizePayload(array $payload): array
    {
        $dbSensitive = static::parseList((string) WafuSetting::get('sensitive_fields', ''));
        $custom = array_map('strtolower', array_merge((array) config('wafu.sensitive_fields', []), $dbSensitive));
        $result = [];

        foreach ($payload as $key => $value) {
            $lowerKey = strtolower((string) $key);

            if (static::isSensitiveLogKey($lowerKey, $custom)) {
                $result[$key] = '[REDACTED]';
                continue;
            }

            $result[$key] = is_array($value) ? static::sanitizePayload($value) : $value;
        }

        return $result;
    }

    protected static function isSensitiveLogKey(string $lowerKey, array $custom): bool
    {
        if (in_array($lowerKey, $custom, true)) {
            return true;
        }

        foreach (self::LOG_SENSITIVE_KEY_FRAGMENTS as $fragment) {
            if (str_contains($lowerKey, $fragment)) {
                return true;
            }
        }

        return false;
    }
}
