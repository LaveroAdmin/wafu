<?php

namespace LaveroAdmin\Admin\Wafu\Middleware;

use Bespredel\Wafu\Core\ContextKeys;
use Bespredel\Wafu\Core\Kernel;
use Closure;
use Illuminate\Http\Request;
use LaveroAdmin\Admin\Wafu\Models\WafuBlock;
use LaveroAdmin\Admin\Wafu\Services\WafuService;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;

class WafuFirewallMiddleware
{
    protected ?array $postResponseData = null;

    public function __construct(
        protected ?Kernel $kernel = null,
        protected ?LoggerInterface $logger = null
    ) {
    }

    public function handle(Request $request, Closure $next, string ...$modules): Response
    {
        if (!WafuService::isEnabled()) {
            return $next($request);
        }

        $clientIp = (string) $request->ip();

        if (WafuService::isIpWhitelisted($clientIp) || WafuService::isRouteExcluded($request)) {
            return $next($request);
        }

        // 1. Fast cached check: is client IP blocked? (Zero DB overhead)
        if (WafuService::isModuleEnabled('ip_blocklist') && WafuBlock::isBlocked($clientIp)) {
            $isReportMode = WafuService::getMode() === 'report';

            WafuService::logEvent(
                ip: $clientIp,
                method: $request->method(),
                uri: $request->fullUrl(),
                module: 'ip_blocklist',
                action: $isReportMode ? 'report' : 'block',
                reason: 'IP address is in blocklist',
                statusCode: $isReportMode ? 200 : 403,
                userAgent: $request->userAgent(),
                payload: WafuService::sanitizePayload([
                    'query' => $request->query->all(),
                    'body' => $request->request->all(),
                ]),
                blocked: !$isReportMode
            );

            if (!$isReportMode) {
                return response('Access Denied: Your IP address is blocked by security policy.', 403, [
                    'Content-Type' => 'text/plain; charset=utf-8',
                ]);
            }
        }

        // 2. Run WAFU Kernel inspection if available
        $kernel = WafuService::resolveKernel($this->kernel);
        if ($kernel !== null) {
            $pipeline = (array) ($kernel->getConfig()['pipeline'] ?? []);
            if (empty($pipeline)) {
                return $next($request);
            }

            $headers = [];
            foreach ($request->headers->all() as $name => $values) {
                $headers[strtolower($name)] = is_array($values) ? implode(', ', $values) : (string) $values;
            }

            $attributes = [];
            if ($this->logger !== null) {
                $attributes[ContextKeys::LOGGER] = $this->logger;
            }

            $only = [];
            if (!empty($modules)) {
                foreach ($modules as $param) {
                    foreach (explode(',', $param) as $alias) {
                        $alias = trim($alias);
                        if ($alias !== '' && WafuService::isModuleEnabled($alias)) {
                            $only[] = $alias;
                        }
                    }
                }

                if (empty($only)) {
                    return $next($request);
                }
            }

            $result = $kernel->handleWithContext(
                $request->server->all(),
                WafuService::stripSensitiveForInspection($request->query->all()),
                WafuService::stripSensitiveForInspection($request->request->all()),
                $request->cookies->all(),
                $headers,
                $attributes,
                $only
            );

            $context = $result['context'];
            $decision = $result['decision'];

            if ($decision->isBlocked()) {
                $detectedModule = (string) ($decision->getMeta()['module'] ?? 'wafu_filter');
                WafuService::recordDecision($request, $context, $decision, $detectedModule);

                $respSpec = $context->getAttribute(ContextKeys::RESPONSE, []);
                $status = $decision->getStatus() > 0 ? $decision->getStatus() : (int) ($respSpec['status'] ?? 403);
                $body = $decision->getBody()
                    ?? (is_string($respSpec['body'] ?? null) ? $respSpec['body'] : null)
                    ?? ($decision->getReason() ?: 'Blocked by WAF');

                $resp = response($body, $status);
                $headersOut = array_replace((array) ($respSpec['headers'] ?? []), $decision->getHeaders());
                foreach ($headersOut as $k => $v) {
                    $resp->header((string) $k, (string) $v);
                }

                if (!$resp->headers->has('Content-Type')) {
                    $resp->header('Content-Type', 'text/plain; charset=utf-8');
                }

                return $resp;
            }

            // Report mode: audit without blocking
            if ($context->getAttribute(ContextKeys::REPORT_ONLY, false)) {
                $detectedModule = (string) ($decision->getMeta()['module'] ?? 'wafu_report');
                WafuService::recordDecision($request, $context, $decision, $detectedModule);
            }

            $this->postResponseData = [
                'kernel' => $kernel,
                'context' => $context,
                'only' => $only,
            ];
        }

        return $next($request);
    }

    /**
     * Terminable middleware callback.
     * Runs strictly after HTTP response is already delivered to the client.
     */
    public function terminate(Request $request, Response $response): void
    {
        if ($this->postResponseData === null) {
            return;
        }

        $kernel = $this->postResponseData['kernel'] ?? $this->kernel;
        if ($kernel === null) {
            return;
        }

        // Post-response handling for 404 abuse detection without slowing down client response
        if ($response->getStatusCode() === 404 && isset($this->postResponseData['context'])) {
            try {
                $kernel->handleResponse(
                    $this->postResponseData['context'],
                    404,
                    $this->postResponseData['only'] ?? []
                );
            } catch (\Throwable) {
            }
        }
    }
}
