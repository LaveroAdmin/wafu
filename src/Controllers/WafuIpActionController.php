<?php

namespace LaveroAdmin\Admin\Wafu\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use LaveroAdmin\Admin\Wafu\Models\WafuBlock;
use LaveroAdmin\Admin\Wafu\Services\WafuService;

class WafuIpActionController extends Controller
{
    public function toggle(Request $request): JsonResponse|RedirectResponse
    {
        $ip = trim((string) $request->input('ip'));

        if ($ip === '') {
            if ($request->expectsJson()) {
                return response()->json([
                    'status'  => false,
                    'message' => 'IP address is required.',
                ], 422);
            }

            admin_toastr('IP address is required.', 'error');
            return back();
        }

        $reason = (string) $request->input('reason', 'Toggled via quick action');
        $record = WafuBlock::toggle($ip, $reason);

        $message = $record->is_blocked
            ? trans('lavero-admin-wafu::wafu.ip_blocked_msg', ['ip' => $ip])
            : trans('lavero-admin-wafu::wafu.ip_unblocked_msg', ['ip' => $ip]);

        if ($request->expectsJson()) {
            return response()->json([
                'status'     => true,
                'is_blocked' => $record->is_blocked,
                'message'    => $message,
            ]);
        }

        admin_toastr($message, 'success');
        return back();
    }

    public function whitelistIp(Request $request): RedirectResponse
    {
        $ip = trim((string) $request->input('ip'));
        if ($ip === '') {
            admin_toastr('IP address is required.', 'error');
            return back();
        }

        $added = WafuService::addWhitelistedIp($ip);
        $message = $added
            ? trans('lavero-admin-wafu::wafu.ip_whitelisted_msg', ['ip' => $ip])
            : trans('lavero-admin-wafu::wafu.ip_already_whitelisted_msg', ['ip' => $ip]);

        admin_toastr($message, 'success');
        return back();
    }

    public function excludeRoute(Request $request): RedirectResponse
    {
        $route = trim((string) $request->input('route'));
        if ($route === '') {
            admin_toastr('Route pattern is required.', 'error');
            return back();
        }

        $added = WafuService::addExcludedRoute($route);
        $message = $added
            ? trans('lavero-admin-wafu::wafu.route_excluded_msg', ['route' => $route])
            : trans('lavero-admin-wafu::wafu.route_already_excluded_msg', ['route' => $route]);

        admin_toastr($message, 'success');
        return back();
    }
}
