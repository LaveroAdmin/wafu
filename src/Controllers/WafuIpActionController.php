<?php

namespace LaveroAdmin\Admin\Wafu\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use LaveroAdmin\Admin\Wafu\Models\WafuBlock;

class WafuIpActionController extends Controller
{
    public function toggle(Request $request): JsonResponse
    {
        $ip = (string)$request->input('ip');

        if (empty($ip)) {
            return response()->json([
                'status'  => false,
                'message' => 'IP address is required.',
            ], 422);
        }

        $reason = (string)$request->input('reason', 'Toggled via quick action');
        $record = WafuBlock::toggle($ip, $reason);

        return response()->json([
            'status'     => true,
            'is_blocked' => $record->is_blocked,
            'message'    => $record->is_blocked
                ? "IP [{$ip}] has been blocked."
                : "IP [{$ip}] has been unblocked.",
        ]);
    }
}
