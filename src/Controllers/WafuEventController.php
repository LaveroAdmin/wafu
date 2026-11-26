<?php

namespace LaveroAdmin\Admin\Wafu\Controllers;

use Illuminate\Routing\Controller;
use LaveroAdmin\Admin\Facades\Admin;
use LaveroAdmin\Admin\Grid;
use LaveroAdmin\Admin\Layout\Content;
use LaveroAdmin\Admin\Show;
use LaveroAdmin\Admin\Wafu\Actions\BlockIpRowAction;
use LaveroAdmin\Admin\Wafu\Actions\ExcludeRouteRowAction;
use LaveroAdmin\Admin\Wafu\Actions\WhitelistIpRowAction;
use LaveroAdmin\Admin\Wafu\Models\WafuBlock;
use LaveroAdmin\Admin\Wafu\Models\WafuEvent;

class WafuEventController extends Controller
{
    public function index(): Content
    {
        return Admin::content(function (Content $content) {
            $content->title(trans('lavero-admin-wafu::wafu.events_title'));
            $content->description(trans('lavero-admin-wafu::wafu.events_desc'));

            $grid = new Grid(new WafuEvent());
            $grid->model()->orderBy('id', 'desc');

            $grid->column('id', __('admin.id'))->sortable();

            $grid->column('ip', trans('lavero-admin-wafu::wafu.ip'))->display(function ($ip) {
                $isBlocked = WafuBlock::isBlocked($ip);
                $badge = $isBlocked
                    ? '<span class="badge bg-danger ms-1">' . trans('lavero-admin-wafu::wafu.blocked') . '</span>'
                    : '<span class="badge bg-secondary ms-1">' . trans('lavero-admin-wafu::wafu.active') . '</span>';

                return "<code>{$ip}</code>{$badge}";
            })->sortable();

            $grid->column('method', trans('lavero-admin-wafu::wafu.method'))->display(function ($method) {
                $colors = [
                    'GET'    => 'success',
                    'POST'   => 'primary',
                    'PUT'    => 'warning',
                    'DELETE' => 'danger',
                    'PATCH'  => 'info',
                    'HEAD'   => 'secondary',
                ];
                $color = $colors[strtoupper($method)] ?? 'secondary';

                return "<span class=\"badge bg-{$color}\">{$method}</span>";
            })->sortable();

            $grid->column('uri', trans('lavero-admin-wafu::wafu.uri'))->display(function ($uri) {
                $short = strlen($uri) > 60 ? substr($uri, 0, 57) . '...' : $uri;
                return "<span title=\"" . htmlspecialchars($uri, ENT_QUOTES) . "\">" . htmlspecialchars($short) . "</span>";
            });

            $grid->column('module', trans('lavero-admin-wafu::wafu.module'))->display(function ($module) {
                $colors = [
                    'sql_injection'   => 'danger',
                    'xss'             => 'warning',
                    'rce'             => 'danger',
                    'lfi'             => 'danger',
                    'path_traversal'  => 'warning',
                    'bad_bots'        => 'dark',
                    'ip_blocklist'    => 'danger',
                    'rate_limit'      => 'info',
                    'not_found_abuse' => 'secondary',
                ];
                $color = $colors[$module] ?? 'primary';

                return "<span class=\"badge bg-{$color}\">{$module}</span>";
            })->sortable();

            $grid->column('reason', trans('lavero-admin-wafu::wafu.reason'))->limit(45);

            $grid->column('action', trans('lavero-admin-wafu::wafu.action'))->display(function ($action) {
                $color = $action === 'block' ? 'danger' : 'info';
                return "<span class=\"badge bg-{$color}\">" . strtoupper($action) . "</span>";
            });

            $grid->column('created_at', trans('lavero-admin-wafu::wafu.time'))->display(function ($time) {
                return $time ? date('Y-m-d H:i:s', strtotime($time)) : '';
            })->sortable();

            $grid->actions(function (Grid\Displayers\Actions\Actions $actions) {
                $actions->disableEdit();
                $actions->add(new BlockIpRowAction());
                $actions->add(new WhitelistIpRowAction());
                $actions->add(new ExcludeRouteRowAction());
            });

            $grid->disableCreateButton();

            $grid->filter(function (Grid\Filter $filter) {
                $filter->disableIdFilter();
                $filter->equal('ip', trans('lavero-admin-wafu::wafu.ip'));
                $filter->like('uri', trans('lavero-admin-wafu::wafu.uri'));
                $filter->equal('module', trans('lavero-admin-wafu::wafu.module'))->select([
                    'sql_injection'   => 'SQL Injection',
                    'xss'             => 'XSS',
                    'rce'             => 'RCE',
                    'lfi'             => 'LFI',
                    'path_traversal'  => 'Path Traversal',
                    'bad_bots'        => 'Bad Bots',
                    'ip_blocklist'    => 'IP Blocklist',
                    'rate_limit'      => 'Rate Limit',
                    'not_found_abuse' => '404 Abuse',
                ]);
                $filter->equal('method', trans('lavero-admin-wafu::wafu.method'))->select([
                    'GET'    => 'GET',
                    'POST'   => 'POST',
                    'PUT'    => 'PUT',
                    'DELETE' => 'DELETE',
                    'PATCH'  => 'PATCH',
                ]);
                $filter->between('created_at', trans('lavero-admin-wafu::wafu.time'))->datetime();
            });

            $content->body($grid);
        });
    }

    public function show(mixed $id): Content
    {
        return Admin::content(function (Content $content) use ($id) {
            $content->title(trans('lavero-admin-wafu::wafu.event_details'));
            $content->description(trans('lavero-admin-wafu::wafu.event') . " #{$id}");

            $event = WafuEvent::findOrFail($id);

            $parsedPath = parse_url((string) $event->uri, PHP_URL_PATH);
            $routePattern = is_string($parsedPath) && $parsedPath !== '' ? $parsedPath : '/';
            $isBlocked = WafuBlock::isBlocked((string) $event->ip);
            $csrf = csrf_token();
            $ipEscaped = htmlspecialchars((string) $event->ip, ENT_QUOTES, 'UTF-8');
            $routeEscaped = htmlspecialchars($routePattern, ENT_QUOTES, 'UTF-8');
            $toggleUrl = route('wafu.ip.toggle');
            $whitelistUrl = route('wafu.event.whitelist_ip');
            $excludeUrl = route('wafu.event.exclude_route');

            $blockLabel = $isBlocked ? trans('lavero-admin-wafu::wafu.unblock_ip') : trans('lavero-admin-wafu::wafu.block_ip');
            $blockBtnClass = $isBlocked ? 'btn-outline-success' : 'btn-outline-danger';
            $whitelistLabel = trans('lavero-admin-wafu::wafu.whitelist_ip');
            $excludeLabel = trans('lavero-admin-wafu::wafu.exclude_route');

            $quickActionsHtml = <<<HTML
<div class="card mb-3">
    <div class="card-body d-flex flex-wrap align-items-center gap-2 py-2 px-3">
        <form action="{$toggleUrl}" method="POST" class="d-inline">
            <input type="hidden" name="_token" value="{$csrf}">
            <input type="hidden" name="ip" value="{$ipEscaped}">
            <input type="hidden" name="reason" value="Toggled from WAF Event #{$id}">
            <button type="submit" class="btn btn-sm {$blockBtnClass}">
                <i class="icon-ban me-1"></i>{$blockLabel} ({$ipEscaped})
            </button>
        </form>
        <form action="{$whitelistUrl}" method="POST" class="d-inline">
            <input type="hidden" name="_token" value="{$csrf}">
            <input type="hidden" name="ip" value="{$ipEscaped}">
            <button type="submit" class="btn btn-sm btn-outline-primary">
                <i class="icon-check-circle me-1"></i>{$whitelistLabel} ({$ipEscaped})
            </button>
        </form>
        <form action="{$excludeUrl}" method="POST" class="d-inline-flex align-items-center gap-1 ms-md-auto">
            <input type="hidden" name="_token" value="{$csrf}">
            <input type="text" name="route" value="{$routeEscaped}" class="form-control form-control-sm font-monospace" style="min-width: 220px;">
            <button type="submit" class="btn btn-sm btn-outline-secondary text-nowrap">
                <i class="icon-filter me-1"></i>{$excludeLabel}
            </button>
        </form>
    </div>
</div>
HTML;

            $content->body($quickActionsHtml);

            $show = new Show($event);
            $show->field('id', __('admin.id'));
            $show->field('ip', trans('lavero-admin-wafu::wafu.ip'))->as(function ($ip) {
                $isBlocked = WafuBlock::isBlocked($ip);
                return $isBlocked ? "{$ip} (" . strtoupper(trans('lavero-admin-wafu::wafu.blocked')) . ")" : "{$ip} (" . strtoupper(trans('lavero-admin-wafu::wafu.active')) . ")";
            });
            $show->field('method', trans('lavero-admin-wafu::wafu.method'));
            $show->field('uri', trans('lavero-admin-wafu::wafu.uri'));
            $show->field('module', trans('lavero-admin-wafu::wafu.module'));
            $show->field('reason', trans('lavero-admin-wafu::wafu.reason'));
            $show->field('status_code', trans('lavero-admin-wafu::wafu.status_code'));
            $show->field('user_agent', trans('lavero-admin-wafu::wafu.user_agent'));
            $show->field('created_at', trans('lavero-admin-wafu::wafu.time'));

            $show->divider();

            $show->field('payload', trans('lavero-admin-wafu::wafu.payload_data'))->unescape()->as(function ($payload) {
                if (empty($payload)) {
                    return '<em>' . trans('admin.none') . '</em>';
                }
                $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                return "<pre class=\"bg-light p-3 border rounded\"><code>" . htmlspecialchars($json) . "</code></pre>";
            });

            $content->body($show);
        });
    }

    public function destroy(mixed $id)
    {
        return WafuEvent::destroy($id);
    }
}
