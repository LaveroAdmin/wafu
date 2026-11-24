<?php

namespace LaveroAdmin\Admin\Wafu\Controllers;

use Illuminate\Routing\Controller;
use LaveroAdmin\Admin\Facades\Admin;
use LaveroAdmin\Admin\Form;
use LaveroAdmin\Admin\Grid;
use LaveroAdmin\Admin\Layout\Content;
use LaveroAdmin\Admin\Wafu\Models\WafuBlock;

class WafuBlockController extends Controller
{
    public function index(): Content
    {
        return Admin::content(function (Content $content) {
            $content->title(trans('lavero-admin-wafu::wafu.blocks_title'));
            $content->description(trans('lavero-admin-wafu::wafu.blocks_desc'));

            $grid = new Grid(new WafuBlock());
            $grid->model()->orderBy('id', 'desc');

            $grid->column('id', __('admin.id'))->sortable();
            $grid->column('ip', trans('lavero-admin-wafu::wafu.ip_cidr'))->display(function ($ip) {
                return "<code>{$ip}</code>";
            })->sortable();

            $grid->column('reason', trans('lavero-admin-wafu::wafu.reason'))->limit(50);

            $states = [
                'on'  => ['value' => 1, 'text' => strtoupper(trans('lavero-admin-wafu::wafu.blocked')), 'color' => 'danger'],
                'off' => ['value' => 0, 'text' => strtoupper(trans('lavero-admin-wafu::wafu.unblocked')), 'color' => 'success'],
            ];
            $grid->column('is_blocked', trans('lavero-admin-wafu::wafu.block_status'))->switch($states);

            $grid->column('blocked_at', trans('lavero-admin-wafu::wafu.blocked_at'))->sortable();
            $grid->column('unblocked_at', trans('lavero-admin-wafu::wafu.unblocked_at'))->sortable();
            $grid->column('created_at', trans('lavero-admin-wafu::wafu.time'))->sortable();

            $grid->filter(function (Grid\Filter $filter) {
                $filter->disableIdFilter();
                $filter->equal('ip', trans('lavero-admin-wafu::wafu.ip'));
                $filter->like('reason', trans('lavero-admin-wafu::wafu.reason'));
                $filter->equal('is_blocked', trans('lavero-admin-wafu::wafu.block_status'))->select([
                    1 => trans('lavero-admin-wafu::wafu.blocked'),
                    0 => trans('lavero-admin-wafu::wafu.unblocked'),
                ]);
            });

            $content->body($grid);
        });
    }

    public function create(): Content
    {
        return Admin::content(function (Content $content) {
            $content->title(trans('lavero-admin-wafu::wafu.block_ip'));
            $content->description(trans('lavero-admin-wafu::wafu.block_ip_desc'));

            $content->body($this->form());
        });
    }

    public function edit(mixed $id): Content
    {
        return Admin::content(function (Content $content) use ($id) {
            $content->title(trans('lavero-admin-wafu::wafu.edit_block_rule'));
            $content->description(trans('lavero-admin-wafu::wafu.rule_number', ['id' => $id]));

            $content->body($this->form()->edit($id));
        });
    }

    protected function form(): Form
    {
        $form = new Form(new WafuBlock());

        $form->text('ip', trans('lavero-admin-wafu::wafu.ip_cidr'))
            ->rules('required|string|max:45')
            ->help('Example: 192.168.1.100 or 10.0.0.0/8');

        $form->text('reason', trans('lavero-admin-wafu::wafu.reason_for_block'))
            ->rules('nullable|string|max:255')
            ->default('Manual block via LaveroAdmin');

        $states = [
            'on'  => ['value' => 1, 'text' => strtoupper(trans('lavero-admin-wafu::wafu.blocked')), 'color' => 'danger'],
            'off' => ['value' => 0, 'text' => strtoupper(trans('lavero-admin-wafu::wafu.unblocked')), 'color' => 'success'],
        ];
        $form->switch('is_blocked', trans('lavero-admin-wafu::wafu.block_status'))->states($states)->default(1);

        $form->saving(function (Form $form) {
            if ($form->is_blocked) {
                $form->model()->blocked_at = now();
                $form->model()->unblocked_at = null;
            } else {
                $form->model()->unblocked_at = now();
            }
        });

        return $form;
    }

    public function store()
    {
        return $this->form()->store();
    }

    public function update(mixed $id)
    {
        return $this->form()->update($id);
    }

    public function destroy(mixed $id)
    {
        return $this->form()->destroy($id);
    }
}
