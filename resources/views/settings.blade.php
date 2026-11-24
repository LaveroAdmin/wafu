<form action="{{ route('wafu.settings.save') }}" method="POST" class="p-3">
    @csrf

    <div class="row mb-4">
        <div class="col-md-12">
            <h5 class="border-bottom pb-2 text-dark fw-bold d-flex align-items-center">
                <span class="badge bg-primary text-dark me-2 px-2 py-1"><i class="icon-sliders-h"></i></span>
                {{ trans('lavero-admin-wafu::wafu.general_protection') }}
            </h5>
        </div>
    </div>

    <div class="row mb-3">
        <label class="col-sm-3 col-form-label fw-bold">{{ trans('lavero-admin-wafu::wafu.master_switch') }}</label>
        <div class="col-sm-9 d-flex align-items-center">
            <div class="form-check form-switch fs-5">
                <input class="form-check-input" type="checkbox" name="enabled" value="1" id="wafuEnabled" {{ !empty($settings['enabled']) ? 'checked' : '' }}>
                <label class="form-check-label fs-6 ms-2" for="wafuEnabled">{{ trans('lavero-admin-wafu::wafu.enable_waf') }}</label>
            </div>
        </div>
    </div>

    <div class="row mb-3">
        <label class="col-sm-3 col-form-label fw-bold">{{ trans('lavero-admin-wafu::wafu.operating_mode') }}</label>
        <div class="col-sm-9">
            <div class="form-check mb-2">
                <input class="form-check-input" type="radio" name="mode" id="modeEnforce" value="enforce" {{ ($settings['mode'] ?? 'enforce') === 'enforce' ? 'checked' : '' }}>
                <label class="form-check-label" for="modeEnforce">
                    <span class="badge bg-danger me-1">{{ trans('lavero-admin-wafu::wafu.mode_enforce') }}</span> {{ trans('lavero-admin-wafu::wafu.mode_enforce_desc') }}
                </label>
            </div>
            <div class="form-check">
                <input class="form-check-input" type="radio" name="mode" id="modeReport" value="report" {{ ($settings['mode'] ?? '') === 'report' ? 'checked' : '' }}>
                <label class="form-check-label" for="modeReport">
                    <span class="badge bg-info text-dark me-1">{{ trans('lavero-admin-wafu::wafu.mode_report') }}</span> {{ trans('lavero-admin-wafu::wafu.mode_report_desc') }}
                </label>
            </div>
        </div>
    </div>

    <div class="row mb-3">
        <label class="col-sm-3 col-form-label fw-bold">{{ trans('lavero-admin-wafu::wafu.trust_headers') }}</label>
        <div class="col-sm-9 d-flex align-items-center">
            <div class="form-check form-switch fs-5">
                <input class="form-check-input" type="checkbox" name="trust_forwarded_headers" value="1" id="trustHeaders" {{ !empty($settings['trust_forwarded_headers']) ? 'checked' : '' }}>
                <label class="form-check-label fs-6 ms-2" for="trustHeaders">{{ trans('lavero-admin-wafu::wafu.trust_headers_desc') }}</label>
            </div>
        </div>
    </div>

    <div class="row mb-4">
        <label class="col-sm-3 col-form-label fw-bold">{{ trans('lavero-admin-wafu::wafu.trusted_proxies') }}</label>
        <div class="col-sm-9">
            <textarea class="form-control" name="trusted_proxies" rows="3" placeholder="127.0.0.1&#10;10.0.0.0/8&#10;172.16.0.0/12">{{ $settings['trusted_proxies'] ?? '' }}</textarea>
            <div class="form-text">{{ trans('lavero-admin-wafu::wafu.trusted_proxies_help') }}</div>
        </div>
    </div>

    <div class="row mb-4 mt-4">
        <div class="col-md-12">
            <h5 class="border-bottom pb-2 text-dark fw-bold d-flex align-items-center">
                <span class="badge bg-primary text-dark me-2 px-2 py-1"><i class="icon-shield-alt"></i></span>
                {{ trans('lavero-admin-wafu::wafu.security_modules') }}
            </h5>
        </div>
    </div>

    <div class="row g-3 mb-4">
        @foreach($modulesData as $key => $mod)
            <div class="col-lg-6 col-12 mb-2">
                <div class="card wafu-module-card h-100 shadow-sm border">
                    <div class="card-body d-flex flex-column p-4">
                        <div class="d-flex align-items-start justify-content-between mb-3">
                            <div class="d-flex align-items-center">
                                <div class="wafu-mod-icon-wrapper rounded-3 bg-{{ $mod['color'] }}-subtle text-{{ $mod['color'] }} p-2 me-3 d-flex align-items-center justify-content-center" style="width: 44px; height: 44px; font-size: 1.25rem;">
                                    <i class="{{ $mod['icon'] }}"></i>
                                </div>
                                <div>
                                    <h6 class="card-title fw-bold mb-1 text-dark">{{ $mod['title'] }}</h6>
                                    <div class="d-flex align-items-center gap-2">
                                        <span class="badge bg-secondary-subtle text-secondary border px-2 py-1" style="font-size: 0.725rem;">
                                            {{ is_numeric($mod['pattern_count']) ? $mod['pattern_count'] . ' ' . trans('lavero-admin-wafu::wafu.rules') : $mod['pattern_count'] }}
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div class="form-check form-switch fs-4 ms-2 mb-0">
                                <input class="form-check-input" type="checkbox" name="{{ $mod['setting_key'] }}" value="1" id="switch_{{ $key }}" {{ !empty($mod['enabled']) ? 'checked' : '' }}>
                            </div>
                        </div>

                        <p class="card-text text-muted small flex-grow-1 mb-3" style="line-height: 1.55;">
                            {{ $mod['description'] }}
                        </p>

                        <div class="d-flex align-items-center justify-content-between pt-3 border-top mt-auto">
                            <div class="text-truncate me-2">
                                <span class="badge bg-light text-dark border small" title="{{ implode(', ', $mod['targets']) }}">
                                    <i class="icon-bullseye text-muted me-1"></i>{{ trans_choice('lavero-admin-wafu::wafu.targets_scope', count($mod['targets']), ['count' => count($mod['targets'])]) }}
                                </span>
                            </div>
                            <button type="button" class="btn btn-sm btn-outline-secondary px-3 py-1 wafu-view-rules-btn d-inline-flex align-items-center" data-module="{{ $key }}">
                                <i class="icon-code me-1 text-primary"></i>
                                <span>{{ trans('lavero-admin-wafu::wafu.rules') }}</span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        @endforeach
    </div>

    <div class="d-flex justify-content-end mt-4 pt-3 border-top">
        <button type="submit" class="btn btn-primary px-4 shadow-sm">
            <i class="icon-save me-1"></i> {{ trans('lavero-admin-wafu::wafu.save_settings') }}
        </button>
    </div>
</form>

<!-- Modal: View Module Rules & Signatures -->
<div class="modal fade" id="wafuRulesModal" tabindex="-1" aria-labelledby="wafuRulesModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-scrollable">
        <div class="modal-content shadow border-0" style="border-radius: 12px;">
            <div class="modal-header border-bottom py-3 px-4 bg-light">
                <div class="d-flex align-items-center">
                    <div id="modalModuleIconWrap" class="rounded-3 p-2 me-3 d-flex align-items-center justify-content-center" style="width: 40px; height: 40px; font-size: 1.2rem;">
                        <i id="modalModuleIcon"></i>
                    </div>
                    <div>
                        <h5 class="modal-title fw-bold text-dark mb-0" id="wafuRulesModalLabel"></h5>
                        <small class="text-muted" id="modalModuleDesc"></small>
                    </div>
                </div>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="{{ trans('admin.close') }}"></button>
            </div>
            <div class="modal-body p-4">
                <!-- Meta Info Badges -->
                <div class="row g-3 mb-4">
                    <div class="col-md-6">
                        <div class="p-3 rounded-3 bg-light border">
                            <div class="text-muted small mb-1 fw-bold"><i class="icon-bullseye text-primary me-1"></i>{{ trans('lavero-admin-wafu::wafu.inspection_targets') }}</div>
                            <div id="modalTargets" class="d-flex flex-wrap gap-1 mt-1"></div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="p-3 rounded-3 bg-light border">
                            <div class="text-muted small mb-1 fw-bold"><i class="icon-ban text-danger me-1"></i>{{ trans('lavero-admin-wafu::wafu.action_on_match') }}</div>
                            <div id="modalAction" class="fw-semibold text-dark mt-1"></div>
                        </div>
                    </div>
                </div>

                <!-- Signatures & Rules List -->
                <div class="mb-4">
                    <div class="d-flex align-items-center justify-content-between mb-2">
                        <h6 class="fw-bold text-dark mb-0 d-flex align-items-center">
                            <i class="icon-list-ul text-primary me-2"></i>
                            <span>{{ trans('lavero-admin-wafu::wafu.active_signatures') }}</span>
                            <span id="modalPatternCount" class="badge bg-secondary ms-2"></span>
                        </h6>
                    </div>

                    <!-- Search Filter -->
                    <div class="mb-3 position-relative" id="modalSearchWrap">
                        <input type="text" class="form-control form-control-sm ps-3" id="modalSearchInput" placeholder="{{ trans('lavero-admin-wafu::wafu.search_signatures') }}">
                    </div>

                    <!-- Patterns Container -->
                    <div id="modalPatternsList" class="rounded-3 border overflow-auto p-2 bg-light font-monospace small" style="max-height: 240px;">
                    </div>
                </div>

                <!-- Examples of Blocked Threats -->
                <div>
                    <h6 class="fw-bold text-dark mb-2 d-flex align-items-center">
                        <i class="icon-shield-virus text-warning me-2"></i>
                        <span>{{ trans('lavero-admin-wafu::wafu.examples_blocked') }}</span>
                    </h6>
                    <ul id="modalExamplesList" class="list-group list-group-flush border rounded-3 small">
                    </ul>
                </div>
            </div>
            <div class="modal-footer border-top py-2 px-4 bg-light">
                <button type="button" class="btn btn-secondary px-4" data-bs-dismiss="modal">{{ trans('lavero-admin-wafu::wafu.close') }}</button>
            </div>
        </div>
    </div>
</div>

<style>
.wafu-module-card {
    border-radius: 12px;
    background: #fff;
    border: 1px solid #e2e8f0;
    transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
}
.wafu-module-card:hover {
    border-color: #cbd5e1;
    box-shadow: 0 6px 18px rgba(15, 23, 42, 0.06) !important;
}
.wafu-mod-icon-wrapper {
    flex-shrink: 0;
}
.bg-danger-subtle { background-color: #fef2f2 !important; color: #dc2626 !important; }
.bg-warning-subtle { background-color: #fffbeb !important; color: #d97706 !important; }
.bg-info-subtle { background-color: #f0fdfa !important; color: #0d9488 !important; }
.bg-primary-subtle { background-color: #eff6ff !important; color: #2563eb !important; }
.bg-secondary-subtle { background-color: #f8fafc !important; color: #475569 !important; }

.wafu-pattern-row {
    padding: 0.35rem 0.6rem;
    border-radius: 6px;
    margin-bottom: 2px;
    background: #ffffff;
    border: 1px solid #f1f5f9;
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.wafu-pattern-row:hover {
    background: #f8fafc;
    border-color: #e2e8f0;
}
.wafu-copy-btn {
    opacity: 0.6;
    font-size: 0.75rem;
    padding: 2px 6px;
}
.wafu-pattern-row:hover .wafu-copy-btn {
    opacity: 1;
}

[data-bs-theme="dark"] .wafu-module-card,
body.dark-mode .wafu-module-card {
    background: #1e293b;
    border-color: #334155;
}
[data-bs-theme="dark"] .wafu-pattern-row,
body.dark-mode .wafu-pattern-row {
    background: #0f172a;
    border-color: #1e293b;
    color: #cbd5e1;
}
</style>

<script>
(function() {
    var modulesData = @json($modulesData);
    var currentPatterns = [];

    document.querySelectorAll('.wafu-view-rules-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var modKey = this.getAttribute('data-module');
            var mod = modulesData[modKey];
            if (!mod) return;

            document.getElementById('wafuRulesModalLabel').textContent = mod.title;
            document.getElementById('modalModuleDesc').textContent = mod.description;

            var iconWrap = document.getElementById('modalModuleIconWrap');
            iconWrap.className = 'rounded-3 p-2 me-3 d-flex align-items-center justify-content-center bg-' + mod.color + '-subtle text-' + mod.color;
            var icon = document.getElementById('modalModuleIcon');
            icon.className = mod.icon;

            // Targets
            var targetsWrap = document.getElementById('modalTargets');
            targetsWrap.innerHTML = '';
            (mod.targets || []).forEach(function(t) {
                var span = document.createElement('span');
                span.className = 'badge bg-secondary-subtle text-secondary border px-2 py-1';
                span.textContent = t;
                targetsWrap.appendChild(span);
            });

            // Action
            document.getElementById('modalAction').textContent = mod.action;

            // Patterns count
            document.getElementById('modalPatternCount').textContent = mod.pattern_count;

            // Patterns list
            currentPatterns = mod.patterns || [];
            renderPatterns(currentPatterns);

            // Search input reset
            var searchInput = document.getElementById('modalSearchInput');
            searchInput.value = '';
            searchInput.oninput = function() {
                var q = this.value.toLowerCase().trim();
                if (!q) {
                    renderPatterns(currentPatterns);
                    return;
                }
                var filtered = currentPatterns.filter(function(p) {
                    return String(p).toLowerCase().indexOf(q) !== -1;
                });
                renderPatterns(filtered);
            };

            // Examples list
            var examplesWrap = document.getElementById('modalExamplesList');
            examplesWrap.innerHTML = '';
            (mod.examples || []).forEach(function(ex) {
                var li = document.createElement('li');
                li.className = 'list-group-item bg-light text-dark font-monospace py-2 px-3 border-0 border-bottom';
                li.innerHTML = '<i class="icon-exclamation-triangle text-warning me-2"></i><code>' + escapeHtml(ex) + '</code>';
                examplesWrap.appendChild(li);
            });

            var modalEl = document.getElementById('wafuRulesModal');
            if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                var modal = bootstrap.Modal.getOrCreateInstance(modalEl);
                modal.show();
            } else if (window.$ && $.fn.modal) {
                $(modalEl).modal('show');
            }
        });
    });

    function renderPatterns(patterns) {
        var container = document.getElementById('modalPatternsList');
        container.innerHTML = '';
        if (!patterns || patterns.length === 0) {
            container.innerHTML = '<div class="text-center text-muted py-3">{{ trans('lavero-admin-wafu::wafu.no_signatures_found') }}</div>';
            return;
        }

        patterns.forEach(function(p) {
            var row = document.createElement('div');
            row.className = 'wafu-pattern-row';

            var code = document.createElement('code');
            code.className = 'text-break me-2';
            code.textContent = p;

            var copyBtn = document.createElement('button');
            copyBtn.type = 'button';
            copyBtn.className = 'btn btn-xs btn-outline-secondary wafu-copy-btn ms-auto flex-shrink-0';
            copyBtn.innerHTML = '<i class="icon-copy"></i>';
            copyBtn.title = '{{ trans("lavero-admin-wafu::wafu.copy_pattern") }}';
            copyBtn.onclick = function() {
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(p).then(function() {
                        copyBtn.innerHTML = '<i class="icon-check text-success"></i>';
                        setTimeout(function() { copyBtn.innerHTML = '<i class="icon-copy"></i>'; }, 1500);
                    });
                }
            };

            row.appendChild(code);
            row.appendChild(copyBtn);
            container.appendChild(row);
        });
    }

    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
})();
</script>
