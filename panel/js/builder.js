// panel/js/builder.js
(function () {
    'use strict';

    // ── Helpers ────────────────────────────────────────────────────────

    function safeJson(text) {
        try { return JSON.parse(text); } catch (e) { return null; }
    }

    function getApiUrl() {
        if (window.Auth && window.Auth.url) return window.Auth.url.replace(/\/$/, '');
        return window.location.origin;
    }

    function getApiKey() {
        if (window.Auth && window.Auth.key) return window.Auth.key;
        return sessionStorage.getItem('c2_key') || '';
    }

    function escStr(s) {
        return String(s || '')
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/\"/g,'&quot;').replace(/'/g,'&#39;');
    }

    function val(id, def) {
        var el = document.getElementById(id);
        return (el && el.value) ? el.value : def;
    }
    function intVal(id, def) {
        var el = document.getElementById(id);
        if (!el || el.value === '') return def;
        var n = parseInt(el.value, 10);
        return isNaN(n) ? def : n;
    }
    function chk(id) {
        var el = document.getElementById(id);
        return el ? el.checked : false;
    }

    // ── Log pane — scrollable ring-buffer with line numbers & filters ─

    var _logLines   = [];   // { type, text, cls } — never exceeds MAX_LINES entries
    var _logFilter  = 'all';
    var _lineCounter = 0;   // monotonic; absolute line numbers never reset mid-build

    var MAX_LINES = 50;     // hard cap; oldest row evicted when exceeded

    var LOG_TYPE = {
        'text-green-400':  'ok',
        'text-red-400':    'error',
        'text-yellow-400': 'warn',
        'text-cyan-400':   'info',
    };

    function logEl()    { return document.getElementById('builder-log'); }
    function logTable() { return document.getElementById('builder-log-table'); }

    // Apply (or re-apply) scroll constraints to the log container.
    // Called from both init() and clearLog() so the container is always
    // properly sized whether or not a build has started yet.
    function _applyScrollStyle() {
        var el = logEl();
        if (!el) return;
        // flex:1 in the HTML lets the element grow with its flex parent,
        // which makes the overflow never fire. Override to a fixed size.
        el.style.flex        = 'none';
        el.style.height      = '380px';
        el.style.maxHeight   = '380px';
        el.style.overflowY   = 'auto';
        el.style.overflowX   = 'hidden';
    }

    function clearLog() {
        _logLines    = [];
        _logFilter   = 'all';
        _lineCounter = 0;

        var el = logEl();
        if (!el) return;

        el.style.padding = '0';
        _applyScrollStyle();
        el.innerHTML = '<table id="builder-log-table" style="width:100%;border-collapse:collapse;table-layout:fixed;"></table>';

        _updateFilterBtns();
        _showFilters(false);
    }

    function _showFilters(show) {
        var bar = document.getElementById('builder-log-filters');
        if (bar) bar.style.display = show ? 'flex' : 'none';
    }

    function _updateFilterBtns() {
        ['all','info','warn','ok'].forEach(function(k) {
            var btn = document.getElementById('blf-' + k);
            if (!btn) return;
            var isActive = (k === _logFilter);
            btn.style.background  = isActive ? 'var(--bg-hover)'    : '';
            btn.style.color       = isActive ? 'var(--text-primary)' : '';
            btn.style.borderColor = isActive ? 'var(--border-light)' : '';
        });
    }

    function _isVisible(type) {
        if (_logFilter === 'all')  return true;
        if (_logFilter === 'info') return type === 'info' || type === 'dim';
        if (_logFilter === 'warn') return type === 'warn';
        if (_logFilter === 'ok')   return type === 'ok' || type === 'error';
        return true;
    }

    function appendLog(text, cls) {
        var type = LOG_TYPE[cls] || 'dim';

        // Assign an absolute line number before capping so numbers keep
        // climbing even as old rows are evicted from the front.
        _lineCounter++;
        var lineNum = _lineCounter;

        _logLines.push({ type: type, text: text, cls: cls || 'text-gray-300' });

        var tbl = logTable();
        if (!tbl) {
            clearLog();
            tbl = logTable();
            if (!tbl) { console.error('[Builder]', text); return; }
        }

        var tr = document.createElement('tr');
        tr.dataset.ltype = type;
        if (!_isVisible(type)) tr.style.display = 'none';

        // Line-number cell (narrow, right-aligned, non-selectable)
        var tdN = document.createElement('td');
        tdN.style.cssText = [
            'user-select:none',
            'text-align:right',
            'padding:1px 8px 1px 10px',
            'color:#4b5563',
            'font-size:11px',
            'font-family:inherit',
            'vertical-align:top',
            'white-space:nowrap',
            'width:38px',
        ].join(';');
        tdN.textContent = lineNum;

        // Text cell — wraps long compiler output, never forces horizontal scroll
        var tdT = document.createElement('td');
        tdT.style.cssText = [
            'padding:1px 12px 1px 0',
            'font-size:12px',
            'line-height:1.55',
            'white-space:pre-wrap',      // preserve indentation, wrap at container edge
            'word-break:break-all',       // break unbreakable tokens (hex hashes, paths)
            'overflow-wrap:anywhere',
        ].join(';');
        tdT.className = cls || 'text-gray-300';
        tdT.textContent = text;

        tr.appendChild(tdN);
        tr.appendChild(tdT);
        tbl.appendChild(tr);

        // ── Ring-buffer cap: evict the oldest row once we exceed MAX_LINES ──
        // _logLines is trimmed first so _isVisible stays in sync with the DOM.
        if (_logLines.length > MAX_LINES) {
            _logLines.shift();
            var oldest = tbl.querySelector('tr');
            if (oldest) oldest.remove();
        }

        // Show the filter toolbar as soon as the first line arrives
        if (_logLines.length === 1) _showFilters(true);

        // Auto-scroll to the latest line
        var el = logEl();
        if (el) el.scrollTop = el.scrollHeight;
    }

    function filterLog(f) {
        _logFilter = f;
        _updateFilterBtns();

        var tbl = logTable();
        if (tbl) {
            tbl.querySelectorAll('tr').forEach(function(tr) {
                tr.style.display = _isVisible(tr.dataset.ltype) ? '' : 'none';
            });
        }

        var el = logEl();
        if (el) el.scrollTop = el.scrollHeight;
    }

    // ── Status badge / button ──────────────────────────────────────────

    function setBadge(html, cls) {
        var el = document.getElementById('builder-status-badge');
        if (!el) return;
        el.className = cls || 'hidden';
        el.innerHTML = html || '';
    }

    function setBtn(html, disabled) {
        var btn = document.getElementById('builder-btn');
        if (!btn) return;
        btn.disabled = !!disabled;
        btn.innerHTML = html;
    }

    function resetBtn() {
        setBtn('<i class="fas fa-hammer mr-2"></i>Build Agent', false);
    }

    // ── Per-job poll registry ──────────────────────────────────────────

    var polls     = {};   // jobId -> intervalId
    var logCounts = {};   // jobId -> last log line index shown

    function stopPolling(jobId) {
        if (polls[jobId]) {
            clearInterval(polls[jobId]);
            delete polls[jobId];
        }
    }

    // ── Active job: the one currently displayed in the log pane ───────

    var activeJobId = null;

    // ── Build ──────────────────────────────────────────────────────────

    function build() {
        var apiKey = getApiKey();
        if (!apiKey) { window.Modal.alert('Not logged in.', 'warning'); return; }

        var host = val('builder-host', '').trim();
        var port = val('builder-port', '').trim();
        if (!host || !port) {
            clearLog();
            appendLog('[-] Host and port are required.', 'text-red-400');
            return;
        }

        var payload = {
            host, port,
            platform:   val('builder-platform',   'linux'),
            transport:  val('builder-transport',   'tls'),
            profile:    val('builder-profile',     'default'),
            format:     val('builder-format',      'exe'),
            sleep:      intVal('builder-sleep',     40),
            jitter_min: intVal('builder-jitter-min', 20),
            jitter_max: intVal('builder-jitter-max', 10),
            bloat:      intVal('builder-bloat',      0),
            debug:      chk('builder-debug'),
            days:       intVal('builder-days',       0),
            // Evasion
            sleep_mask:        val('builder-sleep-mask',        'ekko'),
            indirect_syscalls: chk('builder-indirect-syscalls'),
            stack_spoof:       chk('builder-stack-spoof'),
            patch_amsi_etw:    chk('builder-patch-amsi-etw'),
            heap_encrypt:      chk('builder-heap-encrypt'),
            // Guardrails
            guard_domain:      val('builder-guard-domain',      '').trim(),
            guard_hostname:    val('builder-guard-hostname',    '').trim(),
            guard_hour_start:  intVal('builder-guard-hour-start', 0),
            guard_hour_end:    intVal('builder-guard-hour-end',   0),
            guard_no_system:   chk('builder-guard-no-system'),
        };

        clearLog();
        appendLog('[*] Submitting build request...', 'text-cyan-400');
        setBadge('', 'hidden');
        var dlRow = document.getElementById('builder-download-row');
        if (dlRow) dlRow.classList.add('hidden');

        setBtn('<i class="fas fa-spinner fa-spin mr-2"></i>Submitting...', true);

        fetch(getApiUrl() + '/api/builder/build', {
            method:  'POST',
            headers: { 'X-API-KEY': apiKey, 'Content-Type': 'application/json' },
            body:    JSON.stringify(payload),
        })
        .then(function (res) {
            return res.text().then(function (t) { return { ok: res.ok, status: res.status, text: t }; });
        })
        .then(function (r) {
            resetBtn();

            if (!r.ok) {
                var parsed = safeJson(r.text);
                var msg = (parsed && parsed.error) ? parsed.error : (r.text || 'HTTP ' + r.status);
                appendLog('[-] ' + msg, 'text-red-400');
                setBadge('<i class="fas fa-times-circle mr-1"></i>Request failed',
                    'inline-flex items-center gap-2 px-3 py-1 rounded text-xs font-bold bg-red-900 text-red-200 border border-red-700');
                return;
            }

            var data = safeJson(r.text);
            if (!data || !data.job_id) {
                appendLog('[-] Unexpected server response: ' + r.text, 'text-red-400');
                return;
            }

            activeJobId           = data.job_id;
            logCounts[activeJobId] = 0;

            appendLog('[*] Job queued: ' + data.job_id, 'text-cyan-400');
            appendLog('[*] Compiling... (this takes several minutes)', 'text-gray-400');

            startPolling(data.job_id, true);
            refreshJobList();
        })
        .catch(function (err) {
            resetBtn();
            appendLog('[-] Network error: ' + err.message, 'text-red-400');
            appendLog('    URL: ' + getApiUrl(), 'text-yellow-400');
        });
    }

    // ── Polling ────────────────────────────────────────────────────────

    function startPolling(jobId, isActive) {
        stopPolling(jobId);
        if (!logCounts[jobId]) logCounts[jobId] = 0;

        polls[jobId] = setInterval(function () {
            fetch(getApiUrl() + '/api/builder/jobs/' + jobId + '/status', {
                headers: { 'X-API-KEY': getApiKey() },
            })
            .then(function (res) { return res.text(); })
            .then(function (text) {
                var data = safeJson(text);
                if (!data) return;

                if (jobId === activeJobId) {
                    var newLines = (data.log || []).slice(logCounts[jobId]);
                    newLines.forEach(function (line) {
                        var cls = line.startsWith('[+]') ? 'text-green-400'
                                : line.startsWith('[-]') ? 'text-red-400'
                                : line.startsWith('[!]') ? 'text-yellow-400'
                                : line.startsWith('[*]') ? 'text-cyan-400'
                                : 'text-gray-300';
                        appendLog(line, cls);
                    });
                }
                logCounts[jobId] = (data.log || []).length;

                if (data.status === 'success') {
                    stopPolling(jobId);
                    if (jobId === activeJobId) showSuccess(jobId, data.artifact_name);
                    refreshJobList();
                    if (window.Notify) window.Notify.toast(
                        'Build done: ' + (data.artifact_name || jobId.slice(0,8)), 'success', 8000);

                } else if (data.status === 'failed') {
                    stopPolling(jobId);
                    if (jobId === activeJobId) {
                        setBadge('<i class="fas fa-times-circle mr-1"></i>Build failed',
                            'inline-flex items-center gap-2 px-3 py-1 rounded text-xs font-bold bg-red-900 text-red-200 border border-red-700');
                    }
                    refreshJobList();
                    if (window.Notify) window.Notify.toast(
                        'Build failed — check log for job ' + jobId.slice(0,8), 'error', 8000);
                }
            })
            .catch(function () { /* transient — keep polling */ });
        }, 2000);
    }

    function showSuccess(jobId, artifactName) {
        setBadge('<i class="fas fa-check-circle mr-1"></i>Build succeeded',
            'inline-flex items-center gap-2 px-3 py-1 rounded text-xs font-bold bg-green-900 text-green-200 border border-green-700');

        var dlRow  = document.getElementById('builder-download-row');
        var dlLink = document.getElementById('builder-download-link');
        if (dlRow && dlLink) {
            dlLink.setAttribute('data-job-id', jobId);
            dlLink.onclick = function (e) {
                e.preventDefault();
                downloadJob(jobId);
            };
            var span = dlLink.querySelector('span');
            if (span) span.textContent = artifactName || 'Download agent';
            dlRow.classList.remove('hidden');
        }
    }

    // ── Download via fetch+blob so X-API-KEY header is sent ──────────

    function downloadJob(jobId) {
        fetch(getApiUrl() + '/api/builder/jobs/' + jobId + '/download', {
            headers: { 'X-API-KEY': getApiKey() },
        })
        .then(function (res) {
            if (!res.ok) {
                return res.text().then(function (t) {
                    throw new Error(t || 'HTTP ' + res.status);
                });
            }
            var cd       = res.headers.get('Content-Disposition') || '';
            var match    = cd.match(/filename="([^"]+)"/);
            var filename = match ? match[1] : 'agent';
            return res.blob().then(function (blob) { return { blob: blob, filename: filename }; });
        })
        .then(function (r) {
            var a      = document.createElement('a');
            a.href     = URL.createObjectURL(r.blob);
            a.download = r.filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
        })
        .catch(function (err) {
            if (window.Notify) window.Notify.toast('Download failed: ' + err.message, 'error');
            else window.Modal.alert('Download failed: ' + err.message, 'error');
        });
    }

    // ── View a past job's log in the log pane ──────────────────────────

    function viewJob(jobId) {
        activeJobId = jobId;
        clearLog();
        appendLog('[*] Loading log for job ' + jobId + '...', 'text-cyan-400');

        fetch(getApiUrl() + '/api/builder/jobs/' + jobId + '/status', {
            headers: { 'X-API-KEY': getApiKey() },
        })
        .then(function (res) { return res.text(); })
        .then(function (text) {
            var data = safeJson(text);
            if (!data) { appendLog('[-] Failed to load job log.', 'text-red-400'); return; }
            clearLog();
            (data.log || []).forEach(function (line) {
                var cls = line.startsWith('[+]') ? 'text-green-400'
                        : line.startsWith('[-]') ? 'text-red-400'
                        : line.startsWith('[!]') ? 'text-yellow-400'
                        : line.startsWith('[*]') ? 'text-cyan-400'
                        : 'text-gray-300';
                appendLog(line, cls);
            });
            logCounts[jobId] = (data.log || []).length;

            if (data.status === 'success') {
                showSuccess(jobId, data.artifact_name);
            } else if (data.status === 'running') {
                appendLog('[*] Build still running — tailing live...', 'text-cyan-400');
                startPolling(jobId, true);
            }
        })
        .catch(function (err) { appendLog('[-] ' + err.message, 'text-red-400'); });
    }

    // ── Job list ───────────────────────────────────────────────────────

    function refreshJobList() {
        var tbody = document.getElementById('builder-jobs-tbody');
        if (!tbody) return;

        fetch(getApiUrl() + '/api/builder/jobs', {
            headers: { 'X-API-KEY': getApiKey() },
        })
        .then(function (res) { return res.text(); })
        .then(function (text) {
            var jobs = safeJson(text);
            if (!Array.isArray(jobs)) return;

            if (!jobs.length) {
                tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-gray-500 text-sm">No builds yet</td></tr>';
                return;
            }

            tbody.innerHTML = jobs.map(function (j) {
                var sCls  = j.status === 'success' ? 'bg-green-900 text-green-200'
                          : j.status === 'failed'  ? 'bg-red-900 text-red-200'
                          : 'bg-yellow-900 text-yellow-200';
                var sIcon = j.status === 'success' ? 'fa-check-circle'
                          : j.status === 'failed'  ? 'fa-times-circle'
                          : 'fa-spinner fa-spin';
                var ts    = (j.started_at  || '').replace('T', ' ').replace(/\.\d+Z?$/, '');
                var fin   = (j.finished_at || '').replace('T', ' ').replace(/\.\d+Z?$/, '');
                var art   = j.artifact_name ? escStr(j.artifact_name) : '';

                var dlBtn = (j.status === 'success' && art)
                    ? '<button onclick="window.BuilderManager.downloadJob(\'' + escStr(j.job_id) + '\')" '
                    + 'class="text-green-400 hover:text-white border border-green-700 hover:bg-green-800 '
                    + 'px-2 py-1 rounded text-xs transition mr-1">'
                    + '<i class="fas fa-download mr-1"></i>' + art + '</button>'
                    : '';

                var viewBtn = '<button onclick="window.BuilderManager.viewJob(\'' + escStr(j.job_id) + '\')" '
                    + 'class="text-gray-400 hover:text-white border border-gray-700 hover:bg-gray-700 '
                    + 'px-2 py-1 rounded text-xs transition">'
                    + '<i class="fas fa-scroll mr-1"></i>Log</button>';

                return '<tr class="border-b border-gray-700 hover:bg-gray-800/40">'
                    + '<td class="p-3 font-mono text-xs text-gray-500">' + escStr(j.job_id.slice(0,8)) + '</td>'
                    + '<td class="p-3"><span class="px-2 py-0.5 rounded text-xs font-bold ' + sCls + '">'
                    +   '<i class="fas ' + sIcon + ' mr-1"></i>' + escStr(j.status) + '</span></td>'
                    + '<td class="p-3 text-xs text-gray-400 font-mono hide-mobile">' + escStr(ts) + '</td>'
                    + '<td class="p-3 text-xs text-gray-400 font-mono hide-mobile">' + escStr(fin || '—') + '</td>'
                    + '<td class="p-3">' + dlBtn + viewBtn + '</td>'
                    + '</tr>';
            }).join('');
        })
        .catch(function (err) { console.error('Builder job list:', err); });
    }

    // ── Public API ─────────────────────────────────────────────────────

    window.BuilderManager = {
        init: function () {
            // Constrain the log container immediately on page load so it is
            // already the right size before any build is started or viewed.
            _applyScrollStyle();
        },
        build:          build,
        downloadJob:    downloadJob,
        viewJob:        viewJob,
        refreshJobList: refreshJobList,
        filterLog:      filterLog,
    };

}());
