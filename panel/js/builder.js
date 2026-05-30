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
            .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
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

    // ── Log pane ───────────────────────────────────────────────────────
    // The log div has a fixed pixel height set in the HTML (height:360px,
    // overflow-y:auto). appendLog just appends and scrolls — no growth.

    function logEl() { return document.getElementById('builder-log'); }

    function clearLog() {
        var el = logEl();
        if (el) el.innerHTML = '';
    }

    function appendLog(text, cls) {
        var el = logEl();
        if (!el) { console.error('[Builder]', text); return; }
        var div = document.createElement('div');
        div.className = 'font-mono text-xs leading-5 whitespace-pre-wrap ' + (cls || 'text-gray-300');
        div.textContent = text;
        el.appendChild(div);
        el.scrollTop = el.scrollHeight;
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
    // We track each job's poll interval separately so multiple jobs can
    // be monitored independently and new builds don't kill old monitors.

    var polls = {};          // jobId -> intervalId
    var logCounts = {};      // jobId -> last log line index shown

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
        if (!apiKey) { alert('Not logged in.'); return; }

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
        };

        // Reset the active log pane for this new submission
        clearLog();
        appendLog('[*] Submitting build request...', 'text-cyan-400');
        setBadge('', 'hidden');
        var dlRow = document.getElementById('builder-download-row');
        if (dlRow) dlRow.classList.add('hidden');

        // Disable button only during the HTTP submit, re-enable once job is queued
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
            resetBtn(); // re-enable immediately — user can queue another build

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

            // Make this the active job (log pane follows it)
            activeJobId       = data.job_id;
            logCounts[activeJobId] = 0;

            appendLog('[*] Job queued: ' + data.job_id, 'text-cyan-400');
            appendLog('[*] Compiling... (this takes several minutes)', 'text-gray-400');

            startPolling(data.job_id, true /* is active */);
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
        stopPolling(jobId); // clear any existing interval for this job
        if (!logCounts[jobId]) logCounts[jobId] = 0;

        polls[jobId] = setInterval(function () {
            fetch(getApiUrl() + '/api/builder/jobs/' + jobId + '/status', {
                headers: { 'X-API-KEY': getApiKey() },
            })
            .then(function (res) { return res.text(); })
            .then(function (text) {
                var data = safeJson(text);
                if (!data) return;

                // If this job is the active one, stream new lines into the log pane
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
                    if (jobId === activeJobId) {
                        showSuccess(jobId, data.artifact_name);
                    }
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
            // Store the jobId so the onclick handler can fetch it with the auth header.
            // We use fetch()+blob rather than a plain href so the X-API-KEY header is sent.
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
            // Extract filename from Content-Disposition header
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
            else alert('Download failed: ' + err.message);
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
                var ts    = (j.started_at || '').replace('T', ' ').replace(/\.\d+Z?$/, '');
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
                    + '<td class="p-3 text-xs text-gray-400 font-mono">' + escStr(ts) + '</td>'
                    + '<td class="p-3 text-xs text-gray-400 font-mono">' + escStr(fin || '—') + '</td>'
                    + '<td class="p-3">' + dlBtn + viewBtn + '</td>'
                    + '</tr>';
            }).join('');
        })
        .catch(function (err) { console.error('Builder job list:', err); });
    }

    // ── Public API ─────────────────────────────────────────────────────

    window.BuilderManager = {
        init:           function () {},
        build:          build,
        downloadJob:    downloadJob,
        viewJob:        viewJob,
        refreshJobList: refreshJobList,
    };

}());
