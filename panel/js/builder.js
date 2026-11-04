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

    // ── Log pane - scrollable ring-buffer with line numbers ────────────
    // Sizing lives in style.css (#builder-log): viewport-relative clamp
    // plus a vertical resize handle. No fixed pixel heights here.

    var _logLines     = [];   // { text, cls } - never exceeds MAX_LINES entries
    var _lineCounter  = 0;    // monotonic; absolute line numbers never reset mid-build
    var _anchorBottom = true; // when true, new lines force-scroll the pane

    var MAX_LINES = 50;      // hard cap; oldest row evicted when exceeded

    function logEl()    { return document.getElementById('builder-log'); }
    function logTable() { return document.getElementById('builder-log-table'); }

    function clearLog() {
        _logLines    = [];
        _lineCounter = 0;

        var el = logEl();
        if (!el) return;

        el.style.padding = '0';
        el.innerHTML = '<table id="builder-log-table" style="width:100%;border-collapse:collapse;table-layout:fixed;"></table>';
    }

    function appendLog(text, cls) {
        // Assign an absolute line number before capping so numbers keep
        // climbing even as old rows are evicted from the front.
        _lineCounter++;
        var lineNum = _lineCounter;

        _logLines.push({ text: text, cls: cls || 'text-gray-300' });

        var tbl = logTable();
        if (!tbl) {
            clearLog();
            tbl = logTable();
            if (!tbl) { console.error('[Builder]', text); return; }
        }

        var tr = document.createElement('tr');

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

        // Text cell - wraps long compiler output, never forces horizontal scroll
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
        if (_logLines.length > MAX_LINES) {
            _logLines.shift();
            var oldest = tbl.querySelector('tr');
            if (oldest) oldest.remove();
        }

        // Auto-scroll to the latest line only while anchored to the bottom
        var el = logEl();
        if (el && _anchorBottom) el.scrollTop = el.scrollHeight;
    }

    // ── Log options menu (3-dot dropdown on the log card) ──────────────

    function _closeLogMenuOnOutside(e) {
        var menu = document.getElementById('builder-log-menu');
        var btn  = document.getElementById('builder-log-menu-btn');
        if (!menu || menu.classList.contains('hidden')) {
            document.removeEventListener('click', _closeLogMenuOnOutside);
            return;
        }
        if (menu.contains(e.target) || (btn && btn.contains(e.target))) return;
        menu.classList.add('hidden');
        document.removeEventListener('click', _closeLogMenuOnOutside);
    }

    function toggleLogMenu(ev) {
        if (ev && ev.stopPropagation) ev.stopPropagation();
        var menu = document.getElementById('builder-log-menu');
        if (!menu) return;
        var opening = menu.classList.contains('hidden');
        menu.classList.toggle('hidden');
        if (opening) {
            // Defer so the click that opened the menu doesn't close it again.
            setTimeout(function () {
                document.addEventListener('click', _closeLogMenuOnOutside);
            }, 0);
        } else {
            document.removeEventListener('click', _closeLogMenuOnOutside);
        }
    }

    function setLogAnchor(on) {
        _anchorBottom = !!on;
        var el = logEl();
        if (_anchorBottom && el) el.scrollTop = el.scrollHeight;
    }

    function copyLog() {
        var text = _logLines.map(function (l) { return l.text; }).join('\n');
        if (!text) {
            if (window.Notify) window.Notify.toast('Log is empty.', 'info', 3000);
            return;
        }
        copyText(text, 'Log copied to clipboard');
    }

    // ── Collapsible form sections ──────────────────────────────────────

    function toggleSection(bodyId, hdr) {
        var body = document.getElementById(bodyId);
        if (!body) return;
        body.classList.toggle('hidden');
        if (hdr && hdr.classList) {
            hdr.classList.toggle('open', !body.classList.contains('hidden'));
        }
    }

    function openSection(bodyId) {
        var body = document.getElementById(bodyId);
        if (!body || !body.classList.contains('hidden')) return;
        body.classList.remove('hidden');
        var hdr = body.previousElementSibling;
        if (hdr && hdr.classList) hdr.classList.add('open');
    }

    // ── Simplified / Advanced mode ─────────────────────────────────────
    // Simplified (default, pure CSS - the page starts without the
    // mode-advanced class) shows only the core build fields. Advanced
    // reveals every collapsible group on top of that.

    function setMode(mode) {
        var advanced = mode === 'advanced';
        var page = document.getElementById('page-builder');
        if (page) page.classList.toggle('mode-advanced', advanced);
        ['simplified', 'advanced'].forEach(function (m) {
            var btn = document.getElementById('builder-mode-' + m);
            if (btn) btn.classList.toggle('active', m === mode);
        });
    }

    // ── Artifact randomizer ────────────────────────────────────────────
    // The generator itself lives in js/builder/randomize.js (loaded
    // before this file) and is exposed as window.ArtifactRandomizer.
    // builder.js only wires the button up and reports a clear error if
    // the module failed to load.

    function randomizeArtifact() {
        if (window.ArtifactRandomizer && typeof window.ArtifactRandomizer.randomize === 'function') {
            window.ArtifactRandomizer.randomize();
            return;
        }
        if (window.Notify) {
            window.Notify.toast('Randomizer unavailable: js/builder/randomize.js not loaded.', 'error');
        }
    }

    // ── Custom tooltips ────────────────────────────────────────────────
    // Every element inside the builder page that carries a title
    // attribute gets a styled tooltip (see #builder-tip in style.css).
    // The native browser tooltip is suppressed while hovering - the
    // title attribute is parked in data-tip-orig and restored on leave -
    // so it still works as a fallback everywhere else.

    var _tipBoxEl  = null;
    var _tipTarget = null;

    function tipBox() {
        if (!_tipBoxEl) {
            _tipBoxEl = document.createElement('div');
            _tipBoxEl.id = 'builder-tip';
            document.body.appendChild(_tipBoxEl);
        }
        return _tipBoxEl;
    }

    function showTip(target) {
        var text = target.getAttribute('title');
        if (!text) return;
        target.setAttribute('data-tip-orig', text);
        target.removeAttribute('title');
        var box = tipBox();
        box.textContent = text;
        box.style.display = 'block';
        var r  = target.getBoundingClientRect();
        var bw = box.offsetWidth, bh = box.offsetHeight;
        var left = r.left + (r.width - bw) / 2;
        left = Math.max(8, Math.min(left, window.innerWidth - bw - 8));
        var top = r.bottom + 8;
        if (top + bh > window.innerHeight - 8) top = r.top - bh - 8;
        if (top < 8) top = r.bottom + 8;
        box.style.left = left + 'px';
        box.style.top  = top + 'px';
    }

    function hideTip(target) {
        if (_tipBoxEl) _tipBoxEl.style.display = 'none';
        if (target) {
            var orig = target.getAttribute('data-tip-orig');
            if (orig) {
                target.setAttribute('title', orig);
                target.removeAttribute('data-tip-orig');
            }
        }
    }

    function bindTooltips() {
        var page = document.getElementById('page-builder');
        if (!page || page.dataset.tooltipsBound === '1') return;
        page.dataset.tooltipsBound = '1';

        page.addEventListener('mouseover', function (e) {
            var t = e.target.closest ? e.target.closest('[title]') : null;
            if (t && page.contains(t)) {
                if (_tipTarget && _tipTarget !== t) hideTip(_tipTarget);
                _tipTarget = t;
                showTip(t);
                return;
            }
            if (_tipTarget && !_tipTarget.contains(e.target)) {
                hideTip(_tipTarget);
                _tipTarget = null;
            }
        });

        page.addEventListener('mouseout', function (e) {
            if (!_tipTarget) return;
            if (e.relatedTarget && _tipTarget.contains(e.relatedTarget)) return;
            hideTip(_tipTarget);
            _tipTarget = null;
        });

        page.addEventListener('click', function () {
            if (_tipTarget) {
                hideTip(_tipTarget);
                _tipTarget = null;
            }
        }, true);
    }

    // ── Time formatting ────────────────────────────────────────────────
    // ISO-8601 UTC timestamps from the API are rendered in the browser's
    // local timezone and locale; unparseable values fall back to the raw
    // string with the T/Z decoration stripped.

    function fmtTime(iso) {
        if (!iso) return '-';
        var d = new Date(iso);
        if (isNaN(d.getTime())) {
            return String(iso).replace('T', ' ').replace(/\.\d+Z?$/, '');
        }
        return d.toLocaleString();
    }

    // Plain UTC rendering, e.g. "2026-11-02 14:27:49 UTC" - used when the
    // user clicks a timestamp to toggle it from local time back to UTC.
    function utcTimeStr(iso) {
        if (!iso) return '-';
        var d = new Date(iso);
        if (isNaN(d.getTime())) return fmtTime(iso);
        return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '') + ' UTC';
    }

    // Clicking a Started/Finished timestamp flips it between the browser's
    // locale rendering and the raw UTC value (delegated, so rows re-rendered
    // by refreshJobList keep working).
    function bindTimeToggle() {
        var tbody = document.getElementById('builder-jobs-tbody');
        if (!tbody || tbody.dataset.tsBound === '1') return;
        tbody.dataset.tsBound = '1';
        tbody.addEventListener('click', function (ev) {
            var span = ev.target && ev.target.closest ? ev.target.closest('.ts-toggle') : null;
            if (!span) return;
            var iso = span.getAttribute('data-utc') || '';
            if (!iso) return;
            if (span.classList.contains('show-utc')) {
                span.textContent = fmtTime(iso);
                span.classList.remove('show-utc');
            } else {
                span.textContent = utcTimeStr(iso);
                span.classList.add('show-utc');
            }
        });
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
    var jobFormats  = {};   // jobId -> requested format, for stage-link rendering
    // ── File upload helpers (icon / certs bundle -> base64) ───────────

    function readFileB64(id) {
        return new Promise(function (resolve) {
            var el = document.getElementById(id);
            if (!el || !el.files || !el.files.length) { resolve(null); return; }
            var reader = new FileReader();
            reader.onload = function () {
                var res = String(reader.result || '');
                var idx = res.indexOf('base64,');
                resolve(idx >= 0 ? res.slice(idx + 7) : res);
            };
            reader.onerror = function () { resolve(null); };
            reader.readAsDataURL(el.files[0]);
        });
    }

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
            jitter_min: intVal('builder-jitter-min', 0),
            jitter_max: intVal('builder-jitter-max', 100),
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
            // Shellcode (only used when format === 'shellcode')
            sc_hash:     val('builder-sc-hash',     '0x10').trim(),
            sc_userdata: val('builder-sc-userdata', 'None'),
            sc_flags:    intVal('builder-sc-flags',  0),
            sc_output:   val('builder-sc-output',   'bin'),
            // Advanced
            sign:        chk('builder-sign'),
            allow_vm:    chk('builder-allow-vm'),
            hibernation_mode: chk('builder-hibernation'),
        };

        // Optional advanced fields - only sent when set
        // Parent-process allowlist (comma-separated; API field name assumed
        // to be valid_parents, matching the guardrails group)
        var validParents = val('builder-valid-parents', '').trim();
        if (validParents) payload.valid_parents = validParents;
        var signCert = val('builder-sign-cert', '').trim();
        if (signCert) payload.sign_cert = signCert;
        var signPass = val('builder-sign-pass', '');
        if (signPass) payload.sign_pass = signPass;
        var signTs = val('builder-sign-ts', '').trim();
        if (signTs) payload.sign_ts = signTs;
        // Authenticode metadata overrides (only forwarded when signing)
        if (payload.sign) {
            var signName = val('builder-sign-name', '').trim();
            if (signName) payload.sign_name = signName;
            var signUrl = val('builder-sign-url', '').trim();
            if (signUrl) payload.sign_url = signUrl;
            var signCn = val('builder-sign-cn', '').trim();
            if (signCn) payload.sign_cn = signCn;
        }
        var sni = val('builder-sni-override', '').trim();
        if (sni) payload.sni_override = sni;
        var alpn = val('builder-alpn', '').trim();
        if (alpn) payload.alpn_protocols = alpn.split(',').map(s => s.trim()).filter(Boolean);
        var batchSize = val('builder-batch-size', '').trim();
        if (batchSize) payload.batch_size = parseInt(batchSize, 10);
        var pivotPort = val('builder-auto-pivot-port', '').trim();
        if (pivotPort) payload.auto_pivot_port = parseInt(pivotPort, 10);

        // Artifact customization
        var nameVal = val('builder-name', '').trim();
        if (nameVal) payload.name = nameVal;
        var preset = val('builder-icon-preset', '');
        if (preset) payload.icon_preset = preset;

        // PE VERSIONINFO (Windows exe/service)
        var peCompany  = val('builder-pe-company', '').trim();
        if (peCompany) payload.pe_company = peCompany;
        var peProduct  = val('builder-pe-product', '').trim();
        if (peProduct) payload.pe_product = peProduct;
        var peDesc     = val('builder-pe-description', '').trim();
        if (peDesc) payload.pe_description = peDesc;
        var peFileVer  = val('builder-pe-file-version', '').trim();
        if (peFileVer) payload.pe_file_version = peFileVer;
        var peProdVer  = val('builder-pe-product-version', '').trim();
        if (peProdVer) payload.pe_product_version = peProdVer;

        // ELF .comment (Linux targets)
        var elfComment = val('builder-elf-comment', '').trim();
        if (elfComment) payload.elf_comment = elfComment;

        // Custom PIC C source (only used when format === 'pic_c')
        if (payload.format === 'pic_c') {
            var picSrc = val('builder-pic-src', '');
            if (picSrc.trim()) payload.pic_src = picSrc;
        }

        // Conversion pipeline (only used when format === 'bin'; omit when
        // empty so the server applies its default, e.g. pe,donut on Windows)
        if (payload.format === 'bin') {
            var pipeline = val('builder-pipeline', '').trim();
            if (pipeline) payload.pipeline = pipeline;
        }

        clearLog();
        appendLog('[*] Submitting build request...', 'text-cyan-400');
        setBadge('', 'hidden');
        var dlRow = document.getElementById('builder-download-row');
        if (dlRow) dlRow.classList.add('hidden');
        var plRow0 = document.getElementById('builder-public-link-row');
        if (plRow0) plRow0.style.display = 'none';

        setBtn('<i class="fas fa-spinner fa-spin mr-2"></i>Submitting...', true);

        // Read optional uploads (icon / certs bundle) as base64 first.
        Promise.all([
            readFileB64('builder-icon-file'),
            readFileB64('builder-certs-ca'),
            readFileB64('builder-certs-client'),
            readFileB64('builder-certs-key'),
        ]).then(function (results) {
            if (results[0]) {
                payload.icon_b64 = results[0];
                delete payload.icon_preset; // custom icon file wins over preset
            }
            var ca = results[1], cc = results[2], ck = results[3];
            if ((ca || cc || ck) && !(ca && cc && ck)) {
                resetBtn();
                appendLog('[-] Certs bundle incomplete: provide ca.crt, client.crt and client.key.der (all three).', 'text-red-400');
                return;
            }
            if (ca && cc && ck) {
                payload.certs_ca_b64         = ca;
                payload.certs_client_crt_b64 = cc;
                payload.certs_client_key_b64 = ck;
            }
            submitBuild(payload);
        });
    }

    function submitBuild(payload) {
        var apiKey = getApiKey();
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
            jobFormats[activeJobId] = payload.format;

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
                    if (jobId === activeJobId) showSuccess(jobId, data.artifact_name, data.download_url, jobFormats[jobId]);
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
                        'Build failed - check log for job ' + jobId.slice(0,8), 'error', 8000);
                }
            })
            .catch(function () { /* transient - keep polling */ });
        }, 2000);
    }

    function showSuccess(jobId, artifactName, downloadUrl, format) {
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

        // Public (unauthenticated) download link, shown next to the
        // authenticated download button when the server registered one.
        var plRow = document.getElementById('builder-public-link-row');
        var plIn  = document.getElementById('builder-public-link');
        if (plRow && plIn) {
            if (downloadUrl) {
                plIn.value = window.location.origin + downloadUrl;
                plRow.style.display = 'flex';
            } else {
                plRow.style.display = 'none';
            }
        }

        // Staged-download link for stager builds. The stage URL is derived
        // from the job id (GET /stage/<build_id> on the server).
        var stRow = document.getElementById('builder-stage-link-row');
        var stIn  = document.getElementById('builder-stage-link');
        if (stRow && stIn) {
            if (format === 'stager') {
                stIn.value = window.location.origin + '/stage/' + jobId;
                stRow.style.display = 'flex';
            } else {
                stRow.style.display = 'none';
            }
        }
    }

    // ── Copy helpers for the public download link ──────────────────────

    function copyText(text, okMsg) {
        var done = function (ok) {
            if (window.Notify) window.Notify.toast(
                ok ? (okMsg || 'Copied to clipboard') : 'Copy failed - select and copy manually',
                ok ? 'success' : 'error');
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(
                function () { done(true); },
                function () { legacyCopy(text, done); });
        } else {
            legacyCopy(text, done);
        }
    }

    function legacyCopy(text, done) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity  = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(ta);
        done(ok);
    }

    function copyPublicLink() {
        var el = document.getElementById('builder-public-link');
        if (el && el.value) copyText(el.value, 'Public link copied to clipboard');
    }

    function copyStageLink() {
        var el = document.getElementById('builder-stage-link');
        if (el && el.value) copyText(el.value);
    }

    function copyLink(url) {
        var full = (url && url.charAt(0) === '/') ? window.location.origin + url : url;
        copyText(full);
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
                // Old jobs are not in jobFormats; recover the requested
                // format from the "[*] Format: <name>" build-log line.
                var fmt = jobFormats[jobId];
                if (!fmt) {
                    var fmtLine = (data.log || []).find(function (l) { return l.indexOf('Format:') !== -1; });
                    if (fmtLine) {
                        var m = fmtLine.match(/Format:\s+(\S+)/);
                        if (m) fmt = m[1];
                    }
                }
                showSuccess(jobId, data.artifact_name, data.download_url, fmt);
            } else if (data.status === 'running') {
                appendLog('[*] Build still running - tailing live...', 'text-cyan-400');
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
                var ts    = fmtTime(j.started_at);
                var fin   = fmtTime(j.finished_at);
                var art   = j.artifact_name ? escStr(j.artifact_name) : '';

                var finCell = j.finished_at
                    ? '<span class="ts-toggle" data-utc="' + escStr(j.finished_at) + '" '
                      + 'title="Click to toggle between local time and UTC">' + escStr(fin) + '</span>'
                    : '-';

                var dlBtn = (j.status === 'success' && art)
                    ? '<button onclick="window.BuilderManager.downloadJob(\'' + escStr(j.job_id) + '\')" '
                    + 'class="text-green-400 hover:text-white border border-green-700 hover:bg-green-800 '
                    + 'px-2 py-1 rounded text-xs transition mr-1">'
                    + '<i class="fas fa-download mr-1"></i>' + art + '</button>'
                    : '';

                var linkBtn = (j.status === 'success' && j.download_url)
                    ? '<button onclick="window.BuilderManager.copyLink(\'' + escStr(j.download_url) + '\')" '
                    + 'class="text-cyan-400 hover:text-white border border-cyan-700 hover:bg-cyan-800 '
                    + 'px-2 py-1 rounded text-xs transition mr-1" title="Copy public (no-auth) link">'
                    + '<i class="fas fa-link mr-1"></i>Link</button>'
                    : '';

                var viewBtn = '<button onclick="window.BuilderManager.viewJob(\'' + escStr(j.job_id) + '\')" '
                    + 'class="text-gray-400 hover:text-white border border-gray-700 hover:bg-gray-700 '
                    + 'px-2 py-1 rounded text-xs transition">'
                    + '<i class="fas fa-scroll mr-1"></i>Log</button>';

                return '<tr class="border-b border-gray-700 hover:bg-gray-800/40">'
                    + '<td class="p-3 font-mono text-xs text-gray-500">' + escStr(j.job_id.slice(0,8)) + '</td>'
                    + '<td class="p-3"><span class="px-2 py-0.5 rounded text-xs font-bold ' + sCls + '">'
                    +   '<i class="fas ' + sIcon + ' mr-1"></i>' + escStr(j.status) + '</span></td>'
                    + '<td class="p-3 text-xs text-gray-400 font-mono hide-mobile">'
                    +   '<span class="ts-toggle" data-utc="' + escStr(j.started_at || '') + '" '
                    +     'title="Click to toggle between local time and UTC">' + escStr(ts) + '</span></td>'
                    + '<td class="p-3 text-xs text-gray-400 font-mono hide-mobile">' + finCell + '</td>'
                    + '<td class="p-3">' + dlBtn + linkBtn + viewBtn + '</td>'
                    + '</tr>';
            }).join('');
        })
        .catch(function (err) { console.error('Builder job list:', err); });
    }

    // ── Platform-conditional visibility ────────────────────────────────
    //
    // Driven by data-platforms attributes (comma-separated platform list)
    // on sections/fields, plus option-level data-platforms on the format
    // select. The mapping mirrors src/build_validate.rs and
    // src/api/routes/builder.rs validate_request:
    //   - dll/service/shellcode/donut/pe_to_shellcode/bin: windows only
    //   - format=stager: transport restricted to http/https
    //   - evasion flags + sleep mask: windows-only behavior
    //   - icon/PE version/signing: windows; ELF .comment: linux/linux-musl
    //   - guardrails (domain/hostname/hours/no_system): every platform
    function applyPlatformVisibility() {
        var platEl  = document.getElementById('builder-platform');
        var fmtSel  = document.getElementById('builder-format');
        var trSel   = document.getElementById('builder-transport');
        if (!platEl) return;
        var platform = platEl.value;

        // Sections and fields tagged with data-platforms
        document.querySelectorAll('#page-builder [data-platforms]').forEach(function (el) {
            if (el.tagName === 'OPTION') return;   // handled below
            var list = el.getAttribute('data-platforms').split(',');
            el.style.display = list.indexOf(platform) === -1 ? 'none' : '';
        });

        // Format options: disable windows-only formats on other platforms,
        // coerce the selection to exe when the active one is unsupported.
        var fmt = fmtSel ? fmtSel.value : 'exe';
        if (fmtSel) {
            Array.prototype.forEach.call(fmtSel.options, function (opt) {
                var plats = opt.getAttribute('data-platforms');
                opt.disabled = !!(plats && plats.split(',').indexOf(platform) === -1);
            });
            if (fmtSel.selectedIndex >= 0 && fmtSel.options[fmtSel.selectedIndex].disabled) {
                fmtSel.value = 'exe';
                fmt = 'exe';
                if (window.Notify) window.Notify.toast('Selected format is Windows-only - switched to exe.', 'info');
            }
        }

        // format=stager can only speak HTTPS to /stage/<build_id> (raw-TCP
        // HTTP fallback) - restrict transport accordingly and coerce.
        if (trSel) {
            var stagerOk = ['http', 'https'];
            Array.prototype.forEach.call(trSel.options, function (opt) {
                opt.disabled = (fmt === 'stager') && stagerOk.indexOf(opt.value) === -1;
            });
            if (fmt === 'stager' && stagerOk.indexOf(trSel.value) === -1) {
                trSel.value = 'https';
                if (window.Notify) window.Notify.toast('format=stager requires http/https - transport switched to https.', 'info');
            }
        }
        return fmt;
    }

    // Suggested C2 addresses for the host combo box. Suggestion source
    // only: free text stays usable and an absent endpoint is not an error.
    function loadC2Hints() {
        var dl = document.getElementById('builder-host-ips');
        if (!dl) return;
        fetch(getApiUrl() + '/api/server/c2-hints', {
            headers: { 'X-API-KEY': getApiKey() },
        })
        .then(function (r) {
            if (r.status === 401) { if (window.Auth) window.Auth.logout(); return null; }
            if (!r.ok) return null;   // endpoint not present on older servers
            return r.json();
        })
        .then(function (data) {
            if (!data || !Array.isArray(data.ips)) return;
            dl.innerHTML = data.ips.map(function (ip) {
                return '<option value="' + String(ip).replace(/[<>&"]/g, '') + '"></option>';
            }).join('');
        })
        .catch(function () { /* suggestions unavailable - fine */ });
    }

    // ── Public API ─────────────────────────────────────────────────────

    window.BuilderManager = {
        init: function () {
            // Show the per-format option blocks only for the selected format,
            // and force platform=windows for the Windows-only formats
            // (shellcode / donut / pe_to_shellcode / bin).
            var fmtSel = document.getElementById('builder-format');
            var scOpts = document.getElementById('builder-shellcode-opts');
            var picOpts = document.getElementById('builder-pic-opts');
            var pipeOpts = document.getElementById('builder-pipeline-opts');
            var platSel = document.getElementById('builder-platform');
            var syncFormatOpts = function () {
                if (!fmtSel) return;
                var fmt = fmtSel.value;
                var scOn   = fmt === 'shellcode';
                var picOn  = fmt === 'pic_c';
                var pipeOn = fmt === 'bin';
                if (scOpts)   scOpts.style.display   = scOn   ? '' : 'none';
                if (picOpts)  picOpts.style.display  = picOn  ? '' : 'none';
                if (pipeOpts) pipeOpts.style.display = pipeOn ? '' : 'none';
                // The selected format has its own options - surface them.
                if (scOn || picOn || pipeOn) openSection('builder-fmt-opts-body');
                if (fmt === 'shellcode' || fmt === 'donut' || fmt === 'pe_to_shellcode' || fmt === 'bin') {
                    if (platSel && platSel.value !== 'windows') {
                        platSel.value = 'windows';
                        if (window.Notify) window.Notify.toast('Format "' + fmt + '" requires Windows x64 - platform switched.', 'info');
                        applyPlatformVisibility();
                    }
                }
            };
            if (fmtSel) fmtSel.addEventListener('change', function () { syncFormatOpts(); applyPlatformVisibility(); });
            if (platSel) platSel.addEventListener('change', function () { applyPlatformVisibility(); syncFormatOpts(); });
            syncFormatOpts();
            applyPlatformVisibility();
            loadC2Hints();
            bindTooltips();
            bindTimeToggle();
        },
        build:            build,
        downloadJob:      downloadJob,
        viewJob:          viewJob,
        refreshJobList:   refreshJobList,
        toggleSection:    toggleSection,
        randomizeArtifact: randomizeArtifact,
        setMode:          setMode,
        toggleLogMenu:    toggleLogMenu,
        setLogAnchor:     setLogAnchor,
        copyLog:          copyLog,
        copyPublicLink:   copyPublicLink,
        copyStageLink:    copyStageLink,
        copyLink:         copyLink,
    };

}());
