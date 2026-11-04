// panel/js/ui.js
function escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

window.UI = {
    chart: null,

    // ── Chart ─────────────────────────────────────────────────────────
    initChart() {
        const ctx = document.getElementById('osChart');
        if (!ctx || !window.Chart) return;

        // Destroy previous instance on reinit (e.g. page revisit)
        if (this.chart) { this.chart.destroy(); this.chart = null; }

        this.chart = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Windows','Linux','macOS','Other'],
                datasets: [{
                    data: [0,0,0,0],
                    backgroundColor: ['#3b82f6','#eab308','#a855f7','#6b7280'],
                    borderWidth: 2,
                    borderColor: 'transparent',
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,  // lets the canvas fill the wrapper div's height
                cutout: '68%',
                plugins: {
                    legend: { display: false },  // we render our own legend below
                    tooltip: {
                        callbacks: {
                            label: ctx => ` ${ctx.label}: ${ctx.parsed}`
                        }
                    }
                }
            }
        });
    },

    // Build a small custom legend so we control colour and theme
    _renderLegend(wins, linux, mac, other) {
        const el = document.getElementById('chart-legend');
        if (!el) return;
        const isDark  = !document.documentElement.classList.contains('light-theme');
        const txtCol  = isDark ? '#8b9cb5' : '#7a3060';
        const entries = [
            { label:'Windows', val: wins,  colour:'#3b82f6' },
            { label:'Linux',   val: linux, colour:'#eab308' },
            { label:'macOS',   val: mac,   colour:'#a855f7' },
            { label:'Other',   val: other, colour:'#6b7280' },
        ].filter(e => e.val > 0);

        el.innerHTML = entries.map(e => `
            <span style="display:inline-flex;align-items:center;gap:5px;color:${txtCol};font-size:11px;">
              <span style="width:9px;height:9px;border-radius:50%;background:${e.colour};flex-shrink:0;"></span>
              ${escHtml(e.label)} <strong style="color:${isDark?'#f1f5f9':'#2d0a2e'};">${e.val}</strong>
            </span>`).join('') || `<span style="color:${txtCol};font-size:11px;">No sessions</span>`;
    },

    // ── Stats ─────────────────────────────────────────────────────────
    updateStats(hosts) {
        const wins  = hosts.filter(h => h.os.toLowerCase().includes('win')).length;
        const linux = hosts.filter(h => h.os.toLowerCase().includes('linux')).length;
        const mac   = hosts.filter(h => h.os.toLowerCase().includes('mac') || h.os.toLowerCase().includes('darwin')).length;
        const other = hosts.length - wins - linux - mac;

        const set = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
        set('stat-total', hosts.length);
        set('stat-win',   wins);
        set('stat-linux', linux);
        set('stat-mac',   mac);
        set('stat-other', other);

        // Show/hide macOS and Other cards
        const macCard   = document.getElementById('stat-mac-card');
        const otherCard = document.getElementById('stat-other-card');
        if (macCard)   macCard.style.display   = mac   > 0 ? '' : 'none';
        if (otherCard) otherCard.style.display = other > 0 ? '' : 'none';

        // Expand stat-grid columns based on how many cards are visible
        const grid = document.querySelector('#page-stats .stat-grid');
        if (grid) {
            const visible = 3 + (mac > 0 ? 1 : 0) + (other > 0 ? 1 : 0);
            grid.style.gridTemplateColumns = `repeat(${visible}, 1fr)`;
        }

        // Update chart
        if (this.chart) {
            this.chart.data.datasets[0].data = [wins, linux, mac, other];
            this.chart.update('none');
        }
        this._renderLegend(wins, linux, mac, other);

        // Update dashboard session table
        this._updateDashSessions(hosts);
    },

    // ── Dashboard session mini-table ──────────────────────────────────
    _updateDashSessions(hosts) {
        const tbody = document.getElementById('dash-sessions-tbody');
        const count = document.getElementById('dash-session-count');
        if (!tbody) return;

        if (count) count.textContent = hosts.length ? `${hosts.length} session${hosts.length===1?'':'s'}` : '';

        if (!hosts.length) {
            tbody.innerHTML = '<tr><td colspan="5" style="padding:28px;text-align:center;color:var(--text-muted);font-style:italic;">No active sessions</td></tr>';
            return;
        }

        // Sort by most-recently-seen first
        const sorted = [...hosts].sort((a,b) => a.last_seen_secs - b.last_seen_secs);

        tbody.innerHTML = sorted.map(h => {
            const isWin  = h.os.toLowerCase().includes('win');
            const isMac  = h.os.toLowerCase().includes('mac') || h.os.toLowerCase().includes('darwin');
            const osIcon = isWin ? 'fa-windows text-blue-400'
                         : isMac ? 'fa-apple text-purple-400'
                         : 'fa-linux text-yellow-400';
            const osFam  = isWin ? 'Windows' : isMac ? 'macOS' : 'Linux';

            const secs   = h.last_seen_secs ?? 0;
            const ago    = secs < 60  ? `${secs}s`
                         : secs < 3600 ? `${Math.floor(secs/60)}m`
                         : `${Math.floor(secs/3600)}h`;
            const fresh  = secs < 30 ? 'color:#10b981;' : secs < 120 ? 'color:#f59e0b;' : 'color:#ef4444;';

            const tags   = (h.tags||[]).map(t => `<span style="font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(16,185,129,.15);color:#34d399;">${escHtml(t)}</span>`).join('');
            const safe   = escHtml(h.hostname||'');

            return `
            <tr style="border-bottom:1px solid var(--border);transition:background .1s;"
                onmouseenter="this.style.background='var(--bg-hover)'"
                onmouseleave="this.style.background=''">
              <td style="padding:10px 16px;">
                <div style="font-weight:600;color:var(--text-primary);">${safe}</div>
                ${tags ? `<div style="margin-top:3px;">${tags}</div>` : ''}
              </td>
              <td style="padding:10px 16px;">
                <span style="font-size:12px;color:var(--text-secondary);">
                  <i class="fab ${osIcon} mr-1"></i>${escHtml(osFam)}
                </span>
              </td>
              <td style="padding:10px 16px;font-family:monospace;font-size:12px;color:var(--text-muted);">
                ${escHtml(h.ip||'-')}
              </td>
              <td style="padding:10px 16px;font-size:12px;${fresh}">${ago} ago</td>
              <td style="padding:10px 16px;text-align:right;">
                <div style="display:inline-flex;gap:4px;align-items:center;">
                  <button onclick="window.Terminal.open(${h.id}, this.dataset.hostname)"
                          data-hostname="${safe}"
                          title="Shell" style="padding:4px 8px;border-radius:5px;font-size:11px;border:1px solid var(--accent);color:var(--accent);background:none;cursor:pointer;">
                    <i class="fas fa-terminal"></i>
                  </button>
                  <button onclick="window.ProcView.load(${h.id})"
                          title="Processes" style="padding:4px 8px;border-radius:5px;font-size:11px;border:1px solid var(--border);color:var(--text-muted);background:none;cursor:pointer;">
                    <i class="fas fa-list"></i>
                  </button>
                  <button onclick="window.ScreenshotView.capture(${h.id})"
                          title="Screenshot" style="padding:4px 8px;border-radius:5px;font-size:11px;border:1px solid var(--border);color:var(--text-muted);background:none;cursor:pointer;">
                    <i class="fas fa-camera"></i>
                  </button>
                </div>
              </td>
            </tr>`;
        }).join('');
    },

    // ── Activity log ──────────────────────────────────────────────────
    addLog(msg, level) {
        const box = document.getElementById('activity-log');
        if (!box) return;
        const colour = level === 'error'   ? 'var(--red)'
                     : level === 'warning' ? 'var(--yellow)'
                     : 'var(--accent)';
        const icon   = level === 'error'   ? 'fa-exclamation-circle'
                     : level === 'warning' ? 'fa-exclamation-triangle'
                     : 'fa-circle';
        const div = document.createElement('div');
        div.style.cssText = 'display:flex;gap:8px;align-items:flex-start;padding:5px 8px;border-radius:5px;margin-bottom:3px;';
        div.innerHTML = `
            <i class="fas ${icon}" style="color:${colour};font-size:9px;margin-top:4px;flex-shrink:0;"></i>
            <span style="flex:1;min-width:0;">
              <span style="font-size:11px;color:var(--text-muted);">${new Date().toLocaleTimeString()}</span>
              <span style="color:var(--text-primary);margin-left:6px;font-size:12px;">${escHtml(msg)}</span>
            </span>`;
        box.insertBefore(div, box.firstChild);
        // Keep at most 80 entries
        while (box.children.length > 80) box.removeChild(box.lastChild);
    },

    // ── Host table (Network page) ─────────────────────────────────────
    updateHostTable(hosts) {
        const tbody = document.getElementById('hosts-table');
        if (!tbody) return;
        this.ensureTableHeader();
        this._initSessionsMenu();

        const currentIds = new Set(hosts.map(h => h.id));
        Array.from(tbody.children).forEach(row => {
            if (!currentIds.has(parseInt(row.getAttribute('data-id')))) row.remove();
        });

        hosts.forEach(h => {
            let row = document.getElementById(`host-row-${h.id}`);
            if (!row) {
                row = document.createElement('tr');
                row.id = `host-row-${h.id}`;
                row.setAttribute('data-id', h.id);
                row.className = 'hover:bg-gray-800/50 transition border-b border-gray-700 last:border-0';
                row.innerHTML = `
                    <td class="p-4 font-mono text-xs text-gray-500">#${h.id}</td>
                    <td class="p-4 font-bold text-white host-name"></td>
                    <td class="p-4 text-gray-300 font-mono text-sm host-ip"></td>
                    <td class="p-4 host-os-cell col-os"></td>
                    <td class="p-4 font-mono text-xs text-gray-500 truncate max-w-[100px] host-hwid col-hwid"></td>
                    <td class="p-4 host-modules col-scripts"></td>
                    <td class="p-4 host-evasion col-evasion"></td>
                    <td class="p-4 text-right host-actions"></td>`;
                tbody.appendChild(row);
                // Hydrate badge state from command history once per new row.
                window.EvasionFlags?.initFromHistory(h.id);
            }

            const safe = escHtml(h.hostname || '');
            const secs = h.last_seen_secs ?? 0;
            const seenText  = secs < 60 ? `${secs}s` : secs < 3600 ? `${Math.floor(secs/60)}m` : `${Math.floor(secs/3600)}h`;
            const staleClass = secs > 120 ? 'text-yellow-500' : 'text-green-500';
            const tagsHtml   = (h.tags||[]).map(t => `<span class="px-1.5 py-0.5 rounded text-[10px] bg-green-900/60 text-green-300 mr-1">${escHtml(t)}</span>`).join('');
            const hibHtml    = h.hibernation_mode
                ? '<span class="px-1.5 py-0.5 rounded text-[10px] bg-purple-900/60 text-purple-300 mr-1" title="Hibernation mode: claims queued tasks on check-in, no persistent connection"><i class="fas fa-moon"></i> hibernating</span>'
                : '';

            const nameEl = row.querySelector('.host-name');
            nameEl.innerHTML = `${safe} <span class="text-xs font-normal ${staleClass}">${seenText} ago</span>${(hibHtml || tagsHtml) ? '<br>'+hibHtml+tagsHtml : ''}`;

            const ipEl = row.querySelector('.host-ip');
            const ipHtml = this._ipHtml(h.ip);
            if (ipEl.innerHTML !== ipHtml) ipEl.innerHTML = ipHtml;
            if (this._sessionCols.flag) this._loadFlag(ipEl, h.ip);

            const hwidEl = row.querySelector('.host-hwid');
            if (hwidEl.innerText !== h.computer_id) hwidEl.innerText = h.computer_id;

            const osCell  = row.querySelector('.host-os-cell');
            const osClass = h.os.toLowerCase().includes('win') ? 'bg-blue-900 text-blue-200' : 'bg-yellow-900 text-yellow-200';
            const osBadge = `<span class="px-2 py-1 rounded text-xs font-bold ${osClass}">${escHtml(h.os)}</span>`;
            if (osCell.innerHTML !== osBadge) osCell.innerHTML = osBadge;

            const modCell   = row.querySelector('.host-modules');
            const activeEl  = document.activeElement;
            const isFocused = activeEl && activeEl.id === `mod-select-${h.id}`;
            if (modCell.innerHTML === '' || (!isFocused && window.ModuleManager)) {
                const newHtml = window.ModuleManager.renderControls(h.id);
                if (!isFocused && modCell.innerHTML.length !== newHtml.length)
                    modCell.innerHTML = newHtml;
            }

            const actionCell = row.querySelector('.host-actions');
            const evasionCell = row.querySelector('.host-evasion');
            if (evasionCell) {
                const badges = window.EvasionFlags?.renderBadges(h.id) || '';
                const badgesHtml = badges
                    ? `<div style="display:flex;gap:3px;flex-wrap:wrap;">${badges}</div>`
                    : '<span style="font-size:10px;color:var(--text-muted);">-</span>';
                if (evasionCell.innerHTML !== badgesHtml) evasionCell.innerHTML = badgesHtml;
            }
            const proxyBtn   = h.has_proxy
                ? `<button onclick="window.ProxyManager.stop(${h.id})" class="text-red-400 hover:text-white border border-red-500 hover:bg-red-600 px-2 py-1 rounded text-xs transition flex items-center gap-1"><i class="fas fa-stop-circle"></i> Stop</button>`
                : `<button onclick="window.ProxyManager.start(${h.id})" class="text-blue-500 hover:text-white border border-blue-500 hover:bg-blue-600 px-2 py-1 rounded text-xs transition flex items-center gap-1"><i class="fas fa-network-wired"></i> Proxy</button>`;

            const beaconBtn = h.is_active
                ? `<button onclick="window.BeaconManager.toggle(${h.id},this)" class="group relative text-red-500 border border-red-500 bg-red-500/10 px-3 py-1 rounded text-xs transition ml-2 shadow-[0_0_10px_rgba(239,68,68,0.5)] animate-pulse" title="Fast mode active"><i class="fas fa-bolt"></i></button>`
                : `<button onclick="window.BeaconManager.toggle(${h.id},this)" class="text-gray-600 border border-gray-700 hover:text-green-400 hover:border-green-500 hover:bg-green-500/10 px-3 py-1 rounded text-xs transition ml-2" title="Activate fast mode"><i class="fas fa-bed"></i></button>`;

            const termBtn   = `<button onclick="window.Terminal.open(${h.id},this.dataset.hostname)" data-hostname="${safe}" class="bg-gray-900 hover:bg-green-600 border border-green-600 hover:text-white text-green-500 px-3 py-1 rounded text-xs transition flex items-center gap-1 ml-2"><i class="fas fa-terminal"></i> Shell</button>`;
            const procBtn   = `<button onclick="window.ProcView.load(${h.id})" class="text-gray-500 hover:text-cyan-400 border border-gray-700 hover:border-cyan-500 px-2 py-1 rounded text-xs transition ml-1" title="Processes"><i class="fas fa-list"></i></button>`;
            const screenBtn = `<button onclick="window.ScreenshotView.capture(${h.id})" class="text-gray-500 hover:text-purple-400 border border-gray-700 hover:border-purple-500 px-2 py-1 rounded text-xs transition ml-1" title="Screenshot"><i class="fas fa-camera"></i></button>`;
            const notesBtn  = `<button onclick="window.Notes.show(${h.id},this.dataset.hostname)" data-hostname="${safe}" class="text-gray-500 hover:text-yellow-400 border border-gray-700 hover:border-yellow-500 px-2 py-1 rounded text-xs transition ml-1" title="Notes"><i class="fas fa-sticky-note"></i></button>`;

            const actionHtml = `<div class="flex justify-end items-center">${proxyBtn}${beaconBtn}${termBtn}${procBtn}${screenBtn}${notesBtn}</div>`;
            if (actionCell.innerHTML !== actionHtml) actionCell.innerHTML = actionHtml;
        });
    },

    ensureTableHeader() {
        const theadRow = document.querySelector('#hosts-table')?.parentElement?.querySelector('thead tr');
        if (theadRow && !theadRow.innerHTML.includes('col-evasion')) {
            theadRow.innerHTML = `
                <th class="p-4">ID</th>
                <th class="p-4">Hostname</th>
                <th class="p-4">IP Address</th>
                <th class="p-4 col-os">OS</th>
                <th class="p-4 col-hwid">HWID</th>
                <th class="p-4 col-scripts">Scripts</th>
                <th class="p-4 col-evasion">Evasion</th>
                <th class="p-4 text-right">Actions</th>`;
        }
    },

    // ── Sessions table: column & IP display config ───────────────────
    //
    // The 3-dots menu in the Sessions header toggles which columns are
    // visible and how the IP is rendered. Column visibility is pure CSS
    // (hide-col-* classes on #page-control) so the 2s polling re-render
    // never fights it; IP masking/flags are applied when the cell renders.
    // HWID and evasion are hidden by default. Settings persist in
    // localStorage (rcm-sessions-cols).

    _sessionCols: { flag: true, maskIp: false, os: true, scripts: true, hwid: false,
                    evasion: false, flagFallback: '' },
    _sessionsMenuBound: false,
    // ip -> { cc: country code ('' = unresolved), t: timestamp, priv?: true }.
    // Successful lookups stick; failures are retried after GEO_FAIL_TTL
    // (private ranges never retry). Legacy string values are migrated.
    _ipGeo: null,
    _GEO_FAIL_TTL: 3600 * 1000,

    _loadSessionCols() {
        try {
            const s = JSON.parse(localStorage.getItem('rcm-sessions-cols') || 'null');
            if (s && typeof s === 'object') {
                Object.keys(this._sessionCols).forEach(k => {
                    if (typeof s[k] === typeof this._sessionCols[k]) this._sessionCols[k] = s[k];
                });
            }
        } catch (_) { /* keep defaults */ }
        try {
            this._ipGeo = JSON.parse(localStorage.getItem('rcm-ip-geo') || '{}') || {};
        } catch (_) { this._ipGeo = {}; }
        // Migrate legacy { ip: 'US' | '' } entries to { ip: {cc, t} }.
        Object.keys(this._ipGeo).forEach(ip => {
            if (typeof this._ipGeo[ip] === 'string') {
                this._ipGeo[ip] = this._ipGeo[ip]
                    ? { cc: this._ipGeo[ip], t: 0 }
                    : { cc: '', t: 0 };
            }
        });
    },

    _saveSessionCols() {
        try {
            localStorage.setItem('rcm-sessions-cols', JSON.stringify(this._sessionCols));
        } catch (_) { /* private mode */ }
    },

    _saveIpGeo() {
        try {
            localStorage.setItem('rcm-ip-geo', JSON.stringify(this._ipGeo));
        } catch (_) { /* private mode */ }
    },

    // Lazy-bound on the first host render so the static markup is in place.
    _initSessionsMenu() {
        if (this._sessionsMenuBound) return;
        this._sessionsMenuBound = true;
        this._loadSessionCols();

        const wrap = document.getElementById('sessions-cols-menu-wrap');
        const btn  = document.getElementById('sessions-cols-menu-btn');
        const menu = document.getElementById('sessions-cols-menu');
        if (wrap && btn && menu) {
            // Click "pins" the menu open (survives hover-off); clicking the
            // dots again unpins and closes it. Without a pin, hover shows it
            // and hover-off hides it - the hide is deferred briefly (hover
            // intent) and cancelled the moment the pointer reaches the
            // dropdown, so fast diagonal mouse paths can't snap it shut.
            let pinned = false;
            let hideTimer = null;
            const show = () => menu.classList.remove('hidden');
            const hide = () => menu.classList.add('hidden');
            const cancelHide = () => { if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; } };
            const scheduleHide = () => {
                cancelHide();
                hideTimer = setTimeout(() => { if (!pinned) hide(); }, 280);
            };
            wrap.addEventListener('mouseenter', () => { cancelHide(); show(); });
            wrap.addEventListener('mouseleave', scheduleHide);
            menu.addEventListener('mouseenter', cancelHide);
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                cancelHide();
                if (pinned) { pinned = false; hide(); }
                else        { pinned = true;  show(); }
            });
            document.addEventListener('click', (e) => {
                if (!wrap.contains(e.target)) { pinned = false; cancelHide(); hide(); }
            });
            menu.querySelectorAll('input[data-col]').forEach(cb => {
                cb.checked = this._sessionCols[cb.dataset.col];
                cb.addEventListener('change', () => {
                    this._sessionCols[cb.dataset.col] = cb.checked;
                    this._saveSessionCols();
                    this._applySessionCols();
                });
            });
            const fb = document.getElementById('sessions-flag-fallback');
            if (fb) {
                fb.value = this._sessionCols.flagFallback || '';
                fb.addEventListener('change', () => {
                    this._sessionCols.flagFallback = fb.value;
                    this._saveSessionCols();
                    this._applySessionCols();
                });
            }
        }
        this._applySessionCols();
    },

    _applySessionCols() {
        const page = document.getElementById('page-control');
        if (!page) return;
        ['os', 'scripts', 'hwid', 'evasion'].forEach(k => {
            page.classList.toggle('hide-col-' + k, !this._sessionCols[k]);
        });
        // Force immediate re-render so IP mask/flag changes show up without
        // waiting for the next poll tick.
        const tbody = document.getElementById('hosts-table');
        if (tbody) tbody.innerHTML = '';
        if (window.API?.refreshHosts) window.API.refreshHosts();
    },

    // ***.**.*.42 style masking - keeps only the last group of digits.
    _maskIp(ip) {
        if (!ip) return ip;
        if (ip.includes(':')) {                       // IPv6: keep last group
            const g = ip.split(':');
            return g.map((_, i) => i === g.length - 1 ? g[i] : '****').join(':');
        }
        const p = ip.split('.');
        if (p.length < 2) return ip;
        return p.map((_, i) => i === p.length - 1 ? p[i] : '***').join('.');
    },

    _flagImg(cc, isFallback) {
        const style = 'vertical-align:-2px;margin-right:6px;border-radius:2px;' +
            (isFallback ? 'border:1px dashed var(--text-muted);' : '');
        return `<img src="https://flagcdn.com/w20/${escHtml(cc.toLowerCase())}.png" ` +
            `width="16" alt="${escHtml(cc)}" ` +
            `title="${isFallback ? 'Fallback flag - country lookup failed for this IP' : escHtml(cc)}" ` +
            (isFallback ? 'class="flag-fallback" ' : '') +
            `style="${style}">`;
    },

    _ipHtml(ip) {
        const cols = this._sessionCols;
        const display = cols.maskIp ? this._maskIp(ip) : (ip || '');
        if (!cols.flag) return escHtml(display);
        const entry = this._ipGeo?.[ip];
        if (entry && entry.cc) return this._flagImg(entry.cc, false) + escHtml(display);
        // Auto-lookup failed (or still pending): fall back to the configured
        // flag so unresolved IPs still show something meaningful.
        if (cols.flagFallback) return this._flagImg(cols.flagFallback, true) + escHtml(display);
        if (entry) return escHtml(display);   // known-unresolved, no fallback
        return `<span class="ip-flag-pending" data-ip="${escHtml(ip || '')}" style="margin-right:6px;"></span>` +
               escHtml(display);
    },

    // True when we already know the answer (or a fresh failure) and don't
    // need to hit the lookup services again.
    _ipKnown(ip) {
        const e = this._ipGeo?.[ip];
        if (!e) return false;
        if (e.cc || e.priv) return true;
        return Date.now() - e.t < this._GEO_FAIL_TTL;
    },

    // Fill in the country code once known. Resolution chains through
    // multiple free services and is best-effort: private ranges never
    // resolve, transient failures retry after GEO_FAIL_TTL, and the
    // configured fallback flag covers the rest.
    _loadFlag(ipEl, ip) {
        if (!ip || this._ipKnown(ip)) return;
        if (/^(10\.|127\.|0\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80)/.test(ip)) {
            this._ipGeo[ip] = { cc: '', t: Date.now(), priv: true };
            this._saveIpGeo();
            return;
        }
        this._resolveCc(ip).then(cc => {
            this._ipGeo[ip] = { cc, t: Date.now() };
            this._saveIpGeo();
            if (cc) {
                document.querySelectorAll(`.ip-flag-pending[data-ip="${CSS.escape(ip)}"]`)
                    .forEach(s => s.replaceWith(this._flagImgEl(cc)));
            } else {
                // Lookup definitively failed: swap the pending spinner for the
                // fallback flag if one is configured.
                const fb = this._sessionCols.flagFallback;
                if (fb) document.querySelectorAll(`.ip-flag-pending[data-ip="${CSS.escape(ip)}"]`)
                    .forEach(s => s.replaceWith(this._flagImgEl(fb, true)));
            }
        });
    },

    _flagImgEl(cc, isFallback) {
        const img = document.createElement('img');
        img.src = `https://flagcdn.com/w20/${cc.toLowerCase()}.png`;
        img.width = 16;
        img.alt = cc;
        img.title = isFallback ? 'Fallback flag - country lookup failed for this IP' : cc;
        if (isFallback) img.className = 'flag-fallback';
        img.style.cssText = 'vertical-align:-2px;margin-right:6px;border-radius:2px;' +
            (isFallback ? 'border:1px dashed var(--text-muted);' : '');
        return img;
    },

    // Try each resolver in order; '' when every service fails or the IP is
    // not in their databases (e.g. reserved documentation ranges).
    async _resolveCc(ip) {
        const resolvers = [
            async ip => {
                const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/country_code/`);
                if (!r.ok) throw new Error('ipapi ' + r.status);
                const cc = (await r.text()).trim().toUpperCase();
                if (!/^[A-Z]{2}$/.test(cc)) throw new Error('ipapi bad cc');
                return cc;
            },
            async ip => {
                const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
                if (!r.ok) throw new Error('ipwho ' + r.status);
                const d = await r.json();
                const cc = (d.country_code || '').toUpperCase();
                if (d.success === false || !/^[A-Z]{2}$/.test(cc)) throw new Error('ipwho bad cc');
                return cc;
            },
        ];
        for (const fn of resolvers) {
            try { return await fn(ip); } catch (_) { /* try next */ }
        }
        return '';
    },
};

// ── Evasion Status Badges ──────────────────────────────────────────────
//
// Tracks which evasion techniques have been applied to each session.
// State is persisted in localStorage so it survives page refresh.
// Updated in two ways:
//   1. setFlag() called by the terminal when an evasion command is sent
//   2. initFromHistory() called once on page load, scans command history

window.EvasionFlags = {

    // Map of command string fragments -> flag name
    _cmdMap: {
        'evasion:patch_amsi':    'amsi',
        'evasion:patch_etw':     'etw',
        'evasion:unhook_ntdll':  'ntdll',
        'evasion:patch_all':     ['amsi', 'etw', 'ntdll'],
        'evasion:encrypt_heap_aes':  'mask',
    },

    _key(sessionId) { return `rcm_ev_${sessionId}`; },

    get(sessionId) {
        try { return JSON.parse(localStorage.getItem(this._key(sessionId)) || '{}'); }
        catch (_) { return {}; }
    },

    setFlag(sessionId, flag, val = true) {
        const flags = this.get(sessionId);
        if (Array.isArray(flag)) flag.forEach(f => { flags[f] = val; });
        else flags[flag] = val;
        localStorage.setItem(this._key(sessionId), JSON.stringify(flags));
    },

    // Call after dispatching any command from the terminal so the badge
    // updates immediately without waiting for a history refresh.
    onCommand(sessionId, cmd) {
        const lower = cmd.toLowerCase().trim();
        for (const [frag, flag] of Object.entries(this._cmdMap)) {
            if (lower === frag || lower.startsWith(frag + ' ')) {
                this.setFlag(sessionId, flag);
            }
        }
    },

    // Initialise from command history on page load (one fetch per session).
    async initFromHistory(sessionId) {
        const url = window.Auth?.url?.replace(/\/$/, '');
        if (!url) return;
        try {
            const r = await fetch(`${url}/api/hosts/${sessionId}/history`,
                { headers: { 'X-API-KEY': window.Auth.key } });
            if (!r.ok) return;
            const history = await r.json();
            (history || []).forEach(entry => {
                const cmd = (entry.command || '').toLowerCase().trim();
                for (const [frag, flag] of Object.entries(this._cmdMap)) {
                    if (cmd === frag || cmd.startsWith(frag + ' ')) {
                        this.setFlag(sessionId, flag);
                    }
                }
            });
        } catch (_) {}
    },

    // Render the badge row HTML for a given session.
    renderBadges(sessionId) {
        const flags = this.get(sessionId);
        const defs = [
            { key: 'amsi',  label: 'AMSI',  title: 'AMSI scan interface patched' },
            { key: 'etw',   label: 'ETW',   title: 'ETW event write patched' },
            { key: 'ntdll', label: 'NTDLL', title: 'Ntdll .text unhooked' },
            { key: 'mask',  label: 'MASK',  title: 'Heap / sleep encrypted' },
        ];
        return defs.map(d => {
            const on  = !!flags[d.key];
            const cls = on
                ? 'bg-green-900/60 text-green-300 border-green-700'
                : 'bg-gray-800/60 text-gray-600 border-gray-700';
            return `<span class="text-[10px] px-1.5 py-0.5 rounded border font-mono ${cls}"
                         title="${d.title}">${d.label}</span>`;
        }).join('');
    },
};