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
                ${escHtml(h.ip||'—')}
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

    addTaskLog(cmd, targets) {
        const el = document.getElementById('task-list');
        if (!el) return;
        el.innerHTML = `
            <div style="background:var(--bg-elevated);padding:10px 12px;border-radius:6px;border-left:3px solid var(--red);margin-bottom:6px;">
              <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);">
                <span>BROADCAST</span><span>${new Date().toLocaleTimeString()}</span>
              </div>
              <div style="font-family:monospace;color:var(--text-primary);margin-top:4px;font-size:12px;">${escHtml(cmd)}</div>
              <div style="font-size:11px;color:var(--accent);margin-top:3px;">Targets: ${targets}</div>
            </div>` + el.innerHTML;
    },

    updateConnectionStatus(isConnected) {
        const el = document.getElementById('connection-status');
        if (!el) return;
        if (isConnected) {
            el.innerHTML = '<div class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div> Connected';
            el.classList.remove('text-red-400');
            el.classList.add('text-green-400');
        } else {
            el.innerHTML = '<div class="w-2 h-2 rounded-full bg-red-500"></div> Connection Error';
            el.classList.remove('text-green-400');
            el.classList.add('text-red-400');
        }
    },

    // ── Host table (Network page) ─────────────────────────────────────
    updateHostTable(hosts) {
        const tbody = document.getElementById('hosts-table');
        if (!tbody) return;
        this.ensureTableHeader();

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
                    <td class="p-4 host-os-cell"></td>
                    <td class="p-4 font-mono text-xs text-gray-500 truncate max-w-[100px] host-hwid"></td>
                    <td class="p-4 host-modules"></td>
                    <td class="p-4 text-right host-actions"></td>`;
                tbody.appendChild(row);
            }

            const safe = escHtml(h.hostname || '');
            const secs = h.last_seen_secs ?? 0;
            const seenText  = secs < 60 ? `${secs}s` : secs < 3600 ? `${Math.floor(secs/60)}m` : `${Math.floor(secs/3600)}h`;
            const staleClass = secs > 120 ? 'text-yellow-500' : 'text-green-500';
            const tagsHtml   = (h.tags||[]).map(t => `<span class="px-1.5 py-0.5 rounded text-[10px] bg-green-900/60 text-green-300 mr-1">${escHtml(t)}</span>`).join('');

            const nameEl = row.querySelector('.host-name');
            nameEl.innerHTML = `${safe} <span class="text-xs font-normal ${staleClass}">${seenText} ago</span>${tagsHtml ? '<br>'+tagsHtml : ''}`;

            const ipEl = row.querySelector('.host-ip');
            if (ipEl.innerText !== h.ip) ipEl.innerText = h.ip;

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
        if (theadRow && !theadRow.innerHTML.includes('Scripts')) {
            theadRow.innerHTML = `
                <th class="p-4">ID</th>
                <th class="p-4">Hostname</th>
                <th class="p-4">IP Address</th>
                <th class="p-4">OS</th>
                <th class="p-4">HWID</th>
                <th class="p-4">Scripts</th>
                <th class="p-4 text-right">Actions</th>`;
        }
    }
};
