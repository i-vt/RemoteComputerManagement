// panel/js/tasks.js - Broadcast page
//
// The execution log is rendered from server-side records so it is shared
// between operators and survives browser restarts:
//   - command broadcasts come from the audit log (action = 'broadcast'),
//     with the target count reconstructed from the per-session command log
//   - module broadcasts come from the global command history (rows whose
//     command starts with "broadcast module:"), grouped per invocation
window.TaskManager = {
    history: [],
    mode: 'command', // 'command' or 'module'

    async init() {
        this.renderTable();
        await Promise.all([this.loadHistory(), this.loadModules()]);
    },

    toggleMode(newMode) {
        this.mode = newMode;

        const btnCmd = document.getElementById('btn-mode-cmd');
        const btnMod = document.getElementById('btn-mode-mod');
        const grpCmd = document.getElementById('input-group-cmd');
        const grpMod = document.getElementById('input-group-mod');

        if (newMode === 'command') {
            btnCmd.classList.add('bg-gray-700', 'text-white', 'shadow');
            btnCmd.classList.remove('text-gray-400');
            btnMod.classList.remove('bg-gray-700', 'text-white', 'shadow');
            btnMod.classList.add('text-gray-400');

            grpCmd.classList.remove('hidden');
            grpCmd.style.display = '';        // restore to default block
            grpMod.classList.add('hidden');
            grpMod.style.display = 'none';
        } else {
            btnMod.classList.add('bg-gray-700', 'text-white', 'shadow');
            btnMod.classList.remove('text-gray-400');
            btnCmd.classList.remove('bg-gray-700', 'text-white', 'shadow');
            btnCmd.classList.add('text-gray-400');

            grpMod.classList.remove('hidden');
            grpMod.style.display = 'flex';   // clear the inline display:none from HTML
            grpCmd.classList.add('hidden');
            grpCmd.style.display = 'none';
        }
    },

    async loadModules() {
        const select = document.getElementById('broadcast-module-select');
        if (!select) return;

        try {
            // Reuse ModuleManager if available, otherwise fetch
            let modules = [];
            if (window.ModuleManager && window.ModuleManager.availableModules.length > 0) {
                modules = window.ModuleManager.availableModules;
            } else {
                const cleanUrl = window.Auth.url.replace(/\/$/, "");
                const res = await fetch(`${cleanUrl}/api/modules`, { headers: { 'X-API-KEY': window.Auth.key } });
                if (res.status === 401) return window.Auth.logout();
                modules = await res.json();
            }

            if (modules.length === 0) {
                select.innerHTML = `<option value="" disabled selected>No modules found</option>`;
                return;
            }

            select.innerHTML = `<option value="" disabled selected>Select Script</option>` +
                modules.map(m => `<option value="${m}">${m}</option>`).join('');
        } catch(e) {
            select.innerHTML = `<option value="" disabled selected>Error loading modules</option>`;
        }
    },

    // Load broadcast records from the server (audit log + global history)
    async loadHistory() {
        const cleanUrl = window.Auth.url.replace(/\/$/, "");
        const hdrs = { 'X-API-KEY': window.Auth.key };
        let audit = [], history = [];
        try {
            const [aRes, hRes] = await Promise.all([
                fetch(`${cleanUrl}/api/audit`, { headers: hdrs }),
                fetch(`${cleanUrl}/api/history`, { headers: hdrs }),
            ]);
            if (aRes.status === 401 || hRes.status === 401) return window.Auth.logout();
            if (aRes.ok) audit = await aRes.json();
            if (hRes.ok) history = await hRes.json();
        } catch(e) {
            console.error('Broadcast history fetch failed:', e);
        }

        const rows = [];
        const MOD_PREFIX = 'broadcast module:';

        // Command broadcasts: one audit entry per invocation. Target count
        // is reconstructed from per-session command-log rows written at the
        // same moment with the same command text.
        const broadcasts = audit.filter(e => e.action === 'broadcast');
        broadcasts.forEach(e => {
            const t = new Date(e.timestamp).getTime();
            const targets = history.filter(h =>
                h.command === e.details &&
                Math.abs(new Date(h.timestamp).getTime() - t) < 15000
            ).length;
            rows.push({
                type: 'CMD BROADCAST',
                command: e.details || '',
                operator: e.operator_name || '',
                targets,
                timestamp: e.timestamp,
            });
        });

        // Module broadcasts: one history row per target session, identical
        // command text. Group rows written within a 15 s window.
        const modRows = history
            .filter(h => (h.command || '').startsWith(MOD_PREFIX))
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        modRows.forEach(h => {
            const t = new Date(h.timestamp).getTime();
            const last = rows[rows.length - 1];
            if (last && last.type === 'MOD BROADCAST' && last.command === h.command.slice(MOD_PREFIX.length) &&
                Math.abs(new Date(last.timestamp).getTime() - t) < 15000) {
                last.targets++;
                return;
            }
            rows.push({
                type: 'MOD BROADCAST',
                command: h.command.slice(MOD_PREFIX.length),
                operator: '',
                targets: 1,
                timestamp: h.timestamp,
            });
        });

        rows.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        this.history = rows;
        this.renderTable();
    },

    async executeBroadcast() {
        const btn = document.getElementById('broadcast-btn');
        btn.disabled = true;
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';

        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            let endpoint = '';
            let payload = {};
            let logSummary = '';

            if (this.mode === 'command') {
                const cmd = document.getElementById('broadcast-input').value;
                if (!cmd) throw new Error("Command required");
                endpoint = '/api/broadcast';
                payload = { command: cmd };
                logSummary = cmd;
            } else {
                const mod = document.getElementById('broadcast-module-select').value;
                const argsStr = document.getElementById('broadcast-module-args').value;
                if (!mod) throw new Error("Module selection required");

                endpoint = '/api/broadcast/module';
                const args = argsStr.match(/(?:[^\s"]+|"[^"]*")+/g)?.map(a => a.replace(/"/g, "")) || [];
                payload = { module_name: mod, args: args };
                logSummary = `Module: ${mod} ${args.join(' ')}`;
            }

            const res = await fetch(`${cleanUrl}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-KEY': window.Auth.key
                },
                body: JSON.stringify(payload)
            });

            if (res.status === 401) return window.Auth.logout();
            const data = await res.json();

            if (!res.ok) throw new Error(data.error || "Broadcast failed");

            // Clear inputs
            if (this.mode === 'command') document.getElementById('broadcast-input').value = "";
            else document.getElementById('broadcast-module-args').value = "";

            if(window.UI) window.UI.addLog(`Broadcast ${this.mode}: "${logSummary}" to ${data.targets_reached || 0} targets.`);

            // Server writes the audit/history rows asynchronously; give it a
            // moment before reloading the log.
            setTimeout(() => this.loadHistory(), 1500);

        } catch (e) {
            window.Modal.alert("Error: " + e.message, 'error');
        } finally {
            btn.innerHTML = originalHtml;
            btn.disabled = false;
        }
    },

    async reRun(idx) {
        const task = this.history[idx];
        if(!task) return;

        if (task.type === 'CMD BROADCAST') {
            if(await window.Modal.confirm(`Re-broadcast command:\n"${task.command}"`)) {
                this.mode = 'command';
                this.toggleMode('command');
                document.getElementById('broadcast-input').value = task.command;
                this.executeBroadcast();
            }
        } else {
            window.Modal.alert("Please manually re-select the module to re-run.", 'info');
        }
    },

    renderTable() {
        const tbody = document.getElementById('tasks-table-body');
        const searchVal = document.getElementById('task-search')?.value.toLowerCase() || "";

        if (!tbody) return;

        const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

        const filtered = this.history.filter(t =>
            t.command.toLowerCase().includes(searchVal) ||
            t.type.toLowerCase().includes(searchVal) ||
            (t.operator || '').toLowerCase().includes(searchVal)
        );

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-gray-500 italic">No broadcasts recorded yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(t => {
            const dateStr = new Date(t.timestamp).toLocaleString();
            const badgeColor = t.type.includes('MOD') ? 'bg-purple-900 text-purple-200' : 'bg-blue-900 text-blue-200';
            const rerunBtn = t.type === 'CMD BROADCAST'
                ? `<button onclick="window.TaskManager.reRun(${this.history.indexOf(t)})" title="Re-run" class="text-gray-400 hover:text-white"><i class="fas fa-redo"></i></button>`
                : '';

            return `
            <tr class="hover:bg-gray-750 transition border-b border-gray-800 last:border-0 group">
                <td class="p-4 text-xs text-gray-500 font-mono">${esc(dateStr)}</td>
                <td class="p-4"><span class="${badgeColor} text-xs px-2 py-1 rounded font-bold">${esc(t.type)}</span></td>
                <td class="p-4 font-mono text-sm text-white"><span class="text-green-500">$</span> ${esc(t.command)}</td>
                <td class="p-4 text-center"><span class="text-gray-300 font-bold">${t.targets}</span></td>
                <td class="p-4 text-center text-xs text-gray-400">${esc(t.operator) || '-'}</td>
                <td class="p-4 text-right opacity-0 group-hover:opacity-100 transition-opacity">${rerunBtn}</td>
            </tr>
        `}).join('');
    }
};
