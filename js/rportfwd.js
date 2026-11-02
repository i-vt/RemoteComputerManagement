// panel/js/rportfwd.js - Reverse port forwards
//
// Binds a port on the C2 server and relays connections through the agent
// to a target host:port reachable from the agent's network.
// API: GET /api/rportfwds,
//      POST /api/hosts/:id/rportfwd  {bind_port, target_host, target_port}
//      DELETE /api/hosts/:id/rportfwd {bind_port}
window.Rportfwd = {
    forwards: [],

    init() {
        this._syncSessions();
        this.refresh();
    },

    _syncSessions() {
        const sel = document.getElementById('rportfwd-session');
        if (!sel) return;
        const prev = sel.value;
        const hosts = window.API?.hosts || [];
        sel.innerHTML = hosts.length
            ? hosts.map(h => `<option value="${h.id}">#${h.id} ${h.hostname || ''}</option>`).join('')
            : '<option value="">No active sessions</option>';
        if (prev) sel.value = prev;
    },

    async refresh() {
        const wrap = document.getElementById('rportfwd-table-wrap');
        if (!wrap) return;
        try {
            const res = await window.API.apiFetch('/api/rportfwds');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            this.forwards = await res.json();
            this._render();
        } catch (e) {
            if (e.message === 'unauthorized') return;
            wrap.innerHTML = `<p class="text-red-400 text-xs">Failed to load forwards (${e.message})</p>`;
        }
    },

    _render() {
        const wrap = document.getElementById('rportfwd-table-wrap');
        if (!wrap) return;
        const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

        if (!this.forwards.length) {
            wrap.innerHTML = '<p class="text-gray-500 text-xs italic">No active reverse port forwards.</p>';
            return;
        }

        wrap.innerHTML = `<table class="data-table">
            <thead><tr>
                <th>Session</th><th>Server bind port</th><th>Target</th>
                <th style="text-align:right;">Actions</th>
            </tr></thead>
            <tbody>${this.forwards.map(f => `<tr class="border-b border-gray-700">
                <td class="p-2 text-sm text-white">#${esc(f.session_id)}</td>
                <td class="p-2 font-mono text-sm text-green-400">0.0.0.0:${esc(f.bind_port)}</td>
                <td class="p-2 font-mono text-xs text-gray-300">${esc(f.target_host)}:${esc(f.target_port)}</td>
                <td class="p-2 text-right">
                    <button onclick="window.Rportfwd.stop(${f.session_id}, ${f.bind_port})"
                            class="text-red-400 hover:text-white text-xs border border-red-500 px-2 py-1 rounded">Stop</button>
                </td>
            </tr>`).join('')}</tbody>
        </table>`;
    },

    async start() {
        const id = document.getElementById('rportfwd-session')?.value;
        const bindPort = parseInt(document.getElementById('rportfwd-bind-port')?.value, 10);
        const targetHost = (document.getElementById('rportfwd-target-host')?.value || '').trim();
        const targetPort = parseInt(document.getElementById('rportfwd-target-port')?.value, 10);

        if (!id) { window.Notify?.toast('Select a session.', 'warning'); return; }
        if (!bindPort || !targetHost || !targetPort) {
            window.Notify?.toast('Bind port, target host and target port are required.', 'warning');
            return;
        }

        try {
            const res = await window.API.apiFetch(`/api/hosts/${id}/rportfwd`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ bind_port: bindPort, target_host: targetHost, target_port: targetPort })
            });
            const data = await res.json().catch(() => null);
            if (!res.ok) {
                window.Notify?.toast(`rportfwd failed: ${data?.error || `HTTP ${res.status}`}`, 'error');
                return;
            }
            window.Notify?.toast(`rportfwd up: server :${bindPort} -> ${targetHost}:${targetPort} via #${id}`, 'success', 4000);
            if (window.UI) window.UI.addLog(`rportfwd started on :${bindPort} via session #${id} -> ${targetHost}:${targetPort}`);
            this.refresh();
        } catch (e) {
            if (e.message !== 'unauthorized') window.Notify?.toast(`rportfwd failed: ${e.message}`, 'error');
        }
    },

    async stop(sessionId, bindPort) {
        if (!await window.Modal.confirm(`Stop reverse forward on server port ${bindPort} (session #${sessionId})?`)) return;
        try {
            const res = await window.API.apiFetch(`/api/hosts/${sessionId}/rportfwd`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ bind_port: bindPort })
            });
            const data = await res.json().catch(() => null);
            if (!res.ok) {
                window.Notify?.toast(`Stop failed: ${data?.error || `HTTP ${res.status}`}`, 'error');
                return;
            }
            window.Notify?.toast(`Forward on :${bindPort} stopped`, 'success', 2500);
        } catch (e) {
            if (e.message !== 'unauthorized') window.Notify?.toast(`Stop failed: ${e.message}`, 'error');
        }
        this.refresh();
    }
};
