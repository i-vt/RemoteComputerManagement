// panel/js/recon.js — Auto-recon command manager
//
// Commands are normalised server-side (add_recon handler): bare OS commands
// like "whoami" are stored as "shell whoami" automatically, so operators
// don't need to know the internal prefix convention.

window.ReconConfig = {

    async refresh() {
        const url   = window.Auth.url.replace(/\/$/, '');
        const tbody = document.getElementById('recon-tbody');
        if (!tbody) return;

        try {
            const res = await fetch(`${url}/api/config/recon`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if (!res.ok) return;
            const entries = await res.json();

            if (entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-center text-gray-500 text-sm">' +
                    'No auto-recon commands configured.</td></tr>';
                return;
            }

            tbody.innerHTML = entries.map(e => `
                <tr class="border-b border-gray-700/50 hover:bg-gray-800/50">
                    <td class="p-3 font-mono text-xs text-gray-500">${e.sort_order}</td>
                    <td class="p-3 font-mono text-sm text-green-400">${this._esc(e.command)}</td>
                    <td class="p-3 text-right">
                        <button onclick="ReconConfig.remove(${e.id})"
                                class="text-gray-500 hover:text-red-400 text-xs">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`).join('');
        } catch (e) { console.error('Recon fetch error:', e); }
    },

    async add() {
        const input = document.getElementById('recon-cmd-input');
        if (!input || !input.value.trim()) return;

        const raw = input.value.trim();
        const url = window.Auth.url.replace(/\/$/, '');

        try {
            const res = await fetch(`${url}/api/config/recon`, {
                method: 'POST',
                headers: {
                    'X-API-KEY': window.Auth.key,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ command: raw })
            });

            if (res.ok) {
                const data = await res.json();
                input.value = '';
                // Show the normalised command that was actually saved
                const saved = data.command || raw;
                if (window.UI) window.UI.addLog(`Auto-recon added: ${saved}`);
                this.refresh();
            } else {
                const err = await res.json().catch(() => ({}));
                const msg = err.error || `HTTP ${res.status}`;
                if (window.UI) window.UI.addLog(`Failed to add recon command: ${msg}`, 'error');
            }
        } catch (e) {
            if (window.UI) window.UI.addLog(`Network error adding recon command: ${e.message}`, 'error');
        }
    },

    async remove(id) {
        const url = window.Auth.url.replace(/\/$/, '');
        const res = await fetch(`${url}/api/config/recon/${id}`, {
            method: 'DELETE',
            headers: { 'X-API-KEY': window.Auth.key }
        });
        if (res.ok) {
            if (window.UI) window.UI.addLog('Auto-recon command removed.');
        }
        this.refresh();
    },

    _esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }
};
