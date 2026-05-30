// panel/js/recon.js — Auto-recon command manager
window.ReconConfig = {
    async refresh() {
        const url = window.Auth.url.replace(/\/$/, '');
        const tbody = document.getElementById('recon-tbody');
        if(!tbody) return;

        try {
            const res = await fetch(`${url}/api/config/recon`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if(!res.ok) return;
            const entries = await res.json();

            if(entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="p-3 text-center text-gray-500 text-sm">No auto-recon commands configured. New sessions will not run any commands automatically.</td></tr>';
                return;
            }

            tbody.innerHTML = entries.map(e => `
                <tr class="border-b border-gray-700/50 hover:bg-gray-800/50">
                    <td class="p-3 font-mono text-xs text-gray-500">${e.sort_order}</td>
                    <td class="p-3 font-mono text-sm text-green-400">${e.command}</td>
                    <td class="p-3 text-right">
                        <button onclick="ReconConfig.remove(${e.id})" class="text-gray-500 hover:text-red-400 text-xs"><i class="fas fa-trash"></i></button>
                    </td>
                </tr>
            `).join('');
        } catch(e) { console.error('Recon fetch error:', e); }
    },

    async add() {
        const input = document.getElementById('recon-cmd-input');
        if(!input || !input.value.trim()) return;

        const url = window.Auth.url.replace(/\/$/, '');
        const res = await fetch(`${url}/api/config/recon`, {
            method: 'POST',
            headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: input.value.trim() })
        });
        if(res.ok) {
            input.value = '';
            this.refresh();
        }
    },

    async remove(id) {
        const url = window.Auth.url.replace(/\/$/, '');
        await fetch(`${url}/api/config/recon/${id}`, {
            method: 'DELETE',
            headers: { 'X-API-KEY': window.Auth.key }
        });
        this.refresh();
    }
};
