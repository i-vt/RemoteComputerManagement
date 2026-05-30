// panel/js/auditview.js — Audit log viewer
window.AuditView = {
    async refresh() {
        const url = window.Auth.url.replace(/\/$/, '');
        const tbody = document.getElementById('audit-tbody');
        if(!tbody) return;

        try {
            const res = await fetch(`${url}/api/audit`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if(!res.ok) return;
            const entries = await res.json();

            if(entries.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-gray-500">No audit entries</td></tr>';
                return;
            }

            tbody.innerHTML = entries.map(e => {
                const esc = (s) => s ? String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') : '';
                const actionColor = {
                    'command': 'text-green-400',
                    'login': 'text-blue-400',
                    'create_operator': 'text-yellow-400',
                    'delete_operator': 'text-red-400',
                    'create_listener': 'text-cyan-400',
                    'stop_listener': 'text-orange-400',
                }[e.action] || 'text-gray-300';

                const ts = e.timestamp?.split('T');
                const time = ts?.[1]?.split('.')[0] || '';
                const date = ts?.[0] || '';

                return `<tr class="border-b border-gray-700 hover:bg-gray-800/50">
                    <td class="p-3 text-xs text-gray-400">${esc(date)} ${esc(time)}</td>
                    <td class="p-3 text-white text-sm font-bold">${esc(e.operator_name)}</td>
                    <td class="p-3 ${actionColor} text-sm font-mono">${esc(e.action)}</td>
                    <td class="p-3 text-gray-400 text-xs font-mono">${e.target_session != null ? '#' + e.target_session : '—'}</td>
                    <td class="p-3 text-gray-300 text-xs truncate max-w-[300px]" title="${esc(e.details || '')}">${esc(e.details) || '—'}</td>
                </tr>`;
            }).join('');
        } catch(e) { console.error('Audit fetch error:', e); }
    }
};
