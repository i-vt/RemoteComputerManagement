window.ListenerManager = {
    listeners: [],

    async refresh() {
        try {
            const url = window.Auth.url.replace(/\/$/, '');
            const res = await fetch(`${url}/api/listeners`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if(!res.ok) return;
            this.listeners = await res.json();
            this.render();
        } catch(e) { console.error('Listener fetch error:', e); }
    },

    render() {
        const tbody = document.getElementById('listeners-tbody');
        if(!tbody) return;
        
        tbody.innerHTML = this.listeners.map(l => {
            const statusBadge = l.running
                ? '<span class="px-2 py-1 rounded text-xs font-bold bg-green-900 text-green-200">Running</span>'
                : '<span class="px-2 py-1 rounded text-xs font-bold bg-gray-700 text-gray-400">Stopped</span>';
            
            const actions = l.running
                ? `<button onclick="ListenerManager.stop(${l.id})" class="text-red-400 hover:text-white border border-red-500 hover:bg-red-600 px-2 py-1 rounded text-xs">Stop</button>`
                : `<button onclick="ListenerManager.start(${l.id})" class="text-green-400 hover:text-white border border-green-500 hover:bg-green-600 px-2 py-1 rounded text-xs">Start</button>`;

            const deleteBtn = window.Auth.role === 'admin'
                ? ` <button onclick="ListenerManager.remove(${l.id})" class="text-gray-400 hover:text-red-400 px-2 py-1 rounded text-xs ml-1"><i class="fas fa-trash"></i></button>`
                : '';

            const esc = (s) => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
            return `<tr class="border-b border-gray-700">
                <td class="p-3 font-mono text-xs text-gray-500">#${l.id}</td>
                <td class="p-3 text-white font-bold">${esc(l.name)}</td>
                <td class="p-3 font-mono text-sm text-gray-300">${l.port}</td>
                <td class="p-3"><span class="px-2 py-1 rounded text-xs bg-gray-700">${esc(l.transport)}</span></td>
                <td class="p-3">${statusBadge}</td>
                <td class="p-3 text-right">${actions}${deleteBtn}</td>
            </tr>`;
        }).join('');
    },

    async create() {
        const name = document.getElementById('new-listener-name')?.value;
        const port = parseInt(document.getElementById('new-listener-port')?.value);
        const transport = document.getElementById('new-listener-transport')?.value || 'tls';

        if(!name || !port) return alert('Name and port required');

        try {
            const url = window.Auth.url.replace(/\/$/, '');
            const res = await fetch(`${url}/api/listeners`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, port, transport })
            });
            const data = await res.json();
            if(!res.ok) return alert(data.error || 'Failed');
            this.refresh();
        } catch(e) { alert('Error: ' + e.message); }
    },

    async start(id) {
        const url = window.Auth.url.replace(/\/$/, '');
        const res = await fetch(`${url}/api/listeners/${id}/start`, {
            method: 'POST', headers: { 'X-API-KEY': window.Auth.key }
        });
        this.refresh();
    },

    async stop(id) {
        const url = window.Auth.url.replace(/\/$/, '');
        const res = await fetch(`${url}/api/listeners/${id}/stop`, {
            method: 'POST', headers: { 'X-API-KEY': window.Auth.key }
        });
        this.refresh();
    },

    async remove(id) {
        if(!confirm('Delete this listener?')) return;
        const url = window.Auth.url.replace(/\/$/, '');
        await fetch(`${url}/api/listeners/${id}`, {
            method: 'DELETE', headers: { 'X-API-KEY': window.Auth.key }
        });
        this.refresh();
    }
};
