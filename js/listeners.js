window.ListenerManager = {
    listeners: [],
    _profiles: null,   // name -> profile JSON content, from /api/listeners/profiles

    // Load the malleable profile catalog from the server and refresh the
    // datalist options. Cached; retried on the next refresh after failure.
    async _loadProfiles() {
        if (this._profiles) return;
        try {
            const res = await window.API.apiFetch('/api/listeners/profiles');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const list = await res.json();
            this._profiles = {};
            (list || []).forEach(p => { if (p && p.name) this._profiles[p.name] = p.content; });
            const dl = document.getElementById('listener-profile-list');
            if (dl) {
                dl.innerHTML = Object.keys(this._profiles)
                    .map(n => `<option value="${n}"></option>`).join('');
            }
        } catch (e) {
            if (e.message === 'unauthorized') return;
            // Endpoint may be absent on older servers - profile selection is
            // unavailable then, but listener creation still works without one.
            this._profiles = null;
        }
    },

    // ── New-session webhook (admin only) ────────────────────────────────────

    // Load the configured webhook URL. The card stays hidden for non-admin
    // roles (the endpoint is admin-only) and when the server is unreachable.
    async loadWebhook() {
        const card = document.getElementById('webhook-card');
        if (!card) return;
        if (window.Auth?.role !== 'admin') { card.style.display = 'none'; return; }
        try {
            const res = await window.API.apiFetch('/api/config/webhook');
            if (res.status === 403) { card.style.display = 'none'; return; }
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            const input = document.getElementById('webhook-url');
            if (input) input.value = data.webhook_url || '';
            card.style.display = '';
        } catch (e) {
            if (e.message !== 'unauthorized') card.style.display = 'none';
        }
    },

    async saveWebhook() {
        const url = (document.getElementById('webhook-url')?.value || '').trim();
        try {
            const res = await window.API.apiFetch('/api/config/webhook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await res.json().catch(() => null);
            if (!res.ok) {
                window.Notify?.toast(`Webhook not saved: ${data?.error || `HTTP ${res.status}`}`, 'error');
                return;
            }
            window.Notify?.toast(url ? 'Webhook saved.' : 'Webhook cleared.', 'success', 2500);
        } catch (e) {
            if (e.message !== 'unauthorized') window.Notify?.toast(`Webhook not saved: ${e.message}`, 'error');
        }
    },

    async clearWebhook() {
        const input = document.getElementById('webhook-url');
        if (input) input.value = '';
        this.saveWebhook();
    },

    async refresh() {
        const tbody = document.getElementById('listeners-tbody');
        try {
            const url = window.Auth.url.replace(/\/$/, '');
            const res = await fetch(`${url}/api/listeners`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if(res.status === 401) return window.Auth.logout();
            if(!res.ok) {
                if(tbody) tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-red-400">Failed to load listeners (HTTP ${res.status})</td></tr>`;
                return;
            }
            this.listeners = await res.json();
            this.render();
            this._loadProfiles();
            this.loadWebhook();
        } catch(e) {
            console.error('Listener fetch error:', e);
            if(tbody) tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-red-400">Failed to load listeners (server unreachable)</td></tr>';
        }
    },

    render() {
        const tbody = document.getElementById('listeners-tbody');
        if(!tbody) return;

        if(!this.listeners.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="p-6 text-center text-gray-500 italic">No listeners configured - create one above.</td></tr>';
            return;
        }

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
        const profileName = (document.getElementById('new-listener-profile')?.value || '').trim();

        if(!name || !port) { window.Modal.alert('Name and port required', 'warning'); return; }

        // The server stores the raw profile JSON, not a profile name, so
        // resolve the name against the catalog from /api/listeners/profiles.
        let profileJson = null;
        if(profileName) {
            if(!this._profiles) {
                window.Modal.alert('Traffic profile catalog is unavailable (server does not expose /api/listeners/profiles yet). Create the listener without a profile.', 'warning');
                return;
            }
            profileJson = this._profiles[profileName];
            if(!profileJson) {
                window.Modal.alert(`Unknown profile "${profileName}". Available: ${Object.keys(this._profiles).join(', ') || '(none)'}`, 'warning');
                return;
            }
        }

        try {
            const url = window.Auth.url.replace(/\/$/, '');
            const res = await fetch(`${url}/api/listeners`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, port, transport, profile_json: profileJson })
            });
            if(res.status === 401) return window.Auth.logout();
            const data = await res.json();
            if(!res.ok) { window.Modal.alert(data.error || 'Failed to create listener', 'error'); return; }
            window.Notify?.toast(`Listener "${name}" created`, 'success', 2500);
            this.refresh();
        } catch(e) { window.Modal.alert('Error: ' + e.message, 'error'); }
    },

    async start(id) {
        await this._startStop(id, 'start');
    },

    async stop(id) {
        await this._startStop(id, 'stop');
    },

    async _startStop(id, verb) {
        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const res = await fetch(`${url}/api/listeners/${id}/${verb}`, {
                method: 'POST', headers: { 'X-API-KEY': window.Auth.key }
            });
            if(res.status === 401) return window.Auth.logout();
            if(!res.ok) {
                const data = await res.json().catch(() => null);
                window.Notify?.toast(`Failed to ${verb} listener: ${data?.error || `HTTP ${res.status}`}`, 'error');
            }
        } catch(e) {
            window.Notify?.toast(`Failed to ${verb} listener: server unreachable`, 'error');
        }
        this.refresh();
    },

    async remove(id) {
        if(!await window.Modal.confirm('Delete this listener?')) return;
        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const res = await fetch(`${url}/api/listeners/${id}`, {
                method: 'DELETE', headers: { 'X-API-KEY': window.Auth.key }
            });
            if(res.status === 401) return window.Auth.logout();
            if(!res.ok) {
                const data = await res.json().catch(() => null);
                window.Notify?.toast(`Failed to delete listener: ${data?.error || `HTTP ${res.status}`}`, 'error');
            }
        } catch(e) {
            window.Notify?.toast('Failed to delete listener: server unreachable', 'error');
        }
        this.refresh();
    }
};
