// panel/js/users.js — Operator / user management (admin only)
window.UserManager = {

    async init() {
        // Hide the entire page if the current user isn't an admin
        const page = document.getElementById('page-users');
        if (!page) return;
        if (window.Auth?.role !== 'admin') {
            page.innerHTML = `<div class="p-10 text-center text-red-400">
                <i class="fas fa-lock text-4xl mb-4 block"></i>
                Admin access required.</div>`;
            return;
        }
        await this.load();
    },

    async load() {
        const url  = window.Auth.url.replace(/\/$/, '');
        const tbody = document.getElementById('users-tbody');
        if (!tbody) return;
        tbody.innerHTML = '<tr><td colspan="5" class="p-3 text-center text-gray-500">Loading…</td></tr>';

        try {
            const res = await fetch(`${url}/api/operators`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const operators = await res.json();

            if (!operators.length) {
                tbody.innerHTML = '<tr><td colspan="5" class="p-3 text-center text-gray-500">No operators found.</td></tr>';
                return;
            }

            tbody.innerHTML = operators.map(op => {
                const roleBadge = {
                    admin:    'bg-red-900/60 text-red-300',
                    operator: 'bg-blue-900/60 text-blue-300',
                    viewer:   'bg-gray-700 text-gray-400',
                }[op.role] || 'bg-gray-700 text-gray-400';

                const isSelf  = op.username === window.Auth.username;
                const created = op.created_at ? new Date(op.created_at).toLocaleDateString() : '—';
                const login   = op.last_login  ? new Date(op.last_login).toLocaleString()   : 'Never';

                return `
                <tr class="border-b border-gray-700/50 hover:bg-gray-800/40">
                    <td class="px-4 py-3 text-sm text-gray-200 font-mono">
                        ${this._esc(op.username)}
                        ${isSelf ? '<span class="ml-2 text-xs text-green-400">(you)</span>' : ''}
                    </td>
                    <td class="px-4 py-3">
                        <span class="text-xs px-2 py-1 rounded font-medium ${roleBadge}">
                            ${op.role}
                        </span>
                    </td>
                    <td class="px-4 py-3 text-xs text-gray-500">${created}</td>
                    <td class="px-4 py-3 text-xs text-gray-500">${login}</td>
                    <td class="px-4 py-3 text-right">
                        ${isSelf ? '' : `
                        <button onclick="window.UserManager.confirmDelete(${op.id}, '${this._esc(op.username)}')"
                                class="text-xs text-red-500 hover:text-red-400 px-2 py-1
                                       bg-gray-800 hover:bg-gray-700 rounded transition-colors">
                            <i class="fas fa-trash mr-1"></i>Delete
                        </button>`}
                    </td>
                </tr>`;
            }).join('');
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="5" class="p-3 text-red-400">Error: ${e.message}</td></tr>`;
        }
    },

    async create() {
        const username = document.getElementById('new-username')?.value.trim();
        const password = document.getElementById('new-password')?.value;
        const role     = document.getElementById('new-role')?.value;

        if (!username || !password) {
            if (window.UI) window.UI.addLog('Username and password are required.', 'error');
            return;
        }
        if (password.length < 8) {
            if (window.UI) window.UI.addLog('Password must be at least 8 characters.', 'error');
            return;
        }

        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const res = await fetch(`${url}/api/operators`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, role })
            });
            const data = await res.json();

            if (res.ok) {
                document.getElementById('new-username').value = '';
                document.getElementById('new-password').value = '';

                // Show the one-time API key in a dismissible banner
                if (data.api_key) {
                    const banner = document.getElementById('api-key-banner');
                    const keyEl  = document.getElementById('api-key-value');
                    if (banner && keyEl) {
                        keyEl.textContent = data.api_key;
                        banner.classList.remove('hidden');
                    }
                }

                if (window.UI) window.UI.addLog(`Created operator: ${username} (${role})`);
                await this.load();
            } else {
                const msg = data.error || `HTTP ${res.status}`;
                if (window.UI) window.UI.addLog(`Failed to create operator: ${msg}`, 'error');
            }
        } catch (e) {
            if (window.UI) window.UI.addLog(`Network error: ${e.message}`, 'error');
        }
    },

    confirmDelete(id, username) {
        if (!confirm(`Delete operator "${username}"? This cannot be undone.`)) return;
        this.deleteOperator(id, username);
    },

    async deleteOperator(id, username) {
        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const res = await fetch(`${url}/api/operators/${id}`, {
                method: 'DELETE',
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if (res.ok || res.status === 204) {
                if (window.UI) window.UI.addLog(`Deleted operator: ${username}`);
                document.getElementById('api-key-banner')?.classList.add('hidden');
                await this.load();
            } else {
                const data = await res.json().catch(() => ({}));
                if (window.UI) window.UI.addLog(`Failed to delete: ${data.error || res.status}`, 'error');
            }
        } catch (e) {
            if (window.UI) window.UI.addLog(`Network error: ${e.message}`, 'error');
        }
    },

    dismissKey() {
        document.getElementById('api-key-banner')?.classList.add('hidden');
    },

    copyKey() {
        const key = document.getElementById('api-key-value')?.textContent;
        if (key) navigator.clipboard.writeText(key).then(() => {
            if (window.UI) window.UI.addLog('API key copied to clipboard.');
        });
    },

    _esc(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
};
