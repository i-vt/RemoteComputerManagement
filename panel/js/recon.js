// panel/js/recon.js — Auto-recon manager
//
// Three entry types, stored as plain strings with conventions:
//   "shell whoami"          → command sent to agent  (prefix normalised server-side)
//   "module:recon"          → Rhai script run server-side on session connect
//   "ext:load <b64> [args]" → Rhai script pushed to agent as ext:load command
//
// The server's normalise_recon_cmd() auto-prepends "shell " for OS commands.

window.ReconConfig = {
    _modules: [],   // populated once from /api/modules

    async init() {
        await this._loadModules();
        await this.refresh();
        this._syncTypeUI('command');
    },

    async _loadModules() {
        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const r = await fetch(`${url}/api/modules`,
                { headers: { 'X-API-KEY': window.Auth.key } });
            if (r.ok) {
                this._modules = await r.json() || [];
                const sel = document.getElementById('recon-module-select');
                if (sel) {
                    sel.innerHTML = this._modules.length
                        ? this._modules.map(m =>
                            `<option value="${this._esc(m)}">${this._esc(m)}</option>`).join('')
                        : '<option value="" disabled>No modules found</option>';
                }
            }
        } catch (_) {}
    },

    async refresh() {
        const url   = window.Auth.url.replace(/\/$/, '');
        const tbody = document.getElementById('recon-tbody');
        if (!tbody) return;

        try {
            const res = await fetch(`${url}/api/config/recon`,
                { headers: { 'X-API-KEY': window.Auth.key } });
            if (!res.ok) return;
            const entries = await res.json();

            if (!entries.length) {
                tbody.innerHTML =
                    '<tr><td colspan="4" class="p-3 text-center text-gray-500 text-sm">' +
                    'No auto-recon entries. Add a command, module, or extension below.</td></tr>';
                return;
            }

            tbody.innerHTML = entries.map(e => {
                const { icon, badge, label } = this._describe(e.command);
                return `
                <tr class="border-b border-gray-700/50 hover:bg-gray-800/50">
                    <td class="px-3 py-2 text-xs text-gray-500">${e.sort_order}</td>
                    <td class="px-3 py-2">
                        <span class="text-xs px-1.5 py-0.5 rounded font-mono ${badge}">${icon}</span>
                    </td>
                    <td class="px-3 py-2 font-mono text-xs text-green-400 break-all">${this._esc(label)}</td>
                    <td class="px-3 py-2 text-right">
                        <button onclick="ReconConfig.remove(${e.id})"
                                class="text-gray-500 hover:text-red-400 text-xs">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
            }).join('');
        } catch (e) { console.error('recon refresh:', e); }
    },

    _describe(cmd) {
        if (cmd.startsWith('module:')) {
            const name = cmd.slice(7);
            return {
                icon: 'script',
                badge: 'bg-purple-900/60 text-purple-300',
                label: name
            };
        }
        if (cmd.startsWith('ext:load ')) {
            return {
                icon: 'ext',
                badge: 'bg-blue-900/60 text-blue-300',
                label: cmd.length > 60 ? cmd.slice(0, 57) + '…' : cmd
            };
        }
        return {
            icon: 'cmd',
            badge: 'bg-gray-700 text-gray-400',
            label: cmd
        };
    },

    // ── Type switching ─────────────────────────────────────────────────────

    _syncTypeUI(type) {
        ['command','module','extension'].forEach(t => {
            const row = document.getElementById(`recon-row-${t}`);
            const btn = document.getElementById(`recon-tab-${t}`);
            if (row) row.style.display = t === type ? '' : 'none';
            if (btn) {
                btn.classList.toggle('active', t === type);
                btn.style.opacity = t === type ? '1' : '0.5';
            }
        });
    },

    selectType(type) { this._syncTypeUI(type); },

    // ── Add ────────────────────────────────────────────────────────────────

    async add() {
        // Determine which input row is visible
        const types = ['command', 'module', 'extension'];
        let raw = null;

        for (const t of types) {
            const row = document.getElementById(`recon-row-${t}`);
            if (row && row.style.display !== 'none') {
                if (t === 'command') {
                    const v = document.getElementById('recon-cmd-input')?.value.trim();
                    if (!v) { this._err('Enter a command.'); return; }
                    raw = v;
                }
                if (t === 'module') {
                    const v = document.getElementById('recon-module-select')?.value;
                    if (!v) { this._err('Select a module.'); return; }
                    raw = `module:${v}`;
                }
                if (t === 'extension') {
                    const code = document.getElementById('recon-ext-code')?.value.trim();
                    const args = document.getElementById('recon-ext-args')?.value.trim();
                    if (!code) { this._err('Enter extension code.'); return; }
                    const b64 = btoa(unescape(encodeURIComponent(code)));
                    raw = args ? `ext:load ${b64} ${args}` : `ext:load ${b64}`;
                }
                break;
            }
        }

        if (!raw) return;

        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const res = await fetch(`${url}/api/config/recon`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: raw })
            });
            if (res.ok) {
                const data = await res.json();
                // Clear inputs
                ['recon-cmd-input','recon-ext-code','recon-ext-args']
                    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
                if (window.UI) window.UI.addLog(`Auto-recon added: ${data.command || raw}`);
                await this.refresh();
            } else {
                const err = await res.json().catch(() => ({}));
                this._err(err.error || `HTTP ${res.status}`);
            }
        } catch (e) { this._err(e.message); }
    },

    async remove(id) {
        const url = window.Auth.url.replace(/\/$/, '');
        await fetch(`${url}/api/config/recon/${id}`, {
            method: 'DELETE',
            headers: { 'X-API-KEY': window.Auth.key }
        });
        await this.refresh();
    },

    _err(msg) { if (window.UI) window.UI.addLog(`Recon: ${msg}`, 'error'); },
    _esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }
};
