// panel/js/extensions.js — Scripts & Extensions Manager
//
// Manages two kinds of .rhai files:
//
//   extensions  (./extensions/)
//     Agent-side: pushed to the agent via ext:load.
//     API: GET/PUT/DELETE /api/extensions/:name
//
//   modules  (./modules/)
//     Server-side: executed by the server's Rhai engine on session events.
//     Run with access to send_c2_command() / send_c2_extension().
//     API: GET /api/modules (list), GET/PUT/DELETE /api/modules/:name
//
// Exposes window.ExtManager.listNames(kind) so ReconConfig can read
// available extensions without an extra fetch.

window.ExtManager = {
    _kind:    'extensions',  // 'extensions' | 'modules'
    _lists:   { extensions: [], modules: [] },
    _current: null,

    // ── Init ──────────────────────────────────────────────────────────────────

    async init() {
        await this.loadList();
        this._renderEditor(null, '');
    },

    // ── Kind switching ────────────────────────────────────────────────────────

    setKind(kind) {
        this._kind    = kind;
        this._current = null;
        ['extensions','modules'].forEach(k => {
            const btn = document.getElementById(`scripts-tab-${k}`);
            if (!btn) return;
            btn.classList.toggle('active',   k === kind);
            btn.style.opacity = k === kind ? '1' : '0.5';
        });
        const badge = document.getElementById('scripts-kind-badge');
        if (badge) {
            if (kind === 'extensions') {
                badge.textContent = 'Agent-side · pushed via ext:load';
                badge.className   = 'text-xs text-green-400 italic';
            } else {
                badge.textContent = 'Server-side · run by Rhai engine on session events';
                badge.className   = 'text-xs text-yellow-400 italic';
            }
        }
        const dirLabel = document.getElementById('ext-dir-label');
        if (dirLabel) dirLabel.textContent = kind === 'modules' ? 'modules/' : 'extensions/';
        this.loadList();
        this._renderEditor(null, '');
    },

    // ── API helpers ───────────────────────────────────────────────────────────

    _base() { return window.Auth.url.replace(/\/+$/, ''); },
    _hdr()  { return { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' }; },

    _listEndpoint(kind) {
        return kind === 'modules'
            ? `${this._base()}/api/modules`
            : `${this._base()}/api/extensions`;
    },
    _fileEndpoint(kind, name) {
        const seg = kind === 'modules' ? 'modules' : 'extensions';
        return `${this._base()}/api/${seg}/${encodeURIComponent(name)}`;
    },
    _listKey(kind) { return kind === 'modules' ? 'modules' : 'extensions'; },

    // ── Load ──────────────────────────────────────────────────────────────────

    async loadList() {
        try {
            const r = await fetch(this._listEndpoint(this._kind),
                { headers: { 'X-API-KEY': window.Auth.key } });
            const data = await r.json();
            // /api/modules returns a plain array; /api/extensions returns {extensions:[]}
            this._lists[this._kind] = Array.isArray(data)
                ? data
                : (data[this._listKey(this._kind)] || []);
        } catch (_) {
            this._lists[this._kind] = [];
        }
        this._renderList();
        if (this._kind === 'extensions' && window.ReconConfig?._onExtensionsLoaded) {
            window.ReconConfig._onExtensionsLoaded(this._lists.extensions);
        }
    },

    async loadFile(name) {
        try {
            const r = await fetch(this._fileEndpoint(this._kind, name),
                { headers: { 'X-API-KEY': window.Auth.key } });
            if (!r.ok) { window.Notify?.toast(`Not found: ${name}`, 'error'); return; }
            const { content } = await r.json();
            this._renderEditor(name, content);
            this._current = name;
            this._highlightList(name);
        } catch (e) {
            window.Notify?.toast(`Load error: ${e.message}`, 'error');
        }
    },

    // ── Save ──────────────────────────────────────────────────────────────────

    async save() {
        const name    = document.getElementById('ext-name-input')?.value.trim();
        const content = document.getElementById('ext-code-editor')?.value ?? '';
        if (!name) { window.Notify?.toast('Enter a script name.', 'warn'); return; }
        if (!/^[a-zA-Z0-9_\-]+$/.test(name)) {
            window.Notify?.toast('Name: letters, numbers, _ and - only.', 'warn'); return;
        }
        try {
            const r = await fetch(this._fileEndpoint(this._kind, name), {
                method: 'PUT', headers: this._hdr(),
                body: JSON.stringify({ content }),
            });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            this._current = name;
            await this.loadList();
            this._highlightList(name);
            const dir = this._kind === 'modules' ? 'modules' : 'extensions';
            window.Notify?.toast(`Saved ./${dir}/${name}.rhai`, 'success');
        } catch (e) {
            window.Notify?.toast(`Save failed: ${e.message}`, 'error');
        }
    },

    // ── Delete ────────────────────────────────────────────────────────────────

    async deleteScript(name) {
        const label = `${name}.rhai  (${this._kind})`;
        if (!confirm(`Delete "${label}"? This cannot be undone.`)) return;
        try {
            const r = await fetch(this._fileEndpoint(this._kind, name), {
                method: 'DELETE', headers: { 'X-API-KEY': window.Auth.key },
            });
            if (r.status === 404) { window.Notify?.toast('Already deleted.', 'warn'); }
            else if (!r.ok) throw new Error(`HTTP ${r.status}`);
            if (this._current === name) { this._renderEditor(null, ''); this._current = null; }
            await this.loadList();
            window.Notify?.toast(`Deleted "${name}.rhai"`, 'success');
        } catch (e) {
            window.Notify?.toast(`Delete failed: ${e.message}`, 'error');
        }
    },

    // ── Deploy (extensions only) ──────────────────────────────────────────────

    async deploy(sessionId) {
        if (this._kind !== 'extensions') {
            window.Notify?.toast('Deploy is only available for extensions.', 'warn'); return;
        }
        const name = document.getElementById('ext-name-input')?.value.trim();
        if (!name)      { window.Notify?.toast('Save the script first.', 'warn'); return; }
        if (!sessionId) { window.Notify?.toast('No session selected.', 'warn'); return; }
        try {
            const r = await fetch(
                `${this._base()}/api/hosts/${sessionId}/extensions/${encodeURIComponent(name)}`,
                { method: 'POST', headers: { 'X-API-KEY': window.Auth.key } });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            window.Notify?.toast(`Deployed "${name}" to session #${sessionId}`, 'success');
        } catch (e) {
            window.Notify?.toast(`Deploy failed: ${e.message}`, 'error');
        }
    },

    // ── Exposed to other modules ──────────────────────────────────────────────

    listNames(kind) { return [...(this._lists[kind || this._kind] || [])]; },

    // ── New script ────────────────────────────────────────────────────────────

    newScript() {
        this._current = null;
        this._highlightList('');
        this._renderEditor(null, '');
        document.getElementById('ext-name-input')?.focus();
    },

    filterList() { this._renderList(); },

    // ── Rendering ─────────────────────────────────────────────────────────────

    _renderList() {
        const ctr    = document.getElementById('ext-list');
        const filter = (document.getElementById('ext-search')?.value ?? '').toLowerCase();
        if (!ctr) return;

        const all     = this._lists[this._kind] || [];
        const visible = filter ? all.filter(n => n.toLowerCase().includes(filter)) : all;

        if (!visible.length) {
            ctr.innerHTML =
                `<p class="text-gray-500 text-xs italic p-3 text-center">` +
                (filter ? 'No matches.' : `No ${this._kind} yet.`) + `</p>`;
            return;
        }

        ctr.innerHTML = visible.map(name => `
            <div id="ext-item-${this._esc(name)}"
                 class="ext-list-item flex items-center gap-2 px-3 py-2
                        hover:bg-gray-700/60 cursor-pointer group
                        border-b border-gray-700/30 last:border-0
                        ${name === this._current ? 'bg-gray-700/80 text-white' : 'text-gray-300'}"
                 onclick="window.ExtManager.loadFile('${this._esc(name)}')">
              <i class="fas fa-file-code ${this._kind === 'modules' ? 'text-yellow-400' : 'text-green-400'} text-xs w-4 flex-shrink-0"></i>
              <span class="text-xs font-mono flex-1 truncate">${this._esc(name)}.rhai</span>
              <button onclick="event.stopPropagation();window.ExtManager.deleteScript('${this._esc(name)}')"
                      class="opacity-0 group-hover:opacity-100 text-red-400 hover:text-red-300 text-xs"
                      title="Delete">
                <i class="fas fa-trash"></i>
              </button>
            </div>`).join('');
    },

    _highlightList(name) {
        document.querySelectorAll('.ext-list-item').forEach(el => {
            const active = el.id === `ext-item-${this._esc(name)}`;
            el.classList.toggle('bg-gray-700/80', active);
            el.classList.toggle('text-white', active);
            el.classList.toggle('text-gray-300', !active);
        });
    },

    _renderEditor(name, content) {
        const nameEl  = document.getElementById('ext-name-input');
        const codeEl  = document.getElementById('ext-code-editor');
        const titleEl = document.getElementById('ext-editor-title');

        const extStub = [
            '// Agent-side extension script',
            '// Runs on the agent via ext:load',
            '//',
            '// Built-ins: exec_os(cmd), exec_os_timeout(cmd, secs),',
            '//            internal_self_path(), internal_env(var), print_log(msg)',
            '',
            'let out = exec_os("whoami");',
            'print_log("[ext] " + out);',
            'out',
        ].join('\n');

        const modStub = [
            '// Server-side module script',
            '// Runs on the server Rhai engine when triggered',
            '//',
            '// Built-ins: send_c2_command(session_id, cmd),',
            '//            send_c2_extension(session_id, ext_name, args)',
            '',
            'fn run(session_id) {',
            '    send_c2_command(session_id, "shell whoami");',
            '    "done"',
            '}',
        ].join('\n');

        if (nameEl)  nameEl.value = name ?? '';
        if (codeEl)  codeEl.value = content || (name ? '' : (this._kind === 'modules' ? modStub : extStub));
        if (titleEl) titleEl.textContent = name ? `${name}.rhai` : `New ${this._kind.slice(0, -1)}`;
    },

    _esc(s) {
        return String(s)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    },
};
