// panel/js/ioc.js — Artifact / IOC Tracker
//
// Displays all artifacts recorded across all sessions, lets operators
// add new entries, dispatch pre-filled cleanup commands, and mark items
// as cleaned.  Data lives in the server-side `iocs` table.

window.IocTracker = {

    _iocs: [],    // cached from last fetch
    _hosts: [],   // cached from window.API

    // ── Lifecycle ─────────────────────────────────────────────────────────

    async init() {
        this._hosts = window.API?.hosts || [];
        await this.refresh();
        this._bindFilters();
    },

    async refresh() {
        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const r = await fetch(`${url}/api/iocs`,
                { headers: { 'X-API-KEY': window.Auth.key } });
            if (r.ok) this._iocs = await r.json();
        } catch (_) {}
        this._render();
    },

    // ── Rendering ─────────────────────────────────────────────────────────

    _render() {
        const filterSession = document.getElementById('ioc-filter-session')?.value || '';
        const filterStatus  = document.getElementById('ioc-filter-status')?.value  || 'all';
        const search        = (document.getElementById('ioc-search')?.value || '').toLowerCase();

        let rows = this._iocs.filter(i => {
            if (filterSession && String(i.session_id) !== filterSession) return false;
            if (filterStatus === 'active'  && i.cleaned_at) return false;
            if (filterStatus === 'cleaned' && !i.cleaned_at) return false;
            if (search && !`${i.path} ${i.detail || ''} ${i.ioc_type}`.toLowerCase().includes(search)) return false;
            return true;
        });

        const tbody = document.getElementById('ioc-tbody');
        if (!tbody) return;

        const active  = this._iocs.filter(i => !i.cleaned_at).length;
        const cleaned = this._iocs.filter(i => !!i.cleaned_at).length;
        const summary = document.getElementById('ioc-summary');
        if (summary) summary.textContent =
            `${this._iocs.length} total  ·  ${active} active  ·  ${cleaned} cleaned`;

        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="8"
                class="p-6 text-center text-gray-500 italic">No artifacts found.</td></tr>`;
            return;
        }

        tbody.innerHTML = rows.map(i => this._row(i)).join('');
    },

    _row(i) {
        const esc     = s => s ? String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') : '';
        const host    = this._hosts.find(h => h.id === i.session_id);
        const hname   = host ? esc(host.hostname) : `#${i.session_id}`;
        const typeClr = {
            file:     'text-yellow-300',
            registry: 'text-purple-300',
            service:  'text-blue-300',
            task:     'text-cyan-300',
            crontab:  'text-green-300',
            other:    'text-gray-300',
        }[i.ioc_type] || 'text-gray-300';

        const status = i.cleaned_at
            ? `<span class="text-xs text-green-400"><i class="fas fa-check-circle mr-1"></i>cleaned</span>`
            : `<span class="text-xs text-red-400"><i class="fas fa-circle mr-1"></i>active</span>`;

        const actions = i.cleaned_at ? `
            <button onclick="window.IocTracker.deleteEntry(${i.id})"
                    class="text-gray-500 hover:text-red-400 text-xs" title="Remove record">
              <i class="fas fa-trash"></i>
            </button>` : `
            <button onclick="window.IocTracker.clean(${i.id}, ${i.session_id}, ${JSON.stringify(esc(i.cleanup_cmd || ''))})"
                    class="text-green-400 hover:text-white text-xs px-2 py-0.5 rounded
                           border border-green-700 hover:border-green-500 mr-1" title="Mark cleaned">
              Clean
            </button>
            <button onclick="window.IocTracker.deleteEntry(${i.id})"
                    class="text-gray-500 hover:text-red-400 text-xs" title="Delete record">
              <i class="fas fa-trash"></i>
            </button>`;

        return `<tr class="border-b border-gray-700/50 hover:bg-gray-800/40 text-sm">
          <td class="px-3 py-2 text-gray-300 font-mono">${hname}</td>
          <td class="px-3 py-2 ${typeClr} font-mono text-xs">${esc(i.ioc_type)}</td>
          <td class="px-3 py-2 text-gray-200 font-mono text-xs max-w-xs truncate"
              title="${esc(i.path)}">${esc(i.path)}</td>
          <td class="px-3 py-2 text-gray-400 text-xs max-w-xs truncate"
              title="${esc(i.detail || '')}">${esc(i.detail) || '—'}</td>
          <td class="px-3 py-2 text-gray-500 text-xs">${esc(i.operator)}</td>
          <td class="px-3 py-2 text-gray-500 text-xs whitespace-nowrap">${i.created_at?.split('T')[0] || ''}</td>
          <td class="px-3 py-2">${status}</td>
          <td class="px-3 py-2 whitespace-nowrap">${actions}</td>
        </tr>`;
    },

    // ── Actions ───────────────────────────────────────────────────────────

    async clean(id, sessionId, cleanupCmd) {
        const url = window.Auth.url.replace(/\/$/, '');

        if (cleanupCmd) {
            const msg = `Dispatch cleanup command to session #${sessionId}?\n\n${cleanupCmd}`;
            if (!confirm(msg)) return;
            // Send the cleanup command to the agent
            await fetch(`${url}/api/hosts/${sessionId}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-KEY': window.Auth.key },
                body: JSON.stringify({ command: cleanupCmd }),
            });
        }

        // Mark as cleaned in the DB
        await fetch(`${url}/api/iocs/${id}/clean`, {
            method: 'POST',
            headers: { 'X-API-KEY': window.Auth.key },
        });
        await this.refresh();
        window.Notify?.toast('Marked as cleaned', 'success', 2000);
    },

    async deleteEntry(id) {
        if (!confirm('Remove this IOC record? This does not clean the artifact.')) return;
        const url = window.Auth.url.replace(/\/$/, '');
        await fetch(`${url}/api/iocs/${id}`, {
            method: 'DELETE',
            headers: { 'X-API-KEY': window.Auth.key },
        });
        await this.refresh();
    },

    // ── Add IOC modal ─────────────────────────────────────────────────────

    showAddModal() {
        const hosts = (window.API?.hosts || [])
            .map(h => `<option value="${h.id}">${h.hostname} (#${h.id})</option>`)
            .join('');

        const modal = document.createElement('div');
        modal.id = 'ioc-add-modal';
        modal.className = 'fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-8 backdrop-blur-sm';
        modal.onclick = e => { if (e.target === modal) modal.remove(); };
        modal.innerHTML = `
          <div class="bg-gray-900 w-full max-w-lg rounded-xl border border-gray-700 shadow-2xl">
            <div class="bg-gray-800 px-4 py-3 flex justify-between items-center border-b border-gray-700 rounded-t-xl">
              <span class="text-white font-bold text-sm"><i class="fas fa-bug text-red-400 mr-2"></i>Record Artifact</span>
              <button onclick="document.getElementById('ioc-add-modal').remove()"
                      class="text-gray-400 hover:text-white"><i class="fas fa-times"></i></button>
            </div>
            <div class="p-5 flex flex-col gap-3">
              <div class="flex gap-3">
                <div class="flex-1">
                  <label class="text-xs text-gray-400 mb-1 block">Session</label>
                  <select id="ioc-new-session" class="w-full bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-white text-sm">
                    ${hosts || '<option value="">No sessions</option>'}
                  </select>
                </div>
                <div class="w-36">
                  <label class="text-xs text-gray-400 mb-1 block">Type</label>
                  <select id="ioc-new-type" class="w-full bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-white text-sm">
                    <option>file</option>
                    <option>registry</option>
                    <option>service</option>
                    <option>task</option>
                    <option>crontab</option>
                    <option>other</option>
                  </select>
                </div>
              </div>
              <div>
                <label class="text-xs text-gray-400 mb-1 block">Path / Key / Name on target</label>
                <input id="ioc-new-path" type="text" placeholder="e.g. C:\\Windows\\Temp\\payload.exe"
                       class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm text-white font-mono">
              </div>
              <div>
                <label class="text-xs text-gray-400 mb-1 block">Detail <span class="text-gray-600">(optional)</span></label>
                <input id="ioc-new-detail" type="text" placeholder="Extra context"
                       class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm text-white">
              </div>
              <div>
                <label class="text-xs text-gray-400 mb-1 block">Cleanup command <span class="text-gray-600">(optional — dispatched on Clean)</span></label>
                <input id="ioc-new-cleanup" type="text" placeholder="e.g. shell del C:\\Windows\\Temp\\payload.exe"
                       class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm text-white font-mono">
              </div>
            </div>
            <div class="px-5 pb-5">
              <button onclick="window.IocTracker.submitAdd()"
                      class="w-full bg-red-700 hover:bg-red-600 text-white font-bold py-2 rounded text-sm">
                <i class="fas fa-plus mr-1"></i> Record Artifact
              </button>
            </div>
          </div>`;
        document.body.appendChild(modal);
    },

    async submitAdd() {
        const sessionId = document.getElementById('ioc-new-session')?.value;
        const type      = document.getElementById('ioc-new-type')?.value;
        const path      = document.getElementById('ioc-new-path')?.value?.trim();
        if (!sessionId || !path) {
            window.Notify?.toast('Session and path are required', 'error', 3000);
            return;
        }
        const url = window.Auth.url.replace(/\/$/, '');
        await fetch(`${url}/api/hosts/${sessionId}/iocs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-API-KEY': window.Auth.key },
            body: JSON.stringify({
                ioc_type:    type,
                path,
                detail:      document.getElementById('ioc-new-detail')?.value?.trim() || null,
                cleanup_cmd: document.getElementById('ioc-new-cleanup')?.value?.trim() || null,
            }),
        });
        document.getElementById('ioc-add-modal')?.remove();
        await this.refresh();
        window.Notify?.toast('Artifact recorded', 'success', 2000);
    },

    // ── Filter wiring ─────────────────────────────────────────────────────

    _bindFilters() {
        const ids = ['ioc-filter-session', 'ioc-filter-status', 'ioc-search'];
        ids.forEach(id => {
            document.getElementById(id)?.addEventListener('input', () => this._render());
            document.getElementById(id)?.addEventListener('change', () => this._render());
        });
        // Populate session filter with current hosts
        const sel = document.getElementById('ioc-filter-session');
        if (sel && window.API?.hosts?.length) {
            sel.innerHTML = '<option value="">All sessions</option>' +
                window.API.hosts.map(h =>
                    `<option value="${h.id}">${h.hostname} (#${h.id})</option>`
                ).join('');
        }
    },
};
