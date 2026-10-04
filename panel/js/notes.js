// panel/js/notes.js - Session tags & notes
window.Notes = {
    _hostnames: {},   // sessionId -> hostname, captured when the modal opens

    // Escape HTML entities to prevent XSS from agent-controlled data
    esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    },

    async show(sessionId, hostname) {
        if (hostname) this._hostnames[sessionId] = hostname;
        const url = window.Auth.url.replace(/\/$/, '');
        let data;
        try {
            const res = await fetch(`${url}/api/hosts/${sessionId}/notes`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if (res.status === 401) return window.Auth.logout();
            if (!res.ok) {
                window.Notify?.toast(`Failed to load notes (HTTP ${res.status})`, 'error');
                return;
            }
            data = await res.json();
        } catch (e) {
            window.Notify?.toast('Failed to load notes: server unreachable', 'error');
            return;
        }
        const esc = this.esc;
        const safeHostname = esc(this._hostnames[sessionId] || `#${sessionId}`);

        const modal = document.createElement('div');
        modal.id = 'notes-modal';
        modal.className = 'fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-10 backdrop-blur-sm';
        modal.onclick = (e) => { if(e.target === modal) modal.remove(); };

        const noteRows = data.notes.length ? data.notes.map(n => `
            <div class="flex items-start gap-2 border-b border-gray-700/50 py-2">
                ${n.tag ? `<span class="px-2 py-0.5 rounded text-xs bg-green-900 text-green-300 whitespace-nowrap">${esc(n.tag)}</span>` : ''}
                <span class="text-sm text-gray-200 flex-1">${esc(n.note)}</span>
                <span class="text-xs text-gray-500 whitespace-nowrap">${esc(n.operator)} · ${esc(n.timestamp?.split('T')[0])}</span>
                <button onclick="Notes.remove(${parseInt(sessionId)}, ${parseInt(n.id)})" class="text-gray-600 hover:text-red-400 text-xs"><i class="fas fa-trash"></i></button>
            </div>
        `).join('') : '<p class="text-gray-500 text-sm py-2">No notes yet</p>';

        modal.innerHTML = `
            <div class="bg-gray-900 w-full max-w-lg rounded-lg border border-gray-600 shadow-2xl">
                <div class="bg-gray-800 p-3 flex justify-between items-center border-b border-gray-700 rounded-t-lg">
                    <span class="text-white font-bold text-sm"><i class="fas fa-sticky-note"></i> Notes - ${safeHostname} (#${parseInt(sessionId)})</span>
                    <button onclick="document.getElementById('notes-modal').remove()" class="text-red-400 hover:text-white"><i class="fas fa-times"></i></button>
                </div>
                <div class="p-4 max-h-80 overflow-y-auto">${noteRows}</div>
                <div class="p-4 border-t border-gray-700 flex gap-2">
                    <input type="text" id="note-tag" placeholder="tag" class="w-24 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-green-400 text-xs font-mono">
                    <input type="text" id="note-text" placeholder="Note..." class="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-white text-sm"
                           onkeydown="if(event.key==='Enter') Notes.add(${parseInt(sessionId)})">
                    <button onclick="Notes.add(${parseInt(sessionId)})" class="bg-green-600 hover:bg-green-500 text-black font-bold px-3 py-1 rounded text-sm">Add</button>
                </div>
            </div>`;
        document.body.appendChild(modal);
    },

    async add(sessionId) {
        const tag = document.getElementById('note-tag')?.value.trim() || null;
        const note = document.getElementById('note-text')?.value.trim();
        if(!note) return;

        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const res = await fetch(`${url}/api/hosts/${sessionId}/notes`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ note, tag })
            });
            if (res.status === 401) return window.Auth.logout();
            if (!res.ok) {
                window.Notify?.toast(`Note was not saved (HTTP ${res.status})`, 'error');
                return;
            }
        } catch (e) {
            window.Notify?.toast('Note was not saved: server unreachable', 'error');
            return;
        }
        document.getElementById('notes-modal')?.remove();
        this.show(sessionId);
    },

    async remove(sessionId, noteId) {
        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const res = await fetch(`${url}/api/hosts/${sessionId}/notes/${noteId}`, {
                method: 'DELETE', headers: { 'X-API-KEY': window.Auth.key }
            });
            if (res.status === 401) return window.Auth.logout();
            if (!res.ok) {
                window.Notify?.toast(`Note was not deleted (HTTP ${res.status})`, 'error');
                return;
            }
        } catch (e) {
            window.Notify?.toast('Note was not deleted: server unreachable', 'error');
            return;
        }
        document.getElementById('notes-modal')?.remove();
        // Refresh host list to update tags
        window.API?.refreshHosts();
    }
};