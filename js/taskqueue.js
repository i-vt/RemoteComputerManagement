// panel/js/taskqueue.js - Hibernation task queue
//
// Hibernating agents hold no persistent connection: operators enqueue
// commands here, the agent claims and executes the batch on its next
// check-in, and results land back on the same task rows.
// API: POST /api/hosts/:id/queue, GET /api/hosts/:id/tasks,
//      DELETE /api/hosts/:id/tasks/:task_id
window.TaskQueue = {

    // Populate the session dropdown from the live host list and load tasks.
    init() {
        this._syncSessions();
        this.refresh();
    },

    _syncSessions() {
        const sel = document.getElementById('queue-session');
        if (!sel) return;
        const prev = sel.value;
        const hosts = window.API?.hosts || [];
        sel.innerHTML = hosts.length
            ? hosts.map(h => `<option value="${h.id}">#${h.id} ${h.hostname || ''}</option>`).join('')
            : '<option value="">No active sessions</option>';
        if (prev) sel.value = prev;
    },

    _sessionId() {
        return document.getElementById('queue-session')?.value || '';
    },

    async enqueue() {
        const id = this._sessionId();
        const cmd = document.getElementById('queue-command')?.value.trim();
        if (!id)  { window.Notify?.toast('Select a session first.', 'warning'); return; }
        if (!cmd) { window.Notify?.toast('Enter a command.', 'warning'); return; }
        try {
            const res = await window.API.apiFetch(`/api/hosts/${id}/queue`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: cmd })
            });
            const data = await res.json().catch(() => null);
            if (!res.ok) {
                window.Notify?.toast(`Enqueue failed: ${data?.error || `HTTP ${res.status}`}`, 'error');
                return;
            }
            document.getElementById('queue-command').value = '';
            window.Notify?.toast(`Task ${data?.task_id?.slice(0, 8) || ''} queued for session #${id}`, 'success', 2500);
            this.refresh();
        } catch (e) {
            if (e.message !== 'unauthorized') window.Notify?.toast(`Enqueue failed: ${e.message}`, 'error');
        }
    },

    async refresh() {
        const tbody = document.getElementById('queue-tbody');
        if (!tbody) return;
        const id = this._sessionId();
        if (!id) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="5">Select a session to view its queue</td></tr>';
            return;
        }
        try {
            const res = await window.API.apiFetch(`/api/hosts/${id}/tasks`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            this._render(data.tasks || []);
        } catch (e) {
            if (e.message === 'unauthorized') return;
            tbody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-red-400">Failed to load tasks (${e.message})</td></tr>`;
        }
    },

    _render(tasks) {
        const tbody = document.getElementById('queue-tbody');
        if (!tbody) return;
        const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

        if (!tasks.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="p-6 text-center text-gray-500 italic">No queued tasks for this session.</td></tr>';
            return;
        }

        tbody.innerHTML = tasks.map(t => {
            const statusColor = {
                pending:   'bg-blue-900 text-blue-200',
                claimed:   'bg-yellow-900 text-yellow-200',
                completed: 'bg-green-900 text-green-200',
                failed:    'bg-red-900 text-red-200',
                cancelled: 'bg-gray-700 text-gray-400',
            }[t.status] || 'bg-gray-700 text-gray-300';

            const outcome = t.error
                ? `<span class="text-red-400">${esc(t.error)}</span>`
                : esc(t.result || '');
            const shortOutcome = outcome.length > 120 ? outcome.slice(0, 120) + '…' : outcome;
            const created = t.created_at ? new Date(t.created_at * 1000).toLocaleString() : '';

            const cancelBtn = t.status === 'pending'
                ? `<button onclick="window.TaskQueue.cancel('${esc(t.task_id)}')" title="Cancel" class="text-red-400 hover:text-white text-xs border border-red-500 px-2 py-1 rounded">Cancel</button>`
                : '';

            return `<tr class="border-b border-gray-700 hover:bg-gray-800/50">
                <td class="p-3 text-xs text-gray-500 hide-mobile">${esc(created)}</td>
                <td class="p-3 font-mono text-xs text-green-400 break-all" title="task ${esc(t.task_id)}">${esc(t.command)}</td>
                <td class="p-3"><span class="px-2 py-1 rounded text-xs font-bold ${statusColor}">${esc(t.status)}</span></td>
                <td class="p-3 text-xs text-gray-400 hide-mobile" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;">${shortOutcome || '-'}</td>
                <td class="p-3 text-right">${cancelBtn}</td>
            </tr>`;
        }).join('');
    },

    async cancel(taskId) {
        const id = this._sessionId();
        if (!id) return;
        try {
            const res = await window.API.apiFetch(`/api/hosts/${id}/tasks/${encodeURIComponent(taskId)}`, {
                method: 'DELETE'
            });
            if (res.status === 409) {
                window.Notify?.toast('Task already claimed or completed - cannot cancel.', 'warning');
            } else if (!res.ok && res.status !== 204) {
                const data = await res.json().catch(() => null);
                window.Notify?.toast(`Cancel failed: ${data?.error || `HTTP ${res.status}`}`, 'error');
            } else {
                window.Notify?.toast('Task cancelled', 'success', 2000);
            }
        } catch (e) {
            if (e.message !== 'unauthorized') window.Notify?.toast(`Cancel failed: ${e.message}`, 'error');
        }
        this.refresh();
    }
};
