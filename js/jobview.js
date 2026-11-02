// panel/js/jobview.js - Job status panel with per-session job listing
//
// All hosts are probed in parallel (the send_command endpoint blocks up to
// 30 s waiting for an agent ack, so a serial loop scales as N x 30 s).
// Output is polled until available instead of a single fixed-delay fetch.
window.JobView = {
    jobs: {},

    async refresh() {
        if(!window.API?.hosts) return;
        const url = window.Auth.url.replace(/\/$/, '');
        const tbody = document.getElementById('jobs-tbody');
        if(!tbody) return;

        const hosts = window.API.hosts;
        if(!hosts.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-gray-500">No active sessions</td></tr>';
            return;
        }

        const results = await Promise.all(hosts.map(h => this._probeHost(url, h)));

        const allJobs = [];
        let unreachable = 0;
        results.forEach(r => {
            if(!r) { unreachable++; return; }
            r.forEach(j => allJobs.push(j));
        });

        if(allJobs.length === 0) {
            const note = unreachable
                ? `No active jobs (${unreachable} of ${hosts.length} hosts did not reply)`
                : 'No active jobs';
            tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-gray-500">${note}</td></tr>`;
            return;
        }

        const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        tbody.innerHTML = allJobs.map(j => {
            const statusColor = {
                'Running': 'bg-blue-900 text-blue-200',
                'Completed': 'bg-green-900 text-green-200',
                'Failed': 'bg-red-900 text-red-200',
                'Killed': 'bg-yellow-900 text-yellow-200',
            }[j.status] || 'bg-gray-700 text-gray-300';

            const killBtn = j.status === 'Running'
                ? `<button onclick="JobView.kill(${j.session}, ${j.id})" class="text-red-400 hover:text-white text-xs border border-red-500 px-2 py-1 rounded">Kill</button>`
                : '';

            return `<tr class="border-b border-gray-700 hover:bg-gray-800/50">
                <td class="p-3 font-mono text-xs text-gray-500">${esc(j.id)}</td>
                <td class="p-3 text-white text-sm">${esc(j.hostname)}</td>
                <td class="p-3 text-gray-300 text-sm truncate max-w-[200px]" title="${esc(j.description)}">${esc(j.description)}</td>
                <td class="p-3"><span class="px-2 py-1 rounded text-xs font-bold ${statusColor}">${esc(j.status)}</span></td>
                <td class="p-3 text-xs text-gray-400">${j.started_at?.split('T')[1]?.split('.')[0] || ''}</td>
                <td class="p-3 text-xs text-gray-400">${j.finished_at?.split('T')[1]?.split('.')[0] || '-'}</td>
                <td class="p-3 text-right">${killBtn}</td>
            </tr>`;
        }).join('');
    },

    // Probe one host: queue jobs:list, then poll the output endpoint until
    // the reply lands (up to ~12 s). Returns the job array, [] when the
    // agent has no jobs, or null when the host never answered.
    async _probeHost(url, host) {
        try {
            const res = await fetch(`${url}/api/hosts/${host.id}/command`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: 'jobs:list' })
            });
            if(res.status === 401) { window.Auth?.logout(); return null; }
            if(!res.ok) return null;
            const data = await res.json();
            if(!data.request_id) return null;

            for(let attempt = 0; attempt < 8; attempt++) {
                await new Promise(r => setTimeout(r, 1500));
                const out = await fetch(`${url}/api/hosts/${host.id}/output/${data.request_id}`, {
                    headers: { 'X-API-KEY': window.Auth.key }
                });
                if(!out.ok) continue;   // 404 = not ready yet
                const result = await out.json();
                if(result.status !== 'completed') continue;
                if(!result.output) return [];
                try {
                    const jobs = JSON.parse(result.output);
                    if(!Array.isArray(jobs)) return [];
                    return jobs.map(j => ({ ...j, hostname: host.hostname, session: host.id }));
                } catch(e) {
                    return [];
                }
            }
            return null;
        } catch(e) {
            return null;
        }
    },

    async kill(sessionId, jobId) {
        const url = window.Auth.url.replace(/\/$/, '');
        try {
            const res = await fetch(`${url}/api/hosts/${sessionId}/command`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: `jobs:kill ${jobId}` })
            });
            if(res.status === 401) { window.Auth?.logout(); return; }
            if(!res.ok) {
                const data = await res.json().catch(() => null);
                window.Notify?.toast(`Kill failed: ${data?.error || `HTTP ${res.status}`}`, 'error');
                return;
            }
            window.Notify?.toast(`Kill sent for job ${jobId}`, 'success', 2500);
        } catch(e) {
            window.Notify?.toast('Kill failed: server unreachable', 'error');
            return;
        }
        setTimeout(() => this.refresh(), 2000);
    }
};
