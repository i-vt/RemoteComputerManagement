// panel/js/jobview.js — Job status panel with per-session job listing
window.JobView = {
    jobs: {},

    async refresh() {
        if(!window.API?.hosts) return;
        const url = window.Auth.url.replace(/\/$/, '');
        const tbody = document.getElementById('jobs-tbody');
        if(!tbody) return;

        const allJobs = [];
        for(const host of window.API.hosts) {
            try {
                const res = await fetch(`${url}/api/hosts/${host.id}/command`, {
                    method: 'POST',
                    headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ command: 'jobs:list' })
                });
                if(!res.ok) continue;
                const data = await res.json();
                if(data.request_id) {
                    await new Promise(r => setTimeout(r, 1500));
                    const out = await fetch(`${url}/api/hosts/${host.id}/output/${data.request_id}`, {
                        headers: { 'X-API-KEY': window.Auth.key }
                    });
                    if(out.ok) {
                        const result = await out.json();
                        if(result.output) {
                            try {
                                const jobs = JSON.parse(result.output);
                                jobs.forEach(j => allJobs.push({ ...j, hostname: host.hostname, session: host.id }));
                            } catch(e) {}
                        }
                    }
                }
            } catch(e) {}
        }

        if(allJobs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="p-4 text-center text-gray-500">No active jobs</td></tr>';
            return;
        }

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
                <td class="p-3 font-mono text-xs text-gray-500">${j.id}</td>
                <td class="p-3 text-white text-sm">${j.hostname}</td>
                <td class="p-3 text-gray-300 text-sm truncate max-w-[200px]" title="${j.description}">${j.description}</td>
                <td class="p-3"><span class="px-2 py-1 rounded text-xs font-bold ${statusColor}">${j.status}</span></td>
                <td class="p-3 text-xs text-gray-400">${j.started_at?.split('T')[1]?.split('.')[0] || ''}</td>
                <td class="p-3 text-xs text-gray-400">${j.finished_at?.split('T')[1]?.split('.')[0] || '—'}</td>
                <td class="p-3 text-right">${killBtn}</td>
            </tr>`;
        }).join('');
    },

    async kill(sessionId, jobId) {
        const url = window.Auth.url.replace(/\/$/, '');
        await fetch(`${url}/api/hosts/${sessionId}/command`, {
            method: 'POST',
            headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: `jobs:kill ${jobId}` })
        });
        setTimeout(() => this.refresh(), 2000);
    }
};
