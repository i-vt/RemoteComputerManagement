// panel/js/rcm.js - RCM evidence package management (SPEC §5 custody)
//
// Lists the forensic packages under downloads/ and exposes the Sec 17.2
// custody actions: seal (write manifest generation) and verify (check the
// latest manifest against on-disk contents, reporting mismatches).
// API: GET /api/rcm/packages, POST /api/rcm/seal, POST /api/rcm/verify
window.RcmPackages = {

    async refresh() {
        const body = document.getElementById('rcm-packages-body');
        if (!body) return;
        try {
            const res = await window.API.apiFetch('/api/rcm/packages');
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const packages = await res.json();
            this._render(packages || []);
        } catch (e) {
            if (e.message === 'unauthorized') return;
            body.innerHTML = `<p class="text-red-400 p-4 text-center text-xs">Failed to load packages (${e.message})</p>`;
        }
    },

    _render(packages) {
        const body = document.getElementById('rcm-packages-body');
        if (!body) return;
        const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

        if (!packages.length) {
            body.innerHTML = '<p class="text-gray-500 p-4 text-center italic text-xs">No evidence packages yet.</p>';
            return;
        }

        const size = b => {
            if (!b) return '0 B';
            const k = 1024, s = ['B','KB','MB','GB'];
            const i = Math.floor(Math.log(b) / Math.log(k));
            return (b / Math.pow(k, i)).toFixed(1) + ' ' + s[i];
        };

        body.innerHTML = `<table class="data-table">
            <thead><tr>
                <th>Package</th><th>Sealed</th>
                <th class="hide-mobile">Generations</th>
                <th class="hide-mobile">Size</th>
                <th style="text-align:right;">Custody</th>
            </tr></thead>
            <tbody>${packages.map(p => `<tr class="border-b border-gray-700">
                <td class="p-2 text-sm text-white font-mono">${esc(p.name)}</td>
                <td class="p-2">${p.sealed
                    ? '<span class="px-2 py-0.5 rounded text-xs font-bold bg-green-900 text-green-200">sealed</span>'
                    : '<span class="px-2 py-0.5 rounded text-xs bg-gray-700 text-gray-400">open</span>'}</td>
                <td class="p-2 text-xs text-gray-400 hide-mobile">${esc(p.generations)}</td>
                <td class="p-2 text-xs text-gray-400 font-mono hide-mobile">${size(p.size_bytes)}</td>
                <td class="p-2 text-right" style="white-space:nowrap;">
                    <button onclick="window.RcmPackages.verify('${esc(p.name)}')"
                            class="text-blue-400 hover:text-white text-xs border border-blue-500 px-2 py-1 rounded mr-1">Verify</button>
                    <button onclick="window.RcmPackages.seal('${esc(p.name)}')"
                            class="text-purple-400 hover:text-white text-xs border border-purple-500 px-2 py-1 rounded">Seal</button>
                </td>
            </tr>`).join('')}</tbody>
        </table>`;
    },

    async seal(name) {
        if (!await window.Modal.confirm(`Seal package "${name}"? This writes a new custody manifest generation.`)) return;
        try {
            const res = await window.API.apiFetch('/api/rcm/seal', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await res.json().catch(() => null);
            if (!res.ok) {
                window.Notify?.toast(`Seal failed: ${data?.error || `HTTP ${res.status}`}`, 'error');
                return;
            }
            window.Notify?.toast(`Sealed "${name}" - manifest ${data?.manifest || ''} (generation ${data?.generation ?? '?'})`, 'success', 4000);
            this.refresh();
        } catch (e) {
            if (e.message !== 'unauthorized') window.Notify?.toast(`Seal failed: ${e.message}`, 'error');
        }
    },

    async verify(name) {
        try {
            const res = await window.API.apiFetch('/api/rcm/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name })
            });
            const data = await res.json().catch(() => null);
            if (!res.ok) {
                window.Notify?.toast(`Verify failed: ${data?.error || `HTTP ${res.status}`}`, 'error');
                return;
            }
            const mismatches = data?.mismatches || [];
            if (!mismatches.length) {
                window.Notify?.toast(`Package "${name}" verified - no mismatches.`, 'success', 3000);
            } else {
                const list = mismatches.map(m => '- ' + String(m)).join('\n');
                window.Modal.alert(`Package "${name}" has ${mismatches.length} mismatch(es):\n\n${list}`, 'error');
            }
        } catch (e) {
            if (e.message !== 'unauthorized') window.Notify?.toast(`Verify failed: ${e.message}`, 'error');
        }
    }
};
