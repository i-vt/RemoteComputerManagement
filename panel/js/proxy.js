window.ProxyManager = {
    activeProxies: [],

    async start(sessionId) {
        const btn = document.getElementById(`proxy-btn-${sessionId}`);
        if(btn) btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/hosts/${sessionId}/proxy`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key }
            });
            const data = await res.json();

            if(!res.ok) throw new Error(data.error || "Failed");

            window.UI.addLog(`Proxy started for Session #${sessionId} on Port ${data.socks_port}`);
            await window.API.refreshHosts(); 
            this.refreshList();
        } catch(e) {
            alert("Proxy Error: " + e.message);
            if(window.API) window.API.refreshHosts();
        }
    },

    async stop(sessionId) {
        if(!confirm(`Stop proxy for Session #${sessionId}?`)) return;
        
        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/hosts/${sessionId}/proxy`, {
                method: 'DELETE',
                headers: { 'X-API-KEY': window.Auth.key }
            });
            
            if(res.ok) {
                window.UI.addLog(`Proxy stopped for Session #${sessionId}`);
                await window.API.refreshHosts();
                this.refreshList();
            } else {
                alert("Failed to stop proxy");
            }
        } catch(e) { console.error(e); }
    },

    async checkIP(sessionId) {
        const span = document.getElementById(`ip-check-${sessionId}`);
        if(span) span.innerHTML = '<i class="fas fa-circle-notch fa-spin text-yellow-500"></i>';

        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/hosts/${sessionId}/proxy/check`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key }
            });
            const data = await res.json();

            if (res.ok) {
                // [FIX] Ensure country code exists, default to 'un' (United Nations/Unknown) if empty
                const countryCode = data.country_code ? data.country_code.toLowerCase() : 'un';
                const flagUrl = `https://flagcdn.com/24x18/${countryCode}.png`;

                const html = `
                    <div class="group relative flex items-center justify-center gap-2 cursor-help">
                        <img src="${flagUrl}" alt="${countryCode}" class="rounded shadow-sm w-5 h-auto">
                        <span class="text-green-400 font-mono text-xs">${data.ip}</span>
                        
                        <div class="absolute bottom-full mb-2 hidden group-hover:block w-56 p-3 bg-gray-900 border border-gray-600 rounded-lg shadow-2xl text-xs text-left z-50">
                            <div class="flex items-center gap-2 font-bold text-white mb-2 border-b border-gray-700 pb-1">
                                <img src="${flagUrl}" class="w-4 h-3"> ${data.country || 'Unknown Country'}
                            </div>
                            <div class="space-y-1">
                                <div class="text-gray-300 truncate"><span class="text-gray-500 w-10 inline-block">City:</span> ${data.city || 'N/A'}</div>
                                <div class="text-gray-300 truncate"><span class="text-gray-500 w-10 inline-block">ISP:</span> ${data.isp || 'N/A'}</div>
                            </div>
                            <div class="absolute top-full left-1/2 -translate-x-1/2 -mt-1 border-4 border-transparent border-t-gray-600"></div>
                        </div>
                    </div>
                `;
                span.innerHTML = html;
                window.UI.addLog(`Verified #${sessionId}: ${data.ip} (${data.country})`);
            } else {
                span.innerHTML = `<span class="text-red-500 text-xs">${data.error || 'Unreachable'}</span>`;
            }
        } catch (e) {
            span.innerHTML = `<span class="text-red-500 text-xs">Error</span>`;
        }
    },

    async checkAll() {
        if (this.activeProxies.length === 0) return alert("No active proxies.");
        await Promise.all(this.activeProxies.map(p => this.checkIP(p.session_id)));
        window.UI.addLog("Batch Proxy Check Completed.");
    },

    async refreshList() {
        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/proxies`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            if(res.ok) {
                this.activeProxies = await res.json();
                this.renderTable();
            }
        } catch(e) {}
    },

    renderTable() {
        const tbody = document.getElementById('proxies-table');
        if(!tbody) return;

        if(this.activeProxies.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-gray-500">No active proxies running.</td></tr>`;
            return;
        }

        tbody.innerHTML = this.activeProxies.map(p => `
            <tr class="hover:bg-gray-700 transition">
                <td class="p-4 text-green-400 font-bold">#${p.session_id}</td>
                <td class="p-4 font-mono text-gray-400">0.0.0.0:${p.tunnel_port}</td>
                <td class="p-4 font-mono text-yellow-400">127.0.0.1:${p.socks_port}</td>
                <td class="p-4 text-center h-full align-middle" id="ip-check-${p.session_id}">
                    <button onclick="window.ProxyManager.checkIP(${p.session_id})" class="text-blue-400 hover:text-white text-xs border border-blue-500/30 px-2 py-1 rounded hover:bg-blue-500/20 transition">
                        Check IP
                    </button>
                </td>
                <td class="p-4 text-right">
                    <button onclick="window.ProxyManager.stop(${p.session_id})" class="text-red-400 hover:text-white hover:bg-red-900 px-3 py-1 rounded text-xs border border-red-500 transition">
                        <i class="fas fa-stop"></i> Stop
                    </button>
                </td>
            </tr>
        `).join('');
    }
};
