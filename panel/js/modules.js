window.ModuleManager = {
    availableModules: [],

    async init() {
        await this.fetchModules();
    },

    async fetchModules() {
        try {
            if(!window.Auth || !window.Auth.key) return;
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/modules`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });

            if (res.ok) {
                const newModules = await res.json();
                // Only re-render if the list actually changed
                if(JSON.stringify(newModules) !== JSON.stringify(this.availableModules)) {
                    this.availableModules = newModules;
                    // FIX: push the updated dropdown into every existing host row
                    // immediately rather than waiting for the next 2-second poll
                    // cycle. Without this, the "No modules" placeholder sticks
                    // until the host table happens to re-render.
                    this._refreshModuleCells();
                }
            }
        } catch (e) {
            console.error("Module Fetch Error:", e);
        }
    },

    // Update the Scripts cell of every row already in the host table.
    _refreshModuleCells() {
        document.querySelectorAll('[id^="host-row-"]').forEach(row => {
            const id = parseInt(row.getAttribute('data-id'), 10);
            if (isNaN(id)) return;
            const modCell = row.querySelector('.host-modules');
            if (!modCell) return;
            // Don't clobber a dropdown that the user currently has open
            const activeEl = document.activeElement;
            if (activeEl && activeEl.id === `mod-select-${id}`) return;
            modCell.innerHTML = this.renderControls(id);
        });
    },

    async run(sessionId) {
        const select = document.getElementById(`mod-select-${sessionId}`);
        const btn = document.getElementById(`mod-btn-${sessionId}`);
        const moduleName = select ? select.value : null;

        if (!moduleName) {
            window.Notify?.toast("Please select a module first", "error");
            return;
        }

        if(btn) {
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
            btn.disabled = true;
            
            try {
                const cleanUrl = window.Auth.url.replace(/\/$/, "");
                window.Notify?.toast(`Executing ${moduleName}...`, "info");
                
                const res = await fetch(`${cleanUrl}/api/hosts/${sessionId}/modules/${moduleName}`, {
                    method: 'POST',
                    headers: { 'X-API-KEY': window.Auth.key }
                });
                
                const data = await res.json();

                if (res.ok) {
                    window.Notify?.toast(`Success: ${moduleName} executed.`, "success");
                    if(window.UI) window.UI.addLog(`[Module] ${moduleName} run on #${sessionId}. Result: ${data.result.substring(0, 50)}...`);
                } else {
                    window.Notify?.toast(`Error: ${data.error}`, "error");
                }
            } catch (e) {
                window.Notify?.toast("Network execution failed", "error");
            } finally {
                btn.innerHTML = originalHtml;
                btn.disabled = false;
            }
        }
    },

    // Generates the dropdown HTML for one host row
    renderControls(sessionId) {
        if (this.availableModules.length === 0) {
            return `<span class="text-xs text-gray-500 italic">No modules</span>`;
        }

        const options = this.availableModules
            .map(m => `<option value="${m}">${m}</option>`)
            .join('');

        return `
            <div class="flex items-center gap-2">
                <div class="relative">
                    <select id="mod-select-${sessionId}" 
                        class="appearance-none bg-gray-900 text-xs text-gray-300 border border-gray-600 rounded px-2 py-1 pr-6 focus:border-green-500 outline-none transition w-32 cursor-pointer">
                        <option value="" disabled selected>Select Script</option>
                        ${options}
                    </select>
                    <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-500">
                        <i class="fas fa-chevron-down text-[10px]"></i>
                    </div>
                </div>
                <button id="mod-btn-${sessionId}" onclick="window.ModuleManager.run(${sessionId})" 
                    class="bg-gray-800 hover:bg-green-900 text-green-500 hover:text-white border border-green-700/50 rounded px-2 py-1 transition shadow-sm" 
                    title="Run">
                    <i class="fas fa-play text-[10px]"></i>
                </button>
            </div>
        `;
    },
};
