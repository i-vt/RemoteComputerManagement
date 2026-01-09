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
                // Deep compare to avoid unnecessary re-renders
                if(JSON.stringify(newModules) !== JSON.stringify(this.availableModules)) {
                    this.availableModules = newModules;
                }
            }
        } catch (e) {
            console.error("Module Fetch Error:", e);
        }
    },

    async run(sessionId) {
        const select = document.getElementById(`mod-select-${sessionId}`);
        const btn = document.getElementById(`mod-btn-${sessionId}`);
        const moduleName = select ? select.value : null;

        if (!moduleName) {
            this.showToast("Please select a module first", "error");
            return;
        }

        if(btn) {
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
            btn.disabled = true;
            
            try {
                const cleanUrl = window.Auth.url.replace(/\/$/, "");
                this.showToast(`Executing ${moduleName}...`, "info");
                
                const res = await fetch(`${cleanUrl}/api/hosts/${sessionId}/modules/${moduleName}`, {
                    method: 'POST',
                    headers: { 'X-API-KEY': window.Auth.key }
                });
                
                const data = await res.json();

                if (res.ok) {
                    this.showToast(`Success: ${moduleName} executed.`, "success");
                    if(window.UI) window.UI.addLog(`[Module] ${moduleName} run on #${sessionId}. Result: ${data.result.substring(0, 50)}...`);
                } else {
                    this.showToast(`Error: ${data.error}`, "error");
                }
            } catch (e) {
                this.showToast("Network execution failed", "error");
            } finally {
                btn.innerHTML = originalHtml;
                btn.disabled = false;
            }
        }
    },

    // Generates the dropdown HTML
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

    showToast(msg, type = "info") {
        const colors = { "success": "bg-green-600", "error": "bg-red-600", "info": "bg-blue-600" };
        const icons = { "success": "fa-check", "error": "fa-times", "info": "fa-info" };

        const toast = document.createElement("div");
        toast.className = `fixed bottom-5 right-5 ${colors[type]} text-white px-4 py-3 rounded shadow-lg flex items-center gap-3 transform translate-y-10 opacity-0 transition-all duration-300 z-50 text-sm font-bold`;
        toast.innerHTML = `<i class="fas ${icons[type]}"></i> <span>${msg}</span>`;

        document.body.appendChild(toast);
        requestAnimationFrame(() => toast.classList.remove("translate-y-10", "opacity-0"));
        setTimeout(() => {
            toast.classList.add("translate-y-10", "opacity-0");
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
};

// Auto-init on load
document.addEventListener('DOMContentLoaded', () => {
    if(window.ModuleManager) window.ModuleManager.init();
});
