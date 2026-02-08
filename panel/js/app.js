// panel/js/app.js
window.Router = {
    navigate(pageId) {
        // Hide all pages
        document.querySelectorAll('[id^="page-"]').forEach(el => el.classList.add('hidden'));
        
        // Show target page
        const target = document.getElementById(`page-${pageId}`);
        if(target) target.classList.remove('hidden');
        
        // Update Sidebar active state
        document.querySelectorAll('.nav-btn').forEach(el => {
            el.classList.remove('bg-gray-700', 'border-l-4', 'border-green-500');
        });
        
        if (event && event.currentTarget) {
            event.currentTarget.classList.add('bg-gray-700', 'border-l-4', 'border-green-500');
        }

        // Auto-refresh logic based on page
        if(pageId === 'proxies' && window.ProxyManager) {
            window.ProxyManager.refreshList();
        }
        if(pageId === 'control' && window.API) {
            window.API.refreshHosts();
        }
        if(pageId === 'tasks' && window.TaskManager) {
            window.TaskManager.renderTable();
        }
        if(pageId === 'history' && window.HistoryManager) {
            window.HistoryManager.refresh();
        }
        // Network Graph Init
        if(pageId === 'network' && window.NetworkManager) {
            window.NetworkManager.init();
        }
        // [NEW] Files Page Init
        if(pageId === 'files' && window.FileManager && window.API) {
            window.API.refreshHosts().then(() => {
                window.FileManager.updateSessionList(window.API.hosts);
            });
        }
    }
};

// Main Entry Point
document.addEventListener('DOMContentLoaded', () => {
    if(window.UI) window.UI.initChart();
    if(window.TaskManager) window.TaskManager.init();
    if(window.ModuleManager) window.ModuleManager.init();
    // [NEW] Init File Manager listeners
    if(window.FileManager) window.FileManager.init();

    const termInput = document.getElementById('term-input');
    if (termInput) {
        termInput.addEventListener('keydown', (e) => {
            if(e.key === 'Enter') {
                window.Terminal.sendCommand(e.target.value);
                e.target.value = '';
            }
        });
    }

    setTimeout(() => {
        if(window.Auth) window.Auth.init();
    }, 50);
});
