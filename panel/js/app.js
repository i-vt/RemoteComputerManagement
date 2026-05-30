// panel/js/app.js
window.Router = {
    navigate(pageId) {
        document.querySelectorAll('[id^="page-"]').forEach(el => el.classList.add('hidden'));
        const target = document.getElementById(`page-${pageId}`);
        if (target) target.classList.remove('hidden');

        document.querySelectorAll('.nav-btn').forEach(el => {
            el.classList.remove('bg-gray-700', 'border-l-4', 'border-green-500');
        });
        if (event && event.currentTarget) {
            event.currentTarget.classList.add('bg-gray-700', 'border-l-4', 'border-green-500');
        }

        const refreshMap = {
            'proxies':   () => window.ProxyManager?.refreshList(),
            'control':   () => window.API?.refreshHosts(),
            'tasks':     () => window.TaskManager?.renderTable(),
            'history':   () => window.HistoryManager?.refresh(),
            'network':   () => window.NetworkManager?.init(),
            'listeners': () => { window.ListenerManager?.refresh(); window.ReconConfig?.refresh(); },
            'jobs':      () => window.JobView?.refresh(),
            'audit':     () => window.AuditView?.refresh(),
            'builder':   () => window.BuilderManager?.refreshJobList(),
            'files': () => {
                if (window.API && window.FileManager) {
                    window.API.refreshHosts().then(() => {
                        window.FileManager.updateSessionList(window.API.hosts);
                    });
                }
            },
        };
        if (refreshMap[pageId]) refreshMap[pageId]();
    }
};

document.addEventListener('DOMContentLoaded', () => {
    if (window.UI) window.UI.initChart();
    if (window.TaskManager) window.TaskManager.init();
    if (window.ModuleManager) window.ModuleManager.init();
    if (window.FileManager) window.FileManager.init();
    if (window.BuilderManager) window.BuilderManager.init();
    if (window.Theme) window.Theme.init();
    if (window.Shortcuts) window.Shortcuts.init();

    const termInput = document.getElementById('term-input');
    if (termInput) {
        termInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                window.Terminal.sendCommand(e.target.value);
                e.target.value = '';
            }
        });
    }

    setTimeout(() => {
        if (window.Auth) window.Auth.init();
    }, 50);
});
