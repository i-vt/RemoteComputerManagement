// panel/js/shortcuts.js - Global keyboard shortcuts
window.Shortcuts = {
    init() {
        document.addEventListener('keydown', (e) => {
            // Don't trigger shortcuts when typing in inputs
            if(e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

            // Ctrl+K - Quick command palette (focus terminal if open)
            if(e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                const termInput = document.getElementById('term-input');
                const termModal = document.getElementById('terminal-modal');
                if(termModal && !termModal.classList.contains('hidden') && termInput) {
                    termInput.focus();
                } else {
                    window.Notify?.toast('Open a terminal first (click Shell on a host)', 'info', 3000);
                }
                return;
            }

            // Escape - Close any open modal
            if(e.key === 'Escape') {
                ['terminal-modal','proc-modal','loot-preview-modal','fm-modal','fm-preview-modal']
                    .forEach(id => document.getElementById(id)?.classList.add('hidden'));
                // ScreenshotView.close() also releases frame object URLs
                window.ScreenshotView?.close();
                // Dynamically-created modals are removed outright
                document.getElementById('notes-modal')?.remove();
                document.getElementById('ioc-add-modal')?.remove();
                document.getElementById('fm-context-menu')?.classList.add('hidden');
                // Shared app modal resolves as "cancelled"
                const appModal = document.getElementById('app-modal');
                if (appModal && !appModal.classList.contains('hidden')) {
                    window.Modal?._resolve(false);
                }
                window.MobileMore?.close();
                return;
            }

            // Number keys 1-9 for page navigation (no modifier)
            if(!e.ctrlKey && !e.altKey && !e.metaKey) {
                const pages = ['stats', 'network', 'control', 'files', 'proxies', 'tasks', 'history', 'listeners', 'jobs'];
                const idx = parseInt(e.key) - 1;
                if(idx >= 0 && idx < pages.length) {
                    window.Router.navigate(pages[idx]);
                    return;
                }
            }

            // ? - Show shortcut help
            if(e.key === '?') {
                window.Notify?.toast(
                    '1-9: Stats, Network, Sessions, Files, Proxies, Broadcast, History, Listeners, Jobs | ' +
                    'Esc: Close modals | Ctrl+K: Focus terminal | T: Toggle theme | R: Refresh | ?: Help',
                    'info', 10000
                );
                return;
            }

            // T - Toggle theme
            if(e.key === 't' || e.key === 'T') {
                window.Theme?.toggle();
                return;
            }

            // R - Refresh current page
            if(e.key === 'r' || e.key === 'R') {
                window.API?.refreshHosts();
                window.Notify?.toast('Refreshed', 'info', 1500);
                return;
            }
        });
    }
};