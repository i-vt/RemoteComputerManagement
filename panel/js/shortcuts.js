// panel/js/shortcuts.js — Global keyboard shortcuts
window.Shortcuts = {
    init() {
        document.addEventListener('keydown', (e) => {
            // Don't trigger shortcuts when typing in inputs
            if(e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

            // Ctrl+K — Quick command palette (focus terminal if open)
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

            // Escape — Close modals
            if(e.key === 'Escape') {
                document.getElementById('terminal-modal')?.classList.add('hidden');
                document.getElementById('proc-modal')?.classList.add('hidden');
                document.getElementById('screenshot-modal')?.classList.add('hidden');
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

            // ? — Show shortcut help
            if(e.key === '?') {
                window.Notify?.toast(
                    '1-9: Navigate pages | Esc: Close modals | Ctrl+K: Focus terminal | T: Toggle theme | ?: Help',
                    'info', 8000
                );
                return;
            }

            // T — Toggle theme
            if(e.key === 't' || e.key === 'T') {
                window.Theme?.toggle();
                return;
            }

            // R — Refresh current page
            if(e.key === 'r' || e.key === 'R') {
                window.API?.refreshHosts();
                window.Notify?.toast('Refreshed', 'info', 1500);
                return;
            }
        });
    }
};
