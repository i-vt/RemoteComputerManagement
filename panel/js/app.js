// panel/js/app.js — Router, responsive helpers, mobile session cards

window.Router = {
    current: 'stats',

    navigate(pageId, event) {
        // Hide all pages
        document.querySelectorAll('[id^="page-"]').forEach(el => {
            el.classList.add('hidden');
            el.style.display = 'none';
        });

        // Show target page
        const target = document.getElementById('page-' + pageId);
        if (target) {
            target.classList.remove('hidden');
            // Restore flex-display for pages that need it
            if (['page-network', 'page-files'].includes('page-' + pageId)) {
                target.style.display = 'flex';
            } else {
                target.style.display = '';
            }
        }

        // Sync desktop sidebar active state
        document.querySelectorAll('#sidebar .nav-item').forEach(btn => {
            const isActive = btn.getAttribute('data-page') === pageId;
            btn.classList.toggle('active', isActive);
        });

        // Sync mobile bottom nav active state
        document.querySelectorAll('#mobile-nav .mobile-nav-btn').forEach(btn => {
            const isActive = btn.getAttribute('data-page') === pageId;
            btn.classList.toggle('active', isActive);
        });

        // Sync mobile "more" sheet active state
        document.querySelectorAll('#mobile-more-sheet .more-item').forEach(btn => {
            const isActive = btn.getAttribute('data-page') === pageId;
            btn.classList.toggle('active', isActive);
        });

        // If the page is in the "more" sheet, also activate the "more" nav button
        const morePages = ['network','files','proxies','tasks','history','jobs','audit'];
        const moreBtn = document.getElementById('mobile-more-btn');
        if (moreBtn) {
            moreBtn.classList.toggle('active', morePages.includes(pageId));
        }

        this.current = pageId;

        // Page-specific refresh
        const refreshMap = {
            'proxies':   () => window.ProxyManager?.refreshList(),
            'control':   () => { window.API?.refreshHosts(); window.Router.syncMobileCards(); },
            'tasks':     () => window.TaskManager?.renderTable(),
            'history':   () => window.HistoryManager?.refresh(),
            'network':   () => window.NetworkManager?.init(),
            'listeners': () => { window.ListenerManager?.refresh(); window.ReconConfig?.refresh(); },
            'jobs':      () => window.JobView?.refresh(),
            'audit':     () => window.AuditView?.refresh(),
            'builder':   () => window.BuilderManager?.refreshJobList(),
            'files': () => {
                if (window.API && window.FileManager) {
                    window.API.refreshHosts().then?.(() => {
                        window.FileManager.updateSessionList?.(window.API.hosts);
                    });
                }
            },
        };
        if (refreshMap[pageId]) refreshMap[pageId]();
    },

    // Sync mobile session cards from the hosts table data
    syncMobileCards() {
        const cardsContainer = document.getElementById('hosts-cards-mobile');
        if (!cardsContainer) return;

        const isMobile = window.innerWidth < 768;
        cardsContainer.style.display = isMobile ? 'flex' : 'none';

        const tableCard = document.getElementById('hosts-table-card');
        if (tableCard) tableCard.style.display = isMobile ? 'none' : '';

        if (!isMobile) return;

        // Build cards from the hosts table rows
        const rows = document.querySelectorAll('#hosts-table tr');
        cardsContainer.innerHTML = '';

        if (!rows.length) {
            cardsContainer.innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:40px 16px;font-size:13px;">No active sessions</div>';
            return;
        }

        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length < 7) return;

            const id       = cells[0]?.textContent?.trim() || '';
            const hostname = cells[1]?.textContent?.trim() || '';
            const ip       = cells[2]?.textContent?.trim() || '';
            const os       = cells[3]?.textContent?.trim()?.toLowerCase() || '';
            const actionCell = cells[6];

            const isWindows = os.includes('win');
            const iconClass = isWindows ? 'windows' : 'linux';
            const osIcon    = isWindows ? 'fab fa-windows' : 'fab fa-linux';

            const card = document.createElement('div');
            card.className = 'session-card';
            card.innerHTML = `
                <div class="session-os-icon ${iconClass}">
                    <i class="${osIcon}"></i>
                </div>
                <div class="session-info">
                    <div class="session-hostname">${escHtml(hostname)}</div>
                    <div class="session-meta">${escHtml(ip)} · #${escHtml(id)}</div>
                </div>
                <i class="fas fa-chevron-right session-chevron"></i>
            `;

            // Tap opens terminal (same as clicking the terminal button in the table)
            const termBtn = actionCell?.querySelector('[onclick*="Terminal"]') || actionCell?.querySelector('button');
            if (termBtn) {
                card.onclick = () => termBtn.click();
            }

            cardsContainer.appendChild(card);
        });
    }
};

// Update connection status badge in both desktop + mobile
window.updateConnectionStatus = function(connected, username) {
    const dot  = document.querySelector('#connection-status .status-dot');
    const text = document.querySelector('#connection-status span');
    const mdot = document.querySelector('#connection-status-mobile .status-dot');

    if (dot) {
        dot.className = 'status-dot ' + (connected ? 'connected' : 'disconnected');
    }
    if (text) {
        text.textContent = connected ? 'Connected' : 'Disconnected';
    }
    if (mdot) {
        mdot.className = 'status-dot ' + (connected ? 'connected' : 'disconnected');
    }

    const desktopBadge = document.querySelector('#user-badge span');
    const mobileBadge  = document.querySelector('#user-badge-mobile span');
    if (username) {
        if (desktopBadge) desktopBadge.textContent = username;
        if (mobileBadge)  mobileBadge.textContent  = username;
    }

    // Apply connected/disconnected class to the connection-status div
    const statusEl = document.getElementById('connection-status');
    if (statusEl) {
        statusEl.className = 'status-row ' + (connected ? 'connected' : 'disconnected');
    }
};

// Re-sync mobile cards on resize
window.addEventListener('resize', () => {
    if (window.Router.current === 'control') {
        window.Router.syncMobileCards();
    }
    // Collapse more sheet if resized to desktop
    if (window.innerWidth >= 768) {
        window.MobileMore?.close();
    }
});

// MutationObserver: auto-sync mobile cards when hosts table changes
const hostsObserver = new MutationObserver(() => {
    if (window.Router.current === 'control' && window.innerWidth < 768) {
        window.Router.syncMobileCards();
    }
});

document.addEventListener('DOMContentLoaded', () => {
    const hostsTable = document.getElementById('hosts-table');
    if (hostsTable) hostsObserver.observe(hostsTable, { childList: true, subtree: true });

    // Wire terminal input
    const termInput = document.getElementById('term-input');
    if (termInput) {
        termInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                window.Terminal.sendCommand(e.target.value);
                e.target.value = '';
            }
        });
    }

    // Init all managers
    if (window.UI)             window.UI.initChart();
    if (window.TaskManager)    window.TaskManager.init();
    if (window.ModuleManager)  window.ModuleManager.init();
    if (window.FileManager)    window.FileManager.init();
    if (window.BuilderManager) window.BuilderManager.init();
    if (window.Theme)          window.Theme.init();
    if (window.Shortcuts)      window.Shortcuts.init();

    // Mobile more sheet animation
    const sheet = document.getElementById('mobile-more-sheet');
    if (sheet) {
        sheet.addEventListener('transitionend', () => {
            if (!sheet.classList.contains('open')) {
                sheet.style.visibility = 'hidden';
            }
        });
        // Override open/close to handle visibility
        const origOpen  = window.MobileMore.open;
        const origClose = window.MobileMore.close;
        window.MobileMore.open = function() {
            sheet.style.visibility = 'visible';
            origOpen.call(this);
        };
        window.MobileMore.close = function() {
            origClose.call(this);
            // visibility reset happens on transitionend
        };
    }

    // Delay Auth init so all scripts are settled
    setTimeout(() => {
        if (window.Auth) window.Auth.init();
    }, 50);
});
