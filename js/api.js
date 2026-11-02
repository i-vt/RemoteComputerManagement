window.API = {
    hosts: [],
    interval: null,

    // Shared fetch wrapper: injects the API key and logs the operator out
    // on 401 so an expired key does not leave every view silently stale.
    // Throws Error('unauthorized') after triggering logout.
    async apiFetch(path, opts = {}) {
        const cleanUrl = window.Auth.url.replace(/\/$/, "");
        const res = await fetch(`${cleanUrl}${path}`, {
            ...opts,
            headers: { 'X-API-KEY': window.Auth.key, ...(opts.headers || {}) },
        });
        if (res.status === 401) {
            window.Auth.logout();
            throw new Error('unauthorized');
        }
        return res;
    },

    async startPolling() {
        this.refreshHosts();
        this.interval = setInterval(() => this.refreshHosts(), 2000); // Faster polling for responsiveness
    },

    async refreshHosts() {
        try {
            if(!window.Auth || !window.Auth.key) return;

            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/hosts`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            
            if(res.status === 401) return window.Auth.logout();
            if(!res.ok) throw new Error("Connection failed");

            this.hosts = await res.json();
            
            // Check for new sessions and notify
            if(window.Notify) window.Notify.checkNewSessions(this.hosts);

            if(window.UI) {
                window.UI.updateStats(this.hosts);
                window.UI.updateHostTable(this.hosts);
            }
            // Single status renderer (app.js) handles desktop pill, mobile
            // dot and user badge without clobbering the styled markup.
            window.updateConnectionStatus?.(true, window.Auth.username);
            // Keep the file browser session dropdown in sync with every poll.
            window.FileManager?.updateSessionList?.(this.hosts);
        } catch(e) {
            console.error(e);
            window.updateConnectionStatus?.(false);
        }
    }
};