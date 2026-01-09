window.API = {
    hosts: [],
    interval: null,

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
            
            if(window.UI) {
                window.UI.updateStats(this.hosts);
                window.UI.updateHostTable(this.hosts);
                window.UI.updateConnectionStatus(true);
            }
        } catch(e) {
            console.error(e);
            if(window.UI) window.UI.updateConnectionStatus(false);
        }
    }
};
