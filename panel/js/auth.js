window.Auth = {
    url: localStorage.getItem('c2_url') || 'http://127.0.0.1:8080',
    // API key lives in sessionStorage (cleared on tab close) to limit
    // the blast radius of XSS. localStorage persists indefinitely.
    key: sessionStorage.getItem('c2_key') || '',
    username: sessionStorage.getItem('c2_user') || '',
    role: sessionStorage.getItem('c2_role') || '',

    init() {
        if(this.key) {
            // Validate saved key before trusting it
            this.validateAndEnter();
        } else {
            document.getElementById('login-modal').classList.remove('hidden');
        }
    },

    async validateAndEnter() {
        try {
            const res = await fetch(`${this.url.replace(/\/$/, '')}/api/auth/me`, {
                headers: { 'X-API-KEY': this.key }
            });
            if(!res.ok) {
                this.clearSession();
                document.getElementById('login-modal').classList.remove('hidden');
                return;
            }
            const me = await res.json();
            this.username = me.username;
            this.role = me.role;
            document.getElementById('login-modal').classList.add('hidden');
            this.updateUserBadge();
            if(window.API) window.API.startPolling();
        } catch(e) {
            this.clearSession();
            document.getElementById('login-modal').classList.remove('hidden');
        }
    },

    async login() {
        const url = document.getElementById('api-url').value;
        const username = document.getElementById('login-user').value;
        const password = document.getElementById('login-pass').value;
        if(!username || !password) return alert("Username and password required");

        try {
            const res = await fetch(`${url.replace(/\/$/, '')}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if(!res.ok) {
                const err = await res.json().catch(() => ({}));
                return alert(err.error || 'Login failed');
            }

            const data = await res.json();
            this.url = url;
            this.key = data.api_key;
            this.username = data.username;
            this.role = data.role;

            localStorage.setItem('c2_url', url);
            sessionStorage.setItem('c2_key', data.api_key);
            sessionStorage.setItem('c2_user', data.username);
            sessionStorage.setItem('c2_role', data.role);

            document.getElementById('login-modal').classList.add('hidden');
            this.updateUserBadge();
            if(window.API) window.API.startPolling();
        } catch(e) {
            alert('Connection failed: ' + e.message);
        }
    },

    async loginWithKey() {
        const url = document.getElementById('api-url').value;
        const key = document.getElementById('api-key-direct')?.value;
        if(!key) return alert("API Key required");

        try {
            const res = await fetch(`${url.replace(/\/$/, '')}/api/auth/me`, {
                headers: { 'X-API-KEY': key }
            });
            if(!res.ok) return alert("Invalid API key");
            const me = await res.json();

            this.url = url;
            this.key = key;
            this.username = me.username;
            this.role = me.role;

            localStorage.setItem('c2_url', url);
            sessionStorage.setItem('c2_key', key);
            sessionStorage.setItem('c2_user', me.username);
            sessionStorage.setItem('c2_role', me.role);

            document.getElementById('login-modal').classList.add('hidden');
            this.updateUserBadge();
            if(window.API) window.API.startPolling();
        } catch(e) {
            alert('Connection failed: ' + e.message);
        }
    },

    updateUserBadge() {
        const badge = document.getElementById('user-badge');
        if(badge) {
            const roleColor = this.role === 'admin' ? 'text-red-400' : this.role === 'viewer' ? 'text-gray-400' : 'text-green-400';
            badge.textContent = '';
            const span = document.createElement('span');
            span.className = roleColor;
            const icon = document.createElement('i');
            icon.className = 'fas fa-user';
            span.appendChild(icon);
            span.append(` ${this.username} (${this.role})`);
            badge.appendChild(span);
        }
    },

    clearSession() {
        sessionStorage.removeItem('c2_key');
        sessionStorage.removeItem('c2_user');
        sessionStorage.removeItem('c2_role');
        this.key = '';
        this.username = '';
        this.role = '';
    },

    logout() {
        this.clearSession();
        localStorage.removeItem('c2_url');
        location.reload();
    }
};
