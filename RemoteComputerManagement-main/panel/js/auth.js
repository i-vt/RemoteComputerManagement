window.Auth = {
    url: localStorage.getItem('c2_url') || 'http://127.0.0.1:8080',
    // API key lives in sessionStorage (cleared on tab close) to limit
    // the blast radius of XSS. localStorage persists indefinitely.
    key: sessionStorage.getItem('c2_key') || '',
    username: sessionStorage.getItem('c2_user') || '',
    role: sessionStorage.getItem('c2_role') || '',

    init() {
        if(this.key) {
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
            // FIX: fetch modules now that we have a valid key. The initial
            // DOMContentLoaded call in ModuleManager.init() runs before auth
            // is validated, so if the stored key was expired the /api/modules
            // request returned 401 and availableModules stayed empty.
            if(window.ModuleManager) window.ModuleManager.fetchModules();
        } catch(e) {
            this.clearSession();
            document.getElementById('login-modal').classList.remove('hidden');
        }
    },

    _setLoginError(msg) {
        let el = document.getElementById('login-error-msg');
        if (!el) return;
        if (msg) {
            el.textContent = msg;
            el.style.display = '';
        } else {
            el.style.display = 'none';
        }
    },

    async login() {
        this._setLoginError('');
        const url = document.getElementById('api-url').value;
        const username = document.getElementById('login-user').value;
        const password = document.getElementById('login-pass').value;
        if(!username || !password) { this._setLoginError("Username and password are required."); return; }

        const btn = document.querySelector('#login-modal .btn-primary');
        const origHtml = btn ? btn.innerHTML : '';
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Signing in...'; }

        try {
            const res = await fetch(`${url.replace(/\/$/, '')}/api/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if(!res.ok) {
                const err = await res.json().catch(() => ({}));
                this._setLoginError(err.error || 'Login failed. Check credentials.');
                return;
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
            // FIX: same as validateAndEnter — fetch modules with the new key.
            if(window.ModuleManager) window.ModuleManager.fetchModules();
        } catch(e) {
            this._setLoginError('Connection failed: ' + e.message);
        } finally {
            if (btn) { btn.disabled = false; btn.innerHTML = origHtml; }
        }
    },

    async loginWithKey() {
        this._setLoginError('');
        const url = document.getElementById('api-url').value;
        const key = document.getElementById('api-key-direct')?.value;
        if(!key) { this._setLoginError("API Key is required."); return; }

        try {
            const res = await fetch(`${url.replace(/\/$/, '')}/api/auth/me`, {
                headers: { 'X-API-KEY': key }
            });
            if(!res.ok) { this._setLoginError("Invalid API key."); return; }
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
            // FIX: fetch modules with the new key.
            if(window.ModuleManager) window.ModuleManager.fetchModules();
        } catch(e) {
            this._setLoginError('Connection failed: ' + e.message);
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
