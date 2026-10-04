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
            // Fetch modules now that we have a valid key. The initial
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
            // Same as validateAndEnter - fetch modules with the new key.
            if(window.ModuleManager) window.ModuleManager.fetchModules();
        } catch(e) {
            this._setLoginError('Connection failed: ' + e.message);
        } finally {
            if (btn) { btn.disabled = false; btn.innerHTML = origHtml; }
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

    async logout() {
        // Best-effort server-side revocation of THIS session's key; other
        // sessions of the same operator keep working. Local state is
        // cleared regardless of the outcome.
        try {
            await fetch(`${this.url.replace(/\/$/, '')}/api/auth/logout`, {
                method: 'POST',
                headers: { 'X-API-KEY': this.key }
            });
        } catch(_) { /* server unreachable: clear locally anyway */ }
        this.clearSession();
        localStorage.removeItem('c2_url');
        location.reload();
    },

    // ── Password modal (self-service change + admin reset) ───────────────
    _pwMode: 'self',   // 'self' change | 'reset' by admin
    _pwTarget: '',     // target username when _pwMode === 'reset'

    showChangePassword() {
        this._pwMode = 'self';
        this._pwTarget = '';
        document.getElementById('pw-modal-title').textContent = 'Change Password';
        document.getElementById('pw-current-group').style.display = '';
        this._openPwModal();
    },

    showResetPassword(username) {
        this._pwMode = 'reset';
        this._pwTarget = username;
        document.getElementById('pw-modal-title').textContent = `Reset password: ${username}`;
        document.getElementById('pw-current-group').style.display = 'none';
        this._openPwModal();
    },

    _openPwModal() {
        ['pw-current', 'pw-new', 'pw-confirm'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        this._pwError('');
        document.getElementById('pw-modal').classList.remove('hidden');
        setTimeout(() => {
            document.getElementById(this._pwMode === 'self' ? 'pw-current' : 'pw-new')?.focus();
        }, 60);
    },

    closePasswordModal() {
        document.getElementById('pw-modal')?.classList.add('hidden');
    },

    _pwBackdrop(e) {
        if (e.target === document.getElementById('pw-modal')) this.closePasswordModal();
    },

    _pwError(msg) {
        const el = document.getElementById('pw-error');
        if (!el) return;
        if (msg) {
            el.textContent = msg;
            el.style.display = '';
        } else {
            el.style.display = 'none';
        }
    },

    async submitPasswordModal() {
        this._pwError('');
        const newPw     = document.getElementById('pw-new').value;
        const confirmPw = document.getElementById('pw-confirm').value;
        if (newPw.length < 8)   { this._pwError('Password must be at least 8 characters.'); return; }
        if (newPw !== confirmPw) { this._pwError('New passwords do not match.'); return; }

        try {
            let res;
            if (this._pwMode === 'self') {
                const currentPw = document.getElementById('pw-current').value;
                if (!currentPw) { this._pwError('Current password is required.'); return; }
                res = await window.API.apiFetch('/api/auth/change_password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_password: currentPw, new_password: newPw })
                });
            } else {
                res = await window.API.apiFetch(
                    `/api/operators/${encodeURIComponent(this._pwTarget)}/password`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: newPw })
                });
            }
            const data = await res.json().catch(() => ({}));
            if (!res.ok) { this._pwError(data.error || `HTTP ${res.status}`); return; }
            this.closePasswordModal();
            if (window.UI) {
                window.UI.addLog(this._pwMode === 'self'
                    ? 'Password updated.'
                    : `Password reset for ${this._pwTarget}.`);
            }
        } catch (e) {
            // apiFetch already triggered logout on 401; nothing to add.
            if (e.message !== 'unauthorized') this._pwError('Connection failed: ' + e.message);
        }
    }
};