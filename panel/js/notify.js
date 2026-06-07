// panel/js/notify.js — Toast notification system + session change detection
window.Notify = {
    _prevSessionCount: -1,
    _toastId: 0,

    // Show a toast notification
    toast(message, type = 'info', duration = 5000) {
        const container = document.getElementById('toast-container');
        if(!container) return;

        // Escape HTML in message to prevent XSS from agent-controlled data
        const safeMsg = String(message).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

        const id = ++this._toastId;
        const colors = {
            info: 'border-blue-500 bg-blue-900/80 text-blue-200',
            success: 'border-green-500 bg-green-900/80 text-green-200',
            warning: 'border-yellow-500 bg-yellow-900/80 text-yellow-200',
            error: 'border-red-500 bg-red-900/80 text-red-200',
        }[type] || 'border-gray-500 bg-gray-800 text-gray-200';

        const icons = { info: 'info-circle', success: 'check-circle', warning: 'exclamation-triangle', error: 'times-circle' };

        const toast = document.createElement('div');
        toast.id = `toast-${id}`;
        toast.className = `flex items-center gap-3 px-4 py-3 rounded-lg border ${colors} shadow-lg transform translate-x-full transition-transform duration-300 text-sm`;
        toast.innerHTML = `<i class="fas fa-${icons[type] || 'info-circle'}"></i><span class="flex-1">${safeMsg}</span>
            <button onclick="this.parentElement.remove()" class="opacity-50 hover:opacity-100"><i class="fas fa-times"></i></button>`;

        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.remove('translate-x-full'));

        if(duration > 0) {
            setTimeout(() => {
                toast.classList.add('translate-x-full');
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }
    },

    // Check for new sessions (called from API polling)
    checkNewSessions(hosts) {
        if(this._prevSessionCount === -1) {
            this._prevSessionCount = hosts.length;
            return;
        }

        if(hosts.length > this._prevSessionCount) {
            const newCount = hosts.length - this._prevSessionCount;
            const latest = hosts[hosts.length - 1];
            this.toast(
                `New session: ${latest?.hostname || 'unknown'} (${latest?.ip || '?'}) — ${latest?.os || '?'}`,
                'success', 8000
            );

            // Play a subtle notification sound
            try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.connect(gain); gain.connect(ctx.destination);
                osc.frequency.value = 800; gain.gain.value = 0.1;
                osc.start(); osc.stop(ctx.currentTime + 0.15);
            } catch(e) {}
        }
        this._prevSessionCount = hosts.length;
    }
};

// ── App Modal (replaces browser alert/confirm) ─────────────────────────────
window.Modal = {
    _resolveFunc: null,

    _resolve(val) {
        const overlay = document.getElementById('app-modal');
        if (overlay) overlay.classList.add('hidden');
        if (this._resolveFunc) {
            this._resolveFunc(val);
            this._resolveFunc = null;
        }
    },

    _backdropClick(e) {
        if (e.target === document.getElementById('app-modal')) {
            this._resolve(false);
        }
    },

    _show(msg, type, isConfirm) {
        const cfg = {
            info:    { icon: 'fas fa-info-circle',           cls: 'text-blue-400',   ok: 'btn btn-ghost' },
            success: { icon: 'fas fa-check-circle',          cls: 'text-green-400',  ok: 'btn btn-primary' },
            warning: { icon: 'fas fa-exclamation-triangle',  cls: 'text-yellow-400', ok: 'btn btn-ghost' },
            error:   { icon: 'fas fa-times-circle',          cls: 'text-red-400',    ok: 'btn btn-danger' },
        }[type] || { icon: 'fas fa-info-circle', cls: 'text-blue-400', ok: 'btn btn-ghost' };

        const safeMsg = String(msg).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const title = type.charAt(0).toUpperCase() + type.slice(1);

        document.getElementById('app-modal-icon').className = cfg.icon + ' ' + cfg.cls;
        document.getElementById('app-modal-title-text').textContent = title;
        document.getElementById('app-modal-body').innerHTML = safeMsg;

        const cancelBtn = document.getElementById('app-modal-cancel');
        const okBtn     = document.getElementById('app-modal-ok');
        if (cancelBtn) cancelBtn.style.display = isConfirm ? '' : 'none';
        if (okBtn)     okBtn.className = cfg.ok;

        const overlay = document.getElementById('app-modal');
        if (overlay) overlay.classList.remove('hidden');
        setTimeout(() => { if (okBtn) okBtn.focus(); }, 60);
    },

    // Non-blocking alert — returns Promise resolved with true when dismissed
    alert(msg, type = 'info') {
        return new Promise(resolve => {
            this._resolveFunc = resolve;
            this._show(msg, type, false);
        });
    },

    // Confirmation dialog — returns Promise<boolean>
    confirm(msg, type = 'warning') {
        return new Promise(resolve => {
            this._resolveFunc = resolve;
            this._show(msg, type, true);
        });
    }
};
