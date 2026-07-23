// panel/js/loot.js - Loot browser
// Browses the server's downloads/ folder (files pulled from agents during ops).

window.LootBrowser = {
    currentPath: '',

    init() {
        this.load('');
    },

    async load(subpath) {
        this.currentPath = subpath;
        this.renderBreadcrumb(subpath);

        const ctr = document.getElementById('loot-container');
        ctr.innerHTML = '<div class="p-10 text-center text-gray-500">' +
            '<i class="fas fa-circle-notch fa-spin text-2xl"></i></div>';

        const url   = window.Auth.url.replace(/\/$/, '');
        const query = subpath ? `?path=${encodeURIComponent(subpath)}` : '';
        try {
            const r = await fetch(`${url}/api/loot${query}`,
                { headers: { 'X-API-KEY': window.Auth.key } });
            const { entries } = await r.json();
            this.render(entries || []);
        } catch (e) {
            ctr.textContent = '';
            const p = document.createElement('p');
            p.className = 'text-red-400 p-6';
            p.textContent = `Error: ${e.message}`;
            ctr.appendChild(p);
        }
    },

    // Rows are built with DOM APIs (never innerHTML interpolation):
    // agent-controlled file names/paths must not reach inline handler
    // strings or HTML, or a crafted filename becomes stored XSS in the
    // operator panel (window.Auth.key theft).
    render(entries) {
        const ctr = document.getElementById('loot-container');
        if (!entries.length) {
            ctr.innerHTML = '<p class="text-gray-500 p-10 text-center italic">No loot yet.</p>';
            return;
        }

        ctr.textContent = '';
        entries.forEach(e => {
            const row = document.createElement('div');
            row.className = 'flex items-center gap-3 px-4 py-2.5 hover:bg-gray-700/60 ' +
                            'border-b border-gray-700/40 last:border-0 cursor-pointer group';
            row.addEventListener('click', () => {
                if (e.is_dir) this.load(e.path); else this.preview(e.path, e.name);
            });

            const icon = document.createElement('div');
            icon.className = 'w-8 text-center text-lg';
            icon.innerHTML = this._icon(e); // static markup, no user data
            row.appendChild(icon);

            const mid = document.createElement('div');
            mid.className = 'flex-1 min-w-0';
            const nm = document.createElement('div');
            nm.className = 'text-sm text-gray-200 truncate';
            nm.textContent = e.name;
            const dt = document.createElement('div');
            dt.className = 'text-xs text-gray-500';
            dt.textContent = e.modified ? new Date(e.modified * 1000).toLocaleString() : '';
            mid.appendChild(nm);
            mid.appendChild(dt);
            row.appendChild(mid);

            const sz = document.createElement('div');
            sz.className = 'text-xs text-gray-500 font-mono w-20 text-right';
            sz.textContent = e.is_dir ? '' : this._size(e.size);
            row.appendChild(sz);

            const btns = document.createElement('div');
            btns.className = 'flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity';
            const mkBtn = (cls, title, iconHtml, fn) => {
                const b = document.createElement('button');
                b.className = cls;
                b.title = title;
                b.innerHTML = iconHtml; // static markup, no user data
                b.addEventListener('click', (ev) => { ev.stopPropagation(); fn(); });
                return b;
            };
            if (!e.is_dir) {
                btns.appendChild(mkBtn(
                    'text-green-400 hover:text-white text-xs px-2 py-1 bg-gray-800 rounded',
                    'Download file', '<i class="fas fa-download"></i>',
                    () => this.download(e.path, e.name)));
            } else {
                btns.appendChild(mkBtn(
                    'text-blue-400 hover:text-white text-xs px-2 py-1 bg-gray-800 rounded',
                    'Download folder as .zip', '<i class="fas fa-file-archive"></i> zip',
                    () => this.downloadFolder(e.path, e.name)));
            }
            btns.appendChild(mkBtn(
                'text-red-400 hover:text-white text-xs px-2 py-1 bg-gray-800 rounded',
                'Delete', '<i class="fas fa-trash"></i>',
                () => this.confirmDelete(e.path, e.name)));
            row.appendChild(btns);

            ctr.appendChild(row);
        });
    },

    renderBreadcrumb(path) {
        const bc = document.getElementById('loot-breadcrumb');
        if (!bc) return;
        // DOM-built breadcrumb: path segments are agent-controlled
        // directory names, so they go through textContent/addEventListener.
        bc.textContent = '';
        const root = document.createElement('button');
        root.className = 'text-green-400 hover:text-white text-xs font-mono';
        root.textContent = 'downloads/';
        root.addEventListener('click', () => this.load(''));
        bc.appendChild(root);
        const parts = path ? path.split('/') : [];
        let cumulative = '';
        parts.forEach(p => {
            cumulative += (cumulative ? '/' : '') + p;
            const cp = cumulative;
            const sep = document.createElement('span');
            sep.className = 'text-gray-600 mx-1';
            sep.textContent = '/';
            const btn = document.createElement('button');
            btn.className = 'text-gray-300 hover:text-white text-xs font-mono';
            btn.textContent = p;
            btn.addEventListener('click', () => this.load(cp));
            bc.appendChild(sep);
            bc.appendChild(btn);
        });
    },

    // Preview in modal
    async preview(path, name) {
        const url   = window.Auth.url.replace(/\/$/, '');
        // ?key= fallback: /api/downloads requires auth; <img> can't send headers
        const src   = `${url}/api/downloads/${path}?key=${encodeURIComponent(window.Auth.key)}`;
        const ext   = name.split('.').pop().toLowerCase();
        const modal = document.getElementById('loot-preview-modal');
        const title = document.getElementById('loot-preview-title');
        const body  = document.getElementById('loot-preview-body');
        if (!modal) return;
        title.textContent = name;
        modal.classList.remove('hidden');

        if (['png','jpg','jpeg','gif','bmp','webp'].includes(ext)) {
            body.textContent = '';
            const img = document.createElement('img');
            img.src = src;
            img.className = 'max-w-full max-h-full object-contain mx-auto';
            img.style.maxHeight = '70vh';
            body.appendChild(img);
        } else if (['txt','log','json','xml','md','sh','bat','ps1','ini','cfg','csv'].includes(ext)) {
            body.innerHTML = '<div class="text-gray-400 p-4">Loading…</div>';
            try {
                const r = await fetch(src, { headers: { 'X-API-KEY': window.Auth.key } });
                const text = await r.text();
                const pre = document.createElement('pre');
                pre.className = 'text-xs text-green-300 font-mono whitespace-pre-wrap ' +
                                'p-4 overflow-auto';
                pre.style.maxHeight = '65vh';
                pre.textContent = text;
                body.textContent = '';
                body.appendChild(pre);
            } catch (e) {
                body.textContent = '';
                const p = document.createElement('p');
                p.className = 'text-red-400 p-4';
                p.textContent = e.message;
                body.appendChild(p);
            }
        } else {
            body.textContent = '';
            const p = document.createElement('p');
            p.className = 'text-gray-400 p-6 text-center';
            p.append(`No preview available for .${ext} files.`, document.createElement('br'));
            const btn = document.createElement('button');
            btn.className = 'mt-3 px-4 py-2 bg-green-700 hover:bg-green-600 text-white rounded text-sm';
            btn.innerHTML = '<i class="fas fa-download mr-1"></i> Download';
            btn.addEventListener('click', () => this.download(path, name));
            p.appendChild(btn);
            body.appendChild(p);
        }
    },

    download(path, name) {
        const url  = window.Auth.url.replace(/\/$/, '');
        const link = document.createElement('a');
        link.href     = `${url}/api/downloads/${path}`;
        link.download = name;
        fetch(link.href, { headers: { 'X-API-KEY': window.Auth.key } })
            .then(r => r.blob())
            .then(blob => {
                const burl = URL.createObjectURL(blob);
                link.href  = burl;
                link.click();
                setTimeout(() => URL.revokeObjectURL(burl), 1000);
            });
    },

    // Download an entire folder as a single zip file.
    // The server zips it on-the-fly via GET /api/loot/zip?path=...
    // Download an entire folder as a single zip file.
    // Direct <a href> with ?key= streams straight to disk - no fetch+blob
    // buffering that would OOM the browser for large loot folders.
    downloadFolder(path, name) {
        const url  = window.Auth.url.replace(/\/+$/, '');
        const href = `${url}/api/loot/zip?path=${encodeURIComponent(path)}&key=${encodeURIComponent(window.Auth.key)}`;
        const link = document.createElement('a');
        link.href     = href;
        link.download = `${name}.zip`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    },

    confirmDelete(path, name) {
        if (!confirm(`Delete "${name}" from loot? This cannot be undone.`)) return;
        this.deletePath(path);
    },

    async deletePath(path) {
        const url = window.Auth.url.replace(/\/$/, '');
        await fetch(`${url}/api/loot?path=${encodeURIComponent(path)}`, {
            method: 'DELETE',
            headers: { 'X-API-KEY': window.Auth.key }
        });
        this.load(this.currentPath);
    },

    closePreview() {
        document.getElementById('loot-preview-modal')?.classList.add('hidden');
    },

    _icon(e) {
        if (e.is_dir) return '<i class="fas fa-folder text-yellow-400"></i>';
        const ext = e.name.split('.').pop().toLowerCase();
        if (['png','jpg','jpeg','gif','bmp','webp'].includes(ext))
            return '<i class="fas fa-image text-purple-400"></i>';
        if (['zip','gz','tar','7z','rar'].includes(ext))
            return '<i class="fas fa-file-archive text-orange-400"></i>';
        if (['txt','log','json','md','xml','csv'].includes(ext))
            return '<i class="fas fa-file-alt text-blue-400"></i>';
        if (['exe','dll','so','elf','bin'].includes(ext))
            return '<i class="fas fa-cog text-red-400"></i>';
        return '<i class="fas fa-file text-gray-400"></i>';
    },

    _size(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024, s = ['B','KB','MB','GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + s[i];
    }
};
