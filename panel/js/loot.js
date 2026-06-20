// panel/js/loot.js — Loot browser
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
            ctr.innerHTML = `<p class="text-red-400 p-6">Error: ${e.message}</p>`;
        }
    },

    render(entries) {
        const ctr = document.getElementById('loot-container');
        if (!entries.length) {
            ctr.innerHTML = '<p class="text-gray-500 p-10 text-center italic">No loot yet.</p>';
            return;
        }

        ctr.innerHTML = entries.map(e => {
            const icon  = this._icon(e);
            const size  = e.is_dir ? '' : this._size(e.size);
            const date  = e.modified ? new Date(e.modified * 1000).toLocaleString() : '';
            const click = e.is_dir
                ? `window.LootBrowser.load('${e.path}')`
                : `window.LootBrowser.preview('${e.path}', '${e.name}')`;

            return `
            <div class="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-700/60
                        border-b border-gray-700/40 last:border-0 cursor-pointer group"
                 onclick="${click}">
              <div class="w-8 text-center text-lg">${icon}</div>
              <div class="flex-1 min-w-0">
                <div class="text-sm text-gray-200 truncate">${e.name}</div>
                <div class="text-xs text-gray-500">${date}</div>
              </div>
              <div class="text-xs text-gray-500 font-mono w-20 text-right">${size}</div>
              <div class="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                ${!e.is_dir ? `
                  <button onclick="event.stopPropagation();window.LootBrowser.download('${e.path}','${e.name}')"
                          class="text-green-400 hover:text-white text-xs px-2 py-1
                                 bg-gray-800 rounded" title="Download">
                    <i class="fas fa-download"></i>
                  </button>` : ''}
                <button onclick="event.stopPropagation();window.LootBrowser.confirmDelete('${e.path}','${e.name}')"
                        class="text-red-400 hover:text-white text-xs px-2 py-1
                               bg-gray-800 rounded" title="Delete">
                  <i class="fas fa-trash"></i>
                </button>
              </div>
            </div>`;
        }).join('');
    },

    renderBreadcrumb(path) {
        const bc = document.getElementById('loot-breadcrumb');
        if (!bc) return;
        const parts  = path ? path.split('/') : [];
        let html = `<button onclick="window.LootBrowser.load('')"
                            class="text-green-400 hover:text-white text-xs font-mono">
                      downloads/</button>`;
        let cumulative = '';
        parts.forEach(p => {
            cumulative += (cumulative ? '/' : '') + p;
            const cp = cumulative;
            html += `<span class="text-gray-600 mx-1">/</span>
                     <button onclick="window.LootBrowser.load('${cp}')"
                             class="text-gray-300 hover:text-white text-xs font-mono">${p}</button>`;
        });
        bc.innerHTML = html;
    },

    // Preview in modal
    async preview(path, name) {
        const url   = window.Auth.url.replace(/\/$/, '');
        const src   = `${url}/api/downloads/${path}`;
        const ext   = name.split('.').pop().toLowerCase();
        const modal = document.getElementById('loot-preview-modal');
        const title = document.getElementById('loot-preview-title');
        const body  = document.getElementById('loot-preview-body');
        if (!modal) return;
        title.textContent = name;
        modal.classList.remove('hidden');

        if (['png','jpg','jpeg','gif','bmp','webp'].includes(ext)) {
            body.innerHTML = `<img src="${src}" class="max-w-full max-h-full object-contain mx-auto"
                                   style="max-height:70vh">`;
        } else if (['txt','log','json','xml','md','sh','bat','ps1','ini','cfg','csv'].includes(ext)) {
            body.innerHTML = '<div class="text-gray-400 p-4">Loading…</div>';
            try {
                const r = await fetch(src, { headers: { 'X-API-KEY': window.Auth.key } });
                const text = await r.text();
                const safe = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
                body.innerHTML = `<pre class="text-xs text-green-300 font-mono whitespace-pre-wrap
                                            p-4 overflow-auto" style="max-height:65vh">${safe}</pre>`;
            } catch (e) {
                body.innerHTML = `<p class="text-red-400 p-4">${e.message}</p>`;
            }
        } else {
            body.innerHTML = `<p class="text-gray-400 p-6 text-center">
                No preview available for .${ext} files.<br>
                <button onclick="window.LootBrowser.download('${path}','${name}')"
                        class="mt-3 px-4 py-2 bg-green-700 hover:bg-green-600 text-white rounded text-sm">
                  <i class="fas fa-download mr-1"></i> Download
                </button></p>`;
        }
    },

    download(path, name) {
        const url  = window.Auth.url.replace(/\/$/, '');
        const link = document.createElement('a');
        link.href     = `${url}/api/downloads/${path}`;
        link.download = name;
        // Fetch with auth header and create object URL (API key required)
        fetch(link.href, { headers: { 'X-API-KEY': window.Auth.key } })
            .then(r => r.blob())
            .then(blob => {
                const burl = URL.createObjectURL(blob);
                link.href  = burl;
                link.click();
                setTimeout(() => URL.revokeObjectURL(burl), 1000);
            });
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
