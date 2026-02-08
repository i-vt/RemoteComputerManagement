// panel/js/files.js
window.FileManager = {
    currentPath: '/',
    currentSessionId: null,
    uploadInput: null,
    cachedFiles: [], 
    sortCol: 'name',
    sortAsc: true,
    lastSelectedindex: -1, // For shift-click selection (future)

    init() {
        const select = document.getElementById('file-session-select');
        if(!select) return;

        // 1. Session Select Listener
        select.addEventListener('change', (e) => {
            this.currentSessionId = e.target.value;
            this.currentPath = '/'; 
            this.cachedFiles = [];
            if(this.currentSessionId) {
                this.browse('/');
            } else {
                this.renderError("Select a session");
            }
        });

        // 2. Inject UI Controls
        this.injectControls();
        this.injectHeader(); 
        this.injectBreadcrumbContainer();
        this.injectUnifiedModal();
        this.injectPreviewModal();
        this.injectContextMenu(); 
        this.injectShortcutHint(); // [NEW] Shortcut Hints Footer

        // 3. Bind Advanced Interactions
        this.bindGlobalEvents();
        this.bindDragDrop();
        this.bindHotkeys();
    },

    // --- DOM INJECTION ---

    injectControls() {
        const headerActions = document.querySelector('#page-files .flex.items-center.gap-4');
        if(headerActions && !document.getElementById('btn-upload')) {
            // Delete Button
            const delBtn = document.createElement('button');
            delBtn.className = "bg-red-900/80 hover:bg-red-800 text-red-200 border border-red-700 px-3 py-2 rounded text-sm font-bold shadow-lg transition mr-2";
            delBtn.innerHTML = '<i class="fas fa-trash"></i>';
            delBtn.title = "Delete Selected (Del)";
            delBtn.onclick = () => this.deleteSelected();
            headerActions.insertBefore(delBtn, headerActions.firstChild);

            // Create Directory Button
            const mkdirBtn = document.createElement('button');
            mkdirBtn.className = "bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded text-sm font-bold shadow-lg transition mr-2";
            mkdirBtn.innerHTML = '<i class="fas fa-folder-plus"></i>';
            mkdirBtn.title = "New Folder";
            mkdirBtn.onclick = () => this.createDirectory();
            headerActions.insertBefore(mkdirBtn, headerActions.firstChild);

            // Download Selected
            const dlBtn = document.createElement('button');
            dlBtn.className = "bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded text-sm font-bold shadow-lg transition mr-2";
            dlBtn.innerHTML = '<i class="fas fa-download"></i>';
            dlBtn.title = "Download Selected";
            dlBtn.onclick = () => this.downloadSelected();
            headerActions.insertBefore(dlBtn, headerActions.firstChild);

            // Upload
            const upBtn = document.createElement('button');
            upBtn.id = 'btn-upload';
            upBtn.className = "bg-purple-600 hover:bg-purple-500 text-white px-3 py-2 rounded text-sm font-bold shadow-lg transition mr-2";
            upBtn.innerHTML = '<i class="fas fa-upload"></i> Upload';
            upBtn.onclick = () => this.triggerUpload();
            headerActions.insertBefore(upBtn, headerActions.firstChild);

            // Hidden Input
            this.uploadInput = document.createElement('input');
            this.uploadInput.type = 'file';
            this.uploadInput.multiple = true; // Allow multiple
            this.uploadInput.style.display = 'none';
            this.uploadInput.onchange = (e) => this.handleFileSelect(e.target.files);
            document.body.appendChild(this.uploadInput);
        }
    },

    injectHeader() {
        const container = document.getElementById('file-list-container');
        if(!container) return;
        const header = container.previousElementSibling;
        
        if(header && header.classList.contains('bg-gray-750')) {
            header.innerHTML = `
                <div class="w-8 flex justify-center items-center">
                    <input type="checkbox" id="file-select-all" class="w-4 h-4 rounded bg-gray-900 border-gray-600 text-green-500 focus:ring-0 cursor-pointer" onclick="window.FileManager.toggleSelectAll(this)">
                </div>
                <div class="w-8"></div>
                <div class="flex-1 cursor-pointer hover:text-white select-none" onclick="window.FileManager.sort('name')">
                    Name <i class="fas fa-sort text-gray-600 ml-1"></i>
                </div>
                <div class="w-24 text-right cursor-pointer hover:text-white select-none" onclick="window.FileManager.sort('size')">
                    Size <i class="fas fa-sort text-gray-600 ml-1"></i>
                </div>
                <div class="w-20 text-center cursor-pointer hover:text-white select-none" onclick="window.FileManager.sort('perms')">
                    Perms <i class="fas fa-sort text-gray-600 ml-1"></i>
                </div>
                <div class="w-32 text-right cursor-pointer hover:text-white select-none mr-2" onclick="window.FileManager.sort('date')">
                    Modified <i class="fas fa-sort text-gray-600 ml-1"></i>
                </div>
            `;
        }
    },

    injectBreadcrumbContainer() {
        const pathInput = document.getElementById('file-path-input');
        if(!pathInput) return;
        
        const parent = pathInput.parentElement;
        pathInput.classList.add('hidden');
        
        const breadcrumbDiv = document.createElement('div');
        breadcrumbDiv.id = 'file-breadcrumbs';
        breadcrumbDiv.className = "flex-1 flex items-center gap-1 overflow-x-auto whitespace-nowrap scrollbar-hide px-2 cursor-text";
        
        const editBtn = document.createElement('button');
        editBtn.className = "text-gray-500 hover:text-white px-2";
        editBtn.innerHTML = '<i class="fas fa-pen text-xs"></i>';
        editBtn.onclick = () => {
            breadcrumbDiv.classList.add('hidden');
            pathInput.classList.remove('hidden');
            pathInput.focus();
        };

        // Breadcrumb div click also triggers edit mode if clicked on empty space
        breadcrumbDiv.onclick = (e) => {
            if(e.target === breadcrumbDiv) editBtn.click();
        };

        parent.insertBefore(breadcrumbDiv, pathInput);
        parent.insertBefore(editBtn, pathInput.nextSibling); 

        pathInput.addEventListener('blur', () => {
            setTimeout(() => {
                if(!document.activeElement.isSameNode(pathInput)) {
                    pathInput.classList.add('hidden');
                    breadcrumbDiv.classList.remove('hidden');
                }
            }, 200);
        });
    },

    injectUnifiedModal() {
        if(document.getElementById('fm-modal')) return;
        const modalHtml = `
            <div id="fm-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
                <div class="bg-gray-800 border border-gray-600 rounded-xl shadow-2xl w-96 transform transition-all scale-100 p-6 flex flex-col">
                    <h3 id="fm-modal-title" class="text-xl font-bold text-white mb-2"></h3>
                    <div id="fm-modal-body" class="mb-6 text-gray-300 text-sm"></div>
                    <div class="flex justify-end gap-3">
                        <button id="fm-modal-cancel" class="px-4 py-2 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition text-sm">Cancel</button>
                        <button id="fm-modal-confirm" class="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold shadow-lg transition text-sm">Confirm</button>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    },

    injectPreviewModal() {
        if(document.getElementById('fm-preview-modal')) return;
        const html = `
            <div id="fm-preview-modal" class="hidden fixed inset-0 z-[60] flex items-center justify-center bg-black/90 backdrop-blur-md p-8">
                <div class="bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-4xl h-full max-h-[85vh] flex flex-col">
                    <div class="flex justify-between items-center p-3 border-b border-gray-800 bg-gray-800 rounded-t-lg">
                        <span id="fm-preview-title" class="text-white font-mono text-sm font-bold"></span>
                        <button onclick="document.getElementById('fm-preview-modal').classList.add('hidden')" class="text-red-400 hover:text-white px-2"><i class="fas fa-times"></i></button>
                    </div>
                    <div id="fm-preview-content" class="flex-1 overflow-auto p-4 font-mono text-xs text-green-400 bg-[#0d1117]"></div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', html);
    },

    injectContextMenu() {
        if(document.getElementById('fm-context-menu')) return;
        const menu = document.createElement('div');
        menu.id = 'fm-context-menu';
        menu.className = 'hidden fixed z-50 bg-gray-800 border border-gray-600 shadow-xl rounded py-1 min-w-[150px]';
        document.body.appendChild(menu);
    },

    // [NEW] Keyboard Shortcut Hints
    injectShortcutHint() {
        const page = document.getElementById('page-files');
        if(!page || document.getElementById('fm-shortcuts')) return;

        const footer = document.createElement('div');
        footer.id = 'fm-shortcuts';
        footer.className = "mt-2 pt-3 border-t border-gray-800 text-[10px] text-gray-500 font-mono flex flex-wrap gap-4 justify-center select-none opacity-70 hover:opacity-100 transition-opacity";
        footer.innerHTML = `
            <span title="Deletes selected files"><span class="bg-gray-800 px-1 rounded text-gray-300">DEL</span> Delete</span>
            <span title="Selects all files"><span class="bg-gray-800 px-1 rounded text-gray-300">CTRL+A</span> Select All</span>
            <span title="Goes up one directory level"><span class="bg-gray-800 px-1 rounded text-gray-300">BACKSPACE</span> Up Dir</span>
            <span title="Enters a selected directory"><span class="bg-gray-800 px-1 rounded text-gray-300">ENTER</span> Open</span>
            <span title="Reloads the file list"><span class="bg-gray-800 px-1 rounded text-gray-300">F5</span> Refresh</span>
        `;
        
        page.appendChild(footer);
    },

    // --- EVENT BINDINGS (INTERACTION) ---

    bindGlobalEvents() {
        document.addEventListener('click', () => this.hideContextMenu());
    },

    bindDragDrop() {
        const container = document.getElementById('file-list-container');
        if(!container) return;

        // Prevent defaults
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            container.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        // Visual Highlight
        container.addEventListener('dragenter', () => container.classList.add('bg-gray-700/50', 'border-green-500', 'border-2', 'border-dashed'));
        container.addEventListener('dragover', () => container.classList.add('bg-gray-700/50', 'border-green-500', 'border-2', 'border-dashed'));
        
        container.addEventListener('dragleave', () => container.classList.remove('bg-gray-700/50', 'border-green-500', 'border-2', 'border-dashed'));
        container.addEventListener('drop', (e) => {
            container.classList.remove('bg-gray-700/50', 'border-green-500', 'border-2', 'border-dashed');
            const files = e.dataTransfer.files;
            this.handleFileSelect(files);
        });
    },

    bindHotkeys() {
        document.addEventListener('keydown', (e) => {
            // Check if FileManager is visible
            const page = document.getElementById('page-files');
            if(!page || page.classList.contains('hidden')) return;

            // Ignore if typing in an input
            if(document.activeElement.tagName === 'INPUT') return;

            // 1. Select All (Ctrl+A)
            if((e.ctrlKey || e.metaKey) && e.key === 'a') {
                e.preventDefault();
                const master = document.getElementById('file-select-all');
                if(master) {
                    master.checked = !master.checked;
                    this.toggleSelectAll(master);
                }
            }

            // 2. Delete (Del)
            if(e.key === 'Delete') {
                e.preventDefault();
                this.deleteSelected();
            }

            // 3. Back (Backspace)
            if(e.key === 'Backspace') {
                e.preventDefault();
                this.up();
            }

            // 4. Refresh (F5 or Ctrl+R)
            if(e.key === 'F5' || ((e.ctrlKey || e.metaKey) && e.key === 'r')) {
                e.preventDefault();
                this.browse();
            }

            // 5. Enter (Interact)
            if(e.key === 'Enter') {
                // Check if only one item selected
                const checked = document.querySelectorAll('.file-checkbox:checked');
                if(checked.length === 1) {
                    e.preventDefault();
                    const name = checked[0].value;
                    const fileObj = this.cachedFiles.find(f => f.name === name);
                    if(fileObj) {
                        if(fileObj.is_dir) this.browse(this.resolvePath(name));
                        else this.promptDownload([name]);
                    }
                }
            }
        });
    },

    // --- CONTEXT MENU LOGIC ---

    showContextMenu(e, file) {
        e.preventDefault();
        const menu = document.getElementById('fm-context-menu');
        if(!menu) return;

        let items = '';
        const ext = file.name.split('.').pop().toLowerCase();
        if(['txt','log','ini','cfg','json','xml','yml','md','sh','bat','ps1'].includes(ext)) {
            items += `<button onclick="window.FileManager.previewFile('${file.name}')" class="w-full text-left px-4 py-2 hover:bg-gray-700 text-white text-xs flex items-center gap-2"><i class="fas fa-eye text-blue-400"></i> Preview</button>`;
        }

        if(!file.is_dir) {
            items += `<button onclick="window.FileManager.promptDownload(['${file.name}'])" class="w-full text-left px-4 py-2 hover:bg-gray-700 text-white text-xs flex items-center gap-2"><i class="fas fa-download text-green-400"></i> Download</button>`;
        } else {
            items += `<button onclick="window.FileManager.browse(window.FileManager.resolvePath('${file.name}'))" class="w-full text-left px-4 py-2 hover:bg-gray-700 text-white text-xs flex items-center gap-2"><i class="fas fa-folder-open text-yellow-400"></i> Open</button>`;
        }

        items += `<div class="border-t border-gray-700 my-1"></div>`;
        items += `<button onclick="window.FileManager.contextDelete('${file.name}')" class="w-full text-left px-4 py-2 hover:bg-red-900/50 text-red-300 text-xs flex items-center gap-2"><i class="fas fa-trash"></i> Delete</button>`;

        menu.innerHTML = items;
        menu.style.left = `${e.pageX}px`;
        menu.style.top = `${e.pageY}px`;
        menu.classList.remove('hidden');
    },

    hideContextMenu() {
        const menu = document.getElementById('fm-context-menu');
        if(menu) menu.classList.add('hidden');
    },

    contextDelete(filename) {
        this.showModal({
            type: 'delete',
            title: 'Delete Item',
            message: `Delete <span class="text-white font-mono">${filename}</span>?`,
            onConfirm: () => {
                this.executeDelete([filename]);
            }
        });
    },

    // --- PREVIEW LOGIC ---

    async previewFile(filename) {
        if(!this.currentSessionId) return;
        const fullPath = this.resolvePath(filename);
        
        const modal = document.getElementById('fm-preview-modal');
        const title = document.getElementById('fm-preview-title');
        const content = document.getElementById('fm-preview-content');
        
        title.innerText = fullPath;
        content.innerHTML = '<div class="flex items-center justify-center h-full"><i class="fas fa-circle-notch fa-spin text-3xl"></i></div>';
        modal.classList.remove('hidden');

        const host = window.API.hosts.find(h => h.id == this.currentSessionId);
        const isWin = host && host.os.toLowerCase().includes('win');
        const catCmd = isWin ? `type "${fullPath}"` : `cat "${fullPath}"`;
        
        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/hosts/${this.currentSessionId}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-KEY': window.Auth.key },
                body: JSON.stringify({ command: catCmd })
            });
            const data = await res.json();
            
            let attempts = 0;
            const poller = setInterval(async () => {
                attempts++;
                if(attempts > 10) { clearInterval(poller); content.innerHTML = "Timeout waiting for preview."; return; }
                
                const outRes = await fetch(`${cleanUrl}/api/hosts/${this.currentSessionId}/output/${data.request_id}`, {
                    headers: { 'X-API-KEY': window.Auth.key }
                });
                if(outRes.ok) {
                    const outData = await outRes.json();
                    if(outData.status === 'completed') {
                        clearInterval(poller);
                        const safeText = outData.output.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                        content.innerHTML = `<pre>${safeText}</pre>`;
                    }
                }
            }, 1000);

        } catch(e) {
            content.innerHTML = "Error requesting preview.";
        }
    },

    // --- MODAL CONTROLLER ---

    showModal({ type = 'alert', title = 'Notification', message = '', onConfirm = null }) {
        const modal = document.getElementById('fm-modal');
        const titleEl = document.getElementById('fm-modal-title');
        const bodyEl = document.getElementById('fm-modal-body');
        const cancelBtn = document.getElementById('fm-modal-cancel');
        const confirmBtn = document.getElementById('fm-modal-confirm');

        if(!modal) return;

        titleEl.innerHTML = title;
        
        const newConfirm = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirm, confirmBtn);
        const newCancel = cancelBtn.cloneNode(true);
        cancelBtn.parentNode.replaceChild(newCancel, cancelBtn);

        const close = () => modal.classList.add('hidden');
        newCancel.onclick = close;

        if (type === 'prompt') {
            bodyEl.innerHTML = `
                <label class="block text-gray-400 mb-2 text-xs uppercase font-bold">${message}</label>
                <input type="text" id="fm-modal-input" class="w-full bg-gray-900 border border-gray-600 rounded p-2 text-white outline-none focus:border-blue-500" autocomplete="off">
            `;
            newConfirm.innerText = "Create";
            newConfirm.className = "px-4 py-2 rounded bg-green-600 hover:bg-green-500 text-white font-bold shadow-lg transition text-sm";
            newConfirm.onclick = () => {
                const val = document.getElementById('fm-modal-input').value;
                if(val && onConfirm) onConfirm(val);
                close();
            };
            setTimeout(() => document.getElementById('fm-modal-input').focus(), 100);
            newCancel.classList.remove('hidden');

        } else if (type === 'confirm') {
            bodyEl.innerHTML = message;
            newConfirm.innerText = "Yes, Proceed";
            newConfirm.className = "px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold shadow-lg transition text-sm";
            newConfirm.onclick = () => {
                if(onConfirm) onConfirm();
                close();
            };
            newCancel.classList.remove('hidden');

        } else if (type === 'delete') {
            bodyEl.innerHTML = message;
            newConfirm.innerText = "Delete Permanently";
            newConfirm.className = "px-4 py-2 rounded bg-red-600 hover:bg-red-500 text-white font-bold shadow-lg transition text-sm";
            newConfirm.onclick = () => {
                if(onConfirm) onConfirm();
                close();
            };
            newCancel.classList.remove('hidden');

        } else { 
            bodyEl.innerHTML = message;
            newConfirm.innerText = "OK";
            newConfirm.className = "px-4 py-2 rounded bg-gray-700 hover:bg-gray-600 text-white font-bold transition text-sm";
            newConfirm.onclick = close;
            newCancel.classList.add('hidden'); 
        }

        modal.classList.remove('hidden');
    },

    // --- NAVIGATION & LOADING ---

    updateSessionList(hosts) {
        const select = document.getElementById('file-session-select');
        if(!select) return;
        const current = select.value;
        select.innerHTML = `<option value="">Select Session...</option>` + 
            hosts.map(h => `<option value="${h.id}">#${h.id} - ${h.hostname} (${h.os})</option>`).join('');
        if(current && hosts.find(h => h.id == current)) select.value = current;
    },

    async browse(path = null) {
        if(!this.currentSessionId) return;
        if(path) this.currentPath = path;

        this.renderBreadcrumbs();

        const pathInput = document.getElementById('file-path-input');
        if(pathInput) pathInput.value = this.currentPath;

        const container = document.getElementById('file-list-container');
        container.innerHTML = `<div class="p-10 text-center"><i class="fas fa-circle-notch fa-spin text-green-500 text-2xl"></i><br><span class="text-gray-500 text-xs mt-2">Fetching file list...</span></div>`;

        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const encodedPath = encodeURIComponent(this.currentPath);
            const res = await fetch(`${cleanUrl}/api/hosts/${this.currentSessionId}/files/browse?path=${encodedPath}`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });

            if(!res.ok) {
                const err = await res.json();
                throw new Error(err.error || "Request failed");
            }

            const files = await res.json();
            if(!Array.isArray(files)) {
                if(files.error) throw new Error(files.error);
                throw new Error("Invalid response format");
            }

            this.cachedFiles = files;
            this.render();

        } catch(e) {
            this.renderError(e.message);
        }
    },

    // --- RENDERING ---

    render() {
        const container = document.getElementById('file-list-container');
        container.innerHTML = '';

        // Apply Sorting
        this.cachedFiles.sort((a, b) => {
            let valA, valB;
            switch(this.sortCol) {
                case 'size': valA = a.size; valB = b.size; break;
                case 'date': valA = a.mod_time; valB = b.mod_time; break;
                case 'perms': valA = a.perms; valB = b.perms; break;
                default: valA = a.name.toLowerCase(); valB = b.name.toLowerCase();
            }
            if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
            if (valA < valB) return this.sortAsc ? -1 : 1;
            if (valA > valB) return this.sortAsc ? 1 : -1;
            return 0;
        });

        const masterCheck = document.getElementById('file-select-all');
        if(masterCheck) masterCheck.checked = false;

        if(this.cachedFiles.length === 0) {
            container.innerHTML = `<div class="text-center text-gray-500 p-10 italic">Empty Directory</div>`;
            return;
        }

        this.cachedFiles.forEach(f => {
            const el = document.createElement('div');
            el.className = "flex items-center px-4 py-2 hover:bg-gray-700 rounded cursor-pointer transition group border-b border-gray-700/50 last:border-0 file-row";
            
            let icon = f.is_dir ? '<i class="fas fa-folder text-yellow-500 text-lg"></i>' : '<i class="fas fa-file text-gray-400 text-lg"></i>';
            if(!f.is_dir) {
                if(f.name.match(/\.(exe|sh|bat|cmd)$/i)) icon = '<i class="fas fa-terminal text-green-500 text-lg"></i>';
                else if(f.name.match(/\.(png|jpg|jpeg|gif|bmp)$/i)) icon = '<i class="fas fa-image text-purple-400 text-lg"></i>';
                else if(f.name.match(/\.(zip|tar|gz|7z|rar)$/i)) icon = '<i class="fas fa-file-archive text-red-400 text-lg"></i>';
                else if(f.name.match(/\.(txt|log|cfg|ini|md)$/i)) icon = '<i class="fas fa-file-alt text-blue-400 text-lg"></i>';
            }

            const sizeStr = f.is_dir ? '-' : this.formatSize(f.size);
            const dateStr = f.mod_time ? new Date(f.mod_time * 1000).toLocaleString() : '-';

            el.innerHTML = `
                <div class="w-8 flex justify-center items-center" onclick="event.stopPropagation()">
                    <input type="checkbox" class="file-checkbox w-4 h-4 rounded bg-gray-900 border-gray-600 text-green-500 focus:ring-0 cursor-pointer" value="${f.name}">
                </div>
                <div class="w-8 flex justify-center">${icon}</div>
                <div class="flex-1 text-sm text-gray-200 font-medium truncate pr-4 pl-2 select-none">${f.name}</div>
                <div class="w-24 text-right text-xs text-gray-400 font-mono">${sizeStr}</div>
                <div class="w-20 text-center text-xs text-gray-500 font-mono">${f.perms}</div>
                <div class="w-32 text-right text-xs text-gray-500 truncate ml-2">${dateStr}</div>
            `;

            el.onclick = (e) => {
                const cb = el.querySelector('.file-checkbox');
                cb.checked = !cb.checked;
            };

            el.ondblclick = () => {
                if(f.is_dir) {
                    this.browse(this.resolvePath(f.name));
                } else {
                    this.promptDownload([f.name]);
                }
            };

            el.oncontextmenu = (e) => this.showContextMenu(e, f);

            container.appendChild(el);
        });
    },

    renderBreadcrumbs() {
        const div = document.getElementById('file-breadcrumbs');
        if(!div) return;
        div.innerHTML = '';

        const isWin = this.currentPath.includes('\\') || this.currentPath.match(/^[a-zA-Z]:/);
        const sep = isWin ? '\\' : '/';
        const parts = this.currentPath.split(sep).filter(p => p !== '');
        
        const rootSpan = document.createElement('span');
        rootSpan.className = "px-2 py-1 bg-gray-700 text-green-400 rounded text-xs cursor-pointer hover:bg-gray-600 font-mono";
        rootSpan.innerHTML = isWin ? 'C:\\' : '/'; 
        rootSpan.onclick = () => this.browse(isWin ? 'C:\\' : '/');
        div.appendChild(rootSpan);

        if(parts.length > 0) {
            parts.forEach((p, idx) => {
                const slash = document.createElement('span');
                slash.className = "text-gray-600 text-xs";
                slash.innerText = '>';
                div.appendChild(slash);

                let clickPath = isWin ? parts.slice(0, idx+1).join('\\') : '/' + parts.slice(0, idx+1).join('/');
                if(isWin && idx === 0 && p.includes(':')) clickPath = p + '\\';
                else if(isWin && !clickPath.includes(':')) clickPath = 'C:\\' + clickPath; 

                const span = document.createElement('span');
                span.className = "px-2 py-1 hover:bg-gray-700 text-gray-300 rounded text-xs cursor-pointer transition";
                span.innerText = p;
                span.onclick = () => this.browse(clickPath);
                div.appendChild(span);
            });
        }
    },

    // --- ACTIONS ---

    resolvePath(name) {
        const sep = this.currentPath.includes('\\') ? '\\' : '/';
        return this.currentPath.endsWith(sep) ? this.currentPath + name : this.currentPath + sep + name;
    },

    sort(column) {
        if(this.sortCol === column) {
            this.sortAsc = !this.sortAsc;
        } else {
            this.sortCol = column;
            this.sortAsc = true;
        }
        this.render();
    },

    toggleSelectAll(masterCb) {
        const cbs = document.querySelectorAll('.file-checkbox');
        cbs.forEach(cb => cb.checked = masterCb.checked);
    },

    createDirectory() {
        if(!this.currentSessionId) return;
        
        this.showModal({
            type: 'prompt',
            title: 'Create Folder',
            message: 'Enter name for new folder:',
            onConfirm: (name) => {
                if(!name) return;
                const fullPath = this.resolvePath(name);
                const cmd = `mkdir "${fullPath}"`;
                
                if(window.Terminal) {
                    window.Terminal.activeSessionId = this.currentSessionId;
                    window.Terminal.sendCommand(cmd);
                }
                
                if(window.UI) window.UI.addLog(`Created directory: ${fullPath}`);
                setTimeout(() => this.browse(), 2000);
            }
        });
    },

    deleteSelected() {
        if(!this.currentSessionId) return;
        const checkboxes = document.querySelectorAll('.file-checkbox:checked');
        if(checkboxes.length === 0) return this.showModal({ type: 'alert', message: 'No items selected.' });

        const names = Array.from(checkboxes).map(cb => cb.value);
        
        this.showModal({
            type: 'delete',
            title: 'Delete Items',
            message: `Permanently delete <span class="text-white font-bold">${names.length}</span> items?<br><span class="text-xs text-red-400">This action cannot be undone.</span>`,
            onConfirm: () => {
                this.executeDelete(names);
            }
        });
    },

    executeDelete(names) {
        const host = window.API.hosts.find(h => h.id == this.currentSessionId);
        const isWin = host && host.os.toLowerCase().includes('win');

        names.forEach(name => {
            const fileObj = this.cachedFiles.find(f => f.name === name);
            const isDir = fileObj ? fileObj.is_dir : false;
            const fullPath = this.resolvePath(name);
            
            let cmd = "";
            if (isWin) {
                cmd = isDir ? `rmdir /s /q "${fullPath}"` : `del /f /q "${fullPath}"`;
            } else {
                cmd = `rm -rf "${fullPath}"`;
            }

            if(window.Terminal) {
                window.Terminal.activeSessionId = this.currentSessionId;
                window.Terminal.sendCommand(cmd);
            }
        });

        if(window.UI) window.UI.addLog(`Sent delete commands for ${names.length} items.`);
        setTimeout(() => this.browse(), 2000); 
    },

    downloadSelected() {
        const checkboxes = document.querySelectorAll('.file-checkbox:checked');
        const files = Array.from(checkboxes).map(cb => cb.value);
        if(files.length === 0) return;
        this.promptDownload(files);
    },

    // --- UPLOAD ---

    triggerUpload() {
        if(!this.currentSessionId) return this.showModal({ type: 'alert', message: 'Select a session first.' });
        this.uploadInput.value = '';
        this.uploadInput.click();
    },

    handleFileSelect(files) {
        if(!files || files.length === 0) return;

        Array.from(files).forEach(file => {
            const reader = new FileReader();
            reader.onload = (evt) => {
                const content = evt.target.result.split(',')[1];
                const fullPath = this.resolvePath(file.name);
                const cmd = `file:write|${fullPath}|${content}`;
                
                if(window.Terminal) {
                    window.Terminal.activeSessionId = this.currentSessionId;
                    window.Terminal.sendCommand(cmd);
                }
                if(window.UI) window.UI.addLog(`Uploading ${file.name}...`);
            };
            reader.readAsDataURL(file);
        });
        
        setTimeout(() => this.browse(), 2000);
    },

    // --- HELPERS ---

    promptDownload(filenames) {
        let msg = "";
        if(filenames.length === 1) {
            msg = `Queue download for <span class="text-green-400 font-mono">${filenames[0]}</span>?`;
        } else {
            msg = `Queue download for <span class="text-green-400 font-bold">${filenames.length}</span> items?`;
        }

        this.showModal({
            type: 'confirm',
            title: 'Confirm Download',
            message: msg,
            onConfirm: () => this.executeDownload(filenames)
        });
    },

    executeDownload(filenames) {
        if(!this.currentSessionId) return;

        filenames.forEach(name => {
            const fileObj = this.cachedFiles.find(f => f.name === name);
            const isDir = fileObj ? fileObj.is_dir : false;
            const fullPath = this.resolvePath(name);
            const cmd = isDir ? `file:read_recursive|${fullPath}` : `file:read|${fullPath}`;

            if(window.Terminal) {
                window.Terminal.activeSessionId = this.currentSessionId;
                window.Terminal.sendCommand(cmd);
            }
        });

        if(window.UI) window.UI.addLog(`Queued downloads for ${filenames.length} items.`);
        document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = false);
    },

    up() {
        if(!this.currentPath || this.currentPath.length < 2) return;
        const isWin = this.currentPath.includes('\\');
        const sep = isWin ? '\\' : '/';
        const parts = this.currentPath.split(sep).filter(p => p !== "");
        
        if(parts.length > 0) {
            parts.pop(); 
            let newPath = parts.join(sep);
            if(isWin && !newPath.includes('\\') && newPath.endsWith(':')) newPath += '\\'; 
            else if(!isWin) newPath = '/' + newPath; 
            if(newPath === '') newPath = sep;
            this.browse(newPath);
        }
    },

    renderError(msg) {
        const container = document.getElementById('file-list-container');
        container.innerHTML = `
            <div class="p-8 text-center">
                <i class="fas fa-exclamation-triangle text-red-500 text-3xl mb-2"></i>
                <div class="text-red-400 font-bold">Error</div>
                <div class="text-gray-500 text-sm mt-1">${msg}</div>
                <button onclick="window.FileManager.browse()" class="mt-4 text-blue-400 hover:text-white underline text-xs">Retry</button>
            </div>
        `;
    },

    formatSize(bytes) {
        if(bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
};
