window.TaskManager = {
    history: [],
    mode: 'command', // 'command' or 'module'

    async init() {
        const saved = localStorage.getItem('c2_task_history');
        if (saved) {
            this.history = JSON.parse(saved);
        }
        this.renderTable();
        // Load modules for the dropdown
        await this.loadModules();
    },

    toggleMode(newMode) {
        this.mode = newMode;
        
        const btnCmd = document.getElementById('btn-mode-cmd');
        const btnMod = document.getElementById('btn-mode-mod');
        const grpCmd = document.getElementById('input-group-cmd');
        const grpMod = document.getElementById('input-group-mod');

        if (newMode === 'command') {
            btnCmd.classList.add('bg-gray-700', 'text-white', 'shadow');
            btnCmd.classList.remove('text-gray-400');
            btnMod.classList.remove('bg-gray-700', 'text-white', 'shadow');
            btnMod.classList.add('text-gray-400');
            
            grpCmd.classList.remove('hidden');
            grpMod.classList.add('hidden');
        } else {
            btnMod.classList.add('bg-gray-700', 'text-white', 'shadow');
            btnMod.classList.remove('text-gray-400');
            btnCmd.classList.remove('bg-gray-700', 'text-white', 'shadow');
            btnCmd.classList.add('text-gray-400');

            grpMod.classList.remove('hidden');
            grpCmd.classList.add('hidden');
        }
    },

    async loadModules() {
        const select = document.getElementById('broadcast-module-select');
        if (!select) return;

        try {
            // Reuse ModuleManager if available, otherwise fetch
            let modules = [];
            if (window.ModuleManager && window.ModuleManager.availableModules.length > 0) {
                modules = window.ModuleManager.availableModules;
            } else {
                const cleanUrl = window.Auth.url.replace(/\/$/, "");
                const res = await fetch(`${cleanUrl}/api/modules`, { headers: { 'X-API-KEY': window.Auth.key } });
                modules = await res.json();
            }

            if (modules.length === 0) {
                select.innerHTML = `<option value="" disabled selected>No modules found</option>`;
                return;
            }

            select.innerHTML = `<option value="" disabled selected>Select Script</option>` + 
                modules.map(m => `<option value="${m}">${m}</option>`).join('');
        } catch(e) {
            select.innerHTML = `<option value="" disabled selected>Error loading modules</option>`;
        }
    },

    async executeBroadcast() {
        const btn = document.getElementById('broadcast-btn');
        btn.disabled = true;
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';

        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            let endpoint = '';
            let payload = {};
            let logSummary = '';

            if (this.mode === 'command') {
                const cmd = document.getElementById('broadcast-input').value;
                if (!cmd) throw new Error("Command required");
                endpoint = '/api/broadcast';
                payload = { command: cmd };
                logSummary = cmd;
            } else {
                const mod = document.getElementById('broadcast-module-select').value;
                const argsStr = document.getElementById('broadcast-module-args').value;
                if (!mod) throw new Error("Module selection required");
                
                endpoint = '/api/broadcast/module';
                const args = argsStr.match(/(?:[^\s"]+|"[^"]*")+/g)?.map(a => a.replace(/"/g, "")) || [];
                payload = { module_name: mod, args: args };
                logSummary = `Module: ${mod} ${args.join(' ')}`;
            }

            const res = await fetch(`${cleanUrl}${endpoint}`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-API-KEY': window.Auth.key 
                },
                body: JSON.stringify(payload)
            });

            const data = await res.json();

            if (!res.ok) throw new Error(data.error || "Broadcast failed");

            // Add to Local Log
            const newTask = {
                id: Date.now(),
                type: this.mode === 'command' ? 'CMD BROADCAST' : 'MOD BROADCAST',
                command: logSummary,
                targets: data.targets_reached || 0,
                timestamp: new Date().toISOString(),
                status: 'Success'
            };

            this.history.unshift(newTask);
            this.save();
            this.renderTable();
            
            // Clear inputs
            if (this.mode === 'command') document.getElementById('broadcast-input').value = "";
            else document.getElementById('broadcast-module-args').value = "";

            if(window.UI) window.UI.addLog(`Broadcast ${this.mode}: "${logSummary}" to ${newTask.targets} targets.`);

        } catch (e) {
            alert("Error: " + e.message);
        } finally {
            btn.innerHTML = originalHtml;
            btn.disabled = false;
        }
    },

    reRun(id) {
        // Simple re-run for commands, alert for modules (too complex to reconstruct args easily in this simple view)
        const task = this.history.find(t => t.id === id);
        if(!task) return;

        if (task.type === 'CMD BROADCAST') {
            if(confirm(`Re-broadcast command: "${task.command}"?`)) {
                this.mode = 'command';
                this.toggleMode('command');
                document.getElementById('broadcast-input').value = task.command;
                this.executeBroadcast();
            }
        } else {
            alert("Please manually re-select the module to re-run.");
        }
    },

    deleteTask(id) {
        this.history = this.history.filter(t => t.id !== id);
        this.save();
        this.renderTable();
    },

    clearHistory() {
        if(confirm("Clear all task history?")) {
            this.history = [];
            this.save();
            this.renderTable();
        }
    },

    save() {
        localStorage.setItem('c2_task_history', JSON.stringify(this.history));
    },

    renderTable() {
        const tbody = document.getElementById('tasks-table-body');
        const searchVal = document.getElementById('task-search')?.value.toLowerCase() || "";
        
        if (!tbody) return;

        const filtered = this.history.filter(t => 
            t.command.toLowerCase().includes(searchVal) || 
            t.type.toLowerCase().includes(searchVal)
        );

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-gray-500 italic">No tasks found.</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(t => {
            const dateStr = new Date(t.timestamp).toLocaleString();
            const badgeColor = t.type.includes('MOD') ? 'bg-purple-900 text-purple-200' : 'bg-blue-900 text-blue-200';
            
            return `
            <tr class="hover:bg-gray-750 transition border-b border-gray-800 last:border-0 group">
                <td class="p-4 text-xs text-gray-500 font-mono">${dateStr}</td>
                <td class="p-4"><span class="${badgeColor} text-xs px-2 py-1 rounded font-bold">${t.type}</span></td>
                <td class="p-4 font-mono text-sm text-white"><span class="text-green-500">$</span> ${t.command}</td>
                <td class="p-4 text-center"><span class="text-gray-300 font-bold">${t.targets}</span></td>
                <td class="p-4 text-center"><span class="text-green-400 text-xs"><i class="fas fa-check-circle"></i> Sent</span></td>
                <td class="p-4 text-right opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onclick="window.TaskManager.reRun(${t.id})" class="text-gray-400 hover:text-white mr-3"><i class="fas fa-redo"></i></button>
                    <button onclick="window.TaskManager.deleteTask(${t.id})" class="text-red-900 hover:text-red-500"><i class="fas fa-trash"></i></button>
                </td>
            </tr>
        `}).join('');
    }
};
