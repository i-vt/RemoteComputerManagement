window.Terminal = {
    activeSessionId: null,

    open(id, hostname) {
        this.activeSessionId = id;
        document.getElementById('term-title').innerText = `Session #${id} - ${hostname}`;
        document.getElementById('terminal-modal').classList.remove('hidden');
        
        // Clear previous output
        const container = document.getElementById('term-output');
        container.innerHTML = '<div class="text-gray-500">Secure connection established.</div><div class="text-gray-600 italic">Loading history...</div>';
        
        // Auto-focus input
        setTimeout(() => document.getElementById('term-input').focus(), 50);

        // Fetch History
        this.loadHistory(id);
    },

    async loadHistory(id) {
        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/hosts/${id}/history`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });
            
            if (!res.ok) throw new Error("Failed to load history");
            
            const logs = await res.json();
            
            // Clear the "Loading history..." text
            const container = document.getElementById('term-output');
            container.innerHTML = '<div class="text-gray-500">Secure connection established.</div>';

            if (logs.length === 0) {
                this.log("No previous history found.", "text-gray-600 italic text-xs");
            }

            logs.forEach(entry => {
                // Parse timestamp for cleaner display
                const time = new Date(entry.timestamp).toLocaleTimeString();
                
                // We don't have the command text in the DB output table (optimized for storage), 
                // so we just show the output. 
                // If you want command echoed, you'd need to store the command string in client_outputs too.
                this.log(`[${time}] Output (Req #${entry.request_id}):`, 'text-blue-400 font-bold text-xs mt-2');
                
                if(entry.output) this.log(entry.output, 'text-green-300 font-mono whitespace-pre-wrap');
                if(entry.error) this.log(`STDERR: ${entry.error}`, 'text-red-400 font-mono whitespace-pre-wrap');
            });
            
            // Scroll to bottom
            container.scrollTop = container.scrollHeight;

        } catch (e) {
            this.log(`[-] Error loading history: ${e.message}`, 'text-red-500');
        }
    },

    close() {
        this.activeSessionId = null;
        document.getElementById('terminal-modal').classList.add('hidden');
    },

    log(text, classes = '') {
        const div = document.createElement('div');
        div.className = classes;
        div.innerText = text;
        const container = document.getElementById('term-output');
        if (container) {
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }
    },

    async sendCommand(cmd) {
        if(!cmd) return;
        const id = this.activeSessionId;
        
        this.log(`$ ${cmd}`, 'text-white font-bold font-mono mt-2');
        
        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/hosts/${id}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-KEY': window.Auth.key },
                body: JSON.stringify({ command: cmd })
            });
            const data = await res.json();
            
            if(data.status === 'queued') {
                this.log(`[+] Queued (Req ID: ${data.request_id}). Waiting for output...`, 'text-gray-500 italic text-xs');
                this.pollOutput(id, data.request_id);
                if(window.UI) window.UI.addLog(`Sent "${cmd}" to Session #${id}`);
            } else {
                this.log(`[-] Error: ${JSON.stringify(data)}`, 'text-red-500');
            }
        } catch(e) {
            this.log(`[-] Network Error: ${e}`, 'text-red-500');
        }
    },

    pollOutput(sessId, reqId) {
        let attempts = 0;
        const cleanUrl = window.Auth.url.replace(/\/$/, "");

        const poller = setInterval(async () => {
            attempts++;
            if(attempts > 30) { 
                clearInterval(poller); 
                this.log("[-] Timeout waiting for response.", 'text-red-500'); 
                return; 
            }

            try {
                const res = await fetch(`${cleanUrl}/api/hosts/${sessId}/output/${reqId}`, {
                    headers: { 'X-API-KEY': window.Auth.key }
                });
                if(res.status === 200) {
                    const data = await res.json();
                    clearInterval(poller);
                    
                    // Display Output
                    if(data.output) this.log(data.output, 'text-green-300 font-mono whitespace-pre-wrap');
                    if(data.error) this.log(`STDERR: ${data.error}`, 'text-red-400 font-mono');
                    if(data.exit_code !== 0) this.log(`[Exit Code: ${data.exit_code}]`, 'text-gray-500 text-xs');
                }
            } catch(e) { clearInterval(poller); }
        }, 1000);
    },

    async broadcast() {
        const cmd = document.getElementById('broadcast-input').value;
        if(!cmd) return;
        const cleanUrl = window.Auth.url.replace(/\/$/, "");
        
        try {
            const res = await fetch(`${cleanUrl}/api/broadcast`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-KEY': window.Auth.key },
                body: JSON.stringify({ command: cmd })
            });
            const data = await res.json();
            
            document.getElementById('broadcast-input').value = "";
            if(window.UI) {
                window.UI.addTaskLog(cmd, data.targets_reached);
                window.UI.addLog(`Broadcast "${cmd}" to ${data.targets_reached} targets`);
            }
        } catch(e) { alert("Broadcast failed"); }
    }
};
