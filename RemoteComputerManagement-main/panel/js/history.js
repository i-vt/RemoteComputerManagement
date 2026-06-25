window.HistoryManager = {
    tooltipTimer: null,

    async refresh() {
        const tbody = document.getElementById('global-history-body');
        if (!tbody) return;

        // Visual Loading State (Safe static HTML)
        if (tbody.rows.length === 0 || tbody.innerText.includes('Loading')) {
            tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center"><i class="fas fa-circle-notch fa-spin text-green-500 text-2xl"></i></td></tr>`;
        }

        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/history`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });

            if (!res.ok) throw new Error(`API Error: ${res.status}`);

            const data = await res.json();
            this.render(data);
        } catch (e) {
            console.error(e);
            tbody.innerHTML = ``; // Clear loading spinner
            const tr = document.createElement('tr');
            tr.innerHTML = `<td colspan="5" class="p-4 text-center text-red-500"></td>`;
            tr.querySelector('td').textContent = `Connection Failed: ${e.message}`;
            tbody.appendChild(tr);
        }
    },

    render(logs) {
        const tbody = document.getElementById('global-history-body');
        tbody.innerHTML = ''; // Clear existing

        // Header Check
        const thead = document.querySelector('#page-history thead tr');
        if (thead && thead.children.length < 5) {
            thead.innerHTML = `
                <th class="p-4 w-32">Timestamp</th>
                <th class="p-4 w-24 text-center">Session</th>
                <th class="p-4 w-64">Command</th>
                <th class="p-4">Output</th>
                <th class="p-4 w-24">Status</th>
            `;
        }

        if (!Array.isArray(logs) || logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-gray-500 italic">No command history found on server.</td></tr>`;
            return;
        }

        logs.forEach(log => {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-gray-800 transition border-b border-gray-800 text-xs group";

            // 1. Timestamp
            const date = new Date(log.timestamp).toLocaleTimeString();
            const tdDate = document.createElement('td');
            tdDate.className = "p-4 text-gray-500 font-mono align-top";
            tdDate.textContent = date;
            tr.appendChild(tdDate);

            // 2. Session ID
            const tdSession = document.createElement('td');
            tdSession.className = "p-4 text-center align-top";
            tdSession.innerHTML = `<span class="bg-gray-700 text-blue-300 px-2 py-1 rounded font-bold"></span>`;
            tdSession.querySelector('span').textContent = `#${log.session_id}`;
            tr.appendChild(tdSession);

            // 3. Command (Safe Rendering)
            const tdCommand = document.createElement('td');
            tdCommand.className = "p-4 font-mono text-white align-top";
            const cmdDiv = document.createElement('div');
            cmdDiv.className = "line-clamp-2 text-green-400 w-64";
            cmdDiv.title = log.command; // Tooltip is safe attribute
            
            const promptSpan = document.createElement('span');
            promptSpan.className = "text-gray-500 mr-1";
            promptSpan.textContent = "$";
            
            const cmdText = document.createTextNode(log.command.length > 100 ? log.command.substring(0, 100) + "..." : log.command);
            
            cmdDiv.appendChild(promptSpan);
            cmdDiv.appendChild(cmdText);
            tdCommand.appendChild(cmdDiv);
            tr.appendChild(tdCommand);

            // 4. Output (Safe Rendering with Metadata)
            const fullOutput = log.output || log.error || "";
            const tdOutput = document.createElement('td');
            
            let outputPreview = "";
            let statusBadge = "";
            let cursorClass = "";

            if (log.output) {
                outputPreview = log.output.substring(0, 50) + (log.output.length > 50 ? "..." : "");
                statusBadge = '<span class="bg-green-900 text-green-200 text-xs px-2 py-1 rounded">Received</span>';
                cursorClass = "cursor-pointer hover:bg-gray-700 hover:text-white";
                tdOutput.classList.add("text-gray-400");
            } else if (log.error) {
                outputPreview = log.error.substring(0, 50) + (log.error.length > 50 ? "..." : "");
                statusBadge = '<span class="bg-red-900 text-red-200 text-xs px-2 py-1 rounded">Error</span>';
                cursorClass = "cursor-pointer hover:bg-gray-700 hover:text-white";
                tdOutput.classList.add("text-red-400");
            } else {
                statusBadge = '<span class="bg-yellow-900 text-yellow-200 text-xs px-2 py-1 rounded">Sent</span>';
                tdOutput.classList.add("text-gray-500", "italic");
                outputPreview = "Pending...";
            }

            tdOutput.className = `p-4 font-mono break-all transition-colors align-top ${cursorClass}`;
            tdOutput.textContent = outputPreview;

            // Store full data safely in memory/properties, not attributes if possible, 
            // but dataset is okay if we strictly use textContent when retrieving.
            if (fullOutput) {
                // Attach event listeners programmatically
                tdOutput.onclick = () => this.openModal(log.command, fullOutput);
                tdOutput.onmouseenter = (e) => this.showTooltip(e, fullOutput);
                tdOutput.onmouseleave = () => this.hideTooltip();
                tdOutput.onmousemove = (e) => this.moveTooltip(e);
                
                // Add expand icon if data exists
                const icon = document.createElement('i');
                icon.className = "fas fa-expand-alt ml-2 text-gray-600 group-hover:text-green-400";
                tdOutput.appendChild(icon);
            }
            tr.appendChild(tdOutput);

            // 5. Status
            const tdStatus = document.createElement('td');
            tdStatus.className = "p-4 text-center align-top";
            tdStatus.innerHTML = statusBadge;
            tr.appendChild(tdStatus);

            tbody.appendChild(tr);
        });
    },

    // ==========================================
    // MODAL LOGIC (Harded)
    // ==========================================

    getModalElement() {
        let modal = document.getElementById('history-enterprise-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'history-enterprise-modal';
            modal.className = 'hidden fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm';
            
            modal.innerHTML = `
                <div class="bg-[#0d1117] border border-gray-700 w-full max-w-5xl h-[90vh] rounded-xl shadow-2xl flex flex-col transform scale-95 transition-all duration-200" id="history-modal-panel">
                    
                    <div class="flex justify-between items-center px-6 py-4 border-b border-gray-800 bg-[#161b22] rounded-t-xl shrink-0">
                        <div class="flex items-center gap-3">
                            <i class="fas fa-terminal text-green-500 text-lg"></i>
                            <h3 class="text-white font-bold text-sm tracking-wide">EXECUTION DETAILS</h3>
                        </div>
                        <button id="modal-close-btn" class="text-gray-400 hover:text-white px-2 transition text-xl">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>

                    <div class="bg-[#1c2128] border-b border-gray-700 shrink-0">
                        <details class="group p-4" open>
                            <summary class="list-none flex items-center justify-between cursor-pointer text-xs font-bold text-gray-400 hover:text-white mb-2">
                                <span class="flex items-center gap-2">
                                    <i class="fas fa-chevron-right text-[10px] transition-transform group-open:rotate-90"></i>
                                    COMMAND EXECUTED
                                </span>
                                <button id="copy-cmd-btn" class="text-[10px] flex items-center gap-1 bg-gray-800 hover:bg-gray-700 border border-gray-600 px-2 py-1 rounded text-gray-300">
                                    <i class="fas fa-copy"></i> Copy Cmd
                                </button>
                            </summary>
                            <div class="mt-2 bg-black border border-gray-700 rounded p-3 relative group/cmd">
                                <pre id="modal-full-command" class="text-green-400 font-mono text-xs whitespace-pre-wrap break-all"></pre>
                            </div>
                        </details>
                    </div>

                    <div class="flex-1 flex flex-col min-h-0 bg-[#0d1117]">
                        <div class="flex items-center justify-between px-4 py-2 bg-[#161b22] border-b border-gray-800 shrink-0">
                            <span class="text-xs font-bold text-gray-400">STANDARD OUTPUT / ERROR</span>
                            <button id="copy-out-btn" class="text-[10px] flex items-center gap-1 bg-blue-900/30 hover:bg-blue-900/50 border border-blue-800/50 px-3 py-1 rounded text-blue-200 transition">
                                <i class="fas fa-copy"></i> Copy Output
                            </button>
                        </div>
                        <div class="flex-1 relative overflow-hidden">
                            <pre id="history-modal-content" class="absolute inset-0 w-full h-full p-6 text-xs font-mono leading-relaxed text-gray-300 whitespace-pre-wrap break-all overflow-y-auto custom-scrollbar selection:bg-blue-900 selection:text-white"></pre>
                        </div>
                    </div>

                    <div class="px-6 py-2 border-t border-gray-800 bg-[#161b22] rounded-b-xl flex justify-between items-center text-[10px] text-gray-500 font-mono shrink-0">
                        <span><i class="fas fa-shield-alt mr-1"></i> Secure Storage</span>
                        <span id="char-count">0 chars</span>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);

            // Bind Static Events
            modal.onclick = (e) => { if (e.target === modal) this.closeModal(); };
            document.onkeydown = (e) => { if (e.key === 'Escape') this.closeModal(); };
            document.getElementById('modal-close-btn').onclick = () => this.closeModal();
            document.getElementById('copy-cmd-btn').onclick = (e) => this.copyToClipboard('modal-full-command', e.currentTarget);
            document.getElementById('copy-out-btn').onclick = (e) => this.copyToClipboard('history-modal-content', e.currentTarget);
        }
        return modal;
    },

    openModal(command, output) {
        // Force hide tooltip
        const tooltip = this.getTooltipElement();
        tooltip.classList.add('hidden');
        if (this.tooltipTimer) clearTimeout(this.tooltipTimer);

        if (!output && !command) return;

        const modal = this.getModalElement();
        const panel = modal.querySelector('#history-modal-panel');
        
        // SAFE INSERTION: Use textContent
        document.getElementById('history-modal-content').textContent = output;
        document.getElementById('modal-full-command').textContent = command;
        document.getElementById('char-count').textContent = `Output Length: ${output.length.toLocaleString()} chars`;

        // Show & Animate
        modal.classList.remove('hidden');
        requestAnimationFrame(() => {
            panel.classList.remove('scale-95');
            panel.classList.add('scale-100');
        });
        document.body.style.overflow = 'hidden';
    },

    closeModal() {
        const modal = document.getElementById('history-enterprise-modal');
        const panel = document.getElementById('history-modal-panel');
        if (modal && !modal.classList.contains('hidden')) {
            panel.classList.remove('scale-100');
            panel.classList.add('scale-95');
            setTimeout(() => {
                modal.classList.add('hidden');
                document.body.style.overflow = '';
            }, 150);
        }
    },

    // Unified Copy Function
    copyToClipboard(elementId, btnElement) {
        const content = document.getElementById(elementId).textContent; // Use textContent
        navigator.clipboard.writeText(content).then(() => {
            const originalHtml = btnElement.innerHTML;
            btnElement.innerHTML = '<i class="fas fa-check text-green-400"></i> Copied!';
            btnElement.classList.add('border-green-500', 'text-green-400');
            
            setTimeout(() => {
                btnElement.innerHTML = originalHtml;
                btnElement.classList.remove('border-green-500', 'text-green-400');
            }, 2000);
        }).catch(err => {
            console.error('Copy failed', err);
        });
    },

    // ==========================================
    // TOOLTIP LOGIC (Hardened)
    // ==========================================

    getTooltipElement() {
        let tooltip = document.getElementById('history-tooltip');
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.id = 'history-tooltip';
            tooltip.className = 'hidden fixed z-[100] bg-gray-900 border border-gray-500 text-xs font-mono text-green-300 p-3 rounded shadow-2xl max-w-md break-all pointer-events-none transition-opacity duration-150 opacity-0';
            document.body.appendChild(tooltip);
        }
        return tooltip;
    },

    showTooltip(e, fullOutput) {
        if (this.tooltipTimer) { clearTimeout(this.tooltipTimer); this.tooltipTimer = null; }
        if (!fullOutput) return;

        const tooltip = this.getTooltipElement();
        
        // Truncate and use textContent for safety
        let text = fullOutput;
        if (text.length > 400) text = text.substring(0, 400) + "\n\n[...Click row to view full output...]";
        
        tooltip.textContent = text;
        
        tooltip.classList.remove('hidden');
        requestAnimationFrame(() => tooltip.classList.remove('opacity-0'));
        this.moveTooltip(e);
    },

    moveTooltip(e) {
        const tooltip = this.getTooltipElement();
        if (tooltip.classList.contains('hidden')) return;

        const x = e.clientX + 15;
        const y = e.clientY + 15;
        const rect = tooltip.getBoundingClientRect();
        let finalX = x;
        let finalY = y;

        if (x + rect.width > window.innerWidth) finalX = e.clientX - rect.width - 20;
        if (y + rect.height > window.innerHeight) finalY = e.clientY - rect.height - 10;

        tooltip.style.left = `${finalX}px`;
        tooltip.style.top = `${finalY}px`;
    },

    hideTooltip() {
        const tooltip = this.getTooltipElement();
        tooltip.classList.add('opacity-0');
        this.tooltipTimer = setTimeout(() => tooltip.classList.add('hidden'), 200);
    }
};
