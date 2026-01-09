window.HistoryManager = {
    tooltipTimer: null,

    async refresh() {
        const tbody = document.getElementById('global-history-body');
        if (!tbody) return;

        // Loading State
        if (tbody.rows.length === 0 || tbody.rows[0].innerText.includes('Loading')) {
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
            tbody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-red-500">Connection Failed: ${e.message}</td></tr>`;
        }
    },

    render(logs) {
        const tbody = document.getElementById('global-history-body');
        
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

        tbody.innerHTML = logs.map(log => {
            const date = new Date(log.timestamp).toLocaleTimeString();
            let statusBadge = '<span class="bg-yellow-900 text-yellow-200 text-xs px-2 py-1 rounded">Sent</span>';
            let cursorClass = "";
            let interactionEvents = "";
            
            // Prepare Data
            const fullOutput = log.output || log.error || "";
            const fullCommand = this.escapeHtml(log.command);
            const fullOutputEscaped = this.escapeHtml(fullOutput);
            
            // Truncate Command for Preview (Logic + CSS class)
            let commandPreview = fullCommand;
            if (commandPreview.length > 100) {
                commandPreview = commandPreview.substring(0, 100) + "...";
            }

            // Truncate Output for Preview
            let outputPreview = "";
            if (log.output) {
                outputPreview = this.escapeHtml(log.output.substring(0, 50)) + (log.output.length > 50 ? "..." : "");
                statusBadge = '<span class="bg-green-900 text-green-200 text-xs px-2 py-1 rounded">Received</span>';
                cursorClass = "cursor-pointer hover:bg-gray-700 hover:text-white";
            } else if (log.error) {
                outputPreview = `<span class="text-red-400">${this.escapeHtml(log.error)}</span>`;
                statusBadge = '<span class="bg-red-900 text-red-200 text-xs px-2 py-1 rounded">Error</span>';
                cursorClass = "cursor-pointer hover:bg-gray-700 hover:text-white";
            }

            // Bind Events if there is data
            if (fullOutput) {
                interactionEvents = `
                    onmouseenter="window.HistoryManager.showTooltip(event, this)" 
                    onmouseleave="window.HistoryManager.hideTooltip()" 
                    onmousemove="window.HistoryManager.moveTooltip(event)"
                    onclick="window.HistoryManager.openModal(this)"
                `;
            }

            return `
                <tr class="hover:bg-gray-800 transition border-b border-gray-800 text-xs group">
                    <td class="p-4 text-gray-500 font-mono align-top">${date}</td>
                    
                    <td class="p-4 text-center align-top">
                        <span class="bg-gray-700 text-blue-300 px-2 py-1 rounded font-bold">#${log.session_id}</span>
                    </td>
                    
                    <td class="p-4 font-mono text-white align-top">
                        <div class="line-clamp-2 text-green-400 w-64" title="${fullCommand}">
                            <span class="text-gray-500 mr-1">$</span>${commandPreview}
                        </div>
                    </td>
                    
                    <td class="p-4 font-mono text-gray-400 break-all transition-colors align-top ${cursorClass}" 
                        data-full-output="${fullOutputEscaped}" 
                        data-full-command="${fullCommand}"
                        ${interactionEvents}>
                        ${outputPreview}
                        ${fullOutput ? '<i class="fas fa-expand-alt ml-2 text-gray-600 group-hover:text-green-400"></i>' : ''}
                    </td>
                    
                    <td class="p-4 text-center align-top">${statusBadge}</td>
                </tr>
            `;
        }).join('');
    },

    // ==========================================
    // MODAL LOGIC (Updated Layout)
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
                        <button onclick="window.HistoryManager.closeModal()" class="text-gray-400 hover:text-white px-2 transition text-xl">
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
                                <button onclick="window.HistoryManager.copyToClipboard('modal-full-command', this)" class="text-[10px] flex items-center gap-1 bg-gray-800 hover:bg-gray-700 border border-gray-600 px-2 py-1 rounded text-gray-300">
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
                            <button onclick="window.HistoryManager.copyToClipboard('history-modal-content', this)" class="text-[10px] flex items-center gap-1 bg-blue-900/30 hover:bg-blue-900/50 border border-blue-800/50 px-3 py-1 rounded text-blue-200 transition">
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

            // Close Events
            modal.onclick = (e) => { if (e.target === modal) this.closeModal(); };
            document.onkeydown = (e) => { if (e.key === 'Escape') this.closeModal(); };
        }
        return modal;
    },

    openModal(element) {
        // Force hide tooltip
        const tooltip = this.getTooltipElement();
        tooltip.classList.add('hidden');
        if (this.tooltipTimer) clearTimeout(this.tooltipTimer);

        // Get Data
        const output = element.getAttribute('data-full-output');
        const command = element.getAttribute('data-full-command');
        
        if (!output) return;

        const modal = this.getModalElement();
        const panel = modal.querySelector('#history-modal-panel');
        const outputBox = document.getElementById('history-modal-content');
        const commandBox = document.getElementById('modal-full-command');
        const charCount = document.getElementById('char-count');

        // Populate
        outputBox.innerHTML = output;
        commandBox.innerHTML = command;
        
        // Stats
        const tempDiv = document.createElement("div");
        tempDiv.innerHTML = output;
        const len = (tempDiv.textContent || "").length;
        charCount.innerText = `Output Length: ${len.toLocaleString()} chars`;

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
        const content = document.getElementById(elementId).innerText;
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
    // TOOLTIP LOGIC (Unchanged)
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

    showTooltip(e, element) {
        if (this.tooltipTimer) { clearTimeout(this.tooltipTimer); this.tooltipTimer = null; }

        const output = element.getAttribute('data-full-output');
        if (!output) return;

        const tooltip = this.getTooltipElement();
        const tempDiv = document.createElement("div");
        tempDiv.innerHTML = output;
        let text = tempDiv.textContent || tempDiv.innerText || "";

        if (text.length > 400) text = text.substring(0, 400) + "\n\n[...Click row to view full output...]";
        tooltip.innerText = text;
        
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
    },

    escapeHtml(text) {
        if (!text) return "";
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
};
