window.NetworkManager = {
    cy: null,
    tooltips: {}, 

    async init() {
        if (!window.API || window.API.hosts.length === 0) {
            if (window.API) await window.API.refreshHosts();
        }
        
        const container = document.getElementById('cy');
        if (!container) return;

        if (this.cy) this.cy.destroy();
        this.clearAllTooltips(); 

        const elements = this.buildElements();

        this.cy = cytoscape({
            container: container,
            elements: elements,
            minZoom: 0.2,
            maxZoom: 3,
            // [FIX] Removed wheelSensitivity to fix console warning
            
            style: [
                {
                    selector: 'node',
                    style: {
                        'label': 'data(label)',
                        'color': '#cbd5e1', 
                        'font-family': 'Consolas, monospace',
                        'font-size': '11px',
                        'text-valign': 'bottom',
                        'text-margin-y': 8,
                        'text-background-color': '#0f172a',
                        'text-background-opacity': 0.8,
                        'text-background-padding': '3px',
                        'text-background-shape': 'roundrectangle',
                        'transition-property': 'background-color, border-width, border-color, width, height',
                        'transition-duration': '0.2s'
                    }
                },
                {
                    selector: 'node[type="server"]',
                    style: {
                        'background-color': '#ef4444', 
                        'width': 70,
                        'height': 70,
                        'shape': 'hexagon',
                        'border-width': 0,
                        'label': 'C2 MAIN',
                        'font-weight': 'bold',
                        'color': '#ef4444',
                        'text-margin-y': 10,
                        'text-background-opacity': 0 
                    }
                },
                {
                    selector: 'node[os="windows"]',
                    style: {
                        'background-color': '#0ea5e9', 
                        'border-color': '#0284c7', 
                        'border-width': 2,
                        'shape': 'round-rectangle',
                        'width': 50,
                        'height': 50,
                        'label': 'data(os_emoji)',
                        'font-size': '24px',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'text-margin-y': 0,
                        'text-background-opacity': 0 
                    }
                },
                {
                    selector: 'node[os="linux"]',
                    style: {
                        'background-color': '#eab308', 
                        'border-color': '#ca8a04', 
                        'border-width': 2,
                        'shape': 'ellipse',
                        'width': 50,
                        'height': 50,
                        'label': 'data(os_emoji)',
                        'font-size': '24px',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'text-margin-y': 0,
                        'text-background-opacity': 0
                    }
                },
                {
                    selector: 'node[os="macos"]',
                    style: {
                        'background-color': '#a855f7', 
                        'border-color': '#9333ea', 
                        'border-width': 2,
                        'shape': 'diamond',
                        'width': 55,
                        'height': 55,
                        'label': 'data(os_emoji)',
                        'font-size': '24px',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'text-margin-y': 0,
                        'text-background-opacity': 0
                    }
                },
                {
                    selector: 'node[?proxy]',
                    style: {
                        'border-width': 6,
                        'border-color': '#22c55e',
                        // [FIX] Removed invalid shadow-blur/shadow-color properties
                        'overlay-color': '#22c55e',
                        'overlay-padding': 5,
                        'overlay-opacity': 0.3
                    }
                },
                {
                    selector: ':selected',
                    style: {
                        'border-width': 4,
                        'border-color': '#fff',
                        'overlay-color': '#fff',
                        'overlay-padding': 8,
                        'overlay-opacity': 0.3
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'curve-style': 'bezier',
                        'line-color': '#475569', 
                        'target-arrow-shape': 'triangle',
                        'target-arrow-color': '#475569',
                        'arrow-scale': 1.5
                    }
                },
                {
                    selector: 'edge[type="tunnel"]',
                    style: {
                        'line-style': 'dashed',
                        'line-dash-pattern': [6, 4],
                        'line-color': '#f59e0b', 
                        'target-arrow-color': '#f59e0b',
                        'width': 3,
                        'opacity': 0.8
                    }
                }
            ],

            layout: {
                name: 'cose', 
                animate: true,
                animationDuration: 800,
                refresh: 20,
                fit: true,
                padding: 60,
                randomize: false,
                componentSpacing: 120,
                nodeRepulsion: 1000000,
                idealEdgeLength: 80,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            }
        });

        this.bindEvents();
    },

    // ... (Keep buildElements, bindEvents, showTooltip, scheduleHideTooltip, clearAllTooltips unchanged) ...
    // Paste the exact helper functions from previous network.js here
    
    // For completeness, here is the helper block again if you need to copy-paste the whole file:
    buildElements() {
        const nodes = [
            { data: { id: 'c2', label: 'C2 Server', type: 'server' } }
        ];
        
        const edges = [];

        window.API.hosts.forEach(h => {
            const hostNodeId = `s${h.id}`;
            
            let osType = 'linux';
            let osEmoji = '🐧'; 

            const rawOs = h.os.toLowerCase();
            if (rawOs.includes('win')) {
                osType = 'windows';
                osEmoji = '🪟';
            } else if (rawOs.includes('mac') || rawOs.includes('darwin')) {
                osType = 'macos';
                osEmoji = '🍎';
            }

            const sourceId = h.parent_id ? `s${h.parent_id}` : 'c2';
            const finalSource = (sourceId === 'c2' || window.API.hosts.some(p => `s${p.id}` === sourceId)) 
                ? sourceId 
                : 'c2';

            nodes.push({
                data: { 
                    id: hostNodeId, 
                    label: h.ip, 
                    full_hostname: h.hostname,
                    type: 'host',
                    os: osType,
                    os_emoji: osEmoji,
                    proxy: h.has_proxy,
                    hwid: h.computer_id,
                    parent_id: h.parent_id
                }
            });

            edges.push({
                data: { 
                    source: finalSource, 
                    target: hostNodeId,
                    type: h.parent_id ? 'tunnel' : 'direct'
                }
            });
        });

        return [...nodes, ...edges];
    },

    bindEvents() {
        if (!this.cy) return;

        this.cy.on('dblclick tap', 'node[type="host"]', (evt) => {
            const node = evt.target;
            const id = node.data('id').replace('s', '');
            this.clearAllTooltips();
            if (window.Terminal) window.Terminal.open(id, node.data('full_hostname'));
        });

        this.cy.on('mouseover', 'node[type="host"]', (evt) => {
            this.showTooltip(evt.target, evt.renderedPosition);
        });

        this.cy.on('mouseout', 'node[type="host"]', (evt) => {
            this.scheduleHideTooltip(evt.target);
        });

        this.cy.on('pan zoom', () => {
            this.clearAllTooltips();
        });
    },

    layout() {
        if(this.cy) this.cy.layout({ name: 'cose', animate: true }).run();
    },

    showTooltip(node, renderPos) {
        const id = node.id();
        if (this.tooltips[id]) {
            clearTimeout(this.tooltips[id].timeout);
            this.tooltips[id].timeout = null;
            const el = this.tooltips[id].el;
            el.style.transition = 'none';
            el.style.opacity = '1';
            return;
        }

        const containerRect = document.getElementById('cy').getBoundingClientRect();
        const x = containerRect.left + renderPos.x + 20; 
        const y = containerRect.top + renderPos.y - 20;
        const data = node.data();
        let osIcon = '<i class="fas fa-question-circle text-gray-400 text-2xl"></i>';
        if(data.os === 'windows') osIcon = '<i class="fab fa-windows text-blue-400 text-2xl"></i>';
        else if(data.os === 'linux') osIcon = '<i class="fab fa-linux text-yellow-400 text-2xl"></i>';
        else if(data.os === 'macos') osIcon = '<i class="fab fa-apple text-purple-400 text-2xl"></i>';

        const proxyBadge = data.proxy ? '<span class="bg-green-900 text-green-300 px-2 py-0.5 rounded text-[10px] uppercase font-bold border border-green-700 w-full text-center block">SOCKS5 Active</span>' : '';
        const connectionType = data.parent_id ? `<span class="text-yellow-400 font-bold">Tunneled via #${data.parent_id}</span>` : `<span class="text-green-400 font-bold">Direct</span>`;
        const osDisplay = data.os.charAt(0).toUpperCase() + data.os.slice(1);

        const el = document.createElement('div');
        el.className = 'network-tooltip bg-gray-900 border border-gray-600 shadow-2xl rounded-lg p-4 text-xs min-w-[220px] backdrop-blur-md bg-opacity-95';
        el.innerHTML = `
            <div class="flex items-start gap-3 mb-3 border-b border-gray-700 pb-2">
                ${osIcon}
                <div>
                    <div class="text-white font-bold text-sm leading-tight">${data.full_hostname}</div>
                    <div class="text-blue-400 font-mono text-xs">${data.label}</div>
                </div>
            </div>
            <div class="space-y-1.5 font-mono text-gray-300 text-[11px]">
                <div class="flex justify-between items-center"><span class="text-gray-500">Session ID:</span> <span class="bg-gray-800 px-1 rounded text-white">#${data.id.replace('s', '')}</span></div>
                <div class="flex justify-between items-center"><span class="text-gray-500">Platform:</span> <span class="text-white">${osDisplay} ${data.os_emoji}</span></div>
                <div class="flex justify-between items-center"><span class="text-gray-500">HWID:</span> <span class="text-gray-400" title="${data.hwid}">${data.hwid.substring(0, 10)}...</span></div>
                <div class="flex justify-between items-center"><span class="text-gray-500">Link:</span> ${connectionType}</div>
                ${proxyBadge ? `<div class="pt-2">${proxyBadge}</div>` : ''}
            </div>
            <div class="mt-3 text-[10px] text-gray-500 italic text-right border-t border-gray-700 pt-1">Double-click to interact</div>
        `;
        el.style.left = `${x}px`;
        el.style.top = `${y}px`;
        document.body.appendChild(el);
        this.tooltips[id] = { el: el, timeout: null };
        el.style.transition = 'opacity 0.3s ease-in-out';
        requestAnimationFrame(() => el.style.opacity = '1');
    },

    scheduleHideTooltip(node) {
        const id = node.id();
        if (!this.tooltips[id]) return;
        this.tooltips[id].timeout = setTimeout(() => {
            const entry = this.tooltips[id];
            if(!entry) return;
            const randomDuration = (Math.floor(Math.random() * 101) + 200) / 100;
            entry.el.style.transition = `opacity ${randomDuration}s ease-out`;
            requestAnimationFrame(() => { entry.el.style.opacity = '0'; });
            setTimeout(() => {
                if (entry.el && entry.el.parentNode && getComputedStyle(entry.el).opacity === '0') {
                    entry.el.parentNode.removeChild(entry.el);
                    delete this.tooltips[id];
                }
            }, randomDuration * 1000);
        }, 500); 
    },

    clearAllTooltips() {
        Object.keys(this.tooltips).forEach(id => {
            const entry = this.tooltips[id];
            if (entry.timeout) clearTimeout(entry.timeout);
            if (entry.el && entry.el.parentNode) { entry.el.parentNode.removeChild(entry.el); }
        });
        this.tooltips = {};
    }
};
