// panel/js/screenshots.js — Screenshot viewer modal
window.ScreenshotView = {
    async capture(sessionId) {
        const url = window.Auth.url.replace(/\/$/, '');
        const modal = document.getElementById('screenshot-modal');
        const container = document.getElementById('screenshot-container');
        if(!modal || !container) return;

        modal.classList.remove('hidden');
        container.innerHTML = '<p class="text-gray-400 text-center p-8">Capturing screenshots...</p>';

        try {
            const res = await fetch(`${url}/api/hosts/${sessionId}/command`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: 'ext:load ' + btoa('let result = internal_screenshot(); "SCREENSHOT_DUMP:" + result') })
            });
            if(!res.ok) { container.innerHTML = '<p class="text-red-400 p-4">Failed to send command</p>'; return; }
            const data = await res.json();

            // Poll for result (screenshots can take a few seconds)
            for(let i = 0; i < 30; i++) {
                await new Promise(r => setTimeout(r, 1000));
                const out = await fetch(`${url}/api/hosts/${sessionId}/output/${data.request_id}`, {
                    headers: { 'X-API-KEY': window.Auth.key }
                });
                if(!out.ok) continue;
                const result = await out.json();
                if(result.status === 'completed' && result.output) {
                    this.renderScreenshots(container, result.output);
                    return;
                }
            }
            container.innerHTML = '<p class="text-yellow-400 p-4">Timeout — the job may still be running. Check Jobs panel.</p>';
        } catch(e) {
            container.innerHTML = `<p class="text-red-400 p-4">Error: ${e.message}</p>`;
        }
    },

    renderScreenshots(container, output) {
        // Output is either raw JSON array or prefixed with JOB_FINAL/SCREENSHOT_DUMP
        let jsonStr = output;
        if(jsonStr.includes('SCREENSHOT_DUMP:')) jsonStr = jsonStr.split('SCREENSHOT_DUMP:')[1];
        if(jsonStr.includes('JOB_FINAL:')) jsonStr = jsonStr.split('|').slice(1).join('|');

        try {
            const screenshots = JSON.parse(jsonStr);
            if(!screenshots.length) {
                container.innerHTML = '<p class="text-gray-400 p-4">No screenshots captured</p>';
                return;
            }

            container.innerHTML = screenshots.map((s, i) => `
                <div class="border border-gray-700 rounded-lg overflow-hidden">
                    <div class="bg-gray-800 px-3 py-2 text-xs text-gray-400 flex justify-between">
                        <span>Monitor ${s.monitor_index} (${s.width}×${s.height})</span>
                        <button onclick="ScreenshotView.download(${i})" class="text-green-400 hover:text-white">
                            <i class="fas fa-download"></i> Save
                        </button>
                    </div>
                    <img src="data:image/png;base64,${s.b64}" class="w-full cursor-zoom-in" 
                         onclick="ScreenshotView.fullscreen(this.src)" data-idx="${i}">
                </div>
            `).join('');
            this._screenshots = screenshots;
        } catch(e) {
            const safeJson = jsonStr.substring(0, 500).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
            container.innerHTML = `<p class="text-red-400 p-4">Parse error: ${e.message}</p><pre class="text-xs text-gray-500 p-2 max-h-32 overflow-auto">${safeJson}</pre>`;
        }
    },

    fullscreen(src) {
        const overlay = document.createElement('div');
        overlay.className = 'fixed inset-0 z-[100] bg-black/90 flex items-center justify-center cursor-pointer';
        overlay.onclick = () => overlay.remove();
        overlay.innerHTML = `<img src="${src}" class="max-w-full max-h-full object-contain">`;
        document.body.appendChild(overlay);
    },

    download(idx) {
        if(!this._screenshots?.[idx]) return;
        const s = this._screenshots[idx];
        const link = document.createElement('a');
        link.href = `data:image/png;base64,${s.b64}`;
        link.download = `screenshot_monitor${s.monitor_index}.png`;
        link.click();
    },

    close() {
        document.getElementById('screenshot-modal')?.classList.add('hidden');
    }
};
