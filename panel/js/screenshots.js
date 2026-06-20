// panel/js/screenshots.js — Screenshot viewer modal
//
// Flow:
//   1. Send ext:load command → agent starts Rhai job, immediately returns
//      "Extension launched as Job N" (this is NOT the screenshot data)
//   2. Poll GET /api/hosts/:id/screenshots until a new folder appears
//      (the server saves PNG files once the job's SCREENSHOT_DUMP output arrives)
//   3. Load images from GET /api/downloads/<folder>/monitor_N.png
//
// This decouples display from the job req_id, which always resolves to
// "Extension launched as Job N" and never to the actual screenshot data.

window.ScreenshotView = {

    async capture(sessionId) {
        const url    = window.Auth.url.replace(/\/$/, '');
        const modal  = document.getElementById('screenshot-modal');
        const ctr    = document.getElementById('screenshot-container');
        if (!modal || !ctr) return;

        modal.classList.remove('hidden');
        ctr.innerHTML = '<p class="text-gray-400 text-center p-8">Sending capture command…</p>';

        // Timestamp before sending so we can detect new folders created after now
        const beforeMs = Date.now();

        try {
            // Send ext:load command
            const res = await fetch(`${url}/api/hosts/${sessionId}/command`, {
                method: 'POST',
                headers: { 'X-API-KEY': window.Auth.key, 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    command: 'ext:load ' + btoa(
                        'let result = internal_screenshot(); "SCREENSHOT_DUMP:" + result'
                    )
                })
            });
            if (!res.ok) {
                ctr.innerHTML = '<p class="text-red-400 p-4">Failed to send command</p>';
                return;
            }

            ctr.innerHTML = '<p class="text-gray-400 text-center p-8">' +
                            '<i class="fas fa-spinner fa-spin mr-2"></i>Waiting for capture…</p>';

            // Poll for a new screenshot folder (up to 45s)
            const folder = await this._waitForFolder(url, sessionId, beforeMs, 45);
            if (!folder) {
                ctr.innerHTML = '<p class="text-yellow-400 p-4">Timed out waiting for screenshot. ' +
                                'The job may still be running — try again in a moment.</p>';
                return;
            }

            await this._renderFromFolder(url, sessionId, folder, ctr);

        } catch (e) {
            ctr.innerHTML = `<p class="text-red-400 p-4">Error: ${e.message}</p>`;
        }
    },

    // Poll /api/hosts/:id/screenshots until a folder newer than `beforeMs` appears.
    // Returns the folder name or null on timeout.
    async _waitForFolder(url, sessionId, beforeMs, timeoutSec) {
        for (let i = 0; i < timeoutSec; i++) {
            await new Promise(r => setTimeout(r, 1000));
            try {
                const r = await fetch(
                    `${url}/api/hosts/${sessionId}/screenshots`,
                    { headers: { 'X-API-KEY': window.Auth.key } }
                );
                if (!r.ok) continue;
                const { folders } = await r.json();
                if (folders && folders.length) {
                    // Folder names: screenshots_YYYYMMDD_HHMMSS_<sessid>
                    // Parse the embedded timestamp to find one created after `beforeMs`.
                    for (const f of folders) {
                        const ts = this._folderTimestamp(f);
                        if (ts && ts >= beforeMs - 3000) return f; // 3s grace window
                    }
                }
            } catch (_) { /* keep polling */ }
        }
        return null;
    },

    // Parse UTC timestamp out of folder name "screenshots_YYYYMMDD_HHMMSS_N"
    _folderTimestamp(name) {
        const m = name.match(/screenshots_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_/);
        if (!m) return null;
        return Date.UTC(+m[1], +m[2]-1, +m[3], +m[4], +m[5], +m[6]);
    },

    // Load monitor_0.png, monitor_1.png … from the API until one returns 404.
    async _renderFromFolder(url, sessionId, folder, ctr) {
        const imgs = [];
        for (let i = 0; i < 16; i++) {
            const src = `${url}/api/downloads/${folder}/monitor_${i}.png`;
            try {
                const r = await fetch(src, { headers: { 'X-API-KEY': window.Auth.key } });
                if (!r.ok) break;
                imgs.push({ src, idx: i });
            } catch (_) { break; }
        }

        if (!imgs.length) {
            ctr.innerHTML = '<p class="text-gray-400 p-4">No screenshots found in folder.</p>';
            return;
        }

        this._folder = folder;
        this._imgs   = imgs;

        ctr.innerHTML = imgs.map(({ src, idx }) => `
            <div class="border border-gray-700 rounded-lg overflow-hidden">
                <div class="bg-gray-800 px-3 py-2 text-xs text-gray-400 flex justify-between">
                    <span>Monitor ${idx}</span>
                    <a href="${src}" download="monitor_${idx}.png"
                       class="text-green-400 hover:text-white">
                        <i class="fas fa-download"></i> Save
                    </a>
                </div>
                <img src="${src}" class="w-full cursor-zoom-in"
                     onclick="ScreenshotView.fullscreen(this.src)">
            </div>
        `).join('');
    },

    fullscreen(src) {
        const overlay = document.createElement('div');
        overlay.className =
            'fixed inset-0 z-[100] bg-black/90 flex items-center justify-center cursor-pointer';
        overlay.onclick = () => overlay.remove();
        overlay.innerHTML = `<img src="${src}" class="max-w-full max-h-full object-contain">`;
        document.body.appendChild(overlay);
    },

    close() {
        document.getElementById('screenshot-modal')?.classList.add('hidden');
    }
};
