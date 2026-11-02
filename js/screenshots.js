// panel/js/screenshots.js - Screenshot viewer modal (RCM flow)
//
// Flow (SPEC §5 / Sec-11):
//   1. Send ext:load command -> agent starts Rhai job, immediately returns
//      "Extension launched as Job N" (this is NOT the screenshot data)
//   2. The server stores each frame as an RCM Sec-11 screenshot in the
//      session's package: downloads/<RootFolder>/output/screenshots/
//      screenshot.<YYYYMMDD-HHMMSS>.<toolspecific>.<ext> (+ sidecar)
//   3. Poll GET /api/hosts/:id/screenshots until a shot with a NEW file
//      path appears (snapshot taken before the command is sent), then
//      render every frame of that capture via
//      GET /api/downloads/<shot.file> (path relative to downloads/).
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

        try {
            // Snapshot existing shots BEFORE sending the command: a fast
            // capture landing between POST and snapshot would otherwise be
            // "not new" and cause a spurious 45s timeout. Diff keys on the
            // full file path (ts+toolspecific+counter is unique) - ts alone
            // has 1-second granularity and cannot detect two captures in
            // the same second. A failed snapshot fetch is retried (never
            // treated as an empty set, which would make the newest OLD
            // capture look fresh).
            let existing = null;
            for (let attempt = 0; attempt < 5 && !existing; attempt++) {
                try {
                    existing = await this._snapshotShots(url, sessionId);
                } catch (_) {
                    await new Promise(r => setTimeout(r, 1000));
                }
            }
            if (!existing) {
                ctr.innerHTML = '<p class="text-red-400 p-4">Could not list existing screenshots</p>';
                return;
            }

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

            // Poll for a new capture (up to 45s)
            const captureResult = await this._waitForFolder(url, sessionId, 45, existing);
            if (!captureResult) {
                ctr.innerHTML = '<p class="text-yellow-400 p-4">Timed out waiting for screenshot. ' +
                                'The job may still be running - try again in a moment.</p>';
                return;
            }

            await this._renderFromFolder(url, sessionId, captureResult);

        } catch (e) {
            ctr.textContent = '';
            const p = document.createElement('p');
            p.className = 'text-red-400 p-4';
            p.textContent = `Error: ${e.message}`;
            ctr.appendChild(p);
        }
    },

    // Fetch the current shot list and return the set of file paths.
    // Throws on fetch/HTTP failure so callers can retry instead of
    // diffing against a bogus empty set.
    async _snapshotShots(url, sessionId) {
        const r = await fetch(
            `${url}/api/hosts/${sessionId}/screenshots`,
            { headers: { 'X-API-KEY': window.Auth.key } }
        );
        if (!r.ok) throw new Error('snapshot fetch failed');
        const { shots } = await r.json();
        return new Set((shots || []).map(s => s.file));
    },

    // Poll /api/hosts/:id/screenshots until a shot appears whose FILE PATH
    // was not in the pre-command snapshot. Returns {ts, files:[shot,...]}
    // for all frames of that capture (frames share one capture ts).
    // No wall-clock parsing needed: avoids clock-skew issues.
    async _waitForFolder(url, sessionId, timeoutSec, existing) {
        for (let i = 0; i < timeoutSec; i++) {
            await new Promise(r => setTimeout(r, 1000));
            try {
                const r = await fetch(
                    `${url}/api/hosts/${sessionId}/screenshots`,
                    { headers: { 'X-API-KEY': window.Auth.key } }
                );
                if (!r.ok) continue; // retry next tick, never treat as empty
                const { shots } = await r.json();
                const list = shots || [];
                // Find the newest file we haven't seen before (list is
                // newest-first)
                for (const s of list) {
                    if (!existing.has(s.file)) {
                        return {
                            ts: s.ts,
                            files: list.filter(x => x.ts === s.ts),
                        };
                    }
                }
            } catch (_) { /* keep polling */ }
        }
        return null;
    },

    // Render every frame of the capture. Each shot.file is the package-
    // relative path (from downloads/) of one Sec-11 screenshot.
    // Frames are fetched with the API key header and shown via object URLs,
    // so the key never appears in a URL (browser history, proxy logs).
    // DOM-built (never innerHTML interpolation): shot.file/monitor are
    // server/agent-controlled and must not reach HTML or inline handlers.
    async _renderFromFolder(url, sessionId, { ts, files }) {
        const ctr = document.getElementById('screenshot-container');
        if (!ctr) return;

        if (!files || !files.length) {
            ctr.innerHTML = '<p class="text-gray-400 p-4">No screenshots found for this capture.</p>';
            return;
        }

        this._ts    = ts;
        this._imgs  = files;
        this._objUrls = [];

        ctr.textContent = '';
        for (const shot of files) {
            const mon = (shot.monitor === null || shot.monitor === undefined) ? '?' : shot.monitor;

            const box = document.createElement('div');
            box.className = 'border border-gray-700 rounded-lg overflow-hidden';

            const head = document.createElement('div');
            head.className = 'bg-gray-800 px-3 py-2 text-xs text-gray-400 flex justify-between';
            const span = document.createElement('span');
            span.textContent = `Monitor ${mon}`;
            head.appendChild(span);

            const img = document.createElement('img');
            img.className = 'w-full cursor-zoom-in';
            img.alt = 'loading…';

            box.appendChild(head);
            box.appendChild(img);
            ctr.appendChild(box);

            try {
                const r = await window.API.apiFetch(`/api/downloads/${shot.file}`);
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                const blob = await r.blob();
                const objUrl = URL.createObjectURL(blob);
                this._objUrls.push(objUrl);
                img.src = objUrl;
                img.addEventListener('click', () => this.fullscreen(objUrl));

                const a = document.createElement('a');
                a.href = objUrl;
                a.setAttribute('download', String(shot.file).split('/').pop());
                a.className = 'text-green-400 hover:text-white';
                a.innerHTML = '<i class="fas fa-download"></i> Save';
                head.appendChild(a);
            } catch (e) {
                if (e.message === 'unauthorized') return;
                img.alt = `failed to load: ${e.message}`;
            }
        }
    },

    fullscreen(src) {
        const overlay = document.createElement('div');
        overlay.className =
            'fixed inset-0 z-[100] bg-black/90 flex items-center justify-center cursor-pointer';
        overlay.onclick = () => overlay.remove();
        const img = document.createElement('img');
        img.src = src;
        img.className = 'max-w-full max-h-full object-contain';
        overlay.appendChild(img);
        document.body.appendChild(overlay);
    },

    close() {
        document.getElementById('screenshot-modal')?.classList.add('hidden');
        // Release object URLs created for the rendered frames
        (this._objUrls || []).forEach(u => URL.revokeObjectURL(u));
        this._objUrls = [];
    }
};