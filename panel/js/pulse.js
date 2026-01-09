window.BeaconManager = {
    async toggle(sessionId, btn) {
        // 1. Determine State via Class (More robust than checking icons)
        // If it has the 'text-red-500' class, it is currently in Fast Mode.
        const isCurrentlyActive = btn.classList.contains('text-red-500');
        const cmd = isCurrentlyActive ? "beacon:mode passive" : "beacon:mode active";
        
        // 2. Save state
        const originalHtml = btn.innerHTML;
        const originalClass = btn.className;
        
        // 3. Visual Loading State
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
        btn.className = "text-yellow-500 border border-yellow-500 px-3 py-1 rounded text-xs transition ml-2";

        try {
            const cleanUrl = window.Auth.url.replace(/\/$/, "");
            const res = await fetch(`${cleanUrl}/api/hosts/${sessionId}/command`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json', 
                    'X-API-KEY': window.Auth.key 
                },
                body: JSON.stringify({ command: cmd })
            });

            if(!res.ok) throw new Error("Request Failed");

            // 4. Wait 300ms before refreshing to ensure DB write completes
            setTimeout(async () => {
                if(window.API) await window.API.refreshHosts();
            }, 300);

        } catch (e) {
            console.error(e);
            // Revert visuals on failure
            btn.innerHTML = originalHtml;
            btn.className = originalClass;
            btn.disabled = false;
            alert("Failed to toggle beacon mode. Check server connection.");
        }
    }
};
