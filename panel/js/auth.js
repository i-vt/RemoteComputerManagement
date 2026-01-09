window.Auth = {
    url: localStorage.getItem('c2_url') || 'http://127.0.0.1:8080',
    key: localStorage.getItem('c2_key') || '',

    init() {
        if(this.key) {
            document.getElementById('login-modal').classList.add('hidden');
            if(window.API) window.API.startPolling();
        } else {
            document.getElementById('login-modal').classList.remove('hidden');
        }
    },

    login() {
        const url = document.getElementById('api-url').value;
        const key = document.getElementById('api-key').value;
        if(!key) return alert("API Key required");
        
        this.url = url;
        this.key = key;
        localStorage.setItem('c2_url', url);
        localStorage.setItem('c2_key', key);
        
        document.getElementById('login-modal').classList.add('hidden');
        if(window.API) window.API.startPolling();
    },

    logout() {
        localStorage.clear();
        location.reload();
    }
};
