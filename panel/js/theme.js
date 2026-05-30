// panel/js/theme.js — Dark/Light theme toggle with CSS variables
window.Theme = {
    current: localStorage.getItem('theme') || 'dark',

    init() {
        this.apply(this.current);
        this.renderToggle();
    },

    toggle() {
        this.current = this.current === 'dark' ? 'light' : 'dark';
        localStorage.setItem('theme', this.current);
        this.apply(this.current);
        this.renderToggle();
    },

    apply(theme) {
        const root = document.documentElement;
        if(theme === 'light') {
            root.classList.add('light-theme');
            // Override Tailwind's dark defaults via CSS custom properties
            document.body.style.setProperty('--bg-primary', '#f3f4f6');
            document.body.style.setProperty('--bg-secondary', '#ffffff');
            document.body.style.setProperty('--bg-sidebar', '#1f2937');
            document.body.style.setProperty('--text-primary', '#111827');
            document.body.style.setProperty('--text-secondary', '#4b5563');
            document.body.style.setProperty('--border-color', '#d1d5db');
            // Apply to main area only (sidebar stays dark)
            const main = document.querySelector('main');
            if(main) {
                main.classList.remove('bg-gray-900');
                main.classList.add('bg-gray-100');
                main.querySelectorAll('.bg-gray-800').forEach(el => {
                    el.classList.remove('bg-gray-800');
                    el.classList.add('bg-white', 'light-card');
                });
                main.querySelectorAll('.text-white').forEach(el => {
                    el.classList.add('light-text');
                });
            }
        } else {
            root.classList.remove('light-theme');
            const main = document.querySelector('main');
            if(main) {
                main.classList.add('bg-gray-900');
                main.classList.remove('bg-gray-100');
                main.querySelectorAll('.light-card').forEach(el => {
                    el.classList.add('bg-gray-800');
                    el.classList.remove('bg-white', 'light-card');
                });
                main.querySelectorAll('.light-text').forEach(el => {
                    el.classList.remove('light-text');
                });
            }
        }
    },

    renderToggle() {
        const btn = document.getElementById('theme-toggle');
        if(btn) {
            const icon = this.current === 'dark' ? 'fa-sun' : 'fa-moon';
            btn.innerHTML = `<i class="fas ${icon}"></i>`;
        }
    }
};
