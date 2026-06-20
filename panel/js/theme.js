// panel/js/theme.js — Dark / Light theme toggle
//
// Uses CSS injection rather than walking the DOM to swap Tailwind class names.
// A <style id="rcm-light-theme"> block is inserted/removed on toggle.
// This approach is persistent across dynamic content and doesn't break when
// new elements are added after the toggle fires.

const LIGHT_CSS = `
  /* ── CSS variable overrides ──────────────────────────────── */
  :root {
    --bg-primary:     #f3f4f6;
    --bg-secondary:   #ffffff;
    --bg-sidebar:     #1e293b;
    --text-primary:   #111827;
    --text-secondary: #374151;
    --text-muted:     #6b7280;
    --border:         #d1d5db;
    --red:            #dc2626;
  }

  /* ── Tailwind utility overrides (main content area only) ─── */
  main.light-main { background-color: #f1f5f9 !important; }

  main.light-main .bg-gray-900  { background-color: #f8fafc !important; }
  main.light-main .bg-gray-800  { background-color: #ffffff !important; }
  main.light-main .bg-gray-750  { background-color: #f1f5f9 !important; }
  main.light-main .bg-gray-700  { background-color: #e5e7eb !important; }
  main.light-main .bg-gray-600  { background-color: #d1d5db !important; }

  main.light-main .border-gray-700 { border-color: #d1d5db !important; }
  main.light-main .border-gray-600 { border-color: #e5e7eb !important; }
  main.light-main .border-gray-800 { border-color: #e5e7eb !important; }

  main.light-main .text-white   { color: #111827 !important; }
  main.light-main .text-gray-200 { color: #1f2937 !important; }
  main.light-main .text-gray-300 { color: #374151 !important; }
  main.light-main .text-gray-400 { color: #6b7280 !important; }
  main.light-main .text-gray-500 { color: #9ca3af !important; }

  main.light-main input,
  main.light-main select,
  main.light-main textarea {
    background-color: #ffffff !important;
    color: #111827 !important;
    border-color: #d1d5db !important;
  }

  main.light-main .card  { background-color: #ffffff !important; border-color: #e5e7eb !important; }
  main.light-main .modal-overlay { background: rgba(0,0,0,0.5) !important; }
  main.light-main [class*="bg-gray-800\\/"] { background-color: rgba(255,255,255,0.6) !important; }
  main.light-main [class*="bg-gray-700\\/"] { background-color: rgba(241,245,249,0.8) !important; }
`;

window.Theme = {
    current: localStorage.getItem('rcm-theme') || 'dark',

    init() {
        this.apply(this.current);
        this.renderToggle();
    },

    toggle() {
        this.current = this.current === 'dark' ? 'light' : 'dark';
        localStorage.setItem('rcm-theme', this.current);
        this.apply(this.current);
        this.renderToggle();
    },

    apply(theme) {
        const main = document.getElementById('main-content');
        let styleEl = document.getElementById('rcm-light-theme');

        if (theme === 'light') {
            // Inject CSS override block if not already present
            if (!styleEl) {
                styleEl = document.createElement('style');
                styleEl.id = 'rcm-light-theme';
                document.head.appendChild(styleEl);
            }
            styleEl.textContent = LIGHT_CSS;
            if (main) main.classList.add('light-main');
        } else {
            // Remove the override block → fall back to dark Tailwind defaults
            if (styleEl) styleEl.remove();
            if (main) main.classList.remove('light-main');
        }
    },

    renderToggle() {
        const icon = this.current === 'dark' ? 'fa-sun' : 'fa-moon';
        const label = this.current === 'dark' ? 'Light mode' : 'Dark mode';
        const html = `<i class="fas ${icon}"></i>`;
        ['theme-toggle', 'theme-toggle-mobile'].forEach(id => {
            const btn = document.getElementById(id);
            if (btn) { btn.innerHTML = html; btn.title = label; }
        });
    }
};
