// panel/js/theme.js — Dark / Pastel Pink theme toggle
//
// Dark (default): the existing green-on-dark palette from style.css.
// Light: a soft blush-and-plum palette injected via a <style> block.
//
// Using CSS injection (not DOM walking) means new elements added after
// the toggle pick up the theme automatically.

// ─────────────────────────────────────────────────────────────────────────────
// Palette reference
//   bg-base      #fce8f3   full-page blush
//   bg-surface   #fdf2f8   sidebar / elevated panels
//   bg-elevated  #fff6fb   cards, modals, dropdowns
//   bg-overlay   #fff0f7   hover backgrounds
//   bg-hover     #fddaee   interactive hover
//
//   accent       #c0397a   hot rose — replaces teal as the primary action colour
//   accent-dim   #a02d66
//   accent-glow  rgba(192,57,122,.15)
//   accent-text  #c0397a
//
//   text-primary   #2d0a2e   deep plum
//   text-secondary #7a3060   medium rose-plum
//   text-muted     #b070a0   dusty rose
//
//   border         #f0b0d8   soft pink rule
//   border-light   #f8d0eb   very faint rule
//
//   red     #d44060   softer coral-red
//   yellow  #c07830   amber (warm)
//   blue    #7050c8   indigo-lavender (replaces flat blue)
//
//   Sidebar stays deep plum so the logo and nav remain legible.
//   Terminal area keeps a dark background; output text shifts to lavender/pink.
// ─────────────────────────────────────────────────────────────────────────────

const PINK_CSS = `

/* ── Root variable overrides ─────────────────────────────────────────── */
html.light-theme {
  --bg-base:      #fce8f3;
  --bg-surface:   #fdf2f8;
  --bg-elevated:  #fff6fb;
  --bg-overlay:   #fff0f7;
  --bg-hover:     #fddaee;

  --border:       #f0b0d8;
  --border-light: #f8d0eb;
  --border-focus: #c0397a;

  --accent:       #c0397a;
  --accent-dim:   #a02d66;
  --accent-glow:  rgba(192,57,122,.15);
  --accent-text:  #c0397a;

  --red:          #d44060;
  --red-dim:      #b83050;
  --red-bg:       rgba(212,64,96,.12);

  --yellow:       #c07830;
  --yellow-bg:    rgba(192,120,48,.12);

  --blue:         #7050c8;
  --blue-bg:      rgba(112,80,200,.12);

  --text-primary:   #2d0a2e;
  --text-secondary: #7a3060;
  --text-muted:     #b070a0;
  --text-accent:    #c0397a;

  --shadow-accent:  0 0 0 3px rgba(192,57,122,.25);
}

/* ── Page shell ──────────────────────────────────────────────────────── */
html.light-theme body { background: var(--bg-base); color: var(--text-primary); }

/* ── Sidebar — deep plum keeps contrast against the blush main area ──── */
html.light-theme #sidebar,
html.light-theme #mobile-topbar,
html.light-theme #mobile-nav,
html.light-theme .more-drawer {
  background: #1a0520;
  border-color: #3a1048;
}
html.light-theme .sidebar-logo          { border-color: #3a1048; }
html.light-theme .sidebar-footer        { border-color: #3a1048; }
html.light-theme .nav-section-label     { color: #9060a8; }
html.light-theme .nav-item              { color: #d0a0e0; }
html.light-theme .nav-item:hover        { background: rgba(192,57,122,.2); color: #f0c0e8; }
html.light-theme .nav-item.active       {
  background: rgba(192,57,122,.25);
  color: #f0b0e0;
  border-color: rgba(192,57,122,.35);
}
html.light-theme .nav-item.active i     { color: #e070c0; }
html.light-theme .sidebar-logo span     { color: #e070c0; }
html.light-theme #mobile-topbar .logo-text { color: #e070c0; }
html.light-theme .user-badge            { color: #a080b8; }
html.light-theme .status-dot.connected  { background: #c0397a; box-shadow: 0 0 6px #c0397a; }
html.light-theme .logout-btn            { color: #a080b8; }
html.light-theme .logout-btn:hover      { background: rgba(212,64,96,.2); color: #f08090; }
html.light-theme .more-handle           { background: #5a2070; }
html.light-theme .more-title            { color: #9060a8; }
html.light-theme .mobile-nav-btn        { color: #9060a8; }
html.light-theme .mobile-nav-btn.active { color: #e070c0; }
html.light-theme .mobile-nav-btn::before { background: #e070c0; }

/* ── Main content area ───────────────────────────────────────────────── */
html.light-theme #main-content         { background: var(--bg-base); }
html.light-theme .page-title           { color: var(--text-primary); }
html.light-theme .page-subtitle        { color: var(--text-muted); }

/* ── Cards ───────────────────────────────────────────────────────────── */
html.light-theme .card {
  background: var(--bg-elevated);
  border-color: var(--border);
  box-shadow: 0 1px 8px rgba(192,57,122,.08);
}
html.light-theme .card-header          { border-color: var(--border); }
html.light-theme .card-title           { color: var(--text-secondary); }

/* ── Buttons ─────────────────────────────────────────────────────────── */
html.light-theme .btn-primary {
  background: linear-gradient(135deg, #c0397a, #9b2d66);
  color: #fff;
  border-color: transparent;
  box-shadow: 0 2px 8px rgba(192,57,122,.3);
}
html.light-theme .btn-primary:hover {
  background: linear-gradient(135deg, #d4408a, #b03070);
}
html.light-theme .btn-ghost {
  background: transparent;
  color: var(--text-secondary);
  border-color: var(--border);
}
html.light-theme .btn-ghost:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
  border-color: var(--accent);
}
html.light-theme .btn-danger {
  background: var(--red-bg);
  color: var(--red);
  border-color: var(--red);
}
html.light-theme .icon-btn             { color: var(--text-muted); }
html.light-theme .icon-btn:hover       { background: var(--bg-hover); color: var(--text-primary); }

/* ── Forms ───────────────────────────────────────────────────────────── */
html.light-theme .form-input,
html.light-theme .form-select,
html.light-theme input[type="text"],
html.light-theme input[type="password"],
html.light-theme input[type="email"],
html.light-theme input[type="number"],
html.light-theme select,
html.light-theme textarea {
  background: #ffffff;
  color: var(--text-primary);
  border-color: var(--border);
}
html.light-theme .form-input:focus,
html.light-theme .form-select:focus,
html.light-theme input:focus,
html.light-theme select:focus,
html.light-theme textarea:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(192,57,122,.15);
  outline: none;
}
html.light-theme input::placeholder,
html.light-theme textarea::placeholder { color: #c090b8; }

/* ── Tables ──────────────────────────────────────────────────────────── */
html.light-theme table                 { color: var(--text-primary); }
html.light-theme thead th              { color: var(--text-muted); border-color: var(--border); }
html.light-theme tbody tr:hover        { background: var(--bg-overlay); }
html.light-theme .border-b             { border-color: var(--border) !important; }

/* ── Modals ──────────────────────────────────────────────────────────── */
html.light-theme .modal-overlay        { background: rgba(45,10,46,.5); }
html.light-theme .modal-content,
html.light-theme [class*="modal"] > div { background: var(--bg-elevated); border-color: var(--border); }
html.light-theme .modal-header         { background: var(--bg-surface); border-color: var(--border); }
html.light-theme .modal-title          { color: var(--text-primary); }
html.light-theme .modal-close          { color: var(--text-muted); }
html.light-theme .modal-close:hover    { color: var(--text-primary); background: var(--bg-hover); }

/* ── Terminal modal — keeps dark bg, shifts text to lavender/pink ─────── */
html.light-theme #terminal-modal .bg-gray-900,
html.light-theme #terminal-modal [class*="bg-gray"] {
  background: #1a0520 !important;
}
html.light-theme #term-output          { background: #1a0520; }
html.light-theme #term-input           {
  background: #2a0838;
  color: #f0c0e8;
  border-color: #5a1878;
}
html.light-theme #term-input:focus     { border-color: #c0397a; }

/* ── Toast / notification ────────────────────────────────────────────── */
html.light-theme .toast {
  background: var(--bg-elevated);
  border-color: var(--border);
  color: var(--text-primary);
  box-shadow: 0 4px 16px rgba(192,57,122,.15);
}

/* ── Tailwind grey overrides (main content only) ─────────────────────── */
html.light-theme #main-content .bg-gray-950 { background: #fce0f0 !important; }
html.light-theme #main-content .bg-gray-900 { background: #fdeef7 !important; }
html.light-theme #main-content .bg-gray-800 { background: #fff0f8 !important; }
html.light-theme #main-content .bg-gray-750 { background: #fff4fa !important; }
html.light-theme #main-content .bg-gray-700 { background: #fff0f8 !important; }
html.light-theme #main-content .bg-gray-600 { background: #f8e0f0 !important; }

html.light-theme #main-content [class*="bg-gray-800/"] { background: rgba(255,240,248,.7) !important; }
html.light-theme #main-content [class*="bg-gray-700/"] { background: rgba(253,218,238,.6) !important; }

html.light-theme #main-content .border-gray-800 { border-color: var(--border) !important; }
html.light-theme #main-content .border-gray-700 { border-color: var(--border) !important; }
html.light-theme #main-content [class*="border-gray-700/"] { border-color: rgba(240,176,216,.5) !important; }
html.light-theme #main-content [class*="border-gray-800/"] { border-color: rgba(240,176,216,.4) !important; }

html.light-theme #main-content .text-white   { color: var(--text-primary)   !important; }
html.light-theme #main-content .text-gray-100 { color: var(--text-primary)  !important; }
html.light-theme #main-content .text-gray-200 { color: var(--text-primary)  !important; }
html.light-theme #main-content .text-gray-300 { color: var(--text-secondary) !important; }
html.light-theme #main-content .text-gray-400 { color: var(--text-secondary) !important; }
html.light-theme #main-content .text-gray-500 { color: var(--text-muted)    !important; }
html.light-theme #main-content .text-gray-600 { color: var(--text-muted)    !important; }

/* Keep accent colours but adjust them to sit on a light background */
html.light-theme #main-content .text-green-400 { color: #a02d66 !important; }
html.light-theme #main-content .text-green-300 { color: #b03070 !important; }
html.light-theme #main-content .bg-green-700   { background: #c0397a !important; }
html.light-theme #main-content .bg-green-600   { background: #d4408a !important; }
html.light-theme #main-content .text-blue-400  { color: #7050c8 !important; }
html.light-theme #main-content .text-blue-300  { color: #8060d8 !important; }
html.light-theme #main-content .text-purple-400 { color: #9040b0 !important; }
html.light-theme #main-content .text-yellow-400 { color: #c07830 !important; }
html.light-theme #main-content .text-yellow-600 { color: #a06020 !important; }
html.light-theme #main-content .text-red-400   { color: var(--red) !important; }
html.light-theme #main-content .text-red-500   { color: var(--red-dim) !important; }
html.light-theme #main-content .text-red-300   { color: #e05070 !important; }
html.light-theme #main-content .text-orange-400 { color: #c06830 !important; }

html.light-theme #main-content .bg-red-900/60  { background: rgba(212,64,96,.15) !important; }
html.light-theme #main-content .bg-blue-900/60 { background: rgba(112,80,200,.15) !important; }

/* ── Loot browser ────────────────────────────────────────────────────── */
html.light-theme #loot-container       { background: #fff6fb; border-color: var(--border); }
html.light-theme #loot-breadcrumb      { background: #fdeef7; border-color: var(--border); }
html.light-theme #loot-preview-body    { background: #fdf2f8; }

/* ── Scrollbars ──────────────────────────────────────────────────────── */
html.light-theme ::-webkit-scrollbar-track { background: #fce8f3; }
html.light-theme ::-webkit-scrollbar-thumb { background: #e8a0cc; }
html.light-theme ::-webkit-scrollbar-thumb:hover { background: #d070a8; }

/* ── Glow effects — rose tint ────────────────────────────────────────── */
html.light-theme .glow-text {
  text-shadow: 0 0 10px rgba(192,57,122,.5), 0 0 25px rgba(192,57,122,.25);
}
html.light-theme .glow-accent {
  box-shadow: 0 0 0 3px rgba(192,57,122,.25);
}

/* ── Selection highlight ─────────────────────────────────────────────── */
html.light-theme ::selection {
  background: rgba(192,57,122,.25);
  color: var(--text-primary);
}
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
        const html   = document.documentElement;
        let styleEl  = document.getElementById('rcm-pink-theme');

        if (theme === 'light') {
            html.classList.add('light-theme');
            if (!styleEl) {
                styleEl = document.createElement('style');
                styleEl.id = 'rcm-pink-theme';
                document.head.appendChild(styleEl);
            }
            styleEl.textContent = PINK_CSS;
        } else {
            html.classList.remove('light-theme');
            if (styleEl) styleEl.remove();
        }
    },

    renderToggle() {
        const isDark = this.current === 'dark';
        const icon  = isDark ? 'fa-sun' : 'fa-moon';
        const label = isDark ? 'Switch to pink mode' : 'Switch to dark mode';
        ['theme-toggle', 'theme-toggle-mobile'].forEach(id => {
            const btn = document.getElementById(id);
            if (btn) { btn.innerHTML = `<i class="fas ${icon}"></i>`; btn.title = label; }
        });
    }
};
