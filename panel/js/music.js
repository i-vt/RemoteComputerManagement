/**
 * MusicManager — Self-contained ambient music player for RCM Panel
 * Injects UI into bottom-right, fetches playlist from ./media/index.json,
 * visualizes audio via Web Audio API, and provides shuffle/repeat controls.
 */
window.MusicManager = (function() {
  'use strict';

  // ── Config ─────────────────────────────────────────────────────
  const CFG = {
    mediaDir: './media',
    manifest: './media/index.json',
    barCount: 48,
    fftSize: 128,
    accent: '#f59e0b',
    primary: '#3b82f6',
    secondary: '#10b981',
    bg: '#07090f',
    cardBg: '#0d1117',
    border: '#1f2937',
    textPrimary: '#e5e7eb',
    textSecondary: '#9ca3af',
    textMuted: '#6b7280'
  };

  // ── State ──────────────────────────────────────────────────────
  let audio, ctx, analyser, source, dataArray, gainNode;
  let tracks = [];
  let currentIndex = -1;
  let isPlaying = false;
  let isShuffle = true;
  let repeatMode = 'none'; // none | all | one
  let isExpanded = false;
  let animationId;
  let historyStack = []; // for "previous" in shuffle

  // ── Helpers ─────────────────────────────────────────────────────
  const $ = (sel, root) => (root || document).querySelector(sel);
  const fmtTime = (s) => {
    if (!isFinite(s)) return '0:00';
    const m = Math.floor(s / 60);
    const sec = Math.floor(s % 60);
    return `${m}:${sec.toString().padStart(2, '0')}`;
  };
  const notify = (msg, type) => {
    if (window.Toast && window.Toast.show) window.Toast.show(msg, type || 'info');
  };

  // ── Styles ──────────────────────────────────────────────────────
  function injectStyles() {
    if ($('#music-player-styles')) return;
    const style = document.createElement('style');
    style.id = 'music-player-styles';
    style.textContent = `
      #music-player {
        position: fixed;
        bottom: 18px;
        right: 18px;
        z-index: 9999;
        font-family: 'JetBrains Mono', monospace;
        user-select: none;
      }
      #music-player.minimized #music-card { display: none !important; }
      #music-player.minimized #music-fab { display: flex; }
      #music-player:not(.minimized) #music-fab { display: none; }
      #music-fab {
        width: 54px;
        height: 54px;
        border-radius: 50%;
        background: ${CFG.cardBg};
        border: 1px solid ${CFG.border};
        box-shadow: 0 8px 32px rgba(0,0,0,0.65), 0 0 0 1px rgba(245,158,11,0.08);
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: transform .2s cubic-bezier(.34,1.56,.64,1), box-shadow .2s;
        position: relative;
        overflow: hidden;
      }
      #music-fab:hover { transform: scale(1.1); box-shadow: 0 0 24px rgba(245,158,11,0.25); }
      #music-fab::before {
        content: '';
        position: absolute;
        inset: -2px;
        border-radius: 50%;
        background: conic-gradient(from 0deg, ${CFG.accent}, ${CFG.primary}, ${CFG.secondary}, ${CFG.accent});
        opacity: 0.15;
        animation: music-spin 4s linear infinite;
      }
      @keyframes music-spin { to { transform: rotate(360deg); } }
      .music-fab-inner {
        position: relative;
        z-index: 1;
        display: flex;
        align-items: flex-end;
        gap: 2px;
        height: 18px;
      }
      .music-fab-bar {
        width: 3px;
        background: linear-gradient(to top, ${CFG.primary}, ${CFG.accent});
        border-radius: 2px;
        animation: music-bounce 1.1s ease-in-out infinite;
      }
      .music-fab-bar:nth-child(1) { height: 35%; animation-delay: 0s; }
      .music-fab-bar:nth-child(2) { height: 65%; animation-delay: .15s; }
      .music-fab-bar:nth-child(3) { height: 45%; animation-delay: .3s; }
      .music-fab-bar:nth-child(4) { height: 75%; animation-delay: .1s; }
      @keyframes music-bounce {
        0%, 100% { transform: scaleY(1); opacity: 1; }
        50% { transform: scaleY(0.35); opacity: .6; }
      }
      #music-card {
        width: 340px;
        background: ${CFG.cardBg};
        border: 1px solid ${CFG.border};
        border-radius: 16px;
        box-shadow: 0 24px 64px rgba(0,0,0,0.75), 0 0 0 1px rgba(245,158,11,0.06);
        overflow: hidden;
        display: flex;
        flex-direction: column;
        animation: music-pop .28s cubic-bezier(.34,1.56,.64,1);
      }
      @keyframes music-pop {
        from { opacity: 0; transform: translateY(16px) scale(0.96); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }
      .music-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 14px;
        border-bottom: 1px solid ${CFG.border};
        background: rgba(7,9,15,0.45);
      }
      .music-header-title {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: ${CFG.accent};
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .music-header-btn {
        background: none;
        border: none;
        color: ${CFG.textMuted};
        cursor: pointer;
        padding: 5px;
        font-size: 12px;
        border-radius: 6px;
        transition: all .15s;
        width: 26px;
        height: 26px;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .music-header-btn:hover { color: ${CFG.textPrimary}; background: rgba(255,255,255,0.05); }
      .music-header-btn.active { color: ${CFG.accent}; background: rgba(245,158,11,0.1); }
      .music-viz-wrap {
        position: relative;
        height: 110px;
        background: linear-gradient(180deg, rgba(7,9,15,0) 0%, rgba(13,17,23,0.5) 100%);
        overflow: hidden;
      }
      .music-viz-wrap canvas { width: 100%; height: 100%; display: block; }
      .music-viz-overlay {
        position: absolute;
        inset: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        pointer-events: none;
      }
      .music-track-info {
        padding: 12px 16px 4px;
        text-align: center;
      }
      .music-track-title {
        font-size: 13px;
        font-weight: 600;
        color: ${CFG.textPrimary};
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .music-track-artist {
        font-size: 11px;
        color: ${CFG.textMuted};
        margin-top: 3px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .music-progress {
        padding: 8px 16px 4px;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .music-progress input[type=range] {
        flex: 1;
        -webkit-appearance: none;
        height: 3px;
        background: ${CFG.border};
        border-radius: 2px;
        outline: none;
        cursor: pointer;
      }
      .music-progress input[type=range]::-webkit-slider-thumb {
        -webkit-appearance: none;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: ${CFG.accent};
        cursor: pointer;
        box-shadow: 0 0 10px rgba(245,158,11,0.5);
        transition: transform .1s;
      }
      .music-progress input[type=range]::-webkit-slider-thumb:hover { transform: scale(1.3); }
      .music-time {
        font-size: 10px;
        color: ${CFG.textMuted};
        font-variant-numeric: tabular-nums;
        min-width: 32px;
      }
      .music-controls {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 16px;
        padding: 8px 16px 4px;
      }
      .music-btn {
        background: none;
        border: none;
        color: ${CFG.textSecondary};
        cursor: pointer;
        font-size: 14px;
        padding: 7px;
        border-radius: 8px;
        transition: all .15s;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .music-btn:hover { color: ${CFG.textPrimary}; background: rgba(255,255,255,0.04); }
      .music-btn-play {
        width: 44px;
        height: 44px;
        border-radius: 50%;
        background: linear-gradient(135deg, ${CFG.accent}, #d97706);
        color: #fff;
        font-size: 15px;
        box-shadow: 0 4px 16px rgba(245,158,11,0.35);
      }
      .music-btn-play:hover { transform: scale(1.08); box-shadow: 0 6px 22px rgba(245,158,11,0.45); color: #fff; }
      .music-footer {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 6px 16px 14px;
      }
      .music-vol {
        display: flex;
        align-items: center;
        gap: 6px;
        flex: 1;
      }
      .music-vol input[type=range] {
        flex: 1;
        -webkit-appearance: none;
        height: 3px;
        background: ${CFG.border};
        border-radius: 2px;
        outline: none;
      }
      .music-vol input[type=range]::-webkit-slider-thumb {
        -webkit-appearance: none;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: ${CFG.primary};
        cursor: pointer;
        box-shadow: 0 0 8px rgba(59,130,246,0.4);
      }
      .music-badge {
        font-size: 10px;
        padding: 2px 7px;
        border-radius: 4px;
        background: rgba(59,130,246,0.12);
        color: ${CFG.primary};
        font-weight: 700;
        letter-spacing: 0.03em;
      }
      .music-badge.on { background: rgba(16,185,129,0.12); color: ${CFG.secondary}; }
    `;
    document.head.appendChild(style);
  }

  // ── Build DOM ───────────────────────────────────────────────────
  function buildUI() {
    const wrap = document.createElement('div');
    wrap.id = 'music-player';
    wrap.className = 'minimized';
    wrap.innerHTML = `
      <div id="music-fab" title="Music Player">
        <div class="music-fab-inner">
          <div class="music-fab-bar"></div>
          <div class="music-fab-bar"></div>
          <div class="music-fab-bar"></div>
          <div class="music-fab-bar"></div>
        </div>
      </div>
      <div id="music-card" style="display:none;">
        <div class="music-header">
          <div class="music-header-title"><i class="fas fa-music"></i> RCM Audio</div>
          <div style="display:flex;gap:3px;">
            <button class="music-header-btn" id="music-btn-shuffle" title="Shuffle"><i class="fas fa-random"></i></button>
            <button class="music-header-btn" id="music-btn-repeat" title="Repeat"><i class="fas fa-redo"></i></button>
            <button class="music-header-btn" id="music-btn-minimize" title="Minimize"><i class="fas fa-chevron-down"></i></button>
          </div>
        </div>
        <div class="music-viz-wrap">
          <canvas id="music-canvas" width="340" height="110"></canvas>
          <div class="music-viz-overlay">
            <div id="music-viz-placeholder" style="color:${CFG.textMuted};font-size:11px;opacity:.6;">No audio</div>
          </div>
        </div>
        <div class="music-track-info">
          <div class="music-track-title" id="music-title">No track loaded</div>
          <div class="music-track-artist" id="music-artist">--</div>
        </div>
        <div class="music-progress">
          <span class="music-time" id="music-cur">0:00</span>
          <input type="range" id="music-progress" value="0" min="0" max="100" step="0.1">
          <span class="music-time" id="music-dur">0:00</span>
        </div>
        <div class="music-controls">
          <button class="music-btn" id="music-prev" title="Previous"><i class="fas fa-step-backward"></i></button>
          <button class="music-btn music-btn-play" id="music-play" title="Play / Pause"><i class="fas fa-play"></i></button>
          <button class="music-btn" id="music-next" title="Next"><i class="fas fa-step-forward"></i></button>
        </div>
        <div class="music-footer">
          <div class="music-vol">
            <i class="fas fa-volume-down" style="font-size:10px;color:${CFG.textMuted};"></i>
            <input type="range" id="music-vol" min="0" max="1" step="0.01" value="0.75">
            <i class="fas fa-volume-up" style="font-size:10px;color:${CFG.textMuted};"></i>
          </div>
          <span class="music-badge" id="music-badge">OFF</span>
        </div>
      </div>
    `;
    document.body.appendChild(wrap);

    // Bind controls
    $('#music-fab').addEventListener('click', () => setExpanded(true));
    $('#music-btn-minimize').addEventListener('click', (e) => { e.stopPropagation(); setExpanded(false); });
    $('#music-play').addEventListener('click', togglePlay);
    $('#music-next').addEventListener('click', () => playNext());
    $('#music-prev').addEventListener('click', () => playPrev());

    $('#music-btn-shuffle').addEventListener('click', () => {
      isShuffle = !isShuffle;
      $('#music-btn-shuffle').classList.toggle('active', isShuffle);
      notify(isShuffle ? 'Shuffle: ON' : 'Shuffle: OFF', 'info');
    });
    $('#music-btn-repeat').addEventListener('click', () => {
      const modes = ['none','all','one'];
      const idx = (modes.indexOf(repeatMode) + 1) % modes.length;
      repeatMode = modes[idx];
      const el = $('#music-btn-repeat');
      el.classList.toggle('active', repeatMode !== 'none');
      el.innerHTML = `<i class="fas ${repeatMode === 'one' ? 'fa-redo-alt' : 'fa-redo'}"></i>`;
      el.title = repeatMode === 'none' ? 'Repeat' : repeatMode === 'all' ? 'Repeat all' : 'Repeat one';
      notify(`Repeat: ${repeatMode.toUpperCase()}`, 'info');
    });

    $('#music-vol').addEventListener('input', (e) => {
      const v = parseFloat(e.target.value);
      if (gainNode) gainNode.gain.value = v;
      if (audio) audio.volume = v;
    });

    const prog = $('#music-progress');
    prog.addEventListener('input', (e) => {
      if (audio && audio.duration) {
        audio.currentTime = (parseFloat(e.target.value) / 100) * audio.duration;
      }
    });
    prog.addEventListener('mousedown', () => { if (audio) audio.pause(); });
    prog.addEventListener('mouseup', () => { if (audio && isPlaying) audio.play(); });

    // Init shuffle visual state
    $('#music-btn-shuffle').classList.toggle('active', isShuffle);
  }

  // ── Audio Engine ────────────────────────────────────────────────
  function initAudioContext() {
    if (ctx) return;
    const AC = window.AudioContext || window.webkitAudioContext;
    ctx = new AC();
    analyser = ctx.createAnalyser();
    analyser.fftSize = CFG.fftSize;
    analyser.smoothingTimeConstant = 0.82;
    dataArray = new Uint8Array(analyser.frequencyBinCount);
    gainNode = ctx.createGain();
    gainNode.gain.value = parseFloat($('#music-vol').value);
    gainNode.connect(ctx.destination);
  }

  function connectSource() {
    if (!audio || !ctx || source) return;
    try {
      source = ctx.createMediaElementSource(audio);
      source.connect(analyser);
      analyser.connect(gainNode);
    } catch (e) {
      // Cross-origin or already connected
    }
  }

  // ── Visualization Loop ──────────────────────────────────────────
  function draw() {
    animationId = requestAnimationFrame(draw);
    const canvas = $('#music-canvas');
    if (!canvas) return;
    const c = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;

    c.clearRect(0, 0, w, h);

    if (!isPlaying || !analyser) {
      // Idle ambient wave
      const t = Date.now() * 0.0015;
      c.beginPath();
      for (let i = 0; i <= w; i += 2) {
        const y = h / 2 + Math.sin(i * 0.015 + t) * 10 + Math.sin(i * 0.04 + t * 1.7) * 5;
        if (i === 0) c.moveTo(i, y); else c.lineTo(i, y);
      }
      const g = c.createLinearGradient(0, 0, w, 0);
      g.addColorStop(0, CFG.accent);
      g.addColorStop(0.5, CFG.primary);
      g.addColorStop(1, CFG.secondary);
      c.strokeStyle = g;
      c.lineWidth = 2;
      c.shadowColor = CFG.accent;
      c.shadowBlur = 8;
      c.stroke();
      c.shadowBlur = 0;
      return;
    }

    analyser.getByteFrequencyData(dataArray);
    const barW = (w / CFG.barCount) * 0.75;
    const gap = (w / CFG.barCount) * 0.25;
    const step = Math.floor(dataArray.length / CFG.barCount);

    for (let i = 0; i < CFG.barCount; i++) {
      let sum = 0;
      for (let j = 0; j < step; j++) sum += dataArray[i * step + j];
      const avg = sum / step;
      const bh = (avg / 255) * h * 0.92;
      const x = i * (barW + gap);
      const y = h - bh;

      const grad = c.createLinearGradient(0, h, 0, y);
      grad.addColorStop(0, CFG.primary + 'cc');
      grad.addColorStop(0.6, CFG.accent + 'dd');
      grad.addColorStop(1, CFG.secondary);

      c.fillStyle = grad;
      c.fillRect(x, y, barW, bh);

      // Cap
      c.fillStyle = 'rgba(255,255,255,0.85)';
      c.fillRect(x, y - 2, barW, 2);
    }

    // Reflection
    c.save();
    c.globalAlpha = 0.12;
    c.translate(0, h);
    c.scale(1, -0.28);
    for (let i = 0; i < CFG.barCount; i++) {
      let sum = 0;
      for (let j = 0; j < step; j++) sum += dataArray[i * step + j];
      const avg = sum / step;
      const bh = (avg / 255) * h * 0.92;
      c.fillStyle = CFG.primary;
      c.fillRect(i * (barW + gap), 0, barW, bh);
    }
    c.restore();
  }

  // ── Playback ────────────────────────────────────────────────────
  function loadTrack(index) {
    if (!tracks.length) return;
    if (index < 0) index = tracks.length - 1;
    if (index >= tracks.length) index = 0;

    // Remember current in history for "previous"
    if (currentIndex !== -1 && currentIndex !== index) historyStack.push(currentIndex);
    if (historyStack.length > 50) historyStack.shift();
    currentIndex = index;

    const track = tracks[index];
    if (!audio) {
      audio = new Audio();
      audio.crossOrigin = 'anonymous';
      audio.addEventListener('ended', onEnded);
      audio.addEventListener('timeupdate', onTimeUpdate);
      audio.addEventListener('loadedmetadata', onTimeUpdate);
      audio.addEventListener('play', () => { isPlaying = true; updatePlayIcon(); $('#music-viz-placeholder').style.opacity = '0'; });
      audio.addEventListener('pause', () => { isPlaying = false; updatePlayIcon(); });
      audio.addEventListener('error', () => {
        notify('Track failed to load, skipping…', 'error');
        setTimeout(playNext, 800);
      });
    }

    audio.src = track.url;
    audio.load();
    $('#music-title').textContent = track.title || 'Unknown';
    $('#music-artist').textContent = track.artist || 'Unknown Artist';
    $('#music-badge').textContent = `${index + 1} / ${tracks.length}`;
    $('#music-badge').classList.toggle('on', true);
    updatePlayIcon();

    if (!ctx) initAudioContext();
    connectSource();
    if (ctx.state === 'suspended') ctx.resume();

    audio.play().catch(() => {
      // Autoplay blocked — user must click play
    });
  }

  function playNext() {
    if (!tracks.length) return;
    let next;
    if (repeatMode === 'one') {
      next = currentIndex;
    } else if (isShuffle) {
      next = Math.floor(Math.random() * tracks.length);
      if (tracks.length > 1 && next === currentIndex) next = (next + 1) % tracks.length;
    } else {
      next = currentIndex + 1;
      if (next >= tracks.length) next = repeatMode === 'all' ? 0 : currentIndex;
    }
    loadTrack(next);
  }

  function playPrev() {
    if (!tracks.length) return;
    if (historyStack.length) {
      loadTrack(historyStack.pop());
    } else {
      let prev = isShuffle ? Math.floor(Math.random() * tracks.length) : currentIndex - 1;
      if (prev < 0) prev = tracks.length - 1;
      loadTrack(prev);
    }
  }

  function onEnded() {
    if (repeatMode === 'one') {
      audio.currentTime = 0;
      audio.play();
    } else {
      playNext();
    }
  }

  function togglePlay() {
    if (!tracks.length) {
      notify('No tracks loaded', 'warn');
      return;
    }
    if (!audio) { loadTrack(0); return; }
    if (audio.paused) {
      audio.play();
      if (ctx && ctx.state === 'suspended') ctx.resume();
    } else {
      audio.pause();
    }
  }

  function updatePlayIcon() {
    const icon = (audio && !audio.paused) ? 'fa-pause' : 'fa-play';
    $('#music-play').innerHTML = `<i class="fas ${icon}"></i>`;
  }

  function onTimeUpdate() {
    if (!audio) return;
    $('#music-cur').textContent = fmtTime(audio.currentTime);
    $('#music-dur').textContent = fmtTime(audio.duration || 0);
    const pct = audio.duration ? (audio.currentTime / audio.duration) * 100 : 0;
    $('#music-progress').value = pct;
  }

  function setExpanded(v) {
    isExpanded = v;
    $('#music-player').classList.toggle('minimized', !v);
  }

  // ── Playlist Loading ────────────────────────────────────────────
  async function loadPlaylist() {
    try {
      const res = await fetch(CFG.manifest, { cache: 'no-store' });
      if (res.ok) {
        const data = await res.json();
        const arr = Array.isArray(data) ? data : (data.tracks || []);
        tracks = arr.map(t => ({
          url: t.url || `${CFG.mediaDir}/${t.file || t}`,
          title: t.title || t.name || t.file || t,
          artist: t.artist || 'Unknown Artist'
        }));
      }
    } catch (e) {
      tracks = [];
    }

    if (!tracks.length) {
      $('#music-title').textContent = 'No tracks found';
      $('#music-artist').textContent = `Place MP3s in ${CFG.mediaDir}/`;
      $('#music-badge').textContent = '0/0';
      $('#music-badge').classList.toggle('on', false);
    } else {
      // Auto-start first track on load (will likely be blocked until interaction)
      // loadTrack(0); // Uncomment to auto-play on load
    }
  }

  // ── Public API ──────────────────────────────────────────────────
  return {
    init() {
      if ($('#music-player')) return;
      injectStyles();
      buildUI();
      loadPlaylist();
      draw();
    },
    play() { togglePlay(); },
    pause() { if (audio) audio.pause(); },
    next() { playNext(); },
    prev() { playPrev(); },
    setVolume(v) {
      const val = Math.max(0, Math.min(1, v));
      $('#music-vol').value = val;
      if (gainNode) gainNode.gain.value = val;
      if (audio) audio.volume = val;
    },
    addTrack(url, title, artist) {
      tracks.push({ url, title: title || url.split('/').pop(), artist: artist || 'Unknown Artist' });
      $('#music-badge').textContent = `${currentIndex + 1} / ${tracks.length}`;
      if (currentIndex === -1) loadTrack(0);
    },
    loadPlaylist,
    getTracks() { return tracks; },
    destroy() {
      if (animationId) cancelAnimationFrame(animationId);
      if (audio) { audio.pause(); audio.src = ''; audio = null; }
      if (ctx) { ctx.close(); ctx = null; }
      $('#music-player')?.remove();
      $('#music-player-styles')?.remove();
    }
  };
})();

// Auto-init when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => window.MusicManager.init());
} else {
  window.MusicManager.init();
}
