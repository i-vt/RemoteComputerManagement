/**
 * MusicManager - Ambient music player for RCM Panel
 * Injects a bottom-right player that fetches ./panel/media/index.json,
 * visualizes audio via Web Audio API, and provides shuffle/repeat controls.
 * Theme-matched to the RCM design system (style.css variables).
 */
window.MusicManager = (function() {
  'use strict';

  // ── Config ─────────────────────────────────────────────────────
  const CFG = {
    mediaDir: './panel/media',
    manifest: './panel/media/index.json',
    barCount: 40,
    fftSize: 128,
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
  let historyStack = [];
  let wasDrag = false;

  // ── Helpers ────────────────────────────────────────────────────
  const $ = (sel, root) => (root || document).querySelector(sel);
  const fmtTime = (s) => {
    if (!isFinite(s)) return '0:00';
    const m = Math.floor(s / 60);
    const sec = Math.floor(s % 60);
    return `${m}:${sec.toString().padStart(2, '0')}`;
  };
  const notify = (msg, type) => {
    if (window.Toast && window.Toast.show) window.Toast.show(msg, type || 'info');
    else if (window.Notify && window.Notify.toast) window.Notify.toast(msg, type || 'info', 2500);
  };

  // ── Styles (uses RCM CSS variables) ───────────────────────────
  function injectStyles() {
    if ($('#music-player-styles')) return;
    const style = document.createElement('style');
    style.id = 'music-player-styles';
    style.textContent = `
      /* ── Player Shell ─────────────────────────────────────────── */
      #music-player {
        position: fixed;
        bottom: 18px;
        right: 18px;
        z-index: 9999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
        user-select: none;
      }
      @media (max-width: 767px) {
        #music-player {
          bottom: calc(var(--nav-h) + var(--nav-safe) + 12px);
          right: 12px;
        }
      }

      /* Minimized: show FAB, hide card */
      #music-player.minimized #music-card { display: none !important; }
      #music-player.minimized #music-fab { display: flex; }

      /* Expanded: hide FAB, show card */
      #music-player:not(.minimized) #music-fab { display: none !important; }
      #music-player:not(.minimized) #music-card { display: flex !important; }

      /* ── Floating Action Button ───────────────────────────────── */
      #music-fab {
        width: 52px;
        height: 52px;
        border-radius: 50%;
        background: var(--bg-surface);
        border: 1px solid var(--border);
        box-shadow: var(--shadow-lg), 0 0 0 1px rgba(16,185,129,0.08);
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: transform .2s cubic-bezier(.34,1.56,.64,1), box-shadow .2s;
        position: relative;
        overflow: hidden;
      }
      #music-fab:hover { transform: scale(1.08); box-shadow: 0 0 24px rgba(16,185,129,0.22); }
      #music-fab::before {
        content: '';
        position: absolute;
        inset: -2px;
        border-radius: 50%;
        background: conic-gradient(from 0deg, var(--accent), var(--blue), var(--yellow), var(--accent));
        opacity: 0.12;
        animation: music-spin 4s linear infinite;
      }
      @keyframes music-spin { to { transform: rotate(360deg); } }
      .music-fab-inner {
        position: relative;
        z-index: 1;
        display: flex;
        align-items: flex-end;
        gap: 2px;
        height: 16px;
      }
      .music-fab-bar {
        width: 3px;
        background: linear-gradient(to top, var(--blue), var(--accent));
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

      /* ── Card ─────────────────────────────────────────────────── */
      #music-card {
        width: 340px;
        max-width: calc(100vw - 32px);
        background: var(--bg-surface);
        border: 1px solid var(--border);
        border-radius: var(--r-lg);
        box-shadow: var(--shadow-lg), 0 0 0 1px rgba(16,185,129,0.04);
        overflow: hidden;
        flex-direction: column;
        animation: music-pop .26s cubic-bezier(.34,1.56,.64,1);
      }
      @keyframes music-pop {
        from { opacity: 0; transform: translateY(14px) scale(0.96); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }

      .music-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 14px;
        border-bottom: 1px solid var(--border);
        background: var(--bg-elevated);
        flex-shrink: 0;
      }
      .music-header-title {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--accent);
        display: flex;
        align-items: center;
        gap: 6px;
        font-family: 'JetBrains Mono', monospace;
      }
      .music-header-btn {
        background: none;
        border: none;
        color: var(--text-muted);
        cursor: pointer;
        padding: 5px;
        font-size: 12px;
        border-radius: var(--r-sm);
        transition: all .15s;
        width: 26px;
        height: 26px;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .music-header-btn:hover { color: var(--text-primary); background: var(--bg-hover); }
      .music-header-btn.active { color: var(--accent); background: var(--accent-glow); }

      /* ── Visualization ────────────────────────────────────────── */
      .music-viz-wrap {
        position: relative;
        height: 100px;
        background: linear-gradient(180deg, rgba(7,9,15,0) 0%, rgba(13,17,23,0.5) 100%);
        overflow: hidden;
        flex-shrink: 0;
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

      /* ── Track Info ───────────────────────────────────────────── */
      .music-track-info {
        padding: 12px 16px 4px;
        text-align: center;
        flex-shrink: 0;
      }
      .music-track-title {
        font-size: 13px;
        font-weight: 600;
        color: var(--text-primary);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .music-track-artist {
        font-size: 11px;
        color: var(--text-muted);
        margin-top: 3px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      /* ── Progress ───────────────────────────────────────────── */
      .music-progress {
        padding: 8px 16px 4px;
        display: flex;
        align-items: center;
        gap: 8px;
        flex-shrink: 0;
      }
      .music-progress input[type=range] {
        flex: 1;
        -webkit-appearance: none;
        height: 3px;
        background: var(--border);
        border-radius: 2px;
        outline: none;
        cursor: pointer;
      }
      .music-progress input[type=range]::-webkit-slider-thumb {
        -webkit-appearance: none;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: var(--accent);
        cursor: pointer;
        box-shadow: 0 0 10px rgba(16,185,129,0.5);
        transition: transform .1s;
      }
      .music-progress input[type=range]::-webkit-slider-thumb:hover { transform: scale(1.3); }
      .music-time {
        font-size: 10px;
        color: var(--text-muted);
        font-variant-numeric: tabular-nums;
        min-width: 32px;
        font-family: 'JetBrains Mono', monospace;
      }

      /* ── Controls ─────────────────────────────────────────────── */
      .music-controls {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 16px;
        padding: 6px 16px 4px;
        flex-shrink: 0;
      }
      .music-btn {
        background: none;
        border: none;
        color: var(--text-secondary);
        cursor: pointer;
        font-size: 14px;
        padding: 7px;
        border-radius: var(--r-sm);
        transition: all .15s;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
      }
      .music-btn:hover { color: var(--text-primary); background: var(--bg-hover); }
      .music-btn-play {
        width: 42px;
        height: 42px;
        border-radius: 50%;
        background: var(--accent);
        color: #000;
        font-size: 14px;
        box-shadow: 0 4px 16px rgba(16,185,129,0.35);
      }
      .music-btn-play:hover {
        transform: scale(1.08);
        box-shadow: 0 6px 22px rgba(16,185,129,0.45);
        color: #000;
        background: var(--accent-text);
      }

      /* ── Footer ───────────────────────────────────────────────── */
      .music-footer {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 6px 16px 14px;
        flex-shrink: 0;
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
        background: var(--border);
        border-radius: 2px;
        outline: none;
      }
      .music-vol input[type=range]::-webkit-slider-thumb {
        -webkit-appearance: none;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: var(--blue);
        cursor: pointer;
        box-shadow: 0 0 8px rgba(59,130,246,0.4);
      }
      .music-badge {
        font-size: 10px;
        padding: 2px 7px;
        border-radius: var(--r-sm);
        background: var(--blue-bg);
        color: var(--blue);
        font-weight: 700;
        letter-spacing: 0.03em;
        font-family: 'JetBrains Mono', monospace;
      }
      .music-badge.on { background: rgba(16,185,129,0.12); color: var(--accent); }
    `;
    document.head.appendChild(style);
  }

  // ── Build DOM ───────────────────────────────────────────────────
  function buildUI() {
    if ($('#music-player')) return;
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
      <div id="music-card">
        <div class="music-header">
          <div class="music-header-title"><i class="fas fa-music"></i> RCM Audio</div>
          <div style="display:flex;gap:3px;">
            <button class="music-header-btn" id="music-btn-shuffle" title="Shuffle"><i class="fas fa-random"></i></button>
            <button class="music-header-btn" id="music-btn-repeat" title="Repeat"><i class="fas fa-redo"></i></button>
            <button class="music-header-btn" id="music-btn-minimize" title="Minimize"><i class="fas fa-chevron-down"></i></button>
          </div>
        </div>
        <div class="music-viz-wrap">
          <canvas id="music-canvas" width="340" height="100"></canvas>
          <div class="music-viz-overlay">
            <div id="music-viz-placeholder" style="color:var(--text-muted);font-size:11px;opacity:.6;">No audio</div>
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
            <i class="fas fa-volume-down" style="font-size:10px;color:var(--text-muted);"></i>
            <input type="range" id="music-vol" min="0" max="1" step="0.01" value="0.75">
            <i class="fas fa-volume-up" style="font-size:10px;color:var(--text-muted);"></i>
          </div>
          <span class="music-badge" id="music-badge">OFF</span>
        </div>
      </div>
    `;
    document.body.appendChild(wrap);

    // ── Bind controls ────────────────────────────────────────────
    $('#music-fab').addEventListener('click', () => setExpanded(true));
    $('#music-btn-minimize').addEventListener('click', (e) => {
      e.stopPropagation();
      setExpanded(false);
    });
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
    prog.addEventListener('mousedown', () => { wasDrag = true; if (audio) audio.pause(); });
    prog.addEventListener('mouseup', () => {
      wasDrag = false;
      if (audio && isPlaying) audio.play();
    });

    // Init visual state
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
      // Already connected or cross-origin
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
    const dpr = window.devicePixelRatio || 1;

    // Handle retina
    if (canvas.clientWidth && canvas.width !== canvas.clientWidth * dpr) {
      canvas.width = canvas.clientWidth * dpr;
      canvas.height = canvas.clientHeight * dpr;
      c.scale(dpr, dpr);
    }

    const drawW = canvas.clientWidth || w;
    const drawH = canvas.clientHeight || h;
    c.clearRect(0, 0, drawW, drawH);

    if (!isPlaying || !analyser) {
      // Idle ambient wave
      const t = Date.now() * 0.0015;
      c.beginPath();
      for (let i = 0; i <= drawW; i += 2) {
        const y = drawH / 2 + Math.sin(i * 0.015 + t) * 8 + Math.sin(i * 0.04 + t * 1.7) * 4;
        if (i === 0) c.moveTo(i, y); else c.lineTo(i, y);
      }
      const g = c.createLinearGradient(0, 0, drawW, 0);
      g.addColorStop(0, '#10b981');
      g.addColorStop(0.5, '#3b82f6');
      g.addColorStop(1, '#f59e0b');
      c.strokeStyle = g;
      c.lineWidth = 2;
      c.shadowColor = '#10b981';
      c.shadowBlur = 8;
      c.stroke();
      c.shadowBlur = 0;
      return;
    }

    analyser.getByteFrequencyData(dataArray);
    const barW = (drawW / CFG.barCount) * 0.72;
    const gap = (drawW / CFG.barCount) * 0.28;
    const step = Math.floor(dataArray.length / CFG.barCount);

    for (let i = 0; i < CFG.barCount; i++) {
      let sum = 0;
      for (let j = 0; j < step; j++) sum += dataArray[i * step + j];
      const avg = sum / step;
      const bh = (avg / 255) * drawH * 0.88;
      const x = i * (barW + gap);
      const y = drawH - bh;

      const grad = c.createLinearGradient(0, drawH, 0, y);
      grad.addColorStop(0, 'rgba(59,130,246,0.85)');
      grad.addColorStop(0.5, 'rgba(16,185,129,0.9)');
      grad.addColorStop(1, 'rgba(245,158,11,0.95)');

      c.fillStyle = grad;
      c.fillRect(x, y, barW, bh);

      // Cap
      c.fillStyle = 'rgba(255,255,255,0.8)';
      c.fillRect(x, y - 2, barW, 2);
    }

    // Reflection
    c.save();
    c.globalAlpha = 0.1;
    c.translate(0, drawH);
    c.scale(1, -0.25);
    for (let i = 0; i < CFG.barCount; i++) {
      let sum = 0;
      for (let j = 0; j < step; j++) sum += dataArray[i * step + j];
      const avg = sum / step;
      const bh = (avg / 255) * drawH * 0.88;
      c.fillStyle = '#3b82f6';
      c.fillRect(i * (barW + gap), 0, barW, bh);
    }
    c.restore();
  }

  // ── Playback ────────────────────────────────────────────────────
  function loadTrack(index) {
    if (!tracks.length) return;
    if (index < 0) index = tracks.length - 1;
    if (index >= tracks.length) index = 0;

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
      audio.addEventListener('play', () => {
        isPlaying = true;
        updatePlayIcon();
        const ph = $('#music-viz-placeholder');
        if (ph) ph.style.opacity = '0';
      });
      audio.addEventListener('pause', () => {
        isPlaying = false;
        updatePlayIcon();
      });
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
      // Autoplay blocked - user must click play
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
      notify('No tracks loaded', 'warning');
      return;
    }
    if (!audio) { loadTrack(currentIndex >= 0 ? currentIndex : 0); return; }
    if (audio.paused) {
      audio.play();
      if (ctx && ctx.state === 'suspended') ctx.resume();
    } else {
      audio.pause();
    }
  }

  function updatePlayIcon() {
    const icon = (audio && !audio.paused) ? 'fa-pause' : 'fa-play';
    const btn = $('#music-play');
    if (btn) btn.innerHTML = `<i class="fas ${icon}"></i>`;
  }

  function onTimeUpdate() {
    if (!audio || wasDrag) return;
    $('#music-cur').textContent = fmtTime(audio.currentTime);
    $('#music-dur').textContent = fmtTime(audio.duration || 0);
    const pct = audio.duration ? (audio.currentTime / audio.duration) * 100 : 0;
    $('#music-progress').value = pct;
  }

  function setExpanded(v) {
    isExpanded = v;
    const player = $('#music-player');
    if (player) player.classList.toggle('minimized', !v);
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
    } else if (currentIndex === -1) {
      // Pre-select a random track so the UI isn't empty on load
      const rand = Math.floor(Math.random() * tracks.length);
      currentIndex = rand;
      const track = tracks[rand];
      $('#music-title').textContent = track.title || 'Unknown';
      $('#music-artist').textContent = track.artist || 'Unknown Artist';
      $('#music-badge').textContent = `${rand + 1} / ${tracks.length}`;
      $('#music-badge').classList.toggle('on', true);
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
      const vol = $('#music-vol');
      if (vol) vol.value = val;
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