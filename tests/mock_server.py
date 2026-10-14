#!/usr/bin/env python3
# tests/mock_server.py
#
# RCM mock C2 server - a lightweight, dependency-free stand-in for the real
# Rust team server. It implements every REST endpoint the web panel consumes
# (docs/api.md) with realistic faux data so the full UX/UI can be exercised
# without compiling or running the actual server, database, or agents.
#
#   * Serves the real panel from ./panel at http://127.0.0.1:18080/
#   * Mirrors the real API surface: auth (X-API-KEY), RBAC roles
#     (admin/operator/viewer), sessions, commands, files, loot, builder
#     jobs, task queue, topology, listeners, IOCs, notes, ...
#   * Simulated agent behaviour: commands "execute" after a short delay,
#     queued hibernation tasks move pending -> claimed -> completed,
#     screenshot captures materialise a few seconds after the ext:load,
#     and a demo session checks in ~45s after startup.
#   * 100% Python standard library - no pip install required.
#
# Nothing here talks to a real agent, database, or filesystem outside the
# repository root. All state is in-memory and resets on restart.
#
# Usage (from the repository root):
#   python3 tests/mock_server.py [--port 18080] [--host 127.0.0.1]
# or simply:
#   ./tests/run_mock_server.sh
#
# Demo credentials:
#   admin / admin        (role: admin)
#   operator / operator  (role: operator)
#   viewer / viewer      (role: viewer)

import argparse
import base64
import binascii
import io
import json
import os
import random
import re
import struct
import sys
import threading
import time
import urllib.parse
import uuid
import zipfile
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 1.1.0: login-page reload-loop fix (public c2-hints/logout, empty-key boot
#        probes get 200 instead of 401), default port 18080, no-store statics.
# Check the RUNNING server with: curl -si http://HOST:PORT/api/server/c2-hints
# -> the Server header shows the version; a 401 there means an old process.
VERSION = "1.1.0"
START_TIME = time.time()

# ── Small helpers ────────────────────────────────────────────────────────────

def now_ts() -> float:
    return time.time()

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def iso_ago(secs: float) -> str:
    return datetime.fromtimestamp(time.time() - secs, timezone.utc).isoformat()

def iso_in(secs: float) -> str:
    return datetime.fromtimestamp(time.time() + secs, timezone.utc).isoformat()

def shot_ts(offset_secs: float = 0) -> str:
    return datetime.fromtimestamp(time.time() - offset_secs, timezone.utc).strftime("%Y%m%d-%H%M%S")

def rand_hex(n: int = 8) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))

# ── Pure-stdlib PNG renderer (faux screenshots) ─────────────────────────────
# Draws a plausible "desktop capture": gradient wallpaper, a taskbar strip and
# a few overlapping window rectangles with title bars. The seed (capture
# timestamp + monitor) makes every capture visually distinct.

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", binascii.crc32(tag + data) & 0xFFFFFFFF))

def make_png(width: int, height: int, seed: str) -> bytes:
    rng = random.Random(seed)
    hue = rng.randint(0, 359)

    def hsl(h, s, l):
        c = (1 - abs(2 * l - 1)) * s
        x = c * (1 - abs((h / 60.0) % 2 - 1))
        m = l - c / 2
        for seg, rgb in enumerate(((c, x, 0), (x, c, 0), (0, c, x),
                                   (0, x, c), (x, 0, c), (c, 0, x))):
            if seg * 60 <= h < (seg + 1) * 60:
                return tuple(int((v + m) * 255) for v in rgb)
        return tuple(int((v + m) * 255) for v in (c, x, 0))

    top = hsl(hue, 0.45, 0.16)
    bottom = hsl((hue + 40) % 360, 0.50, 0.30)
    buf = bytearray(width * height * 3)

    for y in range(height):
        f = y / max(1, height - 1)
        r = int(top[0] + (bottom[0] - top[0]) * f)
        g = int(top[1] + (bottom[1] - top[1]) * f)
        b = int(top[2] + (bottom[2] - top[2]) * f)
        row = bytes((r, g, b)) * width
        buf[y * width * 3:(y + 1) * width * 3] = row

    def rect(x0, y0, x1, y1, color):
        x0, x1 = max(0, x0), min(width, x1)
        y0, y1 = max(0, y0), min(height, y1)
        pix = bytes(color)
        line = pix * (x1 - x0)
        for yy in range(y0, y1):
            off = (yy * width + x0) * 3
            buf[off:off + len(line)] = line

    # Taskbar
    tb = hsl(0, 0.0, 0.08)
    rect(0, height - 40, width, height, tb)
    for i in range(6):  # pinned icons
        c = hsl((hue + i * 47) % 360, 0.65, 0.55)
        rect(14 + i * 40, height - 32, 14 + i * 40 + 24, height - 8, c)
    # Clock block
    rect(width - 90, height - 30, width - 14, height - 10, hsl(0, 0.0, 0.75))

    # Overlapping windows with title bars
    for i in range(rng.randint(2, 4)):
        ww = rng.randint(width // 4, width // 2)
        wh = rng.randint(height // 4, height // 2)
        wx = rng.randint(0, max(1, width - ww))
        wy = rng.randint(10, max(11, height - wh - 50))
        accent = hsl((hue + 90 + i * 60) % 360, 0.55, 0.45)
        rect(wx, wy, wx + ww, wy + 26, accent)                    # title bar
        rect(wx, wy + 26, wx + ww, wy + wh, hsl(0, 0.0, 0.92))    # body
        for ln in range(rng.randint(3, 7)):                       # "text" lines
            lw = rng.randint(ww // 4, ww - 30)
            ly = wy + 40 + ln * 18
            if ly + 8 < wy + wh:
                rect(wx + 14, ly, wx + 14 + lw, ly + 8, hsl(0, 0.0, 0.72))
        rect(wx + ww - 20, wy + 6, wx + ww - 8, wy + 20, hsl(0, 0.7, 0.5))  # close btn

    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)  # filter: none
        raw += buf[y * stride:(y + 1) * stride]

    png = b"\x89PNG\r\n\x1a\n"
    png += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += _png_chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += _png_chunk(b"IEND", b"")
    return png

# ── Faux remote filesystems ──────────────────────────────────────────────────
# Each host gets an in-memory tree so the panel's file browser, preview,
# mkdir and delete flows all behave like a live agent.
# Node: {"dir": bool, "size": int, "perms": "rw"|"r", "mod": epoch,
#        "children": {name: node} (dirs), "content": bytes (files)}

def _d(children=None, perms="rw", age=86400):
    return {"dir": True, "perms": perms, "mod": now_ts() - age,
            "children": dict(children or {}), "size": 0}

def _f(content: bytes, perms="rw", age=43200):
    return {"dir": False, "perms": perms, "mod": now_ts() - age,
            "size": len(content), "content": content}

def _t(text: str, **kw):  # text file helper
    return _f(text.encode(), **kw)

def windows_fs():
    return _d({"C:": _d({
        "Users": _d({
            "jdoe": _d({
                "Documents": _d({
                    "passwords.txt": _t("email: jdoe@acme.corp / Summer2026!\n"
                                        "vpn:   jdoe / Hunter2!\n"
                                        "bank:  saved in browser\n"),
                    "report_Q3.docx": _f(b"PK\x03\x04 faux docx payload bytes" + os.urandom(512)),
                    "notes.txt": _t("TODO:\n- renew certs\n- rotate vpn creds\n"),
                }),
                "Desktop": _d({"shortcut.lnk": _f(os.urandom(256))}),
                "Downloads": _d({"setup.exe": _f(b"MZ" + os.urandom(2048))}),
            }),
            "Public": _d({}),
        }),
        "Windows": _d({"System32": _d({"drivers": _d({})}), "Temp": _d({})}),
        "Program Files": _d({"Notepad++": _d({})}),
    })})

def linux_fs():
    return _d({
        "etc": _d({
            "passwd": _t("root:x:0:0:root:/root:/bin/bash\n"
                         "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                         "deploy:x:1000:1000::/home/deploy:/bin/bash\n"),
            "hosts": _t("127.0.0.1 localhost\n10.10.5.22 web-srv-01\n"),
            "shadow": _t("root:*:19800:0:99999:7:::\n", perms="r"),
        }),
        "home": _d({
            "deploy": _d({".ssh": _d({
                "id_rsa": _t("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                             "b3BlbnNzaC1mYXV4LW1vY2stZGF0YQ==\n"
                             "-----END OPENSSH PRIVATE KEY-----\n", perms="r"),
                "authorized_keys": _t("ssh-ed25519 AAAAC3Faux deploy@build\n"),
            })}),
        }),
        "var": _d({
            "www": _d({"html": _d({
                "index.html": _t("<h1>Acme Corp</h1>\n"),
                "backup.sql": _t("-- MySQL dump\nCREATE TABLE users(id int);\n"),
            })}),
            "log": _d({"auth.log": _t("Oct 11 09:12:01 sshd[812]: Accepted publickey for deploy\n" * 3)}),
        }),
        "tmp": _d({}),
        "opt": _d({"tools": _d({"linpeas.sh": _t("#!/bin/sh\n# faux linpeas\n")})}),
    })

def macos_fs():
    return _d({
        "Users": _d({"mlopez": _d({
            "Documents": _d({"design-brief.pages": _f(os.urandom(384))}),
            "Desktop": _d({"notes.txt": _t("wifi: CoffeeShopGuest\n")}),
        })}),
        "Applications": _d({"Safari.app": _d({})}),
        "etc": _d({"hosts": _t("127.0.0.1 localhost\n")}),
        "Volumes": _d({"Macintosh HD": _d({}), "USB": _d({"photos": _d({})})}),
    })

def fs_list(node):
    """Render a directory node as the agent's fs:ls JSON array."""
    out = []
    for name, n in node["children"].items():
        out.append({"name": name, "is_dir": n["dir"], "size": n["size"],
                    "perms": n["perms"], "mod_time": int(n["mod"])})
    out.sort(key=lambda e: (not e["is_dir"], e["name"]))
    return out

def fs_resolve(root, path):
    """Resolve an OS-appropriate path against a faux tree. Returns node or None."""
    if path in ("", ".", "/", "\\"):
        return root
    parts = [p for p in re.split(r"[/\\]+", path) if p and p != "."]
    node = root
    for p in parts:
        if not node.get("dir"):
            return None
        nxt = node["children"].get(p)
        if nxt is None:
            # Windows drive roots may appear as "C:" or "C:\" -> first component
            return None
        node = nxt
    return node

# ── Loot / downloads tree ────────────────────────────────────────────────────
# Mirrors the on-disk RCM package layout (docs: RCM Data Collection spec):
#   downloads/<HOST>/downloads/...            reconstructed target paths
#   downloads/<HOST>/downloads.metadata/...   XML sidecars
#   downloads/<HOST>/output/screenshots/...   Sec-11 captures
#   downloads/<HOST>/fingerprint.RCM.xml      machine fingerprint
# File node: {"content": bytes, "mod": epoch}; dir node: {"children": {...}, "mod": epoch}

def _ld(children=None):
    return {"children": dict(children or {}), "mod": now_ts() - 3600}

def _lf(content: bytes, age=1800):
    return {"content": content, "mod": now_ts() - age}

def loot_walk(tree, rel):
    """Walk the loot tree. Directory nodes carry 'children', files 'content'."""
    node = tree
    for part in [p for p in rel.split("/") if p]:
        if "children" not in node:  # path continues into a file
            return None
        node = node["children"].get(part)
        if node is None:
            return None
    return node

def loot_list_entries(tree, rel):
    node = loot_walk(tree, rel)
    if node is None:
        return []
    entries = []
    for name, n in node["children"].items():
        is_dir = "content" not in n
        p = f"{rel}/{name}" if rel else name
        entries.append({
            "name": name, "path": p, "is_dir": is_dir,
            "size": 0 if is_dir else len(n["content"]),
            "modified": int(n["mod"]), "children": None,
        })
    entries.sort(key=lambda e: (not e["is_dir"], -e["modified"]))
    return entries

def loot_size(tree) -> int:
    total = 0
    for n in tree["children"].values():
        if "content" in n:
            total += len(n["content"])
        else:
            total += loot_size(n)
    return total

# ── Central in-memory state ──────────────────────────────────────────────────

class State:
    def __init__(self, repo_root: str):
        self.lock = threading.RLock()
        self.repo_root = repo_root

        # Operators (username -> record). Passwords in the clear: this is a mock.
        self.operators = {
            "admin":    {"id": 1, "username": "admin", "password": "admin",
                         "role": "admin",
                         "created_at": iso_ago(90 * 86400), "last_login": None},
            "operator": {"id": 2, "username": "operator", "password": "operator",
                         "role": "operator",
                         "created_at": iso_ago(60 * 86400), "last_login": iso_ago(86400)},
            "viewer":   {"id": 3, "username": "viewer", "password": "viewer",
                         "role": "viewer",
                         "created_at": iso_ago(30 * 86400), "last_login": None},
        }
        self.api_keys = {}           # key -> username
        self._next_op_id = 4

        # Faux sessions (id -> host dict). last_seen is an epoch; the DTO
        # computes last_seen_secs from it on every poll.
        self.hosts = {}
        self._next_host_id = 1
        self._spawn_initial_hosts()

        # Command execution: (session_id, request_id) -> result record
        self.results = {}
        self._next_request_id = 1000
        self.history = []            # UnifiedHistoryDto rows
        self._seed_history()

        self.audit = []              # audit_log rows
        self._next_audit_id = 1
        self._seed_audit()

        self.listeners = [
            {"id": 1, "name": "tls-main",      "port": 4443, "transport": "tls",
             "profile_json": None, "auto_start": True,  "running": True,
             "created_at": iso_ago(12 * 86400)},
            {"id": 2, "name": "https-slack",   "port": 8443, "transport": "https",
             "profile_json": '{"profile":"slack"}', "auto_start": True, "running": True,
             "created_at": iso_ago(9 * 86400)},
            {"id": 3, "name": "http-fallback", "port": 9000, "transport": "http",
             "profile_json": None, "auto_start": False, "running": False,
             "created_at": iso_ago(2 * 86400)},
        ]
        self._next_listener_id = 4

        self.proxies = {}            # session_id -> {session_id, tunnel_port, socks_port}
        self.rportfwds = {}          # (session_id, bind_port) -> record
        self._next_tunnel_port = 20000
        self._next_socks_port = 1080
        self._geo_pool = [
            {"ip": "203.0.113.77",  "country": "Netherlands", "country_code": "NL",
             "city": "Amsterdam", "isp": "MockNet BV"},
            {"ip": "198.51.100.23", "country": "Germany",     "country_code": "DE",
             "city": "Frankfurt", "isp": "Faux hosting GmbH"},
            {"ip": "192.0.2.140",   "country": "United States", "country_code": "US",
             "city": "Ashburn",   "isp": "Example Cloud LLC"},
        ]

        # Hibernation task queue: session_id -> [task]
        self.tasks = {}
        self._seed_tasks()

        self.iocs = [
            {"id": 1, "session_id": 1, "ioc_type": "file",
             "path": "C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe",
             "detail": "Startup folder persistence", "cleanup_cmd": "persist:startup_remove upd.exe",
             "operator": "admin", "created_at": iso_ago(3 * 86400), "cleaned_at": None},
            {"id": 2, "session_id": 5, "ioc_type": "crontab",
             "path": "@reboot /tmp/.cache/upd",
             "detail": None, "cleanup_cmd": "persist:cron_remove /tmp/.cache/upd",
             "operator": "operator", "created_at": iso_ago(86400), "cleaned_at": iso_ago(3600)},
        ]
        self._next_ioc_id = 3

        self.notes = {}              # session_id -> [note]
        self._next_note_id = 1
        self._seed_notes()

        # Scripts: seeded from the real repo directories at startup; edits are
        # kept in memory only (restart resets them).
        self.modules = self._load_scripts("modules")
        self.extensions = self._load_scripts("extensions")

        self.build_jobs = {}         # job_id -> job record
        self.payload_links = {}      # token -> {job_id, name}

        # Loot/downloads tree + RCM package metadata
        self.loot = self._seed_loot()
        self.rcm_sealed = {"DESKTOP-JDOE42": True, "WEB-SRV-01": False}
        self.rcm_generations = {"DESKTOP-JDOE42": 1, "WEB-SRV-01": 0}

        self.screenshots = {}        # session_id -> [shot dict]
        self._png_cache = {}         # shot file path -> png bytes
        self._pending_shots = {}     # session_id -> ready_at epoch
        self._seed_screenshots()

        self.webhook_url = ""
        self.recon = [
            {"id": 1, "command": "shell whoami", "sort_order": 0},
            {"id": 2, "command": "module:survey", "sort_order": 1},
        ]
        self._next_recon_id = 3

        # One-shot demo event: a fresh session checks in ~45s after startup,
        # which exercises the toast/notification and stats updates live.
        self._joiner_at = START_TIME + 45
        self._joiner_fired = False

        # sys:die / exit schedule: session_id -> drop_at epoch
        self._dying = {}

    # ── Seeding ──────────────────────────────────────────────────────────

    def _add_host(self, hostname, ip, os_name, computer_id, *, parent_id=None,
                  hibernation=False, profile="tls", fs=None, user="root",
                  beacon=30.0, tags=None, ifaces=None):
        hid = self._next_host_id
        self._next_host_id += 1
        self.hosts[hid] = {
            "id": hid, "hostname": hostname, "ip": ip, "os": os_name,
            "computer_id": computer_id, "parent_id": parent_id,
            "hibernation_mode": hibernation, "profile": profile,
            "last_seen": now_ts() - random.uniform(1, 5), "is_active": False,
            "beacon_interval": beacon, "tags": list(tags or []),
            "fs": fs, "user": user, "ifaces": ifaces or [],
            "jobs": self._seed_jobs(os_name),
        }
        return hid

    @staticmethod
    def _seed_jobs(os_name):
        base = iso_ago(2400)
        jobs = [{"id": 1, "description": "ext:load (recon)", "status": "Completed",
                 "started_at": iso_ago(5200), "finished_at": iso_ago(5100)}]
        if "windows" in os_name.lower():
            jobs.append({"id": 2, "description": "keylogger", "status": "Running",
                         "started_at": base, "finished_at": None})
        return jobs

    def _spawn_initial_hosts(self):
        self._add_host(
            "DESKTOP-JDOE42", "192.168.1.42", "Windows 11 Pro (22631)", "9F8A-7B6C-5D4E",
            profile="tls", fs=windows_fs(), user="desktop-jdoe42\\jdoe", beacon=8.0,
            tags=["interesting"],
            ifaces=[{"name": "Ethernet0", "addr": "192.168.1.42", "prefix": 24, "up": True}])
        self._add_host(
            "WEB-SRV-01", "203.0.113.10", "Linux Ubuntu 22.04", "A1B2-C3D4-E5F6",
            profile="https/slack", fs=linux_fs(), user="www-data", beacon=25.0,
            ifaces=[{"name": "eth0", "addr": "10.10.5.22", "prefix": 24, "up": True},
                    {"name": "eth1", "addr": "172.16.20.10", "prefix": 24, "up": True},
                    {"name": "docker0", "addr": "10.200.1.1", "prefix": 24, "up": False}])
        self._add_host(
            "DC-BACKUP", "172.16.20.100", "Windows Server 2022", "77AA-11BB-22CC",
            parent_id=2, profile="tls (pivot)", fs=windows_fs(),
            user="dc-backup\\administrator", beacon=40.0,
            ifaces=[{"name": "Ethernet0", "addr": "172.16.20.100", "prefix": 24, "up": True}])
        self._add_host(
            "MACBOOK-DESIGN", "192.168.1.77", "macOS 15.6 (Sequoia)", "M4C5-B00K-0001",
            profile="https", fs=macos_fs(), user="mlopez", beacon=35.0,
            ifaces=[{"name": "en0", "addr": "192.168.1.77", "prefix": 24, "up": True}])
        self._add_host(
            "DB-PROD-02", "10.20.0.15", "Linux Debian 12", "DB02-9988-7766",
            hibernation=True, profile="tls (hibernation)", fs=linux_fs(), user="root",
            beacon=300.0, tags=["production"],
            ifaces=[{"name": "eth0", "addr": "10.20.0.15", "prefix": 24, "up": True}])

    def _fire_joiner(self):
        """Late check-in used to demo live notifications."""
        self._joiner_fired = True
        self._add_host(
            "LAPTOP-ACME06", "95.103.72.18", "Windows 11 Pro (22631)", "F00D-CAFE-0606",
            profile="https/slack", fs=windows_fs(), user="laptop-acme06\\sconnor",
            beacon=6.0,
            ifaces=[{"name": "ens33", "addr": "10.10.0.77", "prefix": 16, "up": True},
                    {"name": "wlan0", "addr": "192.168.0.50", "prefix": 24, "up": True}])

    def _seed_history(self):
        seed = [
            (1, "whoami", "desktop-jdoe42\\jdoe", None, 7200),
            (1, "shell ipconfig", "Windows IP Configuration\n\nEthernet adapter Ethernet0:\n"
             "   IPv4 Address. . . . . . . . . . . : 192.168.1.42\n"
             "   Default Gateway . . . . . . . . . : 192.168.1.1\n", None, 7000),
            (1, "evasion:patch_amsi", "[+] AMSI patched (AmsiScanBuffer -> E_INVALIDARG)", None, 6900),
            (2, "shell id", "uid=33(www-data) gid=33(www-data) groups=33(www-data)", None, 5400),
            (2, "shell cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"
             "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n", None, 5300),
            (5, "shell uname -a", "Linux db-prod-02 6.1.0-31-amd64 #1 SMP Debian 6.1.128-1 x86_64 GNU/Linux", None, 3600),
        ]
        for sid, cmd, out, err, age in seed:
            self._next_request_id += 1
            self.history.append({
                "session_id": sid, "request_id": self._next_request_id,
                "command": cmd, "output": out, "error": err,
                "timestamp": iso_ago(age),
            })

    def _seed_audit(self):
        for op, action, target, details, age in [
            ("admin", "login", None, None, 7800),
            ("admin", "command", 1, "whoami", 7200),
            ("admin", "create_listener", None, "name=http-fallback port=9000 transport=http", 2 * 86400),
            ("operator", "login", None, None, 5400),
            ("operator", "command", 2, "shell id", 5400),
            ("admin", "broadcast", None, "shell whoami", 4000),
            ("operator", "stop_listener", None, "id=3", 3200),
        ]:
            self.log_audit(op, action, target, details, at=iso_ago(age))

    def _seed_tasks(self):
        self.tasks[5] = [{
            "task_id": str(uuid.uuid4()), "command": "shell df -h",
            "status": "completed", "created_at": int(now_ts()) - 4200,
            "claimed_at": int(now_ts()) - 4000,
            "result": "Filesystem      Size  Used Avail Use% Mounted on\n"
                      "/dev/sda1        40G   12G   26G  31% /\n",
            "error": None, "finished_at": int(now_ts()) - 3980,
        }]

    def _seed_notes(self):
        self._add_note(1, "Domain user jdoe - browser creds likely in Documents", tag="interesting")
        self._add_note(1, "Screenshot showed Outlook open with VPN email", tag=None)
        self._add_note(5, "Production DB - do NOT touch during business hours", tag="production")

    def _load_scripts(self, subdir):
        out = {}
        path = os.path.join(self.repo_root, subdir)
        try:
            for fname in sorted(os.listdir(path)):
                if fname.endswith(".rhai"):
                    with open(os.path.join(path, fname), "r", encoding="utf-8", errors="replace") as fh:
                        out[fname[:-5]] = fh.read()
        except OSError:
            pass
        if not out:  # fallback if the repo tree is unavailable
            out = {"survey": "// mock module\nfn run(session_id) {\n"
                             "    send_c2_command(session_id, \"whoami\");\n}\n"}
        return out

    def _seed_loot(self):
        host1 = "DESKTOP-JDOE42"
        host2 = "WEB-SRV-01"
        tree = _ld({
            host1: _ld({
                ".rcmtarget": _lf(b'{"hostname":"DESKTOP-JDOE42","computer_id":"9F8A-7B6C-5D4E"}\n'),
                "fingerprint.RCM.xml": _lf(b'<?xml version="1.0"?>\n<fingerprint host="DESKTOP-JDOE42"'
                                           b' os="Windows 11 Pro (22631)"/>\n'),
                "manifest.RCM.xml": _lf(b'<?xml version="1.0"?>\n<manifest generation="1" sealed="true"/>\n'),
                "downloads": _ld({
                    "C_": _ld({"Users": _ld({"jdoe": _ld({"Documents": _ld({
                        "passwords.txt": _lf(b"email: jdoe@acme.corp / Summer2026!\n"
                                             b"vpn:   jdoe / Hunter2!\n"),
                        "report_Q3.docx": _lf(b"PK\x03\x04 faux docx payload bytes" + os.urandom(512)),
                    })})})}),
                }),
                "downloads.metadata": _ld({
                    "C_": _ld({"Users": _ld({"jdoe": _ld({"Documents": _ld({
                        "passwords.txt.RCM.xml": _lf(b'<?xml version="1.0"?>\n<sidecar sha256="faux1"/>\n'),
                    })})})}),
                }),
                "output": _ld({"screenshots": _ld({})}),
            }),
            host2: _ld({
                "fingerprint.RCM.xml": _lf(b'<?xml version="1.0"?>\n<fingerprint host="WEB-SRV-01"'
                                           b' os="Linux Ubuntu 22.04"/>\n'),
                "downloads": _ld({
                    "var": _ld({"www": _ld({"html": _ld({
                        "backup.sql": _lf(b"-- MySQL dump 10.13  Distrib 8.0.36\n"
                                          b"CREATE TABLE users(id int, user varchar(64), pass varchar(64));\n"
                                          b"INSERT INTO users VALUES (1,'admin','$2y$fauxhash');\n"),
                    })})}),
                }),
                "downloads.metadata": _ld({}),
                "output": _ld({"screenshots": _ld({})}),
            }),
        })
        return tree

    def _seed_screenshots(self):
        # One historical capture per online Windows workstation.
        for sid in (1,):
            root = self.hosts[sid]["hostname"]
            ts = shot_ts(5400)
            fname = f"{root}/output/screenshots/screenshot.{ts}.monitor0.png"
            self.screenshots[sid] = [{"file": fname, "ts": ts, "monitor": 0}]
            self.loot["children"][root]["children"]["output"]["children"]["screenshots"]["children"][
                f"screenshot.{ts}.monitor0.png"] = _lf(b"", age=5400)

    # ── Shared mutators ──────────────────────────────────────────────────

    def log_audit(self, operator, action, target_session=None, details=None, at=None):
        self.audit.insert(0, {
            "id": self._next_audit_id, "operator_name": operator, "action": action,
            "target_session": target_session, "details": details,
            "timestamp": at or iso_now(),
        })
        self._next_audit_id += 1
        del self.audit[200:]

    def _add_note(self, sid, note, tag=None, operator="admin"):
        rec = {"id": self._next_note_id, "session_id": sid, "tag": tag,
               "note": note, "operator": operator, "timestamp": iso_now()}
        self._next_note_id += 1
        self.notes.setdefault(sid, []).insert(0, rec)
        return rec

    def apply_time_dynamics(self):
        """Lazy world-simulation, applied on each /api/hosts poll. No threads."""
        now = now_ts()
        with self.lock:
            # Late-joining demo session
            if not self._joiner_fired and now >= self._joiner_at:
                self._fire_joiner()

            # Beacons: refresh last_seen when an interval has elapsed
            for h in self.hosts.values():
                interval = 1.0 if h["is_active"] else h["beacon_interval"]
                if now - h["last_seen"] >= interval:
                    h["last_seen"] = now - random.uniform(0, min(2.0, interval))

            # Self-destruct / exit removals (after the output was delivered)
            for sid in [s for s, at in self._dying.items() if now >= at]:
                self.hosts.pop(sid, None)
                self._dying.pop(sid, None)

# ── Simulated agent command interpreter ──────────────────────────────────────
# Returns (output, error, exit_code) and applies side effects (screenshots,
# fs mutations, beacon flips, session teardown) exactly where the real agent
# would produce observable state changes for the panel.

WIN_PROCS = [
    ("System Idle Process", 0), ("System", 4), ("smss.exe", 412), ("csrss.exe", 588),
    ("winlogon.exe", 640), ("services.exe", 704), ("lsass.exe", 712),
    ("svchost.exe", 832), ("svchost.exe", 976), ("explorer.exe", 2044),
    ("chrome.exe", 3112), ("chrome.exe", 3620), ("notepad++.exe", 4108),
    ("outlook.exe", 4520), ("msedge.exe", 5012), ("powershell.exe", 6100),
]
LINUX_PROCS = [
    (1, "systemd"), (2, "kthreadd"), (412, "sshd"), (588, "cron"),
    (812, "nginx"), (813, "nginx"), (1104, "postgres"), (1520, "redis-server"),
    (2201, "bash"), (2487, "python3"),
]

def _win_shell(state, host, arg):
    low = arg.lower()
    fs = host["fs"]
    if low == "whoami":
        return host["user"], "", 0
    if low == "hostname":
        return host["hostname"], "", 0
    if low.startswith("ipconfig"):
        iface = host["ifaces"][0] if host["ifaces"] else {"addr": host["ip"]}
        gw = re.sub(r"\d+$", "1", iface["addr"])
        return ("Windows IP Configuration\n\nEthernet adapter Ethernet0:\n\n"
                "   Connection-specific DNS Suffix  . : acme.corp\n"
                f"   IPv4 Address. . . . . . . . . . . : {iface['addr']}\n"
                "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                f"   Default Gateway . . . . . . . . . : {gw}\n"), "", 0
    if low.startswith("tasklist"):
        lines = [f'"{n}","{p}","Services","0","{4000 + p * 7} K"' for n, p in WIN_PROCS]
        return "\n".join(lines) + "\n", "", 0
    if low.startswith("systeminfo"):
        return ("Host Name:                 " + host["hostname"] + "\n"
                "OS Name:                   Microsoft " + host["os"] + "\n"
                "OS Version:                10.0.22631 N/A Build 22631\n"
                "System Manufacturer:       Dell Inc.\n"
                "System Model:              OptiPlex 7010\n"
                "System Type:               x64-based PC\n"
                "Total Physical Memory:     16,384 MB\n"), "", 0
    if low.startswith("netstat"):
        return ("Active Connections\n\n  Proto  Local Address          Foreign Address        State\n"
                f"  TCP    {host['ip']}:51502     203.0.113.10:443       ESTABLISHED\n"
                f"  TCP    {host['ip']}:51510     93.184.216.34:443      TIME_WAIT\n"), "", 0
    m = re.match(r'^type\s+"?([^"]+)"?$', arg, re.I)
    if m:
        node = fs_resolve(fs, m.group(1))
        if node is None or node.get("dir"):
            return "", "The system cannot find the file specified.", 1
        return node["content"].decode("utf-8", "replace"), "", 0
    m = re.match(r'^mkdir\s+(.+)$', arg, re.I)
    if m:
        _fs_mkdir(fs, _unquote(m.group(1)))
        return "", "", 0
    m = re.match(r'^(?:del|erase|rmdir)\s+(.+)$', arg, re.I)
    if m:
        _fs_delete(fs, _unquote(_strip_flags(m.group(1))))
        return "", "", 0
    if low.startswith("dir"):
        path = arg[3:].strip().strip('"') or "C:\\"
        node = fs_resolve(fs, path)
        if node is None or not node.get("dir"):
            return "", "The system cannot find the path specified.", 1
        lines = [f" Directory of {path}\n"]
        for name, n in sorted(node["children"].items()):
            tag = "<DIR>" if n["dir"] else "     "
            lines.append(f"{tag:>9} {n['size']:>12,} {name}" if not n["dir"] else f"{tag:>9} {'':>12} {name}")
        return "\n".join(lines) + "\n", "", 0
    if low.startswith("echo "):
        return arg[5:], "", 0
    if low in ("pwd", "cd"):
        return "C:\\Users\\jdoe", "", 0
    return "", "", 0

def _nix_shell(state, host, arg):
    low = arg.strip().lower()
    fs = host["fs"]
    if low == "whoami":
        return host["user"], "", 0
    if low == "hostname":
        return host["hostname"].lower(), "", 0
    if low == "id":
        u = host["user"]
        uid = 0 if u == "root" else 33 if u == "www-data" else 1000
        return f"uid={uid}({u}) gid={uid}({u}) groups={uid}({u})", "", 0
    if low == "pwd":
        return "/var/www" if host["user"] == "www-data" else "/root", "", 0
    if low.startswith("uname"):
        return (f"Linux {host['hostname'].lower()} 6.1.0-31-amd64 #1 SMP Debian 6.1.128-1 "
                "x86_64 GNU/Linux"), "", 0
    if low.startswith("ps"):
        return "\n".join(f"{p:>6} {n}" for p, n in LINUX_PROCS) + "\n", "", 0
    if low.startswith(("ifconfig", "ip a", "ip addr")):
        out = []
        for i, iface in enumerate(host["ifaces"] or [{"name": "eth0", "addr": host["ip"], "prefix": 24}]):
            flags = "UP,RUNNING" if iface.get("up", True) else "DOWN"
            out.append(f"{i+1}: {iface['name']}: <{flags}> mtu 1500\n"
                       f"    inet {iface['addr']}/{iface.get('prefix', 24)}")
        return "\n".join(out) + "\n", "", 0
    if low.startswith("netstat") or low.startswith("ss "):
        return ("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
                f"tcp        0      0 {host['ip']}:52234      198.51.100.5:443        ESTABLISHED\n"), "", 0
    if low.startswith("df"):
        return ("Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        40G   12G   26G  31% /\n"
                "tmpfs           3.9G     0  3.9G   0% /dev/shm\n"), "", 0
    if low == "uptime":
        return " 14:02:11 up 26 days,  3:41,  1 user,  load average: 0.08, 0.12, 0.09", "", 0
    m = re.match(r'^cat\s+"?([^"]+)"?$', arg)
    if m:
        node = fs_resolve(fs, m.group(1))
        if node is None:
            return "", f"cat: {m.group(1)}: No such file or directory", 1
        if node.get("dir"):
            return "", f"cat: {m.group(1)}: Is a directory", 1
        return node["content"].decode("utf-8", "replace"), "", 0
    m = re.match(r'^ls(?:\s+-\w+)?(?:\s+"?([^"]+)"?)?$', arg)
    if m:
        node = fs_resolve(fs, m.group(1) or "/")
        if node is None or not node.get("dir"):
            return "", f"ls: cannot access '{m.group(1) or '/'}': No such file or directory", 1
        return "\n".join(sorted(node["children"].keys())) + "\n", "", 0
    m = re.match(r'^mkdir\s+(.+)$', arg)
    if m:
        _fs_mkdir(fs, _unquote(_strip_flags(m.group(1))))
        return "", "", 0
    m = re.match(r'^rm\s+(.+)$', arg)
    if m:
        _fs_delete(fs, _unquote(_strip_flags(m.group(1))))
        return "", "", 0
    if low.startswith("echo "):
        return arg[5:], "", 0
    return "", "", 0

def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s

def _strip_flags(s: str) -> str:
    """Drop leading shell flags ('-rf', '/f /q') from an argument string."""
    parts = s.strip().split()
    while parts and (parts[0].startswith("-") or
                     (parts[0].startswith("/") and len(parts[0]) <= 2)):
        parts.pop(0)
    return " ".join(parts)

def _split_parent(fs, path):
    parts = [p for p in re.split(r"[/\\]+", path.strip()) if p and p != "."]
    if not parts:
        return None, None
    parent = fs_resolve(fs, "/".join(parts[:-1])) if len(parts) > 1 else fs
    # Windows drive root as sole component ("C:") is the tree root's child
    if parent is None and len(parts) > 1:
        parent = fs_resolve(fs, "\\".join(parts[:-1]))
    return parent, parts[-1]

def _fs_mkdir(fs, path):
    parent, name = _split_parent(fs, path)
    if parent is not None and parent.get("dir") and name:
        parent["children"].setdefault(name, _d({}))

def _fs_delete(fs, path):
    parent, name = _split_parent(fs, path)
    if parent is not None and parent.get("dir"):
        parent["children"].pop(name, None)

def run_command(state, host, cmd):
    """The faux agent. Returns (output, error, exit_code)."""
    cmd = cmd.strip()
    low = cmd.lower()
    is_win = "windows" in host["os"].lower()
    sid = host["id"]

    # ── Lifecycle ────────────────────────────────────────────────────────
    if low == "sys:die":
        state._dying[sid] = now_ts() + 3
        return "[+] Self-destruct: binary wiped, agent exiting", "", 0
    if low == "exit":
        state._dying[sid] = now_ts() + 3
        return "[+] Agent exiting", "", 0

    # ── Beacon control ───────────────────────────────────────────────────
    if low == "beacon:mode active":
        host["is_active"] = True
        return "[+] Fast mode enabled (100ms poll)", "", 0
    if low == "beacon:mode passive":
        host["is_active"] = False
        return "[+] Passive mode restored (sleep interval)", "", 0
    if low.startswith("sleep "):
        return f"[+] Sleep set: {cmd[6:].strip()}", "", 0

    # ── Jobs ─────────────────────────────────────────────────────────────
    if low == "jobs:list":
        return json.dumps(host["jobs"]), "", 0
    m = re.match(r"^jobs:kill\s+(\d+)$", low)
    if m:
        jid = int(m.group(1))
        for j in host["jobs"]:
            if j["id"] == jid and j["status"] == "Running":
                j["status"] = "Killed"
                j["finished_at"] = iso_now()
                return f"[+] Job {jid} killed", "", 0
        return "", f"Job {jid} not running", 1
    if low == "jobs:purge":
        host["jobs"] = [j for j in host["jobs"] if j["status"] == "Running"]
        return "[+] Finished jobs purged", "", 0
    if low.startswith("bg "):
        jid = max([j["id"] for j in host["jobs"]] + [0]) + 1
        host["jobs"].append({"id": jid, "description": cmd[3:], "status": "Running",
                             "started_at": iso_now(), "finished_at": None})
        return f"[+] Started as Job {jid}", "", 0

    # ── Extensions (agent-side Rhai) ─────────────────────────────────────
    if low.startswith("ext:load"):
        jid = max([j["id"] for j in host["jobs"]] + [0]) + 1
        desc = "ext:load"
        try:
            b64 = cmd.split(None, 2)[1]
            script = base64.b64decode(b64).decode("utf-8", "replace")
            if "internal_screenshot" in script:
                desc = "ext:load (screenshot)"
                state._pending_shots[sid] = now_ts() + 2.5
            elif "keylog" in script:
                desc = "ext:load (keylogger)"
        except Exception:
            pass
        host["jobs"].append({"id": jid, "description": desc, "status": "Running",
                             "started_at": iso_now(), "finished_at": None})
        return f"Extension launched as Job {jid}", "", 0

    # ── File transfer ────────────────────────────────────────────────────
    if low.startswith("file:read_recursive|"):
        path = cmd.split("|", 1)[1]
        return _stage_download(state, host, path, recursive=True)
    if low.startswith("file:read|"):
        path = cmd.split("|", 1)[1]
        return _stage_download(state, host, path, recursive=False)

    # ── Keylogger ────────────────────────────────────────────────────────
    if low == "keylogger:start":
        if not is_win:
            return "", "Not supported on this platform", 1
        return "[+] Keylogger started", "", 0
    if low == "keylogger:stop":
        return "[+] Keylogger stopped", "", 0
    if low == "keylogger:dump":
        if not is_win:
            return "", "Not supported on this platform", 1
        return ("[14:02:11] jdoe@acme.corp\n[14:02:19] Summer2026!\n"
                "[14:03:02] https://vpn.acme.corp/login\n"), "", 0

    # ── Evasion (Windows) ────────────────────────────────────────────────
    evasion_replies = {
        "evasion:patch_amsi": "[+] AMSI patched (AmsiScanBuffer -> E_INVALIDARG)",
        "evasion:patch_etw": "[+] ETW patched (EtwEventWrite -> STATUS_SUCCESS)",
        "evasion:unhook_ntdll": "[+] ntdll .text restored from clean copy",
        "evasion:patch_all": "[+] AMSI patched\n[+] ETW patched\n[+] ntdll unhooked",
        "evasion:encrypt_heap_aes": "[+] Heap encrypted (AES-256-GCM), key stored",
        "evasion:decrypt_heap_aes": "[+] Heap decrypted",
        "evasion:syscall_check": "[*] NtAllocateVirtualMemory: SSN 0x18, gadget 0x7ffe0308\n"
                                 "[*] NtProtectVirtualMemory:  SSN 0x50, gadget 0x7ffe0308",
    }
    if low in evasion_replies:
        if not is_win:
            return "", "Not supported on this platform", 1
        return evasion_replies[low], "", 0

    # ── Persistence ──────────────────────────────────────────────────────
    if low == "persist:list":
        return ("Installed persistence entries:\n"
                "  [startup] upd.exe -> C:\\Users\\jdoe\\AppData\\Roaming\\upd.exe\n"
                if is_win else "No RCM persistence entries installed.\n"), "", 0
    if low == "persist:cleanup":
        return "[+] All RCM persistence entries removed", "", 0
    if low.startswith("persist:"):
        return f"[+] {cmd.split()[0]} applied", "", 0

    # ── Misc ─────────────────────────────────────────────────────────────
    if low == "fallback:config":
        return ("Fallback endpoints (strategy: priority):\n"
                "  [0] tls://cdn-mock.example.com:4443   (profile: slack)\n"
                "  [1] https://static-faux.example.net:8443 (profile: gdrive)\n"
                "DGA: enabled, seed 0x9f8a, window 24h\n"), "", 0
    if low.startswith("timestomp"):
        return "[+] Timestamps updated", "", 0
    if low.startswith("secure_delete"):
        return "[+] 4-pass overwrite complete, file deleted", "", 0
    if low.startswith("proc:inject"):
        pid = cmd.split()[1] if len(cmd.split()) > 1 else "?"
        return f"[+] Shellcode injected into PID {pid} via remote APC", "", 0
    if low.startswith("migrate:spawn"):
        return "[+] Spawned suspended process, migration complete", "", 0
    if low.startswith("migrate:inject"):
        pid = cmd.split()[1] if len(cmd.split()) > 1 else "?"
        return f"[+] Migrated into PID {pid}", "", 0
    if low.startswith("pivot:listener_tcp"):
        port = cmd.split()[1] if len(cmd.split()) > 1 else "?"
        return f"[+] Pivot TCP listener bound on 0.0.0.0:{port}", "", 0
    if low.startswith("proxy:start"):
        port = cmd.split()[1] if len(cmd.split()) > 1 else "1080"
        return f"[+] SOCKS5 proxy tunnel up on port {port}", "", 0
    if low == "proxy:stop":
        return "[+] Proxy stopped", "", 0

    # ── Explicit shell ───────────────────────────────────────────────────
    if low.startswith("shell "):
        arg = cmd[6:]
        return _win_shell(state, host, arg) if is_win else _nix_shell(state, host, arg)
    if cmd.startswith("!"):
        arg = cmd[1:]
        return _win_shell(state, host, arg) if is_win else _nix_shell(state, host, arg)

    # Bare convenience aliases (the docs' own API examples use these)
    if low in ("whoami", "hostname", "id", "pwd", "ifconfig", "ipconfig", "uname -a"):
        return _win_shell(state, host, low) if is_win else _nix_shell(state, host, low)

    return "", (f"Unknown command: '{cmd}'. Use 'shell <cmd>' or '!<cmd>' "
                "for OS shell execution."), 1

def _stage_download(state, host, path, recursive):
    """file:read -> package into the session's RCM loot tree (like the real flow)."""
    node = fs_resolve(host["fs"], path)
    if node is None:
        return "", f"Failed to read path: {path}", 1
    root = host["hostname"]
    rel = re.sub(r"^[A-Za-z]:", lambda m: m.group(0)[:-1] + "_", path.strip("/\\"))
    rel = rel.replace("\\", "/").strip("/")
    pkg = state.loot["children"].setdefault(root, _ld({}))
    downloads = pkg["children"].setdefault("downloads", _ld({}))

    def place(tree_node, rel_parts, src):
        cur = tree_node
        for part in rel_parts[:-1]:
            cur = cur["children"].setdefault(part, _ld({}))
        leaf = rel_parts[-1]
        if src.get("dir"):
            cur["children"].setdefault(leaf, _ld({}))
            for name, child in src["children"].items():
                place(cur["children"][leaf], [name], child)
        else:
            cur["children"][leaf] = _lf(src["content"])

    place(downloads, rel.split("/"), node)
    kind = "directory (recursive)" if recursive else "file"
    return (f"[+] {kind.capitalize()} staged: {path} -> downloads/{root}/downloads/{rel} "
            f"(SHA-256 verified)"), "", 0

# ── HTTP layer ───────────────────────────────────────────────────────────────

MIME = {
    "html": "text/html; charset=utf-8", "js": "application/javascript; charset=utf-8",
    "css": "text/css; charset=utf-8", "png": "image/png", "jpg": "image/jpeg",
    "jpeg": "image/jpeg", "ico": "image/x-icon", "svg": "image/svg+xml",
    "json": "application/json", "mp3": "audio/mpeg", "txt": "text/plain; charset=utf-8",
    "xml": "application/xml", "zip": "application/zip", "map": "application/json",
}

def mime_for(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return MIME.get(ext, "application/octet-stream")

class MockHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, state):
        super().__init__(addr, handler)
        self.state = state

class MockHandler(BaseHTTPRequestHandler):
    server_version = f"rcm-mock/{VERSION}"
    protocol_version = "HTTP/1.1"

    # ── plumbing ─────────────────────────────────────────────────────────
    def log_message(self, fmt, *args):
        # Access log is opt-in (-v / RCM_MOCK_VERBOSE=1): the panel polls
        # /api/hosts every 2s, so per-request lines drown the console.
        if getattr(self.server, "verbose", False):
            sys.stdout.write("  [%s] %s\n" % (datetime.now().strftime("%H:%M:%S"),
                                              fmt % args))

    def _cors_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return None
        if origin == "null" or re.match(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$", origin):
            return origin
        return None

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj).encode(), "application/json", extra)

    def _err(self, code, msg):
        self._json(code, {"error": msg})

    def _body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return b""
        return self.rfile.read(length) if length > 0 else b""

    def _json_body(self):
        raw = self._body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return {}

    def _operator(self):
        """Operator record for the X-API-KEY header, or None."""
        key = self.headers.get("X-API-KEY", "")
        with self.server.state.lock:
            username = self.server.state.api_keys.get(key)
            return self.server.state.operators.get(username) if username else None

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self._cors_origin()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-KEY")
            self.send_header("Access-Control-Max-Age", "3600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):    self._dispatch("GET")
    def do_POST(self):   self._dispatch("POST")
    def do_PUT(self):    self._dispatch("PUT")
    def do_DELETE(self): self._dispatch("DELETE")

    # ── router ───────────────────────────────────────────────────────────
    def _dispatch(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path != "/" and path.endswith("/"):
            path = path[:-1]
        query = urllib.parse.parse_qs(parsed.query)

        for m, pattern, protected, handler in ROUTES:
            if m != method:
                continue
            match = re.fullmatch(pattern, path)
            if not match:
                continue
            if protected:
                op = self._operator()
                if not op:
                    # The panel fires its boot probes (see _BOOT_PROBES) at
                    # EVERY page load - even on the login screen - and answers
                    # a 401 with Auth.logout() + location.reload(), which makes
                    # the login page reload-loop forever. An EMPTY key means
                    # "nobody has logged in yet" (a stale key is non-empty and
                    # still gets a real 401 -> one logout -> fresh login), so
                    # serve those probes an empty list and keep the page put.
                    if not self.headers.get("X-API-KEY") and path in _BOOT_PROBES:
                        self._json(200, _BOOT_PROBES[path])
                        return
                    self._send(401)  # empty body, like the real middleware
                    return
            else:
                op = None
            try:
                handler(self, op, query, *match.groups())
            except BrokenPipeError:
                pass
            except Exception as exc:  # never leave the panel hanging
                sys.stderr.write("  [!] handler error: %r\n" % (exc,))  # always shown
                try:
                    self._err(500, f"mock internal error: {exc}")
                except Exception:
                    pass
            return

        if path.startswith("/api/"):
            self._err(404, "Not found")
        else:
            self._send(404, "File not found", "text/plain; charset=utf-8")

# ── Route table ──────────────────────────────────────────────────────────────
# Endpoints the panel's boot sequence polls BEFORE login (TaskManager.init
# fires modules+audit+history, LootBrowser.init fires loot; builder's
# c2-hints is fully public above). Each empty-key probe gets a shape-correct
# empty answer so the login screen renders "nothing yet" instead of looping.
_BOOT_PROBES = {
    "/api/modules": [],
    "/api/audit":   [],
    "/api/history": [],
    "/api/loot":    {"entries": []},
}

ROUTES = []
def route(method, pattern, protected=True):
    def deco(fn):
        ROUTES.append((method, pattern, protected, fn))
        return fn
    return deco

# ══ Panel static files ═══════════════════════════════════════════════════════

def _serve_panel_file(h, rel):
    root = os.path.join(h.server.state.repo_root, "panel")
    rel = rel.replace("\\", "/").lstrip("/")
    if ".." in rel.split("/"):
        h._send(400, "Invalid path", "text/plain; charset=utf-8")
        return
    full = os.path.normpath(os.path.join(root, rel))
    if not full.startswith(os.path.abspath(root) + os.sep) and rel != "index.html":
        pass  # normpath of a file inside root always starts with root; paranoia guard
    if not os.path.isfile(full):
        h._send(404, "File not found", "text/plain; charset=utf-8")
        return
    with open(full, "rb") as fh:
        data = fh.read()
    # no-store: a stale cached panel (left behind by whatever ran on this
    # origin before) breaks pages silently - always re-fetch from disk.
    h._send(200, data, mime_for(rel),
            extra={"Cache-Control": "no-store, must-revalidate"})


# NOTE on /pwa-service-worker.js (deliberately NOT routed -> honest 404):
# this repo ships no service worker, but a worker registered by ANY app
# previously served on the same origin (the real server, an older panel,
# an unrelated dev tool) stays alive in the browser and keeps polling its
# script URL. While it 404s it stays harmless; answering 200 can make it
# force-reload the tab in a loop. If a stale worker haunts an origin, run
# the mock on a DIFFERENT PORT - a new origin starts completely clean.
# (Default port below is 18080 instead of the real server's 8080 exactly
# so a worker left behind by the real server never interferes.)

@route("GET", r"/", protected=False)
def r_index(h, op, q):
    # index.html hardcodes the login form's Server URL to http://127.0.0.1:8080
    # (the real server's port). Rewrite that one attribute to the address the
    # panel was actually reached on, so first-time login just works no matter
    # which port the mock is running on. Panel files on disk stay untouched.
    path = os.path.join(h.server.state.repo_root, "panel", "index.html")
    with open(path, "rb") as fh:
        data = fh.read()
    host = h.headers.get("Host", "")
    if re.fullmatch(r"[A-Za-z0-9.\-]+(:\d+)?", host or ""):
        data = data.replace(b'value="http://127.0.0.1:8080"',
                            b'value="http://' + host.encode() + b'"', 1)
    h._send(200, data, mime_for("index.html"),
            extra={"Cache-Control": "no-store, must-revalidate"})

@route("GET", r"/panel/(.+)", protected=False)
def r_panel_static(h, op, q, tail):
    _serve_panel_file(h, tail)

@route("GET", r"/favicon\.svg", protected=False)
def r_favicon(h, op, q):
    _serve_panel_file(h, "favicon.svg")

# ══ Auth ═════════════════════════════════════════════════════════════════════

@route("POST", r"/api/auth/login", protected=False)
def r_login(h, op, q):
    body = h._json_body()
    st = h.server.state
    with st.lock:
        rec = st.operators.get(str(body.get("username", "")))
        if not rec or rec["password"] != body.get("password"):
            h._err(401, "Invalid credentials")
            return
        key = str(uuid.uuid4())
        st.api_keys[key] = rec["username"]
        rec["last_login"] = iso_now()
        st.log_audit(rec["username"], "login")
        h._json(200, {"api_key": key, "username": rec["username"], "role": rec["role"]})

@route("GET", r"/api/auth/me")
def r_me(h, op, q):
    h._json(200, {"id": op["id"], "username": op["username"], "role": op["role"]})

# Logout is public like on the real server (routes/mod.rs): signing out with
# an already-expired key must still succeed so the panel can recover.
@route("POST", r"/api/auth/logout", protected=False)
def r_logout(h, op, q):
    st = h.server.state
    with st.lock:
        key = h.headers.get("X-API-KEY", "")
        st.api_keys.pop(key, None)
        if op:  # unauthenticated logout attempts are fine - nothing to audit
            st.log_audit(op["username"], "logout")
    h._json(200, {"status": "logged out"})

@route("POST", r"/api/auth/change_password")
def r_change_password(h, op, q):
    body = h._json_body()
    st = h.server.state
    new = str(body.get("new_password", ""))
    if len(new) < 8:
        h._err(400, "Password must be at least 8 characters")
        return
    with st.lock:
        if op["password"] != body.get("current_password"):
            h._err(403, "Current password is incorrect")
            return
        op["password"] = new
        caller = h.headers.get("X-API-KEY", "")
        revoked = 0
        for k in [k for k, u in st.api_keys.items() if u == op["username"] and k != caller]:
            st.api_keys.pop(k, None)
            revoked += 1
        st.log_audit(op["username"], "change_password", None, f"sessions_revoked={revoked}")
    h._json(200, {"status": "password updated", "sessions_revoked": revoked})

# ══ Operators (admin) ════════════════════════════════════════════════════════

def _admin_only(h, op):
    if op["role"] != "admin":
        h._err(403, "Admin only")
        return True
    return False

@route("GET", r"/api/operators")
def r_ops_list(h, op, q):
    if _admin_only(h, op):
        return
    with h.server.state.lock:
        h._json(200, [{"id": o["id"], "username": u, "role": o["role"],
                       "created_at": o["created_at"], "last_login": o["last_login"]}
                      for u, o in h.server.state.operators.items()])

@route("POST", r"/api/operators")
def r_ops_create(h, op, q):
    if _admin_only(h, op):
        return
    body = h._json_body()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    role = str(body.get("role", ""))
    if len(password) < 8:
        h._err(400, "Password must be at least 8 characters")
        return
    if role not in ("admin", "operator", "viewer"):
        h._err(400, "Role must be admin, operator, or viewer")
        return
    st = h.server.state
    with st.lock:
        if not username or username in st.operators:
            h._err(409, "UNIQUE constraint failed: operators.username")
            return
        rec = {"id": st._next_op_id, "username": username, "password": password,
               "role": role, "created_at": iso_now(), "last_login": None}
        # (username stored on the record: handlers read op["username"])
        st._next_op_id += 1
        st.operators[username] = rec
        key = str(uuid.uuid4())
        st.api_keys[key] = username  # initial key, usable immediately like the real server
        st.log_audit(op["username"], "create_operator", None,
                     f"username={username} role={role}")
        h._json(201, {"id": rec["id"], "username": username, "role": role, "api_key": key})

def _find_operator(st, name):
    if str(name).isdigit():
        for u, o in st.operators.items():
            if o["id"] == int(name):
                return u, o
        return None, None
    return (name, st.operators.get(name)) if name in st.operators else (None, None)

@route("DELETE", r"/api/operators/([^/]+)")
def r_ops_delete(h, op, q, name):
    if _admin_only(h, op):
        return
    st = h.server.state
    uname, target = _find_operator(st, urllib.parse.unquote(name))
    with st.lock:
        if not target:
            h._err(404, "Operator not found")
            return
        if target["id"] == op["id"]:
            h._err(400, "Cannot delete yourself")
            return
        st.operators.pop(uname, None)
        for k in [k for k, u in st.api_keys.items() if u == uname]:
            st.api_keys.pop(k, None)
        st.log_audit(op["username"], "delete_operator", None,
                     f"id={target['id']} name={uname}")
    h._json(200, {"status": "deleted"})

@route("POST", r"/api/operators/([^/]+)/revoke")
def r_ops_revoke(h, op, q, name):
    if _admin_only(h, op):
        return
    st = h.server.state
    uname, target = _find_operator(st, urllib.parse.unquote(name))
    with st.lock:
        if not target:
            h._err(404, "Operator not found")
            return
        if target["id"] == op["id"]:
            h._err(400, "Cannot revoke your own keys; use logout")
            return
        killed = 0
        for k in [k for k, u in st.api_keys.items() if u == uname]:
            st.api_keys.pop(k, None)
            killed += 1
        st.log_audit(op["username"], "revoke_keys", None, f"target={uname} keys_killed={killed}")
    h._json(200, {"status": "revoked", "keys_killed": killed})

@route("POST", r"/api/operators/([^/]+)/password")
def r_ops_password(h, op, q, name):
    if _admin_only(h, op):
        return
    body = h._json_body()
    new = str(body.get("password", ""))
    if len(new) < 8:
        h._err(400, "Password must be at least 8 characters")
        return
    st = h.server.state
    uname, target = _find_operator(st, urllib.parse.unquote(name))
    with st.lock:
        if not target:
            h._err(404, "Operator not found")
            return
        target["password"] = new
        killed = 0
        for k in [k for k, u in st.api_keys.items() if u == uname]:
            st.api_keys.pop(k, None)
            killed += 1
        st.log_audit(op["username"], "reset_password", None,
                     f"target={uname} keys_killed={killed}")
    h._json(200, {"status": "password reset", "keys_killed": killed})

# ══ Audit ════════════════════════════════════════════════════════════════════

@route("GET", r"/api/audit")
def r_audit(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    with h.server.state.lock:
        h._json(200, list(h.server.state.audit))

# ══ Config (webhook + auto-recon) ════════════════════════════════════════════

@route("GET", r"/api/config/webhook")
def r_webhook_get(h, op, q):
    if _admin_only(h, op):
        return
    h._json(200, {"webhook_url": h.server.state.webhook_url})

@route("POST", r"/api/config/webhook")
def r_webhook_set(h, op, q):
    if _admin_only(h, op):
        return
    url = str(h._json_body().get("url", "")).strip()
    if url and not re.match(r"^https?://", url):
        h._err(400, "webhook URL must start with http:// or https://")
        return
    st = h.server.state
    with st.lock:
        st.webhook_url = url
        st.log_audit(op["username"], "set_webhook", None, url)
    h._json(200, {"status": "ok"})

@route("GET", r"/api/config/recon")
def r_recon_list(h, op, q):
    with h.server.state.lock:
        h._json(200, list(h.server.state.recon))

@route("POST", r"/api/config/recon")
def r_recon_add(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    cmd = str(h._json_body().get("command", "")).strip()
    if not cmd:
        h._err(400, "command must not be empty")
        return
    st = h.server.state
    with st.lock:
        rec = {"id": st._next_recon_id, "command": cmd,
               "sort_order": len(st.recon)}
        st._next_recon_id += 1
        st.recon.append(rec)
        st.log_audit(op["username"], "add_recon", None, cmd)
        h._json(201, {"id": rec["id"], "command": cmd})

@route("DELETE", r"/api/config/recon/(\d+)")
def r_recon_del(h, op, q, rid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    with st.lock:
        before = len(st.recon)
        st.recon = [r for r in st.recon if r["id"] != int(rid)]
        if len(st.recon) == before:
            h._err(404, "Not found")
            return
        st.log_audit(op["username"], "remove_recon", None, f"id={rid}")
    h._json(200, {"status": "removed"})

# ══ Listeners ════════════════════════════════════════════════════════════════

# c2-hints is public in the MOCK (the real server protects it). The panel's
# BuilderManager.init() fires this probe at EVERY page load, unguarded, and
# treats a 401 as "session expired" -> Auth.logout() -> location.reload().
# Against any reachable protected server that makes the login page
# reload-loop forever and nobody can sign in. The hints are fake anyway,
# so the mock answers 200 pre-auth and the login page stays put.
@route("GET", r"/api/server/c2-hints", protected=False)
def r_c2_hints(h, op, q):
    h._json(200, {"ips": ["127.0.0.1", "10.10.0.5", "192.168.1.20"]})

@route("GET", r"/api/listeners")
def r_listeners(h, op, q):
    with h.server.state.lock:
        h._json(200, [{"id": l["id"], "name": l["name"], "port": l["port"],
                       "transport": l["transport"], "auto_start": l["auto_start"],
                       "running": l["running"], "created_at": l["created_at"]}
                      for l in h.server.state.listeners])

@route("GET", r"/api/listeners/profiles")
def r_listener_profiles(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    profiles = []
    pdir = os.path.join(st.repo_root, "traffic_profiles")
    try:
        for fname in sorted(os.listdir(pdir)):
            if fname.endswith(".json"):
                with open(os.path.join(pdir, fname), "r", encoding="utf-8", errors="replace") as fh:
                    profiles.append({"name": fname[:-5], "content": fh.read()})
    except OSError:
        pass
    if not profiles:
        profiles = [{"name": "slack", "content": json.dumps({"profile": "slack", "hosts": ["slack.com"]}, indent=2)},
                    {"name": "google_drive", "content": json.dumps({"profile": "gdrive"}, indent=2)}]
    h._json(200, profiles)

@route("POST", r"/api/listeners")
def r_listener_create(h, op, q):
    if _admin_only(h, op):
        return
    body = h._json_body()
    st = h.server.state
    name = str(body.get("name", "")).strip()
    try:
        port = int(body.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    transport = str(body.get("transport", "tls"))
    api_port = h.server.server_address[1]
    if port in (0, api_port):
        h._err(400, f"Port 0 and {api_port} (API) are reserved")
        return
    if transport not in ("tls", "tcp_plain", "http", "https"):
        h._err(400, f"Unknown transport '{transport}': expected tls, tcp_plain, http, or https")
        return
    if port < 1024:
        h._err(400, "Privileged ports (< 1024) are not allowed. Use a reverse proxy or iptables redirect.")
        return
    with st.lock:
        if any(l["port"] == port for l in st.listeners):
            h._err(409, f"Port {port} is already in use by another listener")
            return
        rec = {"id": st._next_listener_id, "name": name, "port": port,
               "transport": transport, "profile_json": body.get("profile_json"),
               "auto_start": True, "running": True, "created_at": iso_now()}
        st._next_listener_id += 1
        st.listeners.append(rec)
        st.log_audit(op["username"], "create_listener", None,
                     f"name={name} port={port} transport={transport}")
        h._json(201, rec)

def _listener_action(h, op, lid, verb):
    st = h.server.state
    with st.lock:
        rec = next((l for l in st.listeners if l["id"] == int(lid)), None)
        if not rec:
            h._err(404, "Listener not found")
            return
        rec["running"] = (verb == "start")
        st.log_audit(op["username"], f"{verb}_listener", None, f"id={lid}")
        h._json(200, {"status": f"Listener '{rec['name']}' {verb}ed"})

@route("POST", r"/api/listeners/(\d+)/start")
def r_listener_start(h, op, q, lid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    _listener_action(h, op, lid, "start")

@route("POST", r"/api/listeners/(\d+)/stop")
def r_listener_stop(h, op, q, lid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    _listener_action(h, op, lid, "stop")

@route("DELETE", r"/api/listeners/(\d+)")
def r_listener_delete(h, op, q, lid):
    if _admin_only(h, op):
        return
    st = h.server.state
    with st.lock:
        rec = next((l for l in st.listeners if l["id"] == int(lid)), None)
        if not rec:
            h._err(404, "Listener not found")
            return
        st.listeners = [l for l in st.listeners if l["id"] != int(lid)]
        st.log_audit(op["username"], "delete_listener", None, f"id={lid}")
    h._json(200, {"status": f"Listener '{rec['name']}' deleted"})

# ══ Sessions (hosts) ═════════════════════════════════════════════════════════

def _session_dto(st, host):
    return {
        "id": host["id"], "hostname": host["hostname"], "ip": host["ip"],
        "os": host["os"], "computer_id": host["computer_id"],
        "has_proxy": host["id"] in st.proxies, "parent_id": host["parent_id"],
        "is_active": host["is_active"], "hibernation_mode": host["hibernation_mode"],
        "profile": host["profile"],
        "last_seen_secs": int(now_ts() - host["last_seen"]),
        "tags": host["tags"],
    }

@route("GET", r"/api/hosts")
def r_hosts(h, op, q):
    st = h.server.state
    st.apply_time_dynamics()
    with st.lock:
        h._json(200, [_session_dto(st, host) for host in st.hosts.values()])

def _history_row(st, sid, req_id, command, ready_at):
    """Record a command in history; output is filled once the result is ready."""
    row = {"session_id": sid, "request_id": req_id, "command": command,
           "output": None, "error": None, "timestamp": iso_now(),
           "_ready_at": ready_at}
    st.history.append(row)
    return row

def _history_dto(row):
    res_ready = row.get("_ready_at", 0) <= now_ts()
    return {"session_id": row["session_id"], "request_id": row["request_id"],
            "command": row["command"],
            "output": row["output"] if (row["output"] is not None or res_ready) else None,
            "error": row["error"] if (row["error"] is not None or res_ready) else None,
            "timestamp": row["timestamp"]}

def _enqueue_command(st, op, sid, command):
    """Shared by /command, /browse internals, upload, broadcast."""
    host = st.hosts.get(sid)
    if not host:
        return None, None
    with st.lock:
        st._next_request_id += 1
        req_id = st._next_request_id
        output, error, code = run_command(st, host, command)
        ready_at = now_ts() + random.uniform(0.4, 1.2)
        st.results[(sid, req_id)] = {"ready_at": ready_at, "output": output,
                                     "error": error, "exit_code": code}
        row = _history_row(st, sid, req_id, command, ready_at)
        row["output"], row["error"] = output, error
        if len(st.history) > 500:
            del st.history[: len(st.history) - 500]
    return req_id, ready_at

@route("POST", r"/api/hosts/(\d+)/command")
def r_command(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Viewers cannot execute commands")
        return
    st = h.server.state
    sid = int(sid)
    cmd = str(h._json_body().get("command", ""))
    if sid not in st.hosts:
        h._err(404, "Session ID not found")
        return
    req_id, _ = _enqueue_command(st, op, sid, cmd)
    st.log_audit(op["username"], "command", sid, cmd)
    h._json(200, {"status": "queued", "session_id": sid, "request_id": req_id})

@route("GET", r"/api/hosts/(\d+)/output/(\d+)")
def r_output(h, op, q, sid, req_id):
    st = h.server.state
    with st.lock:
        entry = st.results.get((int(sid), int(req_id)))
        if entry and entry["ready_at"] <= now_ts():
            h._json(200, {"status": "completed", "output": entry["output"],
                          "error": entry["error"], "exit_code": entry["exit_code"]})
        else:
            h._json(404, {"status": "pending_or_not_found",
                          "message": "Output not available yet or ID invalid"})

@route("GET", r"/api/hosts/(\d+)/history")
def r_host_history(h, op, q, sid):
    with h.server.state.lock:
        rows = [r for r in h.server.state.history if r["session_id"] == int(sid)]
        h._json(200, [_history_dto(r) for r in rows[-100:]])

@route("GET", r"/api/history")
def r_global_history(h, op, q):
    with h.server.state.lock:
        h._json(200, [_history_dto(r) for r in h.server.state.history[-100:]])

@route("POST", r"/api/broadcast")
def r_broadcast(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Viewers cannot broadcast commands")
        return
    st = h.server.state
    cmd = str(h._json_body().get("command", ""))
    with st.lock:
        targets = list(st.hosts.keys())
        for sid in targets:
            _enqueue_command(st, op, sid, cmd)
        st.log_audit(op["username"], "broadcast", None, cmd)
    h._json(200, {"status": "broadcast_queued", "targets_reached": len(targets)})

# ── File browser ─────────────────────────────────────────────────────────────

def _browse_fs(host, path):
    """Return (entries, error). entries mirrors the agent's fs:ls JSON."""
    if path == "__drives__":
        if "windows" in host["os"].lower():
            return [{"name": "C:\\", "is_dir": True, "is_drive": True,
                     "size": 0, "perms": "rw", "mod_time": 0},
                    {"name": "D:\\", "is_dir": True, "is_drive": True,
                     "size": 0, "perms": "rw", "mod_time": 0}], None
        mounts = []
        for mp in ("/media", "/mnt"):
            node = fs_resolve(host["fs"], mp)
            if node:
                mounts.append({"name": mp, "is_dir": True, "is_drive": True,
                               "size": 0, "perms": "rw", "mod_time": int(node["mod"])})
        if not mounts:  # seed a couple so the Linux view isn't empty
            mounts = [{"name": "/media/usb", "is_dir": True, "is_drive": True,
                       "size": 0, "perms": "rw", "mod_time": int(now_ts()) - 7200}]
        return mounts, None
    node = fs_resolve(host["fs"], path)
    if node is None:
        return None, f"Failed to read path: {path}"
    if not node.get("dir"):
        return None, f"Failed to read path: {path}"
    return fs_list(node), None

@route("GET", r"/api/hosts/(\d+)/files/browse")
def r_browse(h, op, q, sid):
    st = h.server.state
    host = st.hosts.get(int(sid))
    if not host:
        h._err(404, "Session offline")
        return
    path = (q.get("path") or ["."])[0]
    with st.lock:
        entries, err = _browse_fs(host, path)
    if err:
        h._err(400, err)
        return
    h._json(200, entries)

# ── Chunked upload (file:write_chunk passthrough) ───────────────────────────

@route("POST", r"/api/hosts/(\d+)/upload")
def r_upload(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Viewers cannot upload files")
        return
    st = h.server.state
    sid = int(sid)
    host = st.hosts.get(sid)
    if not host:
        h._err(404, "Session not found or offline")
        return
    body = h._json_body()
    path = str(body.get("path", ""))
    if not path or ".." in path.split("/"):
        h._err(400, "Invalid path")
        return
    data_b64 = str(body.get("data_b64", ""))
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]*", data_b64):
        h._err(400, "data_b64 contains non-base64 characters")
        return
    try:
        chunk = base64.b64decode(data_b64)
    except (binascii.Error, ValueError):
        h._err(400, "data_b64 contains non-base64 characters")
        return
    batch = str(body.get("batch_ts", ""))
    idx = int(body.get("chunk_idx", 0))
    total = int(body.get("total_chunks", 1))
    with st.lock:
        uploads = getattr(st, "_uploads", None)
        if uploads is None:
            uploads = st._uploads = {}
        slot = uploads.setdefault((sid, batch), {"path": path, "chunks": {}, "total": total})
        slot["chunks"][idx] = chunk
        if len(slot["chunks"]) >= total:
            content = b"".join(slot["chunks"][i] for i in range(total))
            parent, name = _split_parent(host["fs"], path)
            if parent is not None and parent.get("dir") and name:
                parent["children"][name] = _f(content)
            uploads.pop((sid, batch), None)
        st._next_request_id += 1
        req_id = st._next_request_id
    h._json(200, {"status": "queued", "session_id": sid,
                  "request_id": req_id,
                  "chunk_idx": idx, "total_chunks": total})

# ── Screenshots (RCM Sec-11 flow) ────────────────────────────────────────────

def _materialize_shots(st, sid):
    """If a capture job is due, turn it into shot entries + loot PNG files."""
    ready = st._pending_shots.get(sid)
    if not ready or now_ts() < ready:
        return
    st._pending_shots.pop(sid, None)
    host = st.hosts.get(sid)
    if not host:
        return
    root = host["hostname"]
    ts = shot_ts()
    shots = st.screenshots.setdefault(sid, [])
    monitors = 2 if sid % 2 == 0 else 1  # some hosts get a dual-monitor capture
    shots_dir = (st.loot["children"].setdefault(root, _ld({}))["children"]
                 .setdefault("output", _ld({}))["children"]
                 .setdefault("screenshots", _ld({})))
    for mon in range(monitors):
        fname = f"{root}/output/screenshots/screenshot.{ts}.monitor{mon}.png"
        shots.insert(0, {"file": fname, "ts": ts, "monitor": mon})
        shots_dir["children"][f"screenshot.{ts}.monitor{mon}.png"] = _lf(b"", age=0)

@route("GET", r"/api/hosts/(\d+)/screenshots")
def r_screenshots(h, op, q, sid):
    st = h.server.state
    sid = int(sid)
    with st.lock:
        _materialize_shots(st, sid)
        host = st.hosts.get(sid)
        root = host["hostname"] if host else None
        shots = list(st.screenshots.get(sid, []))
    folders = [f"{root}/output/screenshots"] if root and shots else []
    h._json(200, {"folders": folders, "shots": shots})

# ── Notes & tags ─────────────────────────────────────────────────────────────

@route("GET", r"/api/hosts/(\d+)/notes")
def r_notes_get(h, op, q, sid):
    st = h.server.state
    with st.lock:
        notes = list(st.notes.get(int(sid), []))
        tags = sorted({n["tag"] for n in notes if n.get("tag")})
    h._json(200, {"notes": notes, "tags": tags})

@route("POST", r"/api/hosts/(\d+)/notes")
def r_notes_add(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Operator role required")
        return
    body = h._json_body()
    note = str(body.get("note", "")).strip()
    if not note:
        h._err(400, "Note must not be empty")
        return
    st = h.server.state
    with st.lock:
        rec = st._add_note(int(sid), note, tag=body.get("tag") or None,
                           operator=op["username"])
        host = st.hosts.get(int(sid))
        if host and rec["tag"] and rec["tag"] not in host["tags"]:
            host["tags"].append(rec["tag"])
    h._json(201, {"id": rec["id"]})

@route("DELETE", r"/api/hosts/(\d+)/notes/(\d+)")
def r_notes_del(h, op, q, sid, nid):
    if op["role"] == "viewer":
        h._err(403, "Operator role required")
        return
    st = h.server.state
    with st.lock:
        notes = st.notes.get(int(sid), [])
        victim = next((n for n in notes if n["id"] == int(nid)), None)
        if not victim:
            h._err(404, "Not found")
            return
        st.notes[int(sid)] = [n for n in notes if n["id"] != int(nid)]
        host = st.hosts.get(int(sid))
        if host and victim.get("tag"):
            still = any(n.get("tag") == victim["tag"] for n in st.notes[int(sid)])
            if not still and victim["tag"] in host["tags"]:
                host["tags"].remove(victim["tag"])
    h._json(200, {"status": "deleted"})

# ══ Downloads & loot ═════════════════════════════════════════════════════════

def _png_for_path(st, path):
    """Screenshots are stored empty in the loot tree; render on demand."""
    if path in st._png_cache:
        return st._png_cache[path]
    seed = path
    png = make_png(1280, 720, seed)
    st._png_cache[path] = png
    return png

@route("GET", r"/api/downloads/(.+)")
def r_download_file(h, op, q, path):
    st = h.server.state
    rel = urllib.parse.unquote(path).lstrip("/")
    if ".." in rel.split("/"):
        h._send(400, "Invalid path", "text/plain; charset=utf-8")
        return
    with st.lock:
        node = loot_walk(st.loot, rel)
        if node is None or "content" not in node:
            h._send(404, "File not found", "text/plain; charset=utf-8")
            return
        content = node["content"]
        if rel.endswith(".png") and not content:
            content = _png_for_path(st, rel)
    h._send(200, content, mime_for(rel))

@route("GET", r"/api/loot")
def r_loot_list(h, op, q):
    subpath = (q.get("path") or [""])[0].strip("/")
    if ".." in subpath.split("/"):
        h._send(400, "Invalid path", "text/plain; charset=utf-8")
        return
    with h.server.state.lock:
        entries = loot_list_entries(h.server.state.loot, subpath)
    h._json(200, {"path": subpath, "entries": entries})

@route("DELETE", r"/api/loot")
def r_loot_delete(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    subpath = (q.get("path") or [""])[0].strip("/")
    if not subpath or ".." in subpath.split("/"):
        h._send(400, "Invalid path", "text/plain; charset=utf-8")
        return
    st = h.server.state
    with st.lock:
        parent_rel, _, leaf = subpath.rpartition("/")
        parent = loot_walk(st.loot, parent_rel)
        if parent is None or leaf not in parent["children"]:
            h._err(404, "Not found")
            return
        parent["children"].pop(leaf)
        st.log_audit(op["username"], "delete_loot", None, subpath)
    h._json(200, {"status": "deleted", "path": subpath})

@route("GET", r"/api/loot/zip")
def r_loot_zip(h, op, q):
    subpath = (q.get("path") or [""])[0].strip("/")
    if ".." in subpath.split("/"):
        h._send(400, "Invalid path", "text/plain; charset=utf-8")
        return
    st = h.server.state
    with st.lock:
        node = loot_walk(st.loot, subpath)
        if node is None:
            h._err(404, "Not found")
            return
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            def walk(node, prefix):
                for name, n in node["children"].items():
                    p = f"{prefix}/{name}" if prefix else name
                    if "content" in n:
                        content = n["content"]
                        if p.endswith(".png") and not content:
                            content = _png_for_path(st, p)
                        zf.writestr(p, content)
                    else:
                        walk(n, p)
            walk(node, subpath.split("/")[-1] if subpath else "downloads")
        data = buf.getvalue()
    fname = (subpath.split("/")[-1] or "loot") + ".zip"
    h._send(200, data, "application/zip",
            {"Content-Disposition": f'attachment; filename="{fname}"'})

# ══ RCM packages ═════════════════════════════════════════════════════════════

@route("GET", r"/api/rcm/packages")
def r_rcm_packages(h, op, q):
    st = h.server.state
    with st.lock:
        out = []
        for name in sorted(st.loot["children"].keys()):
            out.append({"name": name,
                        "sealed": st.rcm_sealed.get(name, False),
                        "generations": st.rcm_generations.get(name, 0),
                        "size_bytes": loot_size(st.loot["children"][name])})
    h._json(200, out)

@route("POST", r"/api/rcm/seal")
def r_rcm_seal(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    name = str(h._json_body().get("name", ""))
    st = h.server.state
    with st.lock:
        if name not in st.loot["children"]:
            h._err(404, f"unknown package: {name}")
            return
        st.rcm_sealed[name] = True
        st.rcm_generations[name] = st.rcm_generations.get(name, 0) + 1
        gen = st.rcm_generations[name]
        st.log_audit(op["username"], "rcm_seal", None, f"package={name} generation={gen}")
    h._json(200, {"manifest": "manifest.RCM.xml", "generation": gen})

@route("POST", r"/api/rcm/verify")
def r_rcm_verify(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    name = str(h._json_body().get("name", ""))
    st = h.server.state
    with st.lock:
        if name not in st.loot["children"]:
            h._err(404, f"unknown package: {name}")
            return
        if not st.rcm_sealed.get(name):
            h._err(400, f"package not sealed: {name}")
            return
        st.log_audit(op["username"], "rcm_verify", None, f"package={name}")
    h._json(200, {"mismatches": []})

# ══ Proxies & reverse port forwards ═════════════════════════════════════════

@route("GET", r"/api/proxies")
def r_proxies(h, op, q):
    with h.server.state.lock:
        h._json(200, list(h.server.state.proxies.values()))

@route("POST", r"/api/hosts/(\d+)/proxy")
def r_proxy_start(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    sid = int(sid)
    with st.lock:
        if sid not in st.hosts:
            h._err(404, "Session not found")
            return
        if sid in st.proxies:
            h._err(400, "Proxy already active")
            return
        rec = {"session_id": sid, "tunnel_port": st._next_tunnel_port,
               "socks_port": st._next_socks_port}
        st._next_tunnel_port += 1
        st._next_socks_port += 1
        st.proxies[sid] = rec
        st.log_audit(op["username"], "proxy_start", sid, f"socks_port={rec['socks_port']}")
    h._json(200, {"status": "started", "tunnel_port": rec["tunnel_port"],
                  "socks_port": rec["socks_port"]})

@route("DELETE", r"/api/hosts/(\d+)/proxy")
def r_proxy_stop(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    sid = int(sid)
    with st.lock:
        if sid not in st.proxies:
            h._err(404, "No active proxy for this session")
            return
        st.proxies.pop(sid)
        st.log_audit(op["username"], "proxy_stop", sid)
    h._json(200, {"status": "stopped"})

@route("POST", r"/api/hosts/(\d+)/proxy/check")
def r_proxy_check(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    sid = int(sid)
    with st.lock:
        if sid not in st.proxies:
            h._err(404, "Proxy not found")
            return
        geo = st._geo_pool[sid % len(st._geo_pool)]
    time.sleep(0.6)  # the real check round-trips through the tunnel
    h._json(200, geo)

@route("GET", r"/api/rportfwds")
def r_rportfwds(h, op, q):
    with h.server.state.lock:
        h._json(200, list(h.server.state.rportfwds.values()))

@route("POST", r"/api/hosts/(\d+)/rportfwd")
def r_rportfwd_start(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    body = h._json_body()
    try:
        bind_port = int(body.get("bind_port", 0))
        target_port = int(body.get("target_port", 0))
    except (TypeError, ValueError):
        bind_port = target_port = 0
    target_host = str(body.get("target_host", "")).strip()
    if not (0 < bind_port < 65536) or not (0 < target_port < 65536) or not target_host:
        h._err(400, "Invalid bind_port, target_host, or target_port")
        return
    st = h.server.state
    sid = int(sid)
    with st.lock:
        if sid not in st.hosts:
            h._err(404, "Session not found")
            return
        if any(v["bind_port"] == bind_port for v in st.rportfwds.values()):
            h._err(400, "rportfwd already active on this port")
            return
        rec = {"session_id": sid, "bind_port": bind_port,
               "target_host": target_host, "target_port": target_port,
               "tunnel_port": st._next_tunnel_port}
        st._next_tunnel_port += 1
        st.rportfwds[(sid, bind_port)] = rec
        st.log_audit(op["username"], "rportfwd_start", sid,
                     f"bind={bind_port} target={target_host}:{target_port}")
    h._json(200, {"status": "started", "bind_port": bind_port,
                  "tunnel_port": rec["tunnel_port"],
                  "target": f"{target_host}:{target_port}"})

@route("DELETE", r"/api/hosts/(\d+)/rportfwd")
def r_rportfwd_stop(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    body = h._json_body()
    try:
        bind_port = int(body.get("bind_port", 0))
    except (TypeError, ValueError):
        bind_port = 0
    if not bind_port:
        h._err(400, "bind_port required")
        return
    st = h.server.state
    key = (int(sid), bind_port)
    with st.lock:
        if key not in st.rportfwds:
            h._err(404, "No active rportfwd on this port")
            return
        st.rportfwds.pop(key)
        st.log_audit(op["username"], "rportfwd_stop", int(sid), f"bind={bind_port}")
    h._json(200, {"status": "stopped"})

# ══ Hibernation task queue ═══════════════════════════════════════════════════

def _task_dto(st, task):
    """Lazy lifecycle: pending -> claimed (+6s) -> completed (+14s)."""
    now = now_ts()
    if task["status"] in ("cancelled",):
        pass
    elif task["status"] == "pending" and now - task["created_at"] >= 6:
        task["status"] = "claimed"
        task["claimed_at"] = int(now)
        host = st.hosts.get(task["_sid"])
        if host:
            host["last_seen"] = now  # the agent "checked in"
    if task["status"] == "claimed" and now - task["created_at"] >= 14:
        host = st.hosts.get(task["_sid"])
        if host:
            out, err, _ = run_command(st, host, task["command"])
            task["result"], task["error"] = out or "(no output)", err or None
        else:
            task["result"], task["error"] = None, "session gone"
        task["status"] = "completed" if not task["error"] else "failed"
        task["finished_at"] = int(now)
    return {"task_id": task["task_id"], "command": task["command"],
            "status": task["status"], "created_at": int(task["created_at"]),
            "claimed_at": task["claimed_at"], "result": task.get("result"),
            "error": task.get("error"), "finished_at": task.get("finished_at")}

@route("POST", r"/api/hosts/(\d+)/queue")
def r_queue(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Viewers cannot queue tasks")
        return
    cmd = str(h._json_body().get("command", "")).strip()
    if not cmd:
        h._err(400, "command must not be empty")
        return
    st = h.server.state
    sid = int(sid)
    with st.lock:
        if sid not in st.hosts:
            h._err(404, "session not found")
            return
        task = {"task_id": str(uuid.uuid4()), "command": cmd, "status": "pending",
                "created_at": now_ts(), "claimed_at": None, "result": None,
                "error": None, "finished_at": None, "_sid": sid}
        st.tasks.setdefault(sid, []).append(task)
        st.log_audit(op["username"], "queue_task", sid, cmd)
        h._json(201, {"task_id": task["task_id"], "session_id": sid,
                      "command": cmd, "status": "pending"})

@route("GET", r"/api/hosts/(\d+)/tasks")
def r_tasks(h, op, q, sid):
    st = h.server.state
    sid = int(sid)
    with st.lock:
        tasks = [_task_dto(st, t) for t in st.tasks.get(sid, [])]
    tasks.sort(key=lambda t: -t["created_at"])
    h._json(200, {"session_id": sid, "tasks": tasks, "total": len(tasks)})

@route("GET", r"/api/hosts/(\d+)/tasks/([^/]+)")
def r_task(h, op, q, sid, task_id):
    st = h.server.state
    with st.lock:
        task = next((t for t in st.tasks.get(int(sid), []) if t["task_id"] == task_id), None)
        if not task:
            h._err(404, "task not found")
            return
        h._json(200, _task_dto(st, task))

@route("DELETE", r"/api/hosts/(\d+)/tasks/([^/]+)")
def r_task_cancel(h, op, q, sid, task_id):
    if op["role"] == "viewer":
        h._err(403, "Viewers cannot cancel tasks")
        return
    st = h.server.state
    with st.lock:
        task = next((t for t in st.tasks.get(int(sid), []) if t["task_id"] == task_id), None)
        if not task or _task_dto(st, task)["status"] != "pending":
            h._err(409, "task not found or already claimed/completed")
            return
        task["status"] = "cancelled"
        task["finished_at"] = int(now_ts())
    h._send(204)

# ══ Topology ═════════════════════════════════════════════════════════════════

def _iface_score(iface):
    import ipaddress
    score = int(iface.get("prefix", 24))
    name = iface["name"].lower()
    if name.startswith(("eth", "en")):
        score += 20
    elif name.startswith(("wlan", "wlp")):
        score += 10
    try:
        if ipaddress.ip_address(iface["addr"]).is_private:
            score += 5
    except ValueError:
        pass
    if name.startswith(("docker", "br-", "veth")):
        score -= 10
    if not iface.get("up", True):
        score -= 50
    return max(0, score)

def _candidate(host, iface):
    import ipaddress
    net = ipaddress.ip_network(f"{iface['addr']}/{iface.get('prefix', 24)}", strict=False)
    return {"session_id": host["id"], "hostname": host["hostname"],
            "cidr": str(net), "interface": iface["name"],
            "source_addr": iface["addr"], "score": _iface_score(iface)}, net

@route("GET", r"/api/topology/plan")
def r_topo_plan(h, op, q):
    import ipaddress
    target = (q.get("target") or [""])[0].strip()
    try:
        if "/" in target:
            tnet = ipaddress.ip_network(target, strict=False)
        else:
            tnet = ipaddress.ip_network(target + "/32", strict=False)
        if tnet.version != 4:
            raise ValueError
    except ValueError:
        h._err(400, "target must be a valid IPv4 address or CIDR")
        return
    st = h.server.state
    with st.lock:
        cands, seen = [], set()
        for host in st.hosts.values():
            best = None
            for iface in host["ifaces"]:
                cand, net = _candidate(host, iface)
                if net.overlaps(tnet) and (best is None or cand["score"] > best["score"]):
                    best = cand
            if best and host["id"] not in seen:
                seen.add(host["id"])
                cands.append(best)
        cands.sort(key=lambda c: -c["score"])
        rendered = "\n".join(
            f"{'✔' if i == 0 else ' '}  Session #{c['session_id']} ({c['hostname']}) "
            f"via {c['interface']} {c['source_addr']}/{c['cidr'].split('/')[1]} "
            f"[score {c['score']}]" for i, c in enumerate(cands)) or "No route to target."
    h._json(200, {"target": target, "candidates": cands, "rendered": rendered})

@route("GET", r"/api/topology/snapshot")
def r_topo_snapshot(h, op, q):
    st = h.server.state
    with st.lock:
        cands, nets = [], {}
        for host in st.hosts.values():
            for iface in host["ifaces"]:
                cand, net = _candidate(host, iface)
                cands.append(cand)
                nets.setdefault(str(net), set()).add(host["id"])
        shared = [{"cidr": c, "sessions": sorted(s)} for c, s in nets.items() if len(s) > 1]
        conflicts = []
        items = list(nets.items())
        import ipaddress
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                (c1, s1), (c2, s2) = items[i], items[j]
                n1, n2 = ipaddress.ip_network(c1), ipaddress.ip_network(c2)
                if c1 != c2 and n1.overlaps(n2):
                    conflicts.append({"cidr_a": c1, "cidr_b": c2,
                                      "session_a": sorted(s1)[0], "session_b": sorted(s2)[0]})
        cands.sort(key=lambda c: -c["score"])
        h._json(200, {"session_count": len([hst for hst in st.hosts.values() if hst["ifaces"]]),
                      "candidates": cands, "shared_networks": shared,
                      "conflicts": conflicts})

# ══ IOCs ═════════════════════════════════════════════════════════════════════

@route("GET", r"/api/iocs")
def r_iocs(h, op, q):
    with h.server.state.lock:
        h._json(200, list(h.server.state.iocs))

@route("GET", r"/api/hosts/(\d+)/iocs")
def r_iocs_host(h, op, q, sid):
    with h.server.state.lock:
        h._json(200, [i for i in h.server.state.iocs if i["session_id"] == int(sid)])

@route("POST", r"/api/hosts/(\d+)/iocs")
def r_iocs_add(h, op, q, sid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    body = h._json_body()
    if not body.get("ioc_type") or not body.get("path"):
        h._err(400, "ioc_type and path are required")
        return
    st = h.server.state
    with st.lock:
        rec = {"id": st._next_ioc_id, "session_id": int(sid),
               "ioc_type": body["ioc_type"], "path": body["path"],
               "detail": body.get("detail"), "cleanup_cmd": body.get("cleanup_cmd"),
               "operator": op["username"], "created_at": iso_now(), "cleaned_at": None}
        st._next_ioc_id += 1
        st.iocs.append(rec)
        st.log_audit(op["username"], "add_ioc", int(sid), f"{body['ioc_type']} {body['path']}")
    h._json(201, {"id": rec["id"]})

@route("POST", r"/api/iocs/(\d+)/clean")
def r_iocs_clean(h, op, q, iid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    with st.lock:
        rec = next((i for i in st.iocs if i["id"] == int(iid)), None)
        if not rec:
            h._err(500, "no rows updated")
            return
        rec["cleaned_at"] = iso_now()
        st.log_audit(op["username"], "clean_ioc", rec["session_id"], f"id={iid}")
    h._send(204)

@route("DELETE", r"/api/iocs/(\d+)")
def r_iocs_del(h, op, q, iid):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    with st.lock:
        before = len(st.iocs)
        st.iocs = [i for i in st.iocs if i["id"] != int(iid)]
        if len(st.iocs) == before:
            h._err(500, "no rows deleted")
            return
    h._send(204)

# ══ Modules & extensions (script manager) ════════════════════════════════════

def _valid_script_name(name):
    return re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", name or "") is not None

@route("GET", r"/api/modules")
def r_modules(h, op, q):
    with h.server.state.lock:
        h._json(200, sorted(h.server.state.modules.keys()))

@route("GET", r"/api/extensions")
def r_extensions(h, op, q):
    with h.server.state.lock:
        h._json(200, {"extensions": sorted(h.server.state.extensions.keys())})

def _script_get(store):
    def fn(h, op, q, name):
        name = urllib.parse.unquote(name)
        if not _valid_script_name(name):
            h._err(400, "invalid name")
            return
        with h.server.state.lock:
            content = getattr(h.server.state, store).get(name)
        if content is None:
            h._send(404)
            return
        h._json(200, {"name": name, "content": content})
    return fn

def _script_put(store):
    def fn(h, op, q, name):
        if op["role"] == "viewer":
            h._send(403)
            return
        name = urllib.parse.unquote(name)
        if not _valid_script_name(name):
            h._err(400, "invalid name")
            return
        content = str(h._json_body().get("content", ""))
        with h.server.state.lock:
            getattr(h.server.state, store)[name] = content
            h.server.state.log_audit(op["username"], f"save_{store[:-1]}", None, name)
        h._json(200, {"saved": name})
    return fn

def _script_delete(store):
    def fn(h, op, q, name):
        if op["role"] == "viewer":
            h._send(403)
            return
        name = urllib.parse.unquote(name)
        with h.server.state.lock:
            if getattr(h.server.state, store).pop(name, None) is None:
                h._send(404)
                return
        h._send(204)
    return fn

r_extensions_get    = route("GET",    r"/api/extensions/([^/]+)")(_script_get("extensions"))
r_extensions_put    = route("PUT",    r"/api/extensions/([^/]+)")(_script_put("extensions"))
r_extensions_delete = route("DELETE", r"/api/extensions/([^/]+)")(_script_delete("extensions"))
r_modules_get       = route("GET",    r"/api/modules/([^/]+)")(_script_get("modules"))
r_modules_put       = route("PUT",    r"/api/modules/([^/]+)")(_script_put("modules"))
r_modules_delete    = route("DELETE", r"/api/modules/([^/]+)")(_script_delete("modules"))

@route("POST", r"/api/hosts/(\d+)/modules/([^/]+)")
def r_module_exec(h, op, q, sid, name):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    sid = int(sid)
    name = urllib.parse.unquote(name)
    with st.lock:
        if name not in st.modules:
            h._err(404, "Module not found on server")
            return
        if sid not in st.hosts:
            h._err(404, "Session offline")
            return
        args = h._json_body().get("args", [])
        if name == "survey":
            output = ("[*] Survey complete\n"
                      f"    Hostname : {st.hosts[sid]['hostname']}\n"
                      f"    OS       : {st.hosts[sid]['os']}\n"
                      f"    User     : {st.hosts[sid]['user']}\n"
                      "    AV       : Defender (signatures up to date)\n"
                      "    UAC      : enabled (medium integrity)\n")
        else:
            output = (f"[*] Module '{name}' executed for session #{sid} "
                      f"(args: {' '.join(map(str, args)) or 'none'})\n[+] Done (mock)\n")
        st.log_audit(op["username"], "module_exec", sid, name)
        h._json(200, {"module": name, "status": "executed", "result": "ok",
                      "output": output})

@route("POST", r"/api/broadcast/module")
def r_module_broadcast(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    body = h._json_body()
    name = str(body.get("module_name", ""))
    with st.lock:
        if name not in st.modules:
            h._err(404, "Module not found on server")
            return
        results = {}
        for sid in st.hosts:
            results[str(sid)] = {"status": "executed", "result": "ok",
                                 "output": f"[*] Module '{name}' executed for session #{sid} (mock)"}
            _history_row(st, sid, 0, f"broadcast module: {name}", 0)
        st.log_audit(op["username"], "broadcast_module", None, name)
        h._json(200, {"status": "broadcast_executed", "module": name,
                      "targets_reached": len(results), "results": results})

@route("POST", r"/api/hosts/(\d+)/extensions/([^/]+)")
def r_extension_deploy(h, op, q, sid, name):
    if op["role"] == "viewer":
        h._err(403, "Insufficient permissions")
        return
    st = h.server.state
    sid = int(sid)
    name = urllib.parse.unquote(name)
    with st.lock:
        if name not in st.extensions:
            h._err(404, "Extension not found on server")
            return
        host = st.hosts.get(sid)
        if not host:
            h._err(404, "Session offline")
            return
        jid = max([j["id"] for j in host["jobs"]] + [0]) + 1
        host["jobs"].append({"id": jid, "description": f"ext:load ({name})",
                             "status": "Running", "started_at": iso_now(),
                             "finished_at": None})
        if name == "screenshot":
            st._pending_shots[sid] = now_ts() + 2.5
        st.log_audit(op["username"], "extension_deploy", sid, name)
        h._json(200, {"status": "queued",
                      "message": f"Extension '{name}' sent to Client #{sid}"})

# ══ Builder ══════════════════════════════════════════════════════════════════

_FMT_EXT = {"exe": "exe", "dll": "dll", "service": "exe", "stager": "exe",
            "shellcode": "bin", "donut": "bin", "pe_to_shellcode": "bin",
            "pic_c": "bin", "bin": "bin"}

def _job_progress(job):
    """Compute status + visible log lines from elapsed time."""
    elapsed = now_ts() - job["started"]
    lines = [l for t, l in job["log_schedule"] if t <= elapsed]
    if elapsed >= job["duration"]:
        return "success", lines, job["finished_at"]
    return "running", lines, None

@route("POST", r"/api/builder/build")
def r_build(h, op, q):
    if op["role"] == "viewer":
        h._err(403, "Viewers cannot trigger builds")
        return
    body = h._json_body()
    if not body.get("host") or not body.get("port"):
        h._err(400, "host and port are required")
        return
    st = h.server.state
    with st.lock:
        job_id = str(uuid.uuid4())
        fmt = str(body.get("format") or "exe")
        ext = _FMT_EXT.get(fmt, "exe")
        platform = str(body.get("platform") or "windows")
        build_id = rand_hex(16)
        artifact = f"rcm_agent_{job_id[:8]}.{ext}"
        token = uuid.uuid4().hex[:24]
        st.payload_links[token] = {"job_id": job_id, "name": artifact}
        job = {
            "id": job_id, "started": now_ts(), "started_at": iso_now(),
            "duration": 8.5, "finished_at": iso_in(8.5),
            "artifact_name": artifact, "build_id": build_id,
            "download_url": f"/dl/{token}/{artifact}",
            "log_schedule": [
                (0.0, f"[*] Build ID: {build_id}"),
                (0.3, f"[*] Target: {platform} (format: {fmt}, transport: {body.get('transport', 'tls')})"),
                (0.8, f"[*] C2 endpoint: {body.get('host')}:{body.get('port')}"),
                (1.8, "[*] Compiling agent (release profile)..."),
                (4.0, "[*] Applying OPSEC string encryption (strcrypt)..."),
                (5.5, "[*] Stripping symbols and padding sections..."),
                (7.0, f"[*] Writing artifact: dist/{artifact}"),
                (8.2, "[+] Build complete in 8.21s"),
            ],
            "artifact": (b"MZ" + bytes(os.urandom(2048))) if ext == "exe"
                        else os.urandom(512),
        }
        st.build_jobs[job_id] = job
        st.log_audit(op["username"], "build", None,
                     f"job={job_id[:8]} platform={platform} format={fmt}")
    h._json(202, {"job_id": job_id})

def _job_dto(job, full):
    status, lines, finished = _job_progress(job)
    dto = {"job_id": job["id"], "status": status,
           "log": lines if full else [],
           "artifact_name": job["artifact_name"] if status == "success" else None,
           "build_id": job["build_id"] if status == "success" else None,
           "download_url": job["download_url"] if status == "success" else None,
           "started_at": job["started_at"],
           "finished_at": finished}
    return dto

@route("GET", r"/api/builder/jobs")
def r_build_jobs(h, op, q):
    st = h.server.state
    with st.lock:
        out = [_job_dto(j, full=False) for j in st.build_jobs.values()]
    out.sort(key=lambda j: j["started_at"], reverse=True)
    h._json(200, out)

@route("GET", r"/api/builder/jobs/([^/]+)/status")
def r_build_status(h, op, q, job_id):
    job = h.server.state.build_jobs.get(job_id)
    if not job:
        h._err(404, "Job not found")
        return
    h._json(200, _job_dto(job, full=True))

@route("GET", r"/api/builder/jobs/([^/]+)/download")
def r_build_download(h, op, q, job_id):
    job = h.server.state.build_jobs.get(job_id)
    if not job:
        h._send(404, "Job not found", "text/plain; charset=utf-8")
        return
    status, _, _ = _job_progress(job)
    if status != "success":
        h._send(409, "Job not finished", "text/plain; charset=utf-8")
        return
    h._send(200, job["artifact"], "application/octet-stream",
            {"Content-Disposition": f'attachment; filename="{job["artifact_name"]}"'})

# ══ Hosted payload links (unauthenticated, like the real server) ═════════════

@route("GET", r"/dl/([0-9a-f]+)/([^/]+)", protected=False)
def r_dl(h, op, q, token, name):
    st = h.server.state
    link = st.payload_links.get(token)
    if not link:
        h._send(404, "Not found", "text/plain; charset=utf-8")
        return
    job = st.build_jobs.get(link["job_id"])
    if not job:
        h._send(404, "Not found", "text/plain; charset=utf-8")
        return
    h._send(200, job["artifact"], "application/octet-stream",
            {"Content-Disposition": f'attachment; filename="{name}"'})

# ══ Entry point ══════════════════════════════════════════════════════════════

BANNER = r"""
  ____   ____ __  __   __  __            _    
 |  _ \ / ___|  \/  | |  \/  | ___   ___| | __
 | |_) | |   | |\/| | | |\/| |/ _ \ / __| |/ /
 |  _ <| |___| |  | | | |  | | (_) | (__|   < 
 |_| \_\\____|_|  |_| |_|  |_|\___/ \___|_|\_\
"""

def main():
    ap = argparse.ArgumentParser(
        description="RCM mock C2 server - faux APIs for panel UX/UI testing")
    ap.add_argument("--port", "-p", type=int,
                    default=int(os.environ.get("RCM_MOCK_PORT", "18080")),
                    help="listen port (default: 18080; the real server uses 8080 - we avoid it "
                            "so a worker left on that origin cannot interfere)")
    ap.add_argument("--host", default=os.environ.get("RCM_MOCK_HOST", "127.0.0.1"),
                    help="bind address (default: 127.0.0.1)")
    ap.add_argument("--verbose", "-v", action="store_true",
                    default=os.environ.get("RCM_MOCK_VERBOSE", "") == "1",
                    help="log every HTTP request (default: quiet console)")
    args = ap.parse_args()

    # The panel is served from ./panel relative to the repository root, which
    # is the parent directory of this script's tests/ folder.
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isfile(os.path.join(repo_root, "panel", "index.html")):
        sys.stderr.write("[-] panel/index.html not found next to tests/ - "
                         "run this from the RCM repository tree\n")
        sys.exit(1)

    state = State(repo_root)
    server = MockHTTPServer((args.host, args.port), MockHandler, state)
    server.verbose = args.verbose

    print(BANNER)
    print(f"  Mock C2 server v{VERSION} - faux data, no real agents")
    print(f"  Panel:    http://{args.host}:{args.port}/")
    print(f"  API base: http://{args.host}:{args.port}")
    print()
    print("  If the panel ever looks stale, blank, or reload-loops, a leftover")
    print("  service worker owns this origin - just restart on another port (-p).")
    print("  Demo logins:   admin / admin      (admin)")
    print("                 operator / operator (operator)")
    print("                 viewer / viewer     (viewer)")
    print()
    print("  A demo session will check in ~45s after startup. Ctrl+C to stop.")
    if not args.verbose:
        print("  Request log hidden - re-run with -v to see HTTP traffic.")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Mock server stopped")

if __name__ == "__main__":
    main()
