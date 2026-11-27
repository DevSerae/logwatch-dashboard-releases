"""Web installer: served on the board's port with a one-time token, hands the port over to the board when done.

    sudo .venv/bin/python -m installer [--port 8080] [--bind 0.0.0.0]

The token is printed in the terminal (and nowhere else). Everything is one page (installer/web/index.html) talking to
the JSON API below. Save & start: config is written, the images are built while the page stays up, then this server
lets go of the port, `docker compose up -d` starts the board on it, and the page reloads into the board's login.
If the board is already running on the port, the installer uses the next free one and nothing is handed over.

Edit mode (Features → Edit settings on the board): update.sh starts it as root with --edit --socket data/installer.sock
--token-file <file>; the board proxies /setup/ to the socket for its admins, so it works wherever the board does
(tunnels included). Settings that would cut the board off or need the terminal are locked (EDIT_LOCK, edit_guard),
Save & restart saves, restarts the board and exits.
"""
import argparse
import hmac
import json
import os
import secrets
import ipaddress
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import access, checks, configio, discover, pending, prompts
from .schema import ACCESS_FIELDS, ALL_MODULES, BOARD_FIELDS, METHODS, MONITORS

PAGE = Path(__file__).parent / "web" / "index.html"
TOKEN = secrets.token_urlsafe(18)
COOKIE = "lw_installer"
HIDE = ("secret:", "once_")
DISCOVER_TARGETS = [("hosts:syslog", "Syslog: hosts that forward logs", "syslog"),
                    ("ssh:logpull", "SSH log pull", "pull"),
                    ("ssh:images", "Docker image scan", "trivy")]


class Job:
    """One background task at a time (access install, compose); the page polls its log."""

    def __init__(self):
        self.lines, self.running, self.ok, self.kind, self.lock = [], False, None, "", threading.Lock()

    def start(self, kind, fn):
        with self.lock:
            if self.running:
                return False
            self.lines, self.running, self.ok, self.kind = [], True, None, kind
        threading.Thread(target=self._run, args=(fn,), daemon=True).start()
        return True

    def _run(self, fn):
        try:
            self.ok = bool(fn(self.say))
        except Exception as e:   # shown on the page, not swallowed
            self.say(f"error: {e}")
            self.ok = False
        self.running = False

    def say(self, *a):
        self.lines.append(" ".join(str(x) for x in a))

    def view(self, frm):
        return {"lines": self.lines[frm:], "n": len(self.lines), "running": self.running, "ok": self.ok, "kind": self.kind}


EDIT_LOCK = {   # key → why it can't be changed from the board
    "addr": "Fixed once installed: the servers already send to this address.",
    "env:BOARD_PORT": "Changing the port would cut off this page and every proxy or tunnel pointing at the board. Change it in .env on the VM.",
    "admin_user": "Users are managed on the board (Users).",
    "admin_pw": "Users are managed on the board (Users).",
    "admin_pw2": "Users are managed on the board (Users).",
    **{f.key: "VPN and access methods change this VM's networking: use the setup in a terminal on the board VM." for f in ACCESS_FIELDS},
}

APP = {"state": None, "edit": False, "viewer": {}, "job": Job(), "handoff": False, "port": 8080, "board_port": 8080, "server": None, "lock": threading.Lock()}


# --- state ----------------------------------------------------------------------------------------------------------

def field(f):
    return {"key": f.key, "label": f.label, "kind": f.kind, "help": f.help, "required": f.required,
            "options": list(f.options), "placeholder": f.placeholder}


def public_values(st):
    return {k: ("" if k.startswith(HIDE) or k in ("admin_pw", "admin_pw2") else v) for k, v in st["values"].items()}


def _nets(v):
    out = []
    for x in (v if isinstance(v, list) else str(v or "").replace(",", " ").split()):
        try:
            out.append(ipaddress.ip_network(str(x).strip(), strict=False))
        except ValueError:
            pass
    return out


def _in(ip, nets):
    try:
        return any(ipaddress.ip_address(ip) in n for n in nets)
    except ValueError:
        return False


def edit_guard(st):
    """Edit mode: changes that would lock out the admin who is making them (the board says who: X-Lw-Viewer)."""
    if not APP["edit"]:
        return []
    v, w, out = st["values"], APP["viewer"], []
    ip, peer = w.get("ip", ""), w.get("peer", "")
    trusted = _nets(v.get("board.trusted_proxies"))
    via = peer and _in(peer, trusted)
    allow = _nets(v.get("board.allow_cidrs"))
    if w.get("trusted") and not via:
        out.append(f"keep {peer} in Reverse proxies / tunnel connectors: you're connected through it")
    if allow and ip and not _in(ip, allow) and not (v.get("board.proxy_public") and via):
        out.append(f"your address {ip} isn't in Networks that may open the login page: you'd be locked out")
    if v.get("board.cookie_secure") and not w.get("https"):
        out.append("Board is served over HTTPS is on, but you're on plain http: the login cookie would stop working")
    if v.get("board.cf_access.required") and not w.get("cf"):
        out.append("Require Cloudflare Access is on, but this page didn't come through Cloudflare Access: test Access first")
    return out


def problems(st):
    probs = configio.validate(st)
    g = edit_guard(st)
    if g:
        probs = {**probs, "board": probs.get("board", []) + g}
    return probs


def status(st):
    probs = problems(st)
    return {"problems": probs, "enabled": sorted(configio.enabled(st)), "stored": sorted(st["stored"]),
            "values": public_values(st), "mods": st["mods"], "mons": st["mons"],
            "configured": configio.setup.CONFIG.exists()}


def schema():
    return {"board": [field(f) for f in BOARD_FIELDS], "access": [field(f) for f in ACCESS_FIELDS],
            "methods": METHODS, "sub": {m: list(access.SUB.get(m, ())) for m in METHODS},
            "monitors": [{"id": mon.id, "title": mon.title, "what": mon.what,
                          "modules": [{"id": m.id, "title": m.title, "what": m.what, "fields": [field(f) for f in m.fields]}
                                      for m in mon.modules]} for mon in MONITORS],
            "discover": [{"key": k, "label": l, "module": m} for k, l, m in DISCOVER_TARGETS],
            "version": prompts.version(), "root": str(configio.ROOT), "is_root": os.geteuid() == 0,
            "port": APP["port"], "board_port": APP["board_port"], "agents": prompts.agent_clis(),
            "edit": APP["edit"], "locked": EDIT_LOCK if APP["edit"] else {}}


def ensure_key():
    if not configio.pubkey():
        configio.setup.say = lambda *a: None
        configio.init()


def apply(body):
    st = APP["state"]
    with APP["lock"]:
        for k, val in (body.get("values") or {}).items():
            if APP["edit"] and k in EDIT_LOCK:
                continue
            if k in st["values"] or any(f.key == k for f in configio.all_fields()):
                st["values"][k] = val
        for k, val in (body.get("mods") or {}).items():
            if k in ALL_MODULES:
                st["mods"][k] = bool(val)
        for k, val in (body.get("mons") or {}).items():
            st["mons"][k] = bool(val)


# --- jobs -----------------------------------------------------------------------------------------------------------

def run(cmd, say, hide=(), cwd=None):
    say("$ " + " ".join("<key>" if a in hide else a for a in cmd))
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in p.stdout:
        for x in hide:
            line = line.replace(x, "<key>")
        say(line.rstrip())
    if p.wait():
        say(f"failed (exit {p.returncode})")
        return False
    return True


def job_access(m):
    st = APP["state"]
    cmds = access.install_cmds(st, m)
    hide = {st["values"].get(k) for k in ("once_ts_authkey", "once_nb_setup_key")} - {"", None}

    def go(say):
        for c in cmds:
            if not run(c, say, hide):
                return False
        for k in ("once_ts_authkey", "once_nb_setup_key"):
            st["values"][k] = ""
        for lvl, msg in access.check(st, m):
            say(f"[{lvl}] {msg}")
        return True
    return go


def healthy(port, timeout=3):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=timeout) as r:
            return r.status == 200 and not r.headers.get("X-Logwatch-Installer")
    except OSError:
        return False


def write_pending(say):
    try:
        pending.write(APP["state"])
    except Exception as e:   # the board just shows less; never fail the install over it
        say(f"note: couldn't write the setup list for the board: {e}")


def job_edit(say):
    """Edit mode: save, re-render, restart the board and worker on the new config, then this installer exits."""
    st = APP["state"]
    try:
        configio.save(st, log=say)
    except ValueError as e:
        say(f"Not saved: {e}")
        return False
    write_pending(say)
    say("Saved. Restarting the board (about half a minute); this page goes back to the board when it answers.")
    ok = run([sys.executable, "setup.py", "render"], say, cwd=configio.ROOT)
    configio.fix_owner()
    if not (ok and run(["docker", "compose", "up", "-d", "--remove-orphans"], say, cwd=configio.ROOT)):
        return False
    threading.Timer(3, lambda: subprocess.run(["docker", "compose", "restart", "board", "worker"], cwd=configio.ROOT,
                                              capture_output=True)).start()   # let the page read the log first
    threading.Timer(120, lambda: threading.Thread(target=APP["server"].shutdown).start()).start()
    return True


def job_start(say):
    st = APP["state"]
    try:
        configio.save(st, log=say)
    except ValueError as e:
        say(f"Not saved: {e}")
        return False
    write_pending(say)
    APP["board_port"] = int(st["values"].get("env:BOARD_PORT") or 8080)
    say("Building the images (the first build takes a few minutes)")
    if not run(["docker", "compose", "build"], say, cwd=configio.ROOT):
        return False
    if APP["board_port"] == APP["port"]:
        say("Handing the port over to the board…")
        APP["handoff"] = True
        threading.Timer(2.5, APP["server"].shutdown).start()   # let the page read this line; the main loop runs compose up
        return True
    if not run(["docker", "compose", "up", "-d", "--remove-orphans"], say, cwd=configio.ROOT):
        return False
    for _ in range(60):
        if healthy(APP["board_port"]):
            say(f"Board is up on port {APP['board_port']}")
            threading.Timer(20, lambda: threading.Thread(target=APP["server"].shutdown).start()).start()
            return True
        time.sleep(3)
    say("The board didn't answer /healthz within 3 minutes: docker compose logs board")
    return False


def handoff():
    """Port released: start the board on it. True when it answers; False (installer comes back) on failure."""
    job, port = APP["job"], APP["board_port"]
    job.running, job.ok = True, None
    print(f"==> docker compose up -d (board on port {port})", flush=True)
    if not run(["docker", "compose", "up", "-d", "--remove-orphans"], job.say, cwd=configio.ROOT):
        job.running, job.ok = False, False
        return False
    for _ in range(60):
        if healthy(port):
            return True
        time.sleep(3)
    job.say("The board didn't answer /healthz within 3 minutes: docker compose logs board")
    job.running, job.ok = False, False
    subprocess.run(["docker", "compose", "stop", "board"], cwd=configio.ROOT, capture_output=True)
    return False


# --- HTTP -----------------------------------------------------------------------------------------------------------

def results(rows):
    return [{"level": lvl, "msg": msg} for lvl, msg in rows]


class H(BaseHTTPRequestHandler):
    server_version = "logwatch-installer"
    sys_version = ""

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", headers=()):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Logwatch-Installer", "1")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def authed(self):
        if APP["edit"]:   # only the board can reach the socket; it says who is looking
            try:
                APP["viewer"] = json.loads(self.headers.get("X-Lw-Viewer") or "{}")
            except ValueError:
                APP["viewer"] = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE and hmac.compare_digest(v.encode(), TOKEN.encode()):
                return True
        return False

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":
            return self.send(200, {"ok": True, "installer": True})
        if u.path == "/":
            t = (parse_qs(u.query).get("t") or [""])[0]
            if t:
                if hmac.compare_digest(t.encode(), TOKEN.encode()):
                    return self.send(303, b"", "text/plain", [("Location", "/"), ("Set-Cookie",
                                     f"{COOKIE}={TOKEN}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400")])
                return self.send(403, LOCKED.replace("<!--e-->", "<p class=e>That token doesn't match.</p>"), "text/html")
            return self.send(200, PAGE.read_bytes() if self.authed() else LOCKED, "text/html")
        if not self.authed():
            return self.send(401, {"error": "token"})
        if u.path == "/api/init":
            return self.send(200, {"schema": schema(), **status(APP["state"])})
        if u.path == "/api/job":
            return self.send(200, APP["job"].view(int((parse_qs(u.query).get("from") or ["0"])[0])))
        if u.path == "/api/steps":
            mid = (parse_qs(u.query).get("m") or [""])[0]
            st = APP["state"]
            if mid.startswith("acc:"):
                return self.send(200, {"md": access.steps(st, mid[4:])})
            if mid in ALL_MODULES:
                return self.send(200, {"md": prompts.steps(st, mid)})
            return self.send(404, {"error": "module"})
        if u.path == "/api/servers":
            ensure_key()
            return self.send(200, {"servers": prompts.servers(APP["state"]), "agents": prompts.agent_clis()})
        return self.send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if not self.authed() or self.headers.get("X-Installer") != "1":   # SameSite cookie + custom header = no CSRF
            return self.send(401, {"error": "token"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError:
            return self.send(400, {"error": "json"})
        st, job = APP["state"], APP["job"]
        p = u.path
        if p == "/api/state":
            apply(body)
            return self.send(200, status(st))
        if p == "/api/check":
            apply(body)
            s = body.get("scope", "")
            ensure_key()
            if s == "board":
                rows = [r for r in checks.board(st) if not ("board:" in r[1] and "already in use" in r[1] and APP["port"] == int(
                    st["values"].get("env:BOARD_PORT") or 8080))]
                if APP["port"] == int(st["values"].get("env:BOARD_PORT") or 8080):
                    rows.append(("ok", f"board: TCP {APP['port']} is this installer; the board takes it over at the end"))
            elif s == "targets":
                rows = access.targets(st)
            elif s.startswith("acc:"):
                rows = access.check(st, s[4:])
            elif s in ALL_MODULES:
                rows = checks.module(st, s)
            else:
                return self.send(404, {"error": "scope"})
            return self.send(200, {"results": results(rows)})
        if p == "/api/access/install":
            m = body.get("method")
            if APP["edit"]:
                return self.send(400, {"error": EDIT_LOCK["acc_direct"]})
            if m not in METHODS or not access.install_cmds(st, m):
                return self.send(400, {"error": "nothing to install for that method"})
            if os.geteuid() != 0:
                return self.send(400, {"error": "installing needs root: start the installer with sudo"})
            return self.send(200, {"started": job.start("access", job_access(m))})
        if p == "/api/discover":
            apply(body)
            try:
                return self.send(200, discover.proxmox(st))
            except Exception as e:
                return self.send(200, {"error": checks._err(e)})
        if p == "/api/discover/add":
            picked = [(n, ip) for n, ip in body.get("picked") or [] if ip]
            added = []
            for key, label, mid in DISCOVER_TARGETS:
                if key in (body.get("targets") or []) and picked:
                    text, n = discover.merge_hosts(st["values"].get(key), picked)
                    st["values"][key] = text
                    st["mods"][mid] = True
                    st["mons"][next(m.id for m in MONITORS if any(x.id == mid for x in m.modules))] = True
                    added.append(f"{n} to {label.split(':')[0]}")
            return self.send(200, {"added": added, **status(st)})
        if p == "/api/prompt":
            ensure_key()
            text = prompts.servers_prompt(st, body.get("servers"))
            path = configio.ROOT / "installer-prompts" / "servers.md"
            path.parent.mkdir(exist_ok=True)
            path.write_text(text)
            configio.fix_owner()
            return self.send(200, {"text": text, "path": str(path)})
        if p == "/api/installed":
            prompts.mark_installed(body.get("name", ""), body.get("items") or [])
            write_pending(lambda *x: None)
            return self.send(200, {"servers": prompts.servers(st)})
        if p == "/api/save":
            apply(body)
            lines = []
            try:
                g = edit_guard(st)
                if g:
                    raise ValueError("board: " + "; ".join(g))
                configio.save(st, log=lambda *a: lines.append(" ".join(map(str, a))))
                write_pending(lines.append)
            except ValueError as e:
                return self.send(200, {"ok": False, "error": str(e), **status(st)})
            return self.send(200, {"ok": True, "log": lines, **status(st)})
        if p == "/api/quit" and APP["edit"]:
            threading.Timer(0.5, lambda: threading.Thread(target=APP["server"].shutdown).start()).start()
            return self.send(200, {"ok": True})
        if p == "/api/start":
            apply(body)
            probs = problems(st)
            if probs:
                return self.send(200, {"started": False, "problems": probs})
            if APP["edit"]:
                return self.send(200, {"started": job.start("start", job_edit), "board_port": APP["board_port"], "edit": True})
            return self.send(200, {"started": job.start("start", job_start), "board_port": int(st["values"].get("env:BOARD_PORT") or 8080)})
        return self.send(404, {"error": "not found"})


LOCKED = b"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Logwatch setup</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 600px at 50% -10%,#2a2350,#0d0b16 60%);
color:#e9e6f7;font:15px/1.5 system-ui,sans-serif}.b{background:#16131f;border:1px solid #2d2842;border-radius:16px;padding:32px 36px;
max-width:420px;box-shadow:0 20px 60px #0008}h1{margin:0 0 6px;font-size:22px}h1 b{color:#9085e9}p{color:#a49fbd;margin:6px 0 18px}
input{width:100%;box-sizing:border-box;padding:11px 13px;border-radius:10px;border:1px solid #3a3456;background:#0f0d18;color:#fff;font:inherit}
button{margin-top:12px;width:100%;padding:11px;border:0;border-radius:10px;background:#9085e9;color:#0d0b16;font-weight:600;font-size:15px;cursor:pointer}
.e{color:#ff8a9a}</style></head><body><form class=b method=get action="/"><h1>Logwatch<b>.</b> setup</h1>
<p>Paste the setup token printed in the terminal where you ran the installer.</p><!--e-->
<input name=t autocomplete=off autofocus placeholder="token"><button>Open setup</button></form></body></html>"""


def free(port):
    s = socket.socket()
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):   # BaseHTTPRequestHandler wants a (host, port)-ish client address
        sock, _ = super().get_request()
        return sock, ("board", 0)


def serve_edit(a):
    """Edit mode on a unix socket the board proxies to; exits after Save & restart or when systemd's limit is up."""
    global TOKEN
    APP["edit"] = True
    tf = Path(a.token_file)
    raw = tf.read_text().strip()
    tf.unlink(missing_ok=True)
    try:
        TOKEN = json.loads(raw).get("token") or ""
    except ValueError:
        TOKEN = raw
    if len(TOKEN) < 20:
        sys.exit("token too short")
    APP["state"] = configio.load()
    st = APP["state"]["stored"]   # users are managed on the board: no installer admin password to ask for (or save)
    st.add("BOARD_ADMIN_PASSWORD_HASH") if isinstance(st, set) else st.append("BOARD_ADMIN_PASSWORD_HASH")
    APP["board_port"] = APP["port"] = int(APP["state"]["values"].get("env:BOARD_PORT") or 8080)
    sock = Path(a.socket)
    sock.unlink(missing_ok=True)
    old = os.umask(0o177)
    srv = UnixServer(str(sock), H)
    os.umask(old)
    st = configio.ROOT.stat()
    if os.geteuid() == 0:
        os.chown(sock, st.st_uid, st.st_gid)   # the board's containers run as the install dir's owner
    APP["server"] = srv
    print(f"Logwatch settings editor on {sock} (Edit settings on the board)", flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
        sock.unlink(missing_ok=True)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m installer", description="Logwatch Dashboard web installer")
    ap.add_argument("--port", type=int, help="default: the board's port if free, else the next free one")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--edit", action="store_true", help=argparse.SUPPRESS)        # started by update.sh for the board
    ap.add_argument("--socket", default=str(configio.setup.DATA / "installer.sock"), help=argparse.SUPPRESS)
    ap.add_argument("--token-file", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.edit:
        return serve_edit(a)
    if os.geteuid() != 0 and not os.access(configio.ROOT, os.W_OK):
        sys.exit(f"Can't write {configio.ROOT}: run with sudo")
    APP["state"] = configio.load()
    board = int(APP["state"]["values"].get("env:BOARD_PORT") or 8080)
    port = a.port or next(p for p in [board, *range(board + 1, board + 50)] if free(p))
    APP["port"], APP["board_port"] = port, board
    addr = APP["state"]["values"].get("addr") or configio.default_addr() or "this-vm"
    note = "" if port == board else f"  (port {board} is busy, probably the running board: it stays up)\n"
    print(f"\n  Logwatch Dashboard {prompts.version()} setup\n\n"
          f"  Open:  http://{addr}:{port}/?t={TOKEN}\n{note}"
          f"  Token: {TOKEN}   (one-time, only shown here)\n\n"
          "  Ctrl+C stops the installer; config is only written when you press Save.\n", flush=True)
    while True:
        srv = ThreadingHTTPServer((a.bind, port), H)
        srv.daemon_threads = True
        APP["server"] = srv
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
            return
        finally:
            srv.server_close()
        if not APP["handoff"]:
            print(f"Done. Board: http://{addr}:{APP['board_port']}/", flush=True)
            return
        APP["handoff"] = False
        if handoff():
            print(f"==> Board is up: http://{addr}:{APP['board_port']}/  (log in as "
                  f"{APP['state']['values'].get('admin_user') or 'admin'})", flush=True)
            return
        print("xx board didn't start; the installer is back on the same URL with the log", flush=True)
