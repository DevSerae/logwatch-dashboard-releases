"""Install features from the board: the board files /data/feature-request.json ({enable, by, requested}) when an admin
clicks Install; update.sh on the host (root, same systemd units as updates) switches those modules on in config.yaml,
renders and restarts, and reports in /data/feature-status.json. Modules installed this way stay in Set up (kv
features_setup): their tab shows the setup steps instead of the page (GATES) until the admin marks them done.

health() says, per enabled module, whether it can work: "setup" (never finished: required settings missing, the AI
runner never connected, installed from the board and not marked done), "broken" (set up but failing: its checks error,
the runner went offline or its agent fails) or "todo" (works, but the installer still lists servers to install). The
board grays out that feature's buttons with the reason, and Features shows how to fix it. Unfinished work from older
installers/boards comes from data/setup-pending.json (python -m installer pending, run by update.sh).
"""
import json
import re
import time

import db
from settings import CONFIG, DATA, MODULES, mod, secret

try:
    from featureschema import MONITORS   # installer/schema.py, copied into the image
except ImportError:                      # running from a source checkout
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "installer"))
    from schema import MONITORS

REQUEST, STATUS = DATA / "feature-request.json", DATA / "feature-status.json"
BEAT = DATA / "updater.json"
PENDING = DATA / "setup-pending.json"
INSTALL = "sudo bash /opt/logwatch-dashboard/install.sh"
ROOT = "/opt/logwatch-dashboard"
RESTART = f"cd {ROOT} && docker compose up -d && docker compose restart board worker"
# board tabs that only exist when one of these modules is on: off → install page, all on ones still in Set up → setup page
GATES = {"up": ["uptime"], "edge": ["crowdsec", "traffic", "waf"], "infra": ["proxmox", "unifi", "action1", "expiry"]}
GATE_TITLES = {"up": "Status", "edge": "Edge WAF", "infra": "Infrastructure"}
# board checks (collect.py) → the module whose failure they show
CHECKS = {"pull": "pull", "unifi": "unifi", "wan": "unifi", "windows": "windows", "top_domains": "windows", "tls_expiry": "expiry",
          "trivy": "trivy", "crowdsec": "crowdsec", "proxmox": "proxmox", "backups": "proxmox", "disks": "proxmox",
          "action1": "action1", "wazuh": "wazuh", "alertfile": "alertfile"}
TOKENS = {"ai": "AI_RUNNER_TOKEN", "webhook": "INGEST_TOKEN"}   # generated, not asked for
RUNNER_SVC = "systemctl restart logwatch-ai-runner"


def _read(p):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def _where(key):
    if key.startswith("secret:"):
        return f"cd {ROOT} && sudo python3 setup.py secret {key[7:]}"
    if key.startswith("ssh:"):
        return f"config/config.yaml → ssh.hosts, role {key[4:]}"
    if key.startswith("hosts:") or "." not in key:
        return ""   # installer-only: used to write the server steps
    return "config/config.yaml → " + key


def steps(m):
    for mon in MONITORS:
        for x in mon.modules:
            if x.id == m:
                return {"id": m, "title": x.title, "what": x.what, "monitor": mon.title, "install": INSTALL,
                        "fields": [{"label": f.label, "help": f.help, "where": _where(f.key), "secret": f.key.startswith("secret:"),
                                    "required": f.required} for f in x.fields if _where(f.key) or f.help]}
    return None


def _ago(t):
    s = max(0, time.time() - t)
    return f"{int(s)}s" if s < 120 else f"{int(s // 60)} min" if s < 7200 else f"{int(s // 3600)} h" if s < 172800 else f"{int(s // 86400)} days"


def _cfg(key):
    v = CONFIG
    for p in key.split("."):
        v = v.get(p) if isinstance(v, dict) else None
    return v


def _missing(m):
    """Required settings of module m that are empty (labels)."""
    out = []
    for mon in MONITORS:
        for x in mon.modules:
            if x.id != m:
                continue
            for f in x.fields:
                if not f.required:
                    continue
                if f.key.startswith("secret:"):
                    if not secret(f.key[7:]):
                        out.append(f.label)
                elif "." in f.key and not f.key.startswith(("env:", "hosts:", "ssh:", "lines:")) and _cfg(f.key) in (None, "", []):
                    out.append(f.label)
    if m in TOKENS and not secret(TOKENS[m]):
        out.append(TOKENS[m])
    return out


def ai_health(con, board_url=""):
    """(level, reason, fix steps) for the AI runner, or None when it works."""
    url = board_url or "https://<this board's URL>"
    env = f"cd {ROOT} && sudo python3 setup.py runner-env --out runner.env --url {url}"
    if not secret("AI_RUNNER_TOKEN"):
        return "setup", "There's no runner token yet, so no AI runner can connect.", [
            {"text": "On the board VM, create the token and the runner's env file, then restart the board:", "cmd": env + f" && {RESTART}"},
            {"text": "Then set up the runner (next step)."}]
    seen = db.kv_get(con, "ai_runner_seen", 0) or 0
    info = db.kv_get(con, "ai_runner", {}) or {}
    last = db.kv_get(con, "ai_last", {}) or {}
    agent = info.get("agent") or "claude"
    runner = [{"text": "On the machine where your AI agent CLI runs (it needs access to your servers), copy ai-runner/runner.py and "
                       "the runner.env from the board VM, then test it:", "cmd": env},
              {"text": "Test once, then run it permanently (systemd unit logwatch-ai-runner.service, tmux or pm2):",
               "cmd": "python3 runner.py --env runner.env --once"},
              {"text": f"The agent CLI ({agent}) must be installed and signed in for the user the runner runs as. "
                       "Details: ai-runner/README.md."}]
    if not seen:
        return "setup", "The AI runner has never connected to this board.", runner
    if time.time() - seen > 90:
        return "broken", f"The AI runner is offline (last seen {_ago(seen)} ago).", [
            {"text": "On the runner machine, start it again and check its log:", "cmd": RUNNER_SVC + " && journalctl -u logwatch-ai-runner -n 30"},
            {"text": "Started by hand instead? Run it again with `python3 runner.py --env runner.env`. "
                     "It must reach this board's URL (allowed networks, tunnel)."}]
    login = {"claude": "claude   # then /login", "codex": "codex login", "gemini": "gemini   # sign in when asked",
             "opencode": "opencode auth login"}.get(agent, "")
    agent_fix = [{"text": f"On the runner machine, as the runner's user, check that {agent} works on its own and is signed in:",
                  "cmd": login or "(run your AGENT_CMD by hand)"},
                 {"text": "Then restart the runner:", "cmd": RUNNER_SVC}]
    if not info.get("groups"):
        return "broken", (f"The AI runner ({info.get('version') or 'before 2.4.0'}) is too old for bulk \"Resolve with AI\": it would start "
                          "one agent session per item, so bulk runs wait until it's updated."), [
            {"text": "On the runner machine, replace runner.py with this board's ai-runner/runner.py, then restart the runner:",
             "cmd": RUNNER_SVC}]
    if info.get("ready") is False:
        return "broken", f"The runner can't use its agent: {info.get('why') or 'not ready'}", agent_fix
    if last.get("err") and last.get("err_at", 0) > last.get("ok_at", 0) and time.time() - last["err_at"] < 7 * 86400:
        return "broken", f"The last AI job failed ({_ago(last['err_at'])} ago): {last['err'][:300]}", agent_fix
    return None


def health(con, setup=(), board_url=""):
    """{module: {level, reason, fix: [{text, cmd}], steps (markdown), servers}} for enabled modules that aren't fine."""
    pend = (_read(PENDING) or {}).get("modules") or {}
    runs = db.kv_get(con, "collectors", {}) or {}
    out = {}
    for m in MODULES:
        if not mod(m):
            continue
        p = pend.get(m) or {}
        h = {"level": "", "reason": "", "fix": [], "steps": p.get("steps") or "", "servers": p.get("servers") or []}
        miss = _missing(m)
        bad = [(n, r) for n, r in runs.items() if CHECKS.get(n) == m and not r.get("ok")]
        if miss:
            h.update(level="setup", reason="Not set up yet: " + ", ".join(miss) + (" is" if len(miss) == 1 else " are") + " missing.",
                     fix=[{"text": "Add them with Edit settings (Features page), or on the board VM:",
                           "cmd": _where("secret:" + TOKENS[m]) if m in TOKENS and TOKENS[m] in miss else
                           f"cd {ROOT} && sudo .venv/bin/python -m installer"}])
        elif m == "ai":
            a = ai_health(con, board_url)
            if a:
                h.update(level=a[0], reason=a[1], fix=a[2])
        if not h["level"] and bad:
            n, r = bad[0]
            h.update(level="broken", reason=f"Its check '{n}' is failing: {r.get('err') or 'error'}",
                     fix=[{"text": "Fix what the error says (address, key, permissions), then press Run checks on the board. "
                                   "Settings live in Edit settings (Features page)."}])
        if not h["level"] and m == "traffic":
            fails = [r["k"][13:] for r in con.execute("SELECT k, v FROM kv WHERE k LIKE 'traffic_fail:%'") if int(json.loads(r["v"]) or 0) >= 10]
            if fails:
                h.update(level="broken", reason="Can't pull traffic logs from " + ", ".join(fails) + ".",
                         fix=[{"text": "Check SSH from the board to those hosts and that their /etc/logwatch-remote.conf enables trafficpull:",
                               "cmd": "sudo ./linux/check-host.sh --board <board address> --roles trafficpull"}])
        if not h["level"] and p.get("problems"):
            h.update(level="setup", reason="Setup wasn't finished: " + "; ".join(p["problems"]))
        if not h["level"] and m in setup:
            h.update(level="setup", reason="Installed from the board; finish its setup and press Done.")
        if not h["level"] and h["servers"]:
            n = len({x["name"] for x in h["servers"]})
            h.update(level="todo", reason=f"{n} server{'s' if n != 1 else ''} still to set up.")
        if h["level"]:
            out[m] = h
    return out


def access_note(con):
    """The board was opened through a proxy/tunnel that isn't in board.trusted_proxies (auth.note_proxy)."""
    p = db.kv_get(con, "proxy_seen", {}) or {}
    return p if p.get("at", 0) > time.time() - 7 * 86400 else None


def state(con, board_url=""):
    setup = [m for m in (db.kv_get(con, "features_setup", []) or []) if m in MODULES and mod(m)]
    kvsetup = set(setup)
    status = _read(STATUS) or {}
    status = status if status.get("at", 0) > time.time() - 86400 else {}
    beat = _read(BEAT) or {}
    req = _read(REQUEST)
    busy = (req or {}).get("enable") or (status.get("modules") or [] if status.get("state") == "running" else [])
    failed = status.get("modules") or [] if status.get("state") == "failed" else []
    tab = {m: t for t, ms in GATES.items() for m in ms}

    hl = health(con, setup, board_url)
    need = [m for m, h in hl.items() if h["level"] == "setup"]   # can't work yet: their tab is the setup page
    setup = list(dict.fromkeys(setup + need))

    def st(m):
        return "installing" if m in busy else "setup" if m in setup else "on" if mod(m) else "off"
    groups = [{"id": mon.id, "title": mon.title, "what": mon.what,
               "modules": [{"id": x.id, "title": x.title, "what": x.what, "state": st(x.id), "failed": x.id in failed,
                            "tab": tab.get(x.id, ""), "health": hl.get(x.id), "marked": x.id in kvsetup}
                           for x in mon.modules if x.id in MODULES]} for mon in MONITORS]
    gates = {}
    for t, ms in GATES.items():
        g = {"title": GATE_TITLES[t], "off": [m for m in ms if not mod(m)], "setup": [m for m in ms if m in setup and mod(m)],
             "on": [m for m in ms if mod(m)], "busy": [m for m in ms if m in busy]}
        g["take"] = bool(g["on"]) and len(g["setup"]) == len(g["on"])   # nothing on this tab is set up yet: setup is the page
        gates[t] = g
    return {"off": [{"id": x.id, "title": x.title, "what": x.what, "monitor": mon.title}
                    for mon in MONITORS for x in mon.modules if x.id in MODULES and not mod(x.id)],
            "setup": [steps(m) for m in setup], "request": req, "status": status, "busy": busy, "failed": failed,
            "groups": groups, "mods": {x["id"]: x for g in groups for x in g["modules"]},
            "steps": {m: steps(m) for m in setup}, "gates": gates, "loose": [m for m in setup if m not in tab],
            "health": hl, "broken": [m for m, h in hl.items() if h["level"] == "broken"],
            "todo": [m for m, h in hl.items() if h["level"] == "todo"], "access": access_note(con),
            "bad": {m: h["reason"] for m, h in hl.items() if h["level"] in ("setup", "broken")},
            "updater": bool(beat) and beat.get("at", 0) > time.time() - 3600,
            "install": INSTALL, "restart": RESTART}


def install(con, mods, by):
    mods = [m for m in dict.fromkeys(mods) if isinstance(m, str) and re.fullmatch(r"[a-z0-9]+", m)]
    bad = [m for m in mods if m not in MODULES]
    if not mods or bad:
        raise ValueError("unknown feature: " + ", ".join(bad) if bad else "pick a feature")
    if REQUEST.exists():
        raise ValueError("an install is already queued")
    tmp = REQUEST.with_suffix(".tmp")
    tmp.write_text(json.dumps({"enable": mods, "by": by, "requested": int(time.time())}))
    tmp.replace(REQUEST)
    db.kv_set(con, "features_setup", list(dict.fromkeys((db.kv_get(con, "features_setup", []) or []) + mods)))


def done(con, m):
    db.kv_set(con, "features_setup", [x for x in (db.kv_get(con, "features_setup", []) or []) if x != m])


def servers_done(m):
    """The servers the installer still listed for module m count as installed (data/installer.json, like the installer's
    own Mark installed)."""
    pend = _read(PENDING) or {}
    srv = ((pend.get("modules") or {}).get(m) or {}).get("servers") or []
    if not srv:
        raise ValueError("nothing left to mark for that feature")
    st = _read(DATA / "installer.json") or {}
    inst = st.setdefault("installed", {})
    for x in srv:
        inst[x["name"]] = sorted(set(inst.get(x["name"]) or []) | {x["id"]})
    for p, d in ((DATA / "installer.json", st), (PENDING, pend)):
        if p == PENDING:
            pend["modules"][m]["servers"] = []
            if not pend["modules"][m].get("problems"):
                del pend["modules"][m]
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(d, indent=1))
        tmp.replace(p)
