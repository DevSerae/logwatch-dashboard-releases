"""Load the installer state from config.yaml / secrets.env / .env and write it back.

State = {"values": {field key: value}, "mods": {module: bool}, "mons": {monitor: bool}, "stored": {secret names}}.
Unknown config keys (log_rules, crs_exclusions, dnat_map, ...) are kept as they are.
"""
import ipaddress
import json
import os
import re
import secrets as rnd
import sys
from pathlib import Path

import yaml

from .schema import ACCESS_FIELDS, ALL_MODULES, BOARD_FIELDS, MONITORS, SSH_ROLES

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import setup  # noqa: E402  (setup.py: write_secret, hash_password, init, render)

STATE = setup.DATA / "installer.json"   # installer-only answers (hosts for the steps, board address)
HEADER = ("# Logwatch Dashboard configuration, written by the installer (./install.sh or python3 -m installer).\n"
          "# config/config.example.yaml documents every key. Re-run the installer, or edit and run\n"
          "# `python3 setup.py check && python3 setup.py render && docker compose up -d && docker compose restart board worker`.\n")


def all_fields():
    yield from BOARD_FIELDS
    yield from ACCESS_FIELDS
    for m in ALL_MODULES.values():
        yield from m.fields


def dget(d, path, default=None):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def dset(d, path, v):
    ks = path.split(".")
    for k in ks[:-1]:
        if not isinstance(d.get(k), dict):
            d[k] = {}
        d = d[k]
    d[ks[-1]] = v


def lines(text):
    return [x.strip() for x in str(text or "").splitlines() if x.strip() and not x.strip().startswith("#")]


def csv(text):
    return [x.strip() for x in re.split(r"[,\s]+", str(text or "")) if x.strip()]


def default_addr():
    """The address of the interface with the default route."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # no packet is sent
        return s.getsockname()[0]
    except OSError:
        return ""


# --- list formats ---------------------------------------------------------------------------------------------------

def parse_hosts(text):
    """'name address [port]' lines → [{name, address, port}] (+ errors)."""
    out, errs = [], []
    for ln in lines(text):
        p = ln.split()
        if len(p) < 2 or len(p) > 3 or (len(p) == 3 and not p[2].isdigit()):
            errs.append(f"'{ln}': expected name address [port]")
            continue
        out.append({"name": p[0], "address": p[1], **({"port": int(p[2])} if len(p) == 3 and p[2] != "22" else {})})
    return out, errs


def fmt_hosts(hs):
    return "\n".join(f"{h['name']} {h.get('address') or h['name']}" + (f" {h['port']}" if h.get("port") not in (None, 22) else "") for h in hs)


def parse_lines(key, text):
    out, errs = [], []
    for ln in lines(text):
        p = ln.split()
        if key == "crowdsec.hosts":
            if len(p) > 2 or (len(p) == 2 and p[1] != "web"):
                errs.append(f"'{ln}': expected name [web]")
                continue
            out.append({"name": p[0], "web": len(p) == 2})
        elif key == "waf.port_groups":
            name, _, ports = ln.rpartition(":")
            if not name.strip() or not re.fullmatch(r"\d+(-\d+)?(,\s*\d+(-\d+)?)*", ports.strip()):
                errs.append(f"'{ln}': expected name: ports (e.g. App servers: 8000-8100)")
                continue
            out.append({"name": name.strip(), "ports": ports.strip()})
        elif key == "uptime.targets":
            if len(p) >= 3 and p[-2] == "tcp" and ":" in p[-1]:
                h, _, port = p[-1].rpartition(":")
                if not port.isdigit():
                    errs.append(f"'{ln}': bad port")
                    continue
                out.append({"name": " ".join(p[:-2]), "kind": "tcp", "host": h, "port": int(port)})
            elif len(p) >= 2 and re.match(r"https?://", p[-1]):
                out.append({"name": " ".join(p[:-1]), "url": p[-1]})
            else:
                errs.append(f"'{ln}': expected name https://… or name tcp host:port")
        elif key == "expiry.tls":
            hp = p[0]
            host, port = (hp.rsplit(":", 1) if re.search(r":\d+$", hp) else (hp, "443"))
            e = {"host": host, "port": int(port)}
            if len(p) > 1:
                e["sni"] = p[1]
            out.append(e)
    return out, errs


def fmt_lines(key, v):
    v = v or []
    if key == "crowdsec.hosts":
        return "\n".join(f"{h.get('name')}{' web' if h.get('web') else ''}" for h in v if isinstance(h, dict))
    if key == "waf.port_groups":
        return "\n".join(f"{g.get('name')}: {g.get('ports')}" for g in v if isinstance(g, dict))
    if key == "uptime.targets":
        return "\n".join(f"{t.get('name')} tcp {t.get('host')}:{t.get('port')}" if t.get("kind") == "tcp" else f"{t.get('name')} {t.get('url')}"
                         for t in v if isinstance(t, dict))
    if key == "expiry.tls":
        return "\n".join(f"{t.get('host')}:{t.get('port', 443)}" + (f" {t['sni']}" if t.get("sni") else "") for t in v if isinstance(t, dict))
    return ""


# --- load / save ----------------------------------------------------------------------------------------------------

def load():
    cfg = yaml.safe_load((setup.CONFIG if setup.CONFIG.exists() else setup.EXAMPLE).read_text()) or {}
    env, sec = setup.read_env(setup.ENV), setup.read_env(setup.SECRETS)
    extra = json.loads(STATE.read_text()) if STATE.exists() else {}
    vals = {}
    hosts = [h for h in dget(cfg, "ssh.hosts", []) or [] if isinstance(h, dict)]
    for f in all_fields():
        k = f.key
        if k.startswith(("secret:", "once_")) or k in ("admin_pw", "admin_pw2"):
            v = ""
        elif k.startswith("ssh:"):
            v = fmt_hosts([h for h in hosts if k[4:] in (h.get("roles") or [])])
        elif k.startswith("lines:"):
            v = fmt_lines(k[6:], dget(cfg, k[6:]))
        elif k.startswith("env:"):
            v = env.get(k[4:], f.default)
        elif k == "admin_user":
            v = sec.get("BOARD_ADMIN_USER") or f.default
        elif "." in k:
            v = dget(cfg, k, f.default)
        else:
            v = extra.get(k, f.default)
        if f.kind == "csv" and isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        if f.kind == "list" and isinstance(v, list):
            v = "\n".join(v)
        vals[k] = "" if v is None else v
    if not vals.get("addr"):
        vals["addr"] = default_addr()
    if dget(cfg, "waf.cloudflare.zone"):
        vals["cf"] = True
    mods = {m: bool(dget(cfg, f"{m}.enabled", False)) for m in ALL_MODULES}
    first = not setup.CONFIG.exists()
    if first:
        mods = {m: ALL_MODULES[m].default_on for m in ALL_MODULES}
        vals["board.cookie_secure"] = False   # a fresh board is opened over http://<vm>:8080 first
    mons = extra.get("monitors") or {mon.id: any(mods[m.id] for m in mon.modules) for mon in MONITORS}
    stored = {k for k, v in sec.items() if v}
    return {"values": vals, "mods": mods, "mons": mons, "stored": stored}


def enabled(state):
    """Modules that are on: module switch and its monitor switch."""
    return {m.id for mon in MONITORS if state["mons"].get(mon.id) for m in mon.modules if state["mods"].get(m.id)}


def validate(state):
    """{module or 'board': [problems]} for what can't work as entered."""
    v, on, stored = state["values"], enabled(state), state["stored"]
    probs = {}

    def need(scope, f):
        val = v.get(f.key)
        if f.key.startswith("secret:"):
            if (f.required or f.key.startswith("secret:WAZUH_INDEXER")) and not val and f.key[7:] not in stored:
                probs.setdefault(scope, []).append(f"{f.label}: required")
        elif f.required and not str(val or "").strip():
            probs.setdefault(scope, []).append(f"{f.label}: required")

    for f in BOARD_FIELDS:
        need("board", f)
    if v.get("admin_pw") or "BOARD_ADMIN_PASSWORD_HASH" not in stored:
        if len(v.get("admin_pw") or "") < 12:
            probs.setdefault("board", []).append("Admin password: 12+ characters")
        elif v.get("admin_pw") != v.get("admin_pw2"):
            probs.setdefault("board", []).append("Admin passwords don't match")
    for c in csv(v.get("board.allow_cidrs")) + csv(v.get("board.trusted_proxies")) + csv(v.get("board.open_cidrs")):
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            probs.setdefault("board", []).append(f"'{c}' is not a CIDR")
    if str(v.get("board.cf_access.team") or "").strip() and not str(v.get("board.cf_access.aud") or "").strip():
        probs.setdefault("board", []).append("Cloudflare Access AUD tag: needed with a team domain")
    if v.get("board.geoip") == "maxmind":
        for n in ("MAXMIND_ACCOUNT_ID", "MAXMIND_LICENSE_KEY"):
            if not v.get(f"secret:{n}") and n not in stored:
                probs.setdefault("board", []).append(f"{n}: needed for geoip maxmind")
    for mid in on:
        for f in ALL_MODULES[mid].fields:
            if f.key.startswith(("waf.cloudflare", "secret:CLOUDFLARE")) and not v.get("cf"):
                continue
            if f.key.startswith("secret:WAZUH_INDEXER") and not v.get("wazuh.indexer_url"):
                continue
            need(mid, f)
            if f.key.startswith(("ssh:", "hosts:")):
                probs.setdefault(mid, []).extend(parse_hosts(v.get(f.key))[1])
            elif f.key.startswith("lines:"):
                probs.setdefault(mid, []).extend(parse_lines(f.key[6:], v.get(f.key))[1])
            elif f.kind == "int":
                if not str(v.get(f.key, "")).strip().isdigit():
                    probs.setdefault(mid, []).append(f"{f.label}: a number")
            elif f.key.endswith("_url") or f.key.endswith(".url"):
                if v.get(f.key) and not re.match(r"https?://[^\s/]+", str(v.get(f.key))):
                    probs.setdefault(mid, []).append(f"{f.label}: http(s)://host[:port]")
        if mid == "waf" and v.get("cf"):
            for f in ("waf.cloudflare.zone", "waf.cloudflare.account"):
                if not re.fullmatch(r"[0-9a-f]{32}", str(v.get(f) or "")):
                    probs.setdefault(mid, []).append(f"{f.split('.')[-1]} ID: 32 hex characters")
            if not v.get("secret:CLOUDFLARE_API_TOKEN") and "CLOUDFLARE_API_TOKEN" not in stored:
                probs.setdefault(mid, []).append("Cloudflare API token: required")
        if mid == "waf" and not (lines(v.get("ssh:waf")) or lines(v.get("ssh:l4waf"))):
            probs.setdefault(mid, []).append("add at least one edge proxy or port proxy")
    return {k: x for k, x in probs.items() if x}


def _typed(f, val):
    if f.kind == "int":
        return int(str(val).strip())
    if f.kind == "bool":
        return bool(val)
    if f.kind == "csv":
        out = csv(val)
        return [int(x) if x.isdigit() and f.key == "traffic.block_status" else x for x in out]
    return val


def save(state, log=print):
    """config.yaml + secrets.env + .env + docker-compose.override.yml. Raises ValueError when validate() complains."""
    probs = validate(state)
    if probs:
        raise ValueError("; ".join(f"{k}: {', '.join(p)}" for k, p in probs.items()))
    setup.say = log
    if not setup.CONFIG.exists() or len(setup.read_env(setup.SECRETS).get("SESSION_SECRET", "")) < 32 or not setup.SSH_KEY.exists():
        init()
    cfg = yaml.safe_load(setup.CONFIG.read_text()) or {}
    v, on = state["values"], enabled(state)
    extra = {"monitors": state["mons"]}
    for m in ALL_MODULES:
        dset(cfg, f"{m}.enabled", m in on)
    roles = {}   # name → {address, port, roles}
    for f in all_fields():
        k, val = f.key, v.get(f.key)
        if k.startswith("secret:"):
            if val:
                setup.write_secret(k[7:], val)
            continue
        if k.startswith("once_"):
            continue
        if k.startswith("ssh:"):
            mod = next(m for m in ALL_MODULES.values() if f in m.fields)
            if mod.id in on and (k != "ssh:l4waf" or mod.id == "waf"):
                for h in parse_hosts(val)[0]:
                    e = roles.setdefault(h["name"], {"address": h["address"], **({"port": h["port"]} if "port" in h else {}), "roles": []})
                    e["roles"].append(k[4:])
            extra[k] = val  # remembered even while the module is off
            continue
        if k.startswith("lines:"):
            dset(cfg, k[6:], parse_lines(k[6:], val)[0])
        elif k.startswith("env:") or k in ("admin_user", "admin_pw", "admin_pw2"):
            continue
        elif "." in k:
            dset(cfg, k, _typed(f, val))
        else:
            extra[k] = val
    if not v.get("cf"):
        dset(cfg, "waf.cloudflare", {})
    old = [h for h in dget(cfg, "ssh.hosts", []) or [] if isinstance(h, dict)]
    keep = []
    for h in old:   # roles the installer doesn't manage stay; managed ones are rebuilt
        h = dict(h, roles=[r for r in h.get("roles") or [] if r not in SSH_ROLES])
        if h["name"] in roles:
            n = roles.pop(h["name"])
            h.update(address=n["address"], roles=h["roles"] + n["roles"], **({"port": n["port"]} if "port" in n else {}))
        if h["roles"]:
            keep.append(h)
    keep += [{"name": n, **e} for n, e in roles.items()]
    dset(cfg, "ssh.hosts", keep)
    if v.get("wazuh.alerts") == "syslog" and "wazuh" in on and "syslog" not in on:
        log("note: wazuh alerts via syslog need the syslog module; turned it on")
        dset(cfg, "syslog.enabled", True)
    setup.CONFIG.write_text(HEADER + yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False, allow_unicode=True, width=120))
    sec = setup.read_env(setup.SECRETS)
    if "webhook" in on and not sec.get("INGEST_TOKEN"):
        setup.write_secret("INGEST_TOKEN", rnd.token_urlsafe(36))
        log("generated INGEST_TOKEN")
    if "ai" in on and not sec.get("AI_RUNNER_TOKEN"):
        setup.write_secret("AI_RUNNER_TOKEN", rnd.token_urlsafe(36))
        log("generated AI_RUNNER_TOKEN (python3 setup.py runner-env for the runner machine)")
    if v.get("admin_pw"):
        setup.write_secret("BOARD_ADMIN_USER", v.get("admin_user") or "admin")
        setup.write_secret("BOARD_ADMIN_PASSWORD_HASH", setup.hash_password(v["admin_pw"]))
        log("admin login stored")
    env = setup.read_env(setup.ENV)
    for f in BOARD_FIELDS:
        if f.key.startswith("env:") and str(v.get(f.key) or "").strip():
            env[f.key[4:]] = str(v[f.key]).strip()
    setup.ENV.write_text("".join(f"{k}={x}\n" for k, x in env.items()))
    STATE.parent.mkdir(parents=True, exist_ok=True)
    try:   # servers already marked installed stay marked
        extra["installed"] = json.loads(STATE.read_text()).get("installed") or {}
    except (OSError, ValueError):
        pass
    STATE.write_text(json.dumps(extra, indent=1))
    setup.cmd_render(None)
    fix_owner()
    state["stored"] = {k for k, x in setup.read_env(setup.SECRETS).items() if x}
    for k in ("admin_pw", "admin_pw2"):
        v[k] = ""
    for f in all_fields():
        if f.key.startswith("secret:"):
            v[f.key] = ""
    log("saved config/config.yaml, secrets/secrets.env, .env, docker-compose.override.yml")


def init():
    setup.cmd_init(None)
    fix_owner()


def fix_owner():
    """Run as root (install.sh): hand everything to the install dir's owner, which the containers run as."""
    if os.geteuid() != 0:
        return
    st = ROOT.stat()
    if st.st_uid == 0:
        return
    for p in [setup.CONFIG, setup.ENV, setup.OVERRIDE, setup.SECRETS.parent, setup.DATA, ROOT / "installer-prompts"]:
        if p.exists():
            for q in [p, *(p.rglob("*") if p.is_dir() else [])]:
                os.chown(q, st.st_uid, st.st_gid)


def pubkey():
    p = setup.SSH_KEY.with_suffix(".pub")
    return p.read_text().strip() if p.exists() else ""
