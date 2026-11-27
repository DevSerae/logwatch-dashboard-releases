#!/usr/bin/env python3
"""Logwatch Dashboard setup helper. Python 3.8+, standard library only (PyYAML optional, used by `check`).

  python3 setup.py wizard               guided install: pick apps (network, logs, edge, infra) and modules, secrets, login
  python3 setup.py init                 config/config.yaml, secrets/secrets.env (session secret), SSH key, data dir
  python3 setup.py set-password         admin password (prompts; --user NAME, --stdin; creates NAME as admin if missing)
  python3 setup.py user ...             board users, roles, MFA, SSO (`user --help`; runs in the board container)
  python3 setup.py secret NAME          store a secret (prompts; --stdin, or --generate for random tokens)
  python3 setup.py modules              list modules; --enable a,b --disable c to toggle them in config.yaml
  python3 setup.py check                config + required secrets per enabled module
  python3 setup.py render               write .env and docker-compose.override.yml from config.yaml (run after changes)
  python3 setup.py pubkey               the board's SSH public key (for remote/linux/install-agent.sh --pubkey)
  python3 setup.py runner-env --out F   env file for ai-runner/runner.py (board URL + AI_RUNNER_TOKEN), mode 600

Secrets are never printed, except into the file `runner-env --out` writes.
"""
import argparse
import base64
import getpass
import hashlib
import os
import re
import secrets as rnd
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config" / "config.yaml"
EXAMPLE = ROOT / "config" / "config.example.yaml"
SECRETS = ROOT / "secrets" / "secrets.env"
SSH_KEY = ROOT / "secrets" / "ssh" / "id_ed25519"
DATA = ROOT / "data"
ENV = ROOT / ".env"
OVERRIDE = ROOT / "docker-compose.override.yml"

MODULES = ["syslog", "pull", "uptime", "expiry", "proxmox", "trivy", "windows", "unifi", "netflow", "crowdsec",
           "traffic", "waf", "action1", "wazuh", "alertfile", "instatus", "webhook", "ai"]
# secrets a module can't work without (any one of a tuple is enough)
NEEDS = {"proxmox": ["PROXMOX_TOKEN"], "unifi": ["UNIFI_API_KEY"], "instatus": ["INSTATUS_API_KEY"],
         "action1": ["ACTION1_CLIENT_ID", "ACTION1_CLIENT_SECRET", "ACTION1_ORG_ID"], "webhook": ["INGEST_TOKEN"],
         "wazuh": ["WAZUH_API_USER", "WAZUH_API_PASSWORD"],
         "ai": ["AI_RUNNER_TOKEN"]}
OPTIONAL = {"alertfile": ["ALERTFILE_SMB_USER", "ALERTFILE_SMB_PASSWORD"], "waf": ["CLOUDFLARE_API_TOKEN"], "wazuh": ["WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD"], "board": ["MAXMIND_ACCOUNT_ID", "MAXMIND_LICENSE_KEY"]}
# the suite: apps group the modules (a board tab is grayed out when none of its modules are on)
APPS = {"network": ("UniFi gateway events, WAN and flows", ["unifi", "netflow"]),
        "logs": ("Central log search: syslog, SSH pulls, Windows events, alert file, webhook", ["syslog", "pull", "windows", "alertfile", "webhook"]),
        "edge": ("Edge WAF: CrowdSec, request/connection log, custom L7 rules and bans", ["crowdsec", "traffic", "waf"]),
        "infra": ("Uptime, certificates/expiries, Proxmox, image CVEs, patches, Wazuh", ["uptime", "expiry", "proxmox", "trivy", "action1", "wazuh"]),
        "extras": ("Status page maintenance and AI resolve/briefs", ["instatus", "ai"])}
NEEDS_SSH = {"pull": "logpull", "traffic": "trafficpull", "trivy": "images", "waf": "waf"}
SECRET_NAMES = sorted({"BOARD_ADMIN_USER", "BOARD_ADMIN_PASSWORD_HASH", "SESSION_SECRET",
                       *[n for v in NEEDS.values() for n in v], *[n for v in OPTIONAL.values() for n in v]})


# --- small helpers ------------------------------------------------------------------------------------------------

def say(*a):
    print(*a, flush=True)


def die(msg):
    sys.exit(f"error: {msg}")


def read_env(p):
    out = {}
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def write_secret(name, value):
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        die(f"bad secret name {name!r}")
    if "\n" in value:
        die("secret values can't contain newlines")
    SECRETS.parent.mkdir(mode=0o700, exist_ok=True)
    lines = SECRETS.read_text().splitlines() if SECRETS.exists() else ["# Logwatch Dashboard secrets. Never commit or share."]
    lines = [x for x in lines if not re.match(rf"\s*{name}\s*=", x)] + [f"{name}={value}"]
    # keep the file readable by the containers: its current owner, or the containers' UID when root creates it
    st = SECRETS.stat() if SECRETS.exists() else None
    tmp = SECRETS.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(tmp, *((st.st_uid, st.st_gid) if st else owner()))
    tmp.replace(SECRETS)


def config_text():
    if not CONFIG.exists():
        die("config/config.yaml is missing: run `python3 setup.py init` first")
    return CONFIG.read_text()


def block(text, name):
    """(start, end) of a top-level `name:` block in config.yaml, or None."""
    m = re.search(rf"(?m)^{re.escape(name)}:[^\n]*\n", text)
    if not m:
        return None
    n = re.search(r"(?m)^\S", text[m.end():])
    return m.start(), m.end() + (n.start() if n else len(text) - m.end())


def value(text, name, key, default=None):
    b = block(text, name)
    if not b:
        return default
    m = re.search(rf"(?m)^  {re.escape(key)}:\s*([^#\n]*)", text[b[0]:b[1]])
    v = m.group(1).strip().strip('"').strip("'") if m else ""
    return v if v else default


def flags(text):
    return {m: (value(text, m, "enabled", "false").lower() == "true") for m in MODULES}


# --- commands -----------------------------------------------------------------------------------------------------

def cmd_init(a):
    if not CONFIG.exists():
        shutil.copy(EXAMPLE, CONFIG)
        say("created config/config.yaml (edit it, or let your AI agent do it)")
    else:
        say("config/config.yaml exists, kept")
    SECRETS.parent.mkdir(mode=0o700, exist_ok=True)
    env = read_env(SECRETS)
    if len(env.get("SESSION_SECRET", "")) < 32:
        write_secret("SESSION_SECRET", rnd.token_urlsafe(48))
        say("generated SESSION_SECRET")
    if not SSH_KEY.exists():
        SSH_KEY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "logwatch-board", "-f", str(SSH_KEY)], check=True)
        say("generated the board's SSH key (secrets/ssh/id_ed25519)")
    DATA.mkdir(exist_ok=True)
    if not read_env(SECRETS).get("BOARD_ADMIN_PASSWORD_HASH"):
        say("next: python3 setup.py set-password")
    cmd_render(a)


def hash_password(pw, iterations=600_000):
    salt = rnd.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(dk).decode()}"


def compose_python(args, stdin=None):
    """Run app/usercli.py in the board container (exec when it's up, else a one-off run). Exit code, or None
    without Docker."""
    if not shutil.which("docker"):
        return None
    up = subprocess.run(["docker", "compose", "ps", "-q", "--status", "running", "board"], cwd=ROOT,
                        capture_output=True, text=True)
    base = (["docker", "compose", "exec", "-T", "board"] if up.returncode == 0 and up.stdout.strip()
            else ["docker", "compose", "run", "--rm", "--no-deps", "-T", "board"])
    return subprocess.run(base + ["python3", "usercli.py", *args], cwd=ROOT, input=stdin, text=True).returncode


def board_has_users():
    db = DATA / "board.db"
    if not db.exists():
        return False
    try:
        import sqlite3
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return con.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
        finally:
            con.close()
    except Exception:
        return True  # unreadable here (owned by the container user): assume the board has taken over the users


def new_password(prompt, stdin):
    if stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass(prompt)
        if pw != getpass.getpass("Again: "):
            die("passwords don't match")
    if len(pw) < 12:
        die("use at least 12 characters")
    return pw


def cmd_set_password(a):
    env = read_env(SECRETS)
    user = a.user or env.get("BOARD_ADMIN_USER") or "admin"
    pw = new_password(f"New password for {user}: ", a.stdin)
    if board_has_users():  # the board keeps its users in board.db since 2.3.0: change it there
        rc = compose_python(["passwd", user, "--create-admin"], pw + "\n")
        if rc is None:
            die("the board's users live in data/board.db: run this where `docker compose` works")
        if rc:
            sys.exit(rc)
        if user.lower() == env.get("BOARD_ADMIN_USER", "admin").lower():
            write_secret("BOARD_ADMIN_PASSWORD_HASH", hash_password(pw))
        return
    write_secret("BOARD_ADMIN_USER", user)
    write_secret("BOARD_ADMIN_PASSWORD_HASH", hash_password(pw))
    say(f"admin login set for user {user!r}; start or restart the board: docker compose up -d board")


def cmd_user(a):
    args = list(a.args)
    if args[:1] == ["--"]:
        args = args[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        rc = compose_python(["--help"])
        if rc is None:
            die("needs Docker: the users live in the board's database")
        return
    stdin = None
    if args[0] == "add" and "--password-stdin" not in args and "--no-password" not in args:
        if sys.stdin.isatty():
            pw = getpass.getpass("Password (empty = SSO only): ")
            if pw:
                if pw != getpass.getpass("Again: "):
                    die("passwords don't match")
                args.append("--password-stdin")
                stdin = pw + "\n"
    elif args[0] == "add" and "--password-stdin" in args:
        stdin = sys.stdin.readline()
    if "--no-password" in args:
        args.remove("--no-password")
    if args[0] == "passwd":
        stdin = new_password(f"New password for {args[1] if len(args) > 1 else '?'}: ",
                             not sys.stdin.isatty() or "--stdin" in args) + "\n"
        args = [x for x in args if x != "--stdin"]
    if args[:2] == ["sso", "add"]:
        stdin = (getpass.getpass("Client secret (empty = keep the saved one): ") if sys.stdin.isatty()
                 else sys.stdin.readline().rstrip("\n")) + "\n"
    rc = compose_python(args, stdin)
    if rc is None:
        die("needs Docker: the users live in the board's database")
    sys.exit(rc)


def cmd_secret(a):
    if a.name not in SECRET_NAMES:
        say(f"note: {a.name} isn't a secret the board reads (known: {', '.join(SECRET_NAMES)})")
    if a.generate:
        v = rnd.token_urlsafe(36)
    elif a.stdin:
        v = sys.stdin.readline().rstrip("\n")
    else:
        v = getpass.getpass(f"{a.name}: ")
    if not v:
        die("empty value")
    write_secret(a.name, v)
    say(f"stored {a.name} in secrets/secrets.env" + (" (generated)" if a.generate else ""))


def cmd_modules(a):
    text = config_text()
    changes = {m: True for m in (a.enable or "").split(",") if m} | {m: False for m in (a.disable or "").split(",") if m}
    for m, on in changes.items():
        if m not in MODULES:
            die(f"unknown module {m!r} (known: {', '.join(MODULES)})")
        b = block(text, m)
        if not b:
            text += f"\n{m}:\n  enabled: {'true' if on else 'false'}\n"
            continue
        body = text[b[0]:b[1]]
        if re.search(r"(?m)^  enabled:", body):
            body = re.sub(r"(?m)^(  enabled:\s*)\S+", lambda x: x.group(1) + ("true" if on else "false"), body, count=1)
        else:
            body = re.sub(r"^([^\n]*\n)", lambda x: x.group(1) + f"  enabled: {'true' if on else 'false'}\n", body, count=1)
        text = text[:b[0]] + body + text[b[1]:]
    if changes:
        CONFIG.write_text(text)
    for m, on in flags(text).items():
        say(f"  {'[x]' if on else '[ ]'} {m}")
    if changes:
        say("changed: run `python3 setup.py render && docker compose up -d --build && docker compose restart board worker`")


def cmd_check(a):
    text = config_text()
    problems, warns = [], []
    try:
        import yaml
        cfg = yaml.safe_load(text) or {}
    except ImportError:
        cfg = None
        warns.append("PyYAML not installed on this machine: only the basic checks ran (pip install pyyaml for more)")
    except Exception as e:
        die(f"config.yaml is not valid YAML: {e}")
    env = read_env(SECRETS)
    on = flags(text)
    for k in ("SESSION_SECRET", "BOARD_ADMIN_PASSWORD_HASH"):
        if not env.get(k):
            problems.append(f"secret {k} missing ({'setup.py init' if k == 'SESSION_SECRET' else 'setup.py set-password'})")
    for m, names in NEEDS.items():
        if on[m]:
            problems += [f"module {m}: secret {n} missing (setup.py " + ("runner-env" if n == "AI_RUNNER_TOKEN" else f"secret {n}") + ")" for n in names if not env.get(n)]
    if cfg is not None:
        hosts = ((cfg.get("ssh") or {}).get("hosts")) or []
        for m, role in NEEDS_SSH.items():
            if on[m] and not any(role in (h.get("roles") or []) for h in hosts if isinstance(h, dict)):
                warns.append(f"module {m}: no ssh.hosts entry has role {role}")
        if on["crowdsec"] and not (cfg.get("crowdsec") or {}).get("hosts"):
            warns.append("module crowdsec: crowdsec.hosts is empty")
        if on["crowdsec"] and not any("csctl" in (h.get("roles") or []) for h in hosts if isinstance(h, dict)):
            warns.append("module crowdsec: no host has role csctl, so Ban/Unban is hidden")
        for m in ("proxmox", "unifi"):
            if on[m] and not (cfg.get(m) or {}).get("url"):
                problems.append(f"module {m}: url missing")
        if on["uptime"] and not (cfg.get("uptime") or {}).get("targets"):
            warns.append("module uptime: no uptime.targets seed (add checks on the Services tab instead)")
        if on["ai"] and not ((cfg.get("board") or {}).get("cookie_secure", True)):
            warns.append("ai runner talks to the board over HTTP: put the board behind HTTPS before using it across networks")
        if not (cfg.get("board") or {}).get("allow_cidrs"):
            warns.append("board.allow_cidrs is empty: the login page is reachable by anyone who can reach the port")
    if (on["pull"] or on["traffic"] or on["trivy"] or on["crowdsec"] or on["waf"]) and not SSH_KEY.exists():
        problems.append("SSH key missing (setup.py init)")
    if SECRETS.exists() and SECRETS.stat().st_mode & 0o077:
        warns.append("secrets/secrets.env is readable by group/others: chmod 600 secrets/secrets.env")
    lw = read_env(ENV)
    if SECRETS.exists() and lw.get("LW_UID", "").isdigit() and SECRETS.stat().st_uid != int(lw["LW_UID"]):
        problems.append(f"secrets/secrets.env is owned by UID {SECRETS.stat().st_uid}, but the containers run as {lw['LW_UID']}, "
                        f"so the board can't read it after its next restart: sudo python3 setup.py render (or chown "
                        f"{lw['LW_UID']}:{lw.get('LW_GID', lw['LW_UID'])} secrets/secrets.env)")
    for w in warns:
        say(f"warn: {w}")
    for p in problems:
        say(f"FAIL: {p}")
    say("enabled modules: " + ", ".join(m for m, v in on.items() if v))
    if problems:
        sys.exit(1)
    say("ok")


def owner():
    """UID/GID the containers run as: the caller, or, when run as root, the UID/GID already in .env, else the install
    dir's owner (never 0). Keeping .env's wins over the dir owner: an update extracted as root may have changed it."""
    if not hasattr(os, "getuid"):
        return 1000, 1000
    if os.getuid():
        return os.getuid(), os.getgid()
    old = read_env(ENV)
    if old.get("LW_UID", "0").isdigit() and old.get("LW_GID", "0").isdigit() and int(old.get("LW_UID", "0")) > 0:
        return int(old["LW_UID"]), int(old["LW_GID"])
    st = ROOT.stat()
    return (st.st_uid, st.st_gid) if st.st_uid else (1000, 1000)


def cmd_render(a):
    text = config_text()
    on = flags(text)
    old = read_env(ENV)
    syslog_port = value(text, "syslog", "port", "514")
    fwd_port = value(text, "windows", "forward_port", "24224")
    nf_port = value(text, "netflow", "port", "2055")
    profiles = (["collector"] if on["windows"] or on["netflow"] else []) + (["netflow"] if on["netflow"] else [])
    uid, gid = owner()
    env = {"LW_UID": str(uid), "LW_GID": str(gid),
           "TZ": old.get("TZ") or os.environ.get("TZ") or "UTC",
           "BOARD_BIND": old.get("BOARD_BIND") or "0.0.0.0", "BOARD_PORT": old.get("BOARD_PORT") or "8080",
           "VL_RETENTION": old.get("VL_RETENTION") or "30d", "VL_MAX_DISK": old.get("VL_MAX_DISK") or "20GiB",
           "FORWARD_PORT": fwd_port, "WITH_TRIVY": "1" if on["trivy"] else "0", "COMPOSE_PROFILES": ",".join(profiles)}
    keep = {k: v for k, v in old.items() if k not in env}
    ENV.write_text("# Written by `python3 setup.py render`; TZ/BOARD_*/VL_* edits are kept.\n" +
                   "".join(f"{k}={v}\n" for k, v in {**env, **keep}.items()))
    o = ["# Written by `python3 setup.py render` from config/config.yaml. Don't edit: rerun render.", "services:"]
    if on["syslog"]:
        o += ["  victorialogs:", "    ports:", f'      - "{syslog_port}:514/tcp"', f'      - "{syslog_port}:514/udp"']
    if profiles:
        bind = "" if on["windows"] else "127.0.0.1:"  # NetFlow only: the forward port only serves the local log driver
        o += ["  fluent-bit:", "    ports:", f'      - "{bind}{fwd_port}:24224/tcp"']
    if on["netflow"]:
        o += ["  goflow2:", "    ports:", f'      - "{nf_port}:2055/udp"']
    if len(o) == 2:
        o += ["  board: {}"]
    OVERRIDE.write_text("\n".join(o) + "\n")
    if hasattr(os, "geteuid") and os.geteuid() == 0 and uid:  # run with sudo: the containers must read what root wrote
        for p in [CONFIG, ENV, OVERRIDE, SECRETS.parent, DATA]:
            for q in [p, *(p.rglob("*") if p.is_dir() else [])] if p.exists() else []:
                os.chown(q, uid, gid)
    say(f"wrote .env and docker-compose.override.yml (profiles: {','.join(profiles) or 'none'})")


def cmd_pubkey(a):
    p = SSH_KEY.with_suffix(".pub")
    if not p.exists():
        die("no SSH key yet: run `python3 setup.py init`")
    print(p.read_text().strip())


def cmd_runner_env(a):
    env = read_env(SECRETS)
    if not env.get("AI_RUNNER_TOKEN"):
        write_secret("AI_RUNNER_TOKEN", rnd.token_urlsafe(36))
        env = read_env(SECRETS)
        say("generated AI_RUNNER_TOKEN (restart the board: docker compose restart board)")
    out = Path(a.out)
    out.write_text(f"LOGWATCH_URL={a.url}\nAI_RUNNER_TOKEN={env['AI_RUNNER_TOKEN']}\n")
    os.chmod(out, 0o600)
    say(f"wrote {out} (mode 600): copy it next to ai-runner/runner.py on the runner machine")


def ask(q, default=True):
    if not sys.stdin.isatty():
        return default
    a = input(f"{q} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not a else a.startswith("y")


def cmd_wizard(a):
    if not CONFIG.exists() or len(read_env(SECRETS).get("SESSION_SECRET", "")) < 32 or not SSH_KEY.exists():
        cmd_init(a)
    on0 = flags(config_text())
    want = set(a.apps.split(",")) if a.apps else None
    if want and not want <= set(APPS):
        die(f"unknown app (known: {', '.join(APPS)})")
    enable, disable = [], []
    say("Apps (each is a group of modules; you can change this later with `setup.py modules`):")
    for app, (desc, mods) in APPS.items():
        use = app in want if want is not None else ask(f"\n{app}: {desc}?", any(on0[m] for m in mods) or app in ("logs", "infra"))
        for m in mods:
            pick = use and (want is not None or a.all or ask(f"  enable {m}?", on0[m] or m in ("syslog", "uptime", "expiry")))
            (enable if pick else disable).append(m)
    a.enable, a.disable = ",".join(enable), ",".join(disable)
    cmd_modules(a)
    env = read_env(SECRETS)
    for m in enable:
        for n in NEEDS.get(m, []) + OPTIONAL.get(m, []):
            if env.get(n) or n == "AI_RUNNER_TOKEN":
                continue
            if sys.stdin.isatty() and ask(f"store {n} for {m} now?", n in NEEDS.get(m, [])):
                v = getpass.getpass(f"{n}: ")
                if v:
                    write_secret(n, v)
    if "ai" in enable and not env.get("AI_RUNNER_TOKEN"):
        write_secret("AI_RUNNER_TOKEN", rnd.token_urlsafe(36))
        say("generated AI_RUNNER_TOKEN (setup.py runner-env --out F --url U for the runner machine)")
    if not read_env(SECRETS).get("BOARD_ADMIN_PASSWORD_HASH") and sys.stdin.isatty():
        a.user, a.stdin = "admin", False
        cmd_set_password(a)
    cmd_render(a)
    roles = sorted({NEEDS_SSH[m] for m in enable if m in NEEDS_SSH} | ({"csctl"} if "crowdsec" in enable else set()))
    say("\nNext:")
    say("  1. edit config/config.yaml for the enabled modules (hosts, targets, URLs), then: python3 setup.py check")
    if roles or "syslog" in enable or "crowdsec" in enable:
        say("  2. on each host, from remote/linux (as root):")
        say(f"     ./check-host.sh --board <board-address>{' --syslog' if 'syslog' in enable else ''}"
            f"{' --roles ' + ','.join(roles) if roles else ''}{' --crowdsec' if 'crowdsec' in enable else ''}"
            " [--pubkey \"$(python3 setup.py pubkey)\" --fix]")
        say("     (drop the roles/flags a host doesn't need; --fix installs what's missing)")
    say("  3. docker compose up -d --build   (later config changes: also `docker compose restart board worker`)")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("wizard")
    s.add_argument("--apps", help="non-interactive: comma list of apps to enable fully (network,logs,edge,infra,extras)")
    s.add_argument("--all", action="store_true", help="enable every module of each chosen app without asking")
    sub.add_parser("init")
    s = sub.add_parser("set-password")
    s.add_argument("--user", help="default: the current admin user name")
    s.add_argument("--stdin", action="store_true")
    s = sub.add_parser("secret")
    s.add_argument("name")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--stdin", action="store_true")
    g.add_argument("--generate", action="store_true")
    s = sub.add_parser("modules")
    s.add_argument("--enable")
    s.add_argument("--disable")
    s = sub.add_parser("user", add_help=False, help="users, roles, MFA, SSO (setup.py user --help)")
    s.add_argument("args", nargs=argparse.REMAINDER)
    s = sub.add_parser("knowns", add_help=False, help="facts the AI treats as true: knowns list | add TEXT [--match M] | rm ID")
    s.add_argument("args", nargs=argparse.REMAINDER)
    sub.add_parser("check")
    sub.add_parser("render")
    sub.add_parser("pubkey")
    s = sub.add_parser("runner-env")
    s.add_argument("--out", required=True)
    s.add_argument("--url", required=True, help="how the runner machine reaches the board, e.g. https://logwatch.example.com")
    if sys.argv[1:2] == ["user"]:  # everything after `user` goes to usercli.py as is (incl. --help)
        return cmd_user(argparse.Namespace(args=sys.argv[2:]))
    if sys.argv[1:2] == ["knowns"]:  # setup.py knowns list|add|edit|rm ... = setup.py user knowns ...
        return cmd_user(argparse.Namespace(args=["knowns", *sys.argv[2:]]))
    a = p.parse_args()
    {"wizard": cmd_wizard, "init": cmd_init, "set-password": cmd_set_password, "user": cmd_user, "secret": cmd_secret, "modules": cmd_modules, "check": cmd_check,
     "render": cmd_render, "pubkey": cmd_pubkey, "runner-env": cmd_runner_env}[a.cmd](a)


if __name__ == "__main__":
    main()
