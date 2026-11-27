"""Config + secrets for every process (board, worker, setup checks).

config.yaml (non-secret, mounted read-only at /config/config.yaml) holds addresses, toggles and thresholds.
secrets.env (mounted read-only at /secrets/secrets.env) holds keys/passwords, one NAME=value per line.
Paths can be overridden with LOGWATCH_CONFIG / LOGWATCH_SECRETS / LOGWATCH_DATA (used by local tests).
"""
import ipaddress
import os
from pathlib import Path

import yaml

CONFIG_PATH = Path(os.environ.get("LOGWATCH_CONFIG", "/config/config.yaml"))
SECRETS_PATH = Path(os.environ.get("LOGWATCH_SECRETS", "/secrets/secrets.env"))
DATA = Path(os.environ.get("LOGWATCH_DATA", "/data"))
SSH_KEY = Path(os.environ.get("LOGWATCH_SSH_KEY", str(SECRETS_PATH.parent / "ssh" / "id_ed25519")))

MODULES = ["syslog", "pull", "uptime", "expiry", "proxmox", "trivy", "windows", "unifi", "netflow", "crowdsec",
           "traffic", "waf", "action1", "wazuh", "alertfile", "instatus", "webhook", "ai"]


def _load_yaml(p):
    try:
        return yaml.safe_load(p.read_text()) or {}
    except FileNotFoundError:
        return {}


def _load_env(p):
    out = {}
    try:
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return out


CONFIG = _load_yaml(CONFIG_PATH)
SECRETS = _load_env(SECRETS_PATH)


def section(name, default=None):
    v = CONFIG.get(name)
    return v if isinstance(v, dict) else ({} if default is None else default)


def mod(name):
    """A module's config dict when it is enabled, else None."""
    m = CONFIG.get(name)
    return m if isinstance(m, dict) and m.get("enabled") else None


def enabled():
    return {m: bool(mod(m)) for m in MODULES}


def secret(name, default=""):
    return SECRETS.get(name) or os.environ.get(name) or default


BOARD = section("board")
VL = (section("victorialogs").get("url") or "http://victorialogs:9428").rstrip("/")
TITLE = BOARD.get("title") or "Logwatch Dashboard"
HOST_LABEL = BOARD.get("host_label") or ""


def nets(key, src=None):
    out = []
    for c in (src or BOARD).get(key) or []:
        try:
            out.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            pass
    return out


def ssh_hosts(role=None):
    """Configured SSH targets, optionally only those with a role (logpull, trafficpull, csctl, images)."""
    hs = [h for h in (section("ssh").get("hosts") or []) if isinstance(h, dict) and h.get("name")]
    return [h for h in hs if role is None or role in (h.get("roles") or [])]


def ssh_host(name):
    return next((h for h in ssh_hosts() if h["name"] == name), None)
