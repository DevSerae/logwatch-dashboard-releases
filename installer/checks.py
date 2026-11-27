"""Live checks the installer runs from the logwatch VM: ports, APIs with the keys entered, SSH agents on the targets.

Each check returns [(level, message)], level ok | warn | fail. Nothing here changes anything anywhere.
"""
import json
import shutil
import socket
import ssl
import subprocess

import httpx

from . import configio
from .configio import csv, dget, lines, parse_hosts, parse_lines, setup

OK, WARN, FAIL = "ok", "warn", "fail"


def _secret(state, name):
    return state["values"].get(f"secret:{name}") or setup.read_env(setup.SECRETS).get(name, "")


def _http(method, url, **kw):
    kw.setdefault("timeout", 15)
    return httpx.request(method, url, **kw)


def _err(e):
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        hint = {401: "wrong credentials", 403: "the key lacks a permission", 404: "wrong URL or ID"}.get(code, "")
        return f"HTTP {code}{' (' + hint + ')' if hint else ''}"
    if isinstance(e, httpx.ConnectError):
        return f"can't connect ({str(e)[:120] or 'refused/unreachable'}): firewall, address or port?"
    if isinstance(e, httpx.TimeoutException):
        return "timed out: firewall or wrong address?"
    return f"{type(e).__name__}: {str(e)[:160]}"


# --- the logwatch VM itself -----------------------------------------------------------------------------------------

def board(state):
    out = []
    d = shutil.which("docker")
    if not d:
        out.append((FAIL, "Docker is not installed (install.sh installs it, or https://docs.docker.com/engine/install/)"))
    else:
        r = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        out.append((OK, r.stdout.strip()) if r.returncode == 0 else (FAIL, "Docker Compose plugin missing (apt install docker-compose-plugin)"))
        r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True)
        out.append((OK, f"Docker engine {r.stdout.strip()}") if r.returncode == 0 else
                   (FAIL, "can't talk to the Docker engine: run the installer with sudo, or add this user to the docker group"))
    try:
        mem = int(next(ln.split()[1] for ln in open("/proc/meminfo") if ln.startswith("MemTotal"))) / 2**20
        out.append((OK if mem >= 1.8 else WARN, f"{mem:.1f} GiB RAM" + ("" if mem >= 1.8 else ": 2 GiB+ recommended (VictoriaLogs + build)")))
    except (OSError, StopIteration, ValueError):
        pass
    virt = subprocess.run(["systemd-detect-virt", "-c"], capture_output=True, text=True).stdout.strip() if shutil.which("systemd-detect-virt") else ""
    if virt == "lxc":
        out.append((OK, "LXC container") if any(l == OK and m.startswith("Docker engine") for l, m in out) else
                   (WARN, "LXC container: Docker needs nesting=1 (and keyctl=1 for unprivileged CTs) in the CT's Options → Features"))
    if shutil.which("timedatectl"):
        r = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], capture_output=True, text=True)
        if r.returncode == 0:
            out.append((OK, "clock is NTP-synchronised") if r.stdout.strip() == "yes" else
                       (WARN, "clock isn't NTP-synchronised: log times and token checks drift (systemctl enable --now systemd-timesyncd)"))
    for fw, cmd in (("ufw", ["ufw", "status"]), ("firewalld", ["firewall-cmd", "--state"])):
        if shutil.which(cmd[0]):
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0 and ("active" in r.stdout and "inactive" not in r.stdout or r.stdout.strip() == "running"):
                out.append((WARN, f"{fw} is active: allow {', '.join(open_ports(state))} (Docker-published ports usually bypass ufw, but not always firewalld)"))
    free = shutil.disk_usage(setup.ROOT).free / 2**30
    out.append((OK if free >= 25 else WARN, f"{free:.0f} GiB free for logs" + ("" if free >= 25 else " (the default cap is 20 GiB)")))
    out += port_check(int(state["values"].get("env:BOARD_PORT") or 8080), "tcp", "board")
    if not state["values"].get("board.allow_cidrs"):
        out.append((WARN, "no allowed networks: anyone who can reach the port sees the login page"))
    if not state["values"].get("board.cookie_secure"):
        out.append((WARN, "HTTPS off: fine on a LAN; behind a reverse proxy or tunnel turn it on (docs/reverse-proxy.md)"))
    return out


def open_ports(state):
    """Ports other machines connect to on this VM, for firewall hints."""
    v, on = state["values"], configio.enabled(state)
    ps = [f"{v.get('env:BOARD_PORT') or 8080}/tcp"]
    if "syslog" in on:
        ps += [f"{v.get('syslog.port') or 514}/tcp", f"{v.get('syslog.port') or 514}/udp"]
    if "windows" in on:
        ps.append(f"{v.get('windows.forward_port') or 24224}/tcp")
    if "netflow" in on:
        ps.append(f"{v.get('netflow.port') or 2055}/udp")
    return ps


def port_check(port, proto, what):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        return [(OK, f"{what}: {proto.upper()} {port} is free")]
    except PermissionError:
        return [(OK, f"{what}: {proto.upper()} {port} is privileged; Docker publishes it")]
    except OSError:
        r = subprocess.run(["docker", "ps", "--filter", f"publish={port}", "--format", "{{.Names}}"], capture_output=True, text=True) \
            if shutil.which("docker") else None
        who = (r.stdout.strip().splitlines() or [""])[0] if r else ""
        if who.startswith("logwatch"):
            return [(OK, f"{what}: {proto.upper()} {port} is served by {who}")]
        return [(FAIL, f"{what}: {proto.upper()} {port} is already in use{' by ' + who if who else ''}: pick another port")]
    finally:
        s.close()


# --- SSH agents -----------------------------------------------------------------------------------------------------

NEEDS = {"logpull": ("journalctl", "journald"), "csctl": ("cscli", "CrowdSec (cscli)"), "images": ("docker", "Docker"),
         "waf": ("wafctl", "logwatch-wafctl (install-agent.sh with role waf)"), "l4waf": ("nfwafctl", "logwatch-nfwafctl (role l4waf)")}


def hello(h, user="logwatch"):
    """Ask a host's logwatch-remote what it allows. → (dict or None, error)."""
    if not setup.SSH_KEY.exists():
        return None, "the board has no SSH key yet (save once first)"
    kh = setup.DATA / "ssh" / "known_hosts"
    kh.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["ssh", "-i", str(setup.SSH_KEY), "-p", str(h.get("port") or 22), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
           "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={kh}",
           "-o", "LogLevel=ERROR", "-l", user, "--", h["address"], "hello"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, "SSH timed out"
    finally:
        configio.fix_owner()
    if r.returncode == 0:
        try:
            return json.loads(r.stdout.strip().splitlines()[-1]), ""
        except (ValueError, IndexError):
            pass
    err = (r.stderr or r.stdout).strip()[-200:]
    if "Permission denied" in err:
        return None, ("key not accepted: install-agent.sh hasn't run there, ran with another --pubkey or --from, "
                      "or sshd AllowUsers/AllowGroups leave the user out (re-run it with --sshd-allow)")
    if "not allowed" in err:
        return None, "agent is older than this installer: re-run install-agent.sh on it"
    if "Connection refused" in err or "timed out" in err or "No route" in err:
        return None, f"can't reach SSH on port {h.get('port') or 22}: {err}"
    return None, err or f"ssh exit {r.returncode}"


def ssh_role(state, role, key=None):
    v = state["values"]
    hs = parse_hosts(v.get(key or f"ssh:{role}"))[0]
    if not hs:
        return [(WARN, f"no hosts listed for {role}")] if role not in ("l4waf", "csctl") else []
    user = dget(configio.yaml.safe_load(setup.CONFIG.read_text()) if setup.CONFIG.exists() else {}, "ssh.user") or "logwatch"
    out = []
    for h in hs:
        info, err = hello(h, user)
        if not info:
            out.append((FAIL, f"{h['name']} ({h['address']}): {err}"))
            continue
        bad = []
        if role not in info.get("roles", []):
            bad.append(f"role {role} not enabled (install-agent.sh --roles …,{role})")
        need = NEEDS.get(role)
        if need and not info.get("tools", {}).get(need[0]):
            bad.append(f"{need[1]} missing")
        if role == "trafficpull" and not info.get("traffic_files"):
            bad.append("no access/traffic log matches TRAFFIC_GLOBS yet")
        if info.get("host") and info["host"].split(".")[0].lower() != h["name"].lower():
            out.append((WARN, f"{h['name']}: its hostname is {info['host']}; the name should match its syslog hostname"))
        out.append((FAIL if bad and role != "trafficpull" else (WARN if bad else OK),
                    f"{h['name']} ({h['address']}): " + ("; ".join(bad) if bad else f"agent ok, roles {', '.join(info['roles'])}")))
    return out


# --- APIs -----------------------------------------------------------------------------------------------------------

def proxmox(state):
    v = state["values"]
    tok, url = _secret(state, "PROXMOX_TOKEN"), str(v.get("proxmox.url") or "").rstrip("/")
    if "!" not in tok or "=" not in tok:
        return [(FAIL, "token must look like user@realm!tokenid=uuid")]
    try:
        hdr, vf = {"Authorization": f"PVEAPIToken={tok}"}, bool(v.get("proxmox.verify_tls"))
        r = _http("GET", f"{url}/api2/json/version", headers=hdr, verify=vf)
        r.raise_for_status()
        out = [(OK, f"Proxmox VE {r.json()['data'].get('version')}")]
        n = _http("GET", f"{url}/api2/json/nodes", headers=hdr, verify=vf).json().get("data") or []
        out.append((OK, f"{len(n)} node(s) visible") if n else (FAIL, "no nodes visible: give the token PVEAuditor on / (and uncheck Privilege Separation or grant the token itself)"))
        return out
    except Exception as e:
        return [(FAIL, _err(e))]


def unifi(state):
    v = state["values"]
    url = str(v.get("unifi.url") or "").rstrip("/")
    try:
        r = _http("GET", f"{url}/proxy/network/integration/v1/sites", headers={"X-API-KEY": _secret(state, "UNIFI_API_KEY")},
                  verify=bool(v.get("unifi.verify_tls")))
        r.raise_for_status()
        sites = [s.get("internalReference") or s.get("name") for s in r.json().get("data") or []]
        site = v.get("unifi.site") or "default"
        return [(OK, f"UniFi API ok, sites: {', '.join(map(str, sites)) or 'none'}"),
                (OK if site in sites or not sites else WARN, f"site '{site}'" + ("" if site in sites or not sites else " not found"))]
    except Exception as e:
        return [(FAIL, _err(e))]


def action1(state):
    base = str(state["values"].get("action1.base_url") or "https://app.action1.com/api/3.0").rstrip("/")
    try:
        t = _http("POST", f"{base}/oauth2/token", data={"client_id": _secret(state, "ACTION1_CLIENT_ID"),
                                                         "client_secret": _secret(state, "ACTION1_CLIENT_SECRET")})
        t.raise_for_status()
        hdr = {"Authorization": f"Bearer {t.json()['access_token']}"}
        r = _http("GET", f"{base}/endpoints/managed/{_secret(state, 'ACTION1_ORG_ID')}?limit=1", headers=hdr)
        r.raise_for_status()
        return [(OK, f"Action1 ok, {r.json().get('total_items', len(r.json().get('items') or []))} endpoints")]
    except Exception as e:
        return [(FAIL, _err(e))]


def wazuh(state):
    v = state["values"]
    vf, out = bool(v.get("wazuh.verify_tls")), []
    base = str(v.get("wazuh.api_url") or "").rstrip("/")
    try:
        r = _http("POST", f"{base}/security/user/authenticate", auth=(_secret(state, "WAZUH_API_USER"), _secret(state, "WAZUH_API_PASSWORD")), verify=vf)
        r.raise_for_status()
        hdr = {"Authorization": f"Bearer {r.json()['data']['token']}"}
        info = _http("GET", f"{base}/", headers=hdr, verify=vf).json().get("data") or {}
        ag = _http("GET", f"{base}/agents", params={"limit": 1, "select": "id"}, headers=hdr, verify=vf).json().get("data") or {}
        out.append((OK, f"Wazuh manager {info.get('api_version', '?')}, {ag.get('total_affected_items', '?')} agents"))
        major = str(info.get("api_version", "4")).lstrip("v").split(".")[0]
        if major.isdigit() and int(major) < 4:
            out.append((WARN, "built for Wazuh 4.x"))
    except Exception as e:
        out.append((FAIL, f"manager API: {_err(e)}"))
    idx = str(v.get("wazuh.indexer_url") or "").rstrip("/")
    if idx:
        auth = (_secret(state, "WAZUH_INDEXER_USER"), _secret(state, "WAZUH_INDEXER_PASSWORD"))
        for index, what in (("wazuh-alerts-4.x-*", "alerts"), ("wazuh-states-vulnerabilities-*", "vulnerabilities")):
            try:
                r = _http("GET", f"{idx}/{index}/_count", auth=auth, verify=vf)
                r.raise_for_status()
                out.append((OK, f"indexer {what}: {r.json().get('count', 0):,} documents"))
            except Exception as e:
                lvl = WARN if what == "vulnerabilities" and isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 404 else FAIL
                out.append((lvl, f"indexer {what}: {_err(e)}" + (" (vulnerability detection needs Wazuh 4.8+)" if lvl == WARN else "")))
    elif v.get("wazuh.alerts") == "indexer":
        out.append((WARN, "alerts = indexer but no indexer URL: pick syslog or add the indexer"))
    if v.get("wazuh.alerts") == "syslog":
        out.append((OK, "alerts via syslog: add the <syslog_output> block from the steps to the manager's ossec.conf"))
    return out


def cloudflare(state):
    v = state["values"]
    if not v.get("cf"):
        return []
    hdr = {"Authorization": f"Bearer {_secret(state, 'CLOUDFLARE_API_TOKEN')}"}
    api = "https://api.cloudflare.com/client/v4"
    out = []
    for what, url in (("token", f"{api}/user/tokens/verify"),
                      ("zone WAF", f"{api}/zones/{v.get('waf.cloudflare.zone')}/rulesets/phases/http_request_firewall_custom/entrypoint"),
                      ("account lists", f"{api}/accounts/{v.get('waf.cloudflare.account')}/rules/lists")):
        try:
            r = _http("GET", url, headers=hdr)
            if what == "zone WAF" and r.status_code == 404:  # no custom rules yet: fine
                out.append((OK, "zone WAF: reachable (no custom rules yet)"))
                continue
            r.raise_for_status()
            out.append((OK, f"Cloudflare {what} ok"))
        except Exception as e:
            out.append((FAIL, f"Cloudflare {what}: {_err(e)}"))
    return out


def instatus(state):
    try:
        r = _http("GET", f"https://api.instatus.com/v1/{state['values'].get('instatus.page_id')}/components",
                  headers={"Authorization": f"Bearer {_secret(state, 'INSTATUS_API_KEY')}"})
        r.raise_for_status()
        return [(OK, f"Instatus ok, {len(r.json())} components")]
    except Exception as e:
        return [(FAIL, _err(e))]


def uptime(state):
    out = []
    for t in parse_lines("uptime.targets", state["values"].get("lines:uptime.targets"))[0][:20]:
        try:
            if t.get("kind") == "tcp":
                socket.create_connection((t["host"], t["port"]), timeout=6).close()
                out.append((OK, f"{t['name']}: TCP {t['host']}:{t['port']} open"))
            else:
                r = _http("GET", t["url"], follow_redirects=False, verify=False)
                out.append((OK if r.status_code < 400 else WARN, f"{t['name']}: HTTP {r.status_code}"))
        except Exception as e:
            out.append((WARN, f"{t['name']}: {_err(e)} (it shows as down on the board)"))
    return out or [(OK, "no seed checks; add them on the Services tab")]


def expiry(state):
    out = []
    for t in parse_lines("expiry.tls", state["values"].get("lines:expiry.tls"))[0][:20]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            with socket.create_connection((t["host"], t["port"]), timeout=6) as s, ctx.wrap_socket(s, server_hostname=t.get("sni") or t["host"]):
                out.append((OK, f"{t['host']}:{t['port']} answers TLS"))
        except Exception as e:
            out.append((WARN, f"{t['host']}:{t['port']}: {_err(e)}"))
    return out


def alertfile(state):
    path = str(state["values"].get("alertfile.path") or "").strip()
    if not path.startswith(("//", "\\\\")):
        return [(OK, f"local file {path}: the worker reads it inside the container")] if path else [(FAIL, "no file set")]
    host = path.lstrip("/\\").replace("\\", "/").split("/")[0]
    try:
        socket.create_connection((host, 445), timeout=6).close()
        return [(OK, f"{host}: SMB (445) reachable; the worker logs in with the SMB user")]
    except Exception as e:
        return [(FAIL, f"{host}:445 {_err(e)}")]


# --- dispatcher -----------------------------------------------------------------------------------------------------

API = {"proxmox": proxmox, "unifi": unifi, "action1": action1, "wazuh": wazuh, "cloudflare": cloudflare,
       "instatus": instatus, "uptime": uptime, "expiry": expiry, "alertfile": alertfile}


def run(state, check_id):
    try:
        if check_id.startswith("port:"):
            _, key, proto = check_id.split(":")
            return port_check(int(state["values"].get(key) or 0), proto, key.split(".")[0])
        if check_id.startswith("ssh:"):
            return ssh_role(state, check_id[4:])
        return API[check_id](state)
    except Exception as e:
        return [(FAIL, f"check crashed: {type(e).__name__}: {e}")]


def module(state, mid):
    from .schema import ALL_MODULES
    out = []
    for c in ALL_MODULES[mid].checks:
        out += run(state, c)
    return out or [(OK, "nothing to check from here; follow the steps")]
