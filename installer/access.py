"""How this VM reaches the servers it monitors: direct, Tailscale, NetBird, Cloudflare One (WARP) or another VPN.

The board's containers use the host's routes, so an overlay that gives this VM a kernel interface (tailscale0, wt0,
CloudflareWARP) works for them too. Userspace-only modes (tailscaled --tun=userspace-networking, netbird in a
container without NET_ADMIN) don't: the checks flag that.
"""
import json
import re
import shutil
import socket
import subprocess

from .configio import parse_hosts
from .schema import ACCESS_FIELDS as FIELDS, METHODS  # noqa: F401


SUB = {"tailscale": ("once_ts_authkey", "acc_ts_hostname"), "netbird": ("once_nb_setup_key", "acc_nb_management"),
       "cfone": ("acc_cf_team",), "other": ("acc_other_iface",)}
IFACE = {"tailscale0": "Tailscale", "wt0": "NetBird", "CloudflareWARP": "Cloudflare WARP"}


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def _iface(name):
    return _run(["ip", "link", "show", name])[0] == 0


def steps(state, method):
    v = state["values"]
    if method == "direct":
        return "Nothing to install on this VM. Open these paths in the firewalls between your networks:\n\n" + "\n".join(
            f"- {x}" for x in direct_items(state))
    if method == "tailscale":
        return ("Install on this VM (official script) and join with a one-off auth key:\n"
                "```\ncurl -fsSL https://tailscale.com/install.sh | sh\n"
                f"sudo tailscale up --auth-key <key> --hostname {v.get('acc_ts_hostname') or 'logwatch'}\n```\n"
                "Each monitored server must be in the tailnet too (or behind a subnet router with `--accept-routes` here), "
                "and your ACL / grants must allow this VM → servers on TCP 22, and servers → this VM on the syslog port. "
                "Use the servers' 100.x addresses (or MagicDNS names) in the host lists.")
    if method == "netbird":
        mg = v.get("acc_nb_management")
        return ("Install on this VM (official script) and join with a setup key:\n"
                "```\ncurl -fsSL https://pkgs.netbird.io/install.sh | sh\n"
                f"sudo netbird up --setup-key <key>{' --management-url ' + mg if mg else ''}\n```\n"
                "In the dashboard, add an access policy: this peer's group → the servers' group, TCP 22 (SSH roles), "
                "and servers → this peer on the syslog port. Routes to whole LANs: Network Routes with a routing peer. "
                "Use the servers' NetBird IPs (100.x) or DNS names in the host lists.")
    if method == "cfone":
        team = v.get("acc_cf_team") or "<team>"
        return ("The board needs real IP reachability, so use the **WARP client on this VM** with private network routes "
                "(Cloudflare Tunnel / WARP Connector on the server side). `cloudflared access ssh` as a ProxyCommand is not "
                "supported (the board's SSH runs inside a container).\n"
                "```\n# Debian/Ubuntu\ncurl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloudflare-warp.gpg\n"
                "echo \"deb [signed-by=/usr/share/keyrings/cloudflare-warp.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main\" "
                "| sudo tee /etc/apt/sources.list.d/cloudflare-client.list\nsudo apt update && sudo apt install -y cloudflare-warp\n```\n"
                f"Enrol headless with a service token: Zero Trust → Access → Service Auth → create token; add a device enrollment "
                f"rule allowing it; then write /var/lib/cloudflare-warp/mdm.xml:\n"
                f"```\n<dict>\n  <key>organization</key><string>{team}</string>\n  <key>auth_client_id</key><string>…</string>\n"
                "  <key>auth_client_secret</key><string>…</string>\n  <key>service_mode</key><string>warp</string>\n</dict>\n```\n"
                "`sudo systemctl restart warp-svc && warp-cli status`. Split Tunnels must include (Include mode) or not exclude "
                "your servers' private ranges.")
    if method == "other":
        return (f"Bring the VPN up on this VM so its routes are in the host's table (interface {v.get('acc_other_iface') or 'wg0'}). "
                "The checks below show which interface each server is reached through.")
    return ""


def _hostport(url, port):
    m = re.match(r"\w+://([^/:]+)(?::(\d+))?", str(url or ""))
    return f"{m.group(1)}:{m.group(2) or port}" if m else ""


def direct_items(state):
    """Concrete reachability list for the enabled modules (what must be open between this VM and the servers)."""
    from .configio import csv, enabled, lines
    from .schema import ALL_MODULES
    v, on, out = state["values"], enabled(state), []
    me = v.get("addr") or "this VM"
    out.append(f"your browser → **{me}** TCP {v.get('env:BOARD_PORT') or 8080} (the board"
               + (f", from {v.get('board.allow_cidrs')}" if v.get("board.allow_cidrs") else "") + ")")
    ssh = {}
    for mid in sorted(on):
        for f in ALL_MODULES[mid].fields:
            if f.key.startswith("ssh:"):
                for h in parse_hosts(v.get(f.key))[0]:
                    ssh.setdefault((h["name"], h["address"], h.get("port", 22)), []).append(f.key[4:])
    for (n, a, p), roles in ssh.items():
        out.append(f"this VM → **{n}** ({a}) TCP {p}: SSH for {', '.join(roles)}")
    senders = {"syslog": ("hosts:syslog", f"TCP+UDP {v.get('syslog.port') or 514}", "syslog"),
               "windows": ("hosts:windows", f"TCP {v.get('windows.forward_port') or 24224}", "Fluent Bit forward"),
               "netflow": ("hosts:netflow", f"UDP {v.get('netflow.port') or 2055}", "NetFlow/IPFIX")}
    for mid, (key, port, what) in senders.items():
        if mid in on:
            hs = parse_hosts(v.get(key))[0]
            src = ", ".join(f"{h['name']} ({h['address']})" for h in hs) or "each sender"
            out.append(f"{src} → **{me}** {port}: {what}")
    if "crowdsec" in on and "syslog" not in on and "pull" not in on:
        out.append("CrowdSec hosts reach the board through syslog or SSH pull: turn one of them on")
    if "wazuh" in on and v.get("wazuh.alerts") == "syslog":
        out.append(f"Wazuh manager → **{me}** TCP+UDP {v.get('syslog.port') or 514}: alerts via syslog")
    api = {"proxmox": ("proxmox.url", 8006, "Proxmox API"), "unifi": ("unifi.url", 443, "UniFi API"),
           "action1": ("action1.base_url", 443, "Action1 API (internet)")}
    for mid, (key, port, what) in api.items():
        if mid in on and _hostport(v.get(key), port):
            out.append(f"this VM → **{_hostport(v.get(key), port)}**: {what}")
    if "wazuh" in on:
        for key, port, what in (("wazuh.api_url", 55000, "Wazuh manager API"), ("wazuh.indexer_url", 9200, "Wazuh indexer")):
            if _hostport(v.get(key), port):
                out.append(f"this VM → **{_hostport(v.get(key), port)}**: {what}")
    if "waf" in on and v.get("cf"):
        out.append("this VM → **api.cloudflare.com:443**: Cloudflare WAF rules")
    if "alertfile" in on and str(v.get("alertfile.path") or "").startswith(("//", "\\\\")):
        out.append(f"this VM → **{str(v.get('alertfile.path')).lstrip('/').replace(chr(92), '/').split('/')[0]}:445**: alert file (SMB)")
    if "instatus" in on:
        out.append("this VM → **api.instatus.com:443**: status page")
    if "trivy" in on:
        out.append("this VM → **ghcr.io / mirror.gcr.io :443**: vulnerability database for the image scan")
    if "uptime" in on and lines(v.get("lines:uptime.targets")):
        out.append(f"this VM → the {len(lines(v.get('lines:uptime.targets')))} uptime targets (their URL/port)")
    if "expiry" in on and (lines(v.get("lines:expiry.tls")) or csv(v.get("expiry.domains"))):
        out.append("this VM → the TLS endpoints (their port) and **rdap.org:443** for domain dates")
    out.append("this VM → **github.com:443** (release checks and updates) and your DNS server")
    return out


def install_cmds(state, method):
    """Commands the installer may run on this VM (after the user confirms). Secrets are passed but never shown."""
    v = state["values"]
    if method == "tailscale":
        key = v.get("once_ts_authkey")
        return [["sh", "-c", "curl -fsSL https://tailscale.com/install.sh | sh"]] + (
            [["tailscale", "up", "--auth-key", key, "--hostname", v.get("acc_ts_hostname") or "logwatch"]] if key else [])
    if method == "netbird":
        key, mg = v.get("once_nb_setup_key"), v.get("acc_nb_management")
        return [["sh", "-c", "curl -fsSL https://pkgs.netbird.io/install.sh | sh"]] + (
            [["netbird", "up", "--setup-key", key] + (["--management-url", mg] if mg else [])] if key else [])
    return []


def check(state, method):
    out = []
    if method == "tailscale":
        if not shutil.which("tailscale"):
            return [("fail", "tailscale is not installed on this VM")]
        rc, txt = _run(["tailscale", "status", "--json"])
        try:
            j = json.loads(txt)
            st, ips = j.get("BackendState"), (j.get("Self") or {}).get("TailscaleIPs") or []
            out.append(("ok" if st == "Running" else "fail", f"Tailscale {st}" + (f", this VM is {ips[0]}" if ips else "")))
        except ValueError:
            out.append(("fail", f"tailscale status: {txt[:120]}"))
        if not _iface("tailscale0"):
            out.append(("fail", "no tailscale0 interface: tailscaled runs in userspace mode, the containers can't use it"))
    elif method == "netbird":
        if not shutil.which("netbird"):
            return [("fail", "netbird is not installed on this VM")]
        rc, txt = _run(["netbird", "status"])
        conn = "Management: Connected" in txt and "Signal: Connected" in txt
        ip = next((ln.split(":", 1)[1].strip() for ln in txt.splitlines() if ln.startswith("NetBird IP")), "")
        out.append(("ok" if conn else "fail", "NetBird connected" + (f", this VM is {ip}" if ip else "") if conn else f"NetBird: {txt[:160] or 'not running'}"))
        if conn and not _iface("wt0"):
            out.append(("warn", "no wt0 interface: if NetBird runs in userspace mode the containers can't use it"))
    elif method == "cfone":
        if not shutil.which("warp-cli"):
            return [("fail", "warp-cli is not installed on this VM")]
        rc, txt = _run(["warp-cli", "--accept-tos", "status"])
        out.append(("ok" if "Connected" in txt and "Disconnected" not in txt else "fail", "WARP: " + (txt.splitlines() or ["?"])[0][:120]))
    elif method == "other":
        i = state["values"].get("acc_other_iface")
        if i:
            out.append(("ok", f"{i} is up") if _iface(i) else ("fail", f"no interface {i} on this VM"))
    return out


def targets(state):
    """Every server address the enabled modules need → which interface reaches it, and is SSH open."""
    from .configio import enabled
    from .schema import ALL_MODULES
    v, seen, out = state["values"], {}, []
    for mid in sorted(enabled(state)):
        for f in ALL_MODULES[mid].fields:
            if f.key.startswith(("ssh:", "hosts:")):
                for h in parse_hosts(v.get(f.key))[0]:
                    seen.setdefault(h["address"], (h["name"], h.get("port", 22), f.key.startswith("ssh:")))
    for addr, (name, port, ssh) in seen.items():
        try:
            ip = socket.getaddrinfo(addr, None, socket.AF_INET)[0][4][0]
        except OSError:
            out.append(("fail", f"{name}: can't resolve {addr}"))
            continue
        rc, txt = _run(["ip", "route", "get", ip])
        dev = txt.split(" dev ")[1].split()[0] if " dev " in txt else "?"
        via = IFACE.get(dev, dev)
        if not ssh:
            out.append(("ok" if rc == 0 else "fail", f"{name} {ip}: routed via {via}" if rc == 0 else f"{name} {ip}: no route"))
            continue
        s = socket.socket()
        s.settimeout(4)
        try:
            s.connect((ip, port))
            out.append(("ok", f"{name} {ip}: SSH port {port} open, via {via}"))
        except OSError as e:
            out.append(("fail", f"{name} {ip}: SSH port {port} not reachable via {via} ({e.__class__.__name__}): VPN policy or firewall?"))
        finally:
            s.close()
    return out or [("ok", "no servers entered yet")]
