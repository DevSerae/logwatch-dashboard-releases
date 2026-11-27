"""Target-machine steps per module (markdown for the installer) and the matching "paste this to your AI agent" prompts."""
import json
import os
import shutil

from .configio import enabled, lines, parse_hosts, pubkey, setup
from .schema import ALL_MODULES, SSH_ROLES

RELEASES = os.environ.get("LW_RELEASES", "https://github.com/DevSerae/logwatch-dashboard-releases")


def version():
    return (setup.ROOT / "VERSION").read_text().strip()


def fetch_linux():
    v = version()
    return (f"curl -fsSL {RELEASES}/releases/download/v{v}/logwatch-dashboard-{v}.tar.gz | tar xz -C /tmp\n"
            f"cd /tmp/logwatch-dashboard/remote")


def host_roles(state):
    """name → {address, port, roles} over every enabled module (one install-agent run per host)."""
    on, v, out = enabled(state), state["values"], {}
    for mid in on:
        for f in ALL_MODULES[mid].fields:
            if f.key.startswith("ssh:"):
                for h in parse_hosts(v.get(f.key))[0]:
                    e = out.setdefault(h["name"], {**h, "roles": []})
                    if f.key[4:] not in e["roles"]:
                        e["roles"].append(f.key[4:])
    for e in out.values():
        e["roles"].sort(key=SSH_ROLES.index)
    return out


def _ctx(state):
    v = state["values"]
    return {"addr": v.get("addr") or "<this-vm>", "port": v.get("syslog.port") or 514, "pub": pubkey() or "<save first: the board's key>",
            "board": f"http://{v.get('addr') or '<this-vm>'}:{v.get('env:BOARD_PORT') or 8080}"}


def agent_cmd(state, h):
    c, v = _ctx(state), state["values"]
    cmd = f'sudo ./linux/install-agent.sh --roles {",".join(h["roles"])} --pubkey "{c["pub"]}" --from {c["addr"]} --sshd-allow'
    if "trafficpull" in h["roles"]:
        cmd += f' --traffic-globs "{v.get("tglobs") or "/var/log/nginx/access.log"},/var/log/logwatch-traffic.log"'
    return cmd


def _agent_hosts(state, role):
    hs = [h for h in host_roles(state).values() if role in h["roles"]]
    if not hs:
        return f"_Add hosts above first._\n"
    out = ""
    for h in hs:
        out += f"\n**{h['name']}** ({h['address']}), as root:\n```\n{fetch_linux()}\n{agent_cmd(state, h)}\n" \
               f"sudo ./linux/check-host.sh --board {_ctx(state)['addr']} --roles {','.join(h['roles'])}\n```\n"
    return out


def steps(state, mid):
    c, v = _ctx(state), state["values"]
    s = ""
    if mid == "syslog":
        hs = parse_hosts(v.get("hosts:syslog"))[0]
        s = (f"On each Linux host, as root (forwards everything via rsyslog with a disk queue; undo line in the script header):\n"
             f"```\n{fetch_linux()}\nsudo ./linux/logfwd.sh {c['addr']} {c['port']} tcp\n"
             f"sudo ./linux/check-host.sh --board {c['addr']} --syslog\n```\n")
        if hs:
            s += "Hosts: " + ", ".join(f"{h['name']} ({h['address']})" for h in hs) + "\n\n"
        s += (f"Network gear (switches, firewalls, NAS, APs): point remote syslog at **{c['addr']}**, port **{c['port']}** "
              f"(TCP preferred, UDP works). Vendor notes: docs/network-gear.md.\n\n"
              f"Firewall on this VM: allow TCP+UDP {c['port']} from the senders.")
    elif mid == "pull":
        s = "The board's SSH key can only run the logwatch-remote dispatcher with the roles you allow.\n" + _agent_hosts(state, "logpull")
    elif mid == "windows":
        hs = parse_hosts(v.get("hosts:windows"))[0]
        s = (f"On each Windows host, in an elevated PowerShell (Fluent Bit service; uninstall line in the script header):\n"
             f"```\n# copy remote\\windows from the release to the host, then:\n"
             f".\\install.ps1 -Board {c['addr']} -Port {v.get('windows.forward_port') or 24224}{' -Dns' if v.get('windows.dns.enabled') else ''}\n```\n"
             f"Many hosts with OpenSSH: `remote/windows/deploy.sh` from this VM.\n\n"
             f"Firewall on this VM: allow TCP {v.get('windows.forward_port') or 24224} from the Windows hosts.")
        if hs:
            s += "\n\nHosts: " + ", ".join(f"{h['name']} ({h['address']})" for h in hs)
        if v.get("windows.dns.enabled"):
            s += ("\n\nDNS servers: DNS Manager → server Properties → Debug Logging: Log packets for debugging, "
                  "Outgoing+Incoming, UDP+TCP, Queries, Request; details off.")
    elif mid == "webhook":
        s = (f"POST JSON to **{c['board']}/api/ingest** with `Authorization: Bearer <INGEST_TOKEN>` "
             f"(in secrets/secrets.env on this VM). Payloads and examples: docs/webhook.md.")
    elif mid == "crowdsec":
        cs = lines(v.get("lines:crowdsec.hosts"))
        s = ("On each edge host, as root. `--install` adds CrowdSec from its official repo if missing; pick the bouncer "
             "that fits (nftables = host firewall, npm = Nginx Proxy Manager with AppSec WAF, none = detect only):\n"
             f"```\n{fetch_linux()}\nsudo ./crowdsec/setup.sh --install --bouncer nftables\n"
             f"sudo ./linux/check-host.sh --board {c['addr']} --crowdsec\n```\n"
             "The heartbeat and events reach the board through syslog (or pull), so also set up the Syslog module on these hosts.\n")
        if cs:
            s += "\nHosts: " + ", ".join(cs) + "\n"
        s += "\nBan/Unban from the board (role csctl):\n" + _agent_hosts(state, "csctl")
    elif mid == "traffic":
        s = ("HTTP requests come from the proxy's access logs; raw connections from an nftables log table. On each edge host:\n"
             + _agent_hosts(state, "trafficpull") +
             "\nPort-forwarding / firewall hosts also log new connections (own nftables table, doesn't touch your rules):\n"
             "```\nsudo ./linux/nft-traffic-log.sh --input-ports \"22,443\"\n```")
    elif mid == "waf":
        s = ("Edge proxies need CrowdSec with the AppSec WAF (Nginx Proxy Manager / OpenResty bouncer):\n"
             f"```\n{fetch_linux()}\nsudo ./crowdsec/setup.sh --install --bouncer npm --npm-data /opt/npm/data --npm-container npm\n```\n"
             "Then the agent with role waf (rules are pushed log-only first; every change is undoable from the board):\n"
             + _agent_hosts(state, "waf"))
        if lines(v.get("ssh:l4waf")):
            s += ("\nPort proxies (DNAT raw TCP/UDP): role l4waf adds its own nftables table `inet lw_waf`, only for forwarded "
                  "traffic arriving on the public interface (auto-detected; `--wan eth0` to override):\n" + _agent_hosts(state, "l4waf"))
        if v.get("cf"):
            s += ("\n**Cloudflare**: dash.cloudflare.com → My Profile → API Tokens → Create custom token: "
                  "Zone → Zone WAF → Edit (this zone), Account → Account Filter Lists → Edit. Zone and account IDs are on the zone's Overview page.")
    elif mid == "unifi":
        s = ("UniFi Network → Settings → Control Plane → Integrations → Create API key. Copy it once; it is read-only.\n\n"
             "Optional, for gateway events in Logs: Settings → CyberSecure / System → Activity Logging (SIEM server): "
             f"server **{c['addr']}**, port **{c['port']}** (Syslog module).")
    elif mid == "netflow":
        s = (f"On the router: export NetFlow v5/v9 or IPFIX to **{c['addr']}**, UDP **{v.get('netflow.port') or 2055}**. "
             "Examples for common gear: docs/network-gear.md.\n\nFirewall on this VM: allow that UDP port from the exporter.")
    elif mid == "action1":
        s = ("Action1 console → Configuration → API Credentials → Create: role **read-only** (no remote actions). "
             "Copy client ID and secret. The organization ID is in the console URL (…/console/dashboard?org=<id>).\n\n"
             "No agent on hosts: the board only reads the API.")
    elif mid == "wazuh":
        s = ("On the Wazuh manager (Server management → Security, or the API), create a read-only API user:\n"
             "```\n# as the wazuh admin user, e.g. with curl against https://<manager>:55000\n"
             "POST /security/users            {\"username\": \"logwatch\", \"password\": \"<strong password>\"}\n"
             "POST /security/users/<id>/roles?role_ids=<id of role 'readonly'>\n```\n"
             "Allow this VM to reach TCP 55000 on the manager.\n")
        if v.get("wazuh.indexer_url"):
            s += ("\nIndexer (vulnerabilities + alerts): Dashboard → Indexer management → Security → Internal users → create `logwatch`, "
                  "then a role with cluster `cluster_composite_ops_ro` and index permissions `read` on `wazuh-alerts-*` and "
                  "`wazuh-states-vulnerabilities-*`, mapped to that user. Allow TCP 9200 from this VM.\n")
        if v.get("wazuh.alerts") == "syslog":
            s += (f"\nAlerts via syslog: on the manager add to /var/ossec/etc/ossec.conf and restart wazuh-manager:\n"
                  f"```\n<syslog_output>\n  <server>{c['addr']}</server>\n  <port>{c['port']}</port>\n"
                  f"  <format>json</format>\n  <level>{v.get('wazuh.min_level') or 3}</level>\n</syslog_output>\n```\n"
                  "Then `/var/ossec/bin/wazuh-control enable client-syslog && systemctl restart wazuh-manager`.")
        s += "\n\nHosts are matched to Wazuh agents by short hostname, so keep agent names = hostnames."
    elif mid == "trivy":
        s = "The board lists running images over SSH (`docker ps` only) and scans them itself, weekly.\n" + _agent_hosts(state, "images")
    elif mid == "uptime":
        s = "Nothing to install. Probes run from this VM; more checks can be added on the board's Services tab."
    elif mid == "expiry":
        s = "Nothing to install. Certificates are read from this VM; domain dates come from RDAP."
    elif mid == "proxmox":
        s = ("Datacenter → Permissions → API Tokens → Add: user e.g. `logwatch@pve` (create it first under Users), token ID "
             "`board`, untick **Privilege Separation**. Then Permissions → Add → User permission: path `/`, role **PVEAuditor**.\n\n"
             "Token format: `logwatch@pve!board=<uuid>`. Allow this VM to reach TCP 8006.")
    elif mid == "alertfile":
        s = ("Nothing to install. The other system appends one JSON object per line: "
             "`{\"id\": 41, \"severity\": \"Warning\", \"source\": \"Backup\", \"message\": \"...\"}` with increasing ids. "
             "For SMB, give the board a read-only account on that folder and allow this VM to reach TCP 445.")
    elif mid == "instatus":
        s = "Instatus → User settings → Developer → API key. The page ID is in the dashboard URL of the page."
    elif mid == "ai":
        s = (f"On the machine where your agent CLI runs (it needs access to your servers):\n"
             f"```\n# on this VM\npython3 setup.py runner-env --out runner.env --url {c['board']}\n```\n"
             "Copy runner.env and ai-runner/ there and follow ai-runner/README.md.")
    return s


def agent_prompt(state, mids):
    """One prompt for an AI agent that has shell access to the target machines."""
    c = _ctx(state)
    out = [f"I'm installing Logwatch Dashboard {version()} on a VM at {c['addr']} (board: {c['board']}). "
           "You have shell access to my servers. Set up the target machines below for the modules I enabled.",
           "Rules: ask me before running anything on a machine; show me each command and its undo first (every script "
           "prints its undo line in its header); never print or paste secrets; don't change anything else on those hosts; "
           "if a step doesn't fit my system (other distro, no rsyslog, different proxy), stop and ask. "
           f"Scripts come from the release tarball ({RELEASES}); read them before you run them.",
           "When done, run the check-host.sh line shown for each host and give me its output. "
           "I'll then press 'Run checks' in the installer."]
    for mid in mids:
        out.append(f"\n## {ALL_MODULES[mid].title} ({mid})\n\n{steps(state, mid)}")
    return "\n\n".join(out) + "\n"


# --- per-server plan (web installer: one-liners, or an approval-first prompt for any AI agent) -------------

AGENT_CLIS = (("claude", "Claude Code"), ("codex", "OpenAI Codex"), ("gemini", "Gemini CLI"), ("opencode", "OpenCode"),
              ("cursor-agent", "Cursor"), ("junie", "Junie"))


def agent_clis():
    return [{"cmd": c, "name": n} for c, n in AGENT_CLIS if shutil.which(c)]


def installed():
    p = setup.DATA / "installer.json"
    try:
        return json.loads(p.read_text()).get("installed") or {}
    except (OSError, ValueError):
        return {}


def mark_installed(name, items):
    from .configio import STATE, fix_owner
    d = json.loads(STATE.read_text()) if STATE.exists() else {}
    d.setdefault("installed", {})[name] = sorted(set(items))
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(d, indent=1))
    fix_owner()


def servers(state):
    """Every server the enabled + configured modules touch → what goes on it. Only modules that are on and have the
    server in one of their host lists appear; API-only modules (Proxmox, UniFi, Action1, ...) install nothing."""
    on, v, c = enabled(state), state["values"], _ctx(state)
    srv = {}

    def get(name, addr, os_="linux"):
        e = srv.setdefault(name, {"name": name, "address": addr, "os": os_, "items": []})
        if addr and not e["address"]:
            e["address"] = addr
        return e

    def item(e, iid, mid, what, cmd):
        if not any(i["id"] == iid for i in e["items"]):
            e["items"].append({"id": iid, "module": mid, "title": ALL_MODULES[mid].title, "what": what, "cmd": cmd})

    roles = host_roles(state)
    addr_of = {n: h["address"] for n, h in roles.items()}
    if "syslog" in on:
        for h in parse_hosts(v.get("hosts:syslog"))[0]:
            addr_of.setdefault(h["name"], h["address"])
            item(get(h["name"], h["address"]), "syslog", "syslog", f"forward syslog to {c['addr']}:{c['port']} (rsyslog, disk queue)",
                 f"./linux/logfwd.sh {c['addr']} {c['port']} tcp")
    if "crowdsec" in on:
        for ln in lines(v.get("lines:crowdsec.hosts")):
            name = ln.split()[0]
            waf = name in roles and "waf" in roles[name]["roles"]
            b = "npm --npm-data /opt/npm/data --npm-container npm" if waf else "nftables"
            item(get(name, addr_of.get(name, "")), "crowdsec", "crowdsec",
                 "CrowdSec engine + " + ("AppSec WAF in Nginx Proxy Manager" if waf else "nftables bouncer") + ", heartbeat, events",
                 f"./crowdsec/setup.sh --install --bouncer {b}")
    for n, h in roles.items():
        mods = sorted({m for m in on for f in ALL_MODULES[m].fields if f.key.startswith("ssh:") and f.key[4:] in h["roles"]})
        item(get(n, h["address"]), "agent:" + ",".join(h["roles"]), mods[0] if mods else "pull",
             f"remote agent, roles {', '.join(h['roles'])} (SSH key limited to {c['addr']})", agent_cmd(state, h).removeprefix("sudo "))
    if "windows" in on:
        for h in parse_hosts(v.get("hosts:windows"))[0]:
            item(get(h["name"], h["address"], "windows"), "windows", "windows", f"Fluent Bit service → {c['addr']}:{v.get('windows.forward_port') or 24224}",
                 f".\\install.ps1 -Board {c['addr']} -Port {v.get('windows.forward_port') or 24224}{' -Dns' if v.get('windows.dns.enabled') else ''}")
    done = installed()
    for e in srv.values():
        have = set(done.get(e["name"]) or [])
        for i in e["items"]:
            i["done"] = i["id"] in have
        e["pending"] = [i["id"] for i in e["items"] if not i["done"]]
        e["oneliner"] = oneliner(state, e)
    return sorted(srv.values(), key=lambda e: (not e["pending"], e["name"]))


def _checkline(state, e):
    ids = [i["id"] for i in e["items"]]
    flags = (" --syslog" if "syslog" in ids else "") + (" --crowdsec" if "crowdsec" in ids else "")
    roles = next((i[6:] for i in ids if i.startswith("agent:")), "")
    return f"./linux/check-host.sh --board {_ctx(state)['addr']}{flags}{' --roles ' + roles if roles else ''}"


def oneliner(state, e, all_items=False):
    items = [i for i in e["items"] if all_items or not i["done"]]
    if not items:
        return ""
    if e["os"] == "windows":
        return "# elevated PowerShell, in a copy of remote\\windows from the release:\n" + "; ".join(i["cmd"] for i in items)
    v = version()
    url = f"{RELEASES}/releases/download/v{v}/logwatch-dashboard-{v}.tar.gz"
    cmds = " && ".join(i["cmd"] for i in items)
    return (f"curl -fsSL {url} | tar xz -C /tmp && cd /tmp/logwatch-dashboard/remote && sudo bash -c '{cmds.replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))}"
            f" && {_checkline(state, e)}'")


def servers_prompt(state, names=None):
    """Prompt to paste into any AI agent (on the board VM or elsewhere). Access is always requested per server first;
    only pending items."""
    c = _ctx(state)
    plan = [e for e in servers(state) if e["pending"] and (not names or e["name"] in names)]
    out = [f"I'm setting up Logwatch Dashboard {version()}. The board runs on the VM {c['addr']} ({c['board']}); you "
           "may be running there or somewhere else. Install the pieces listed below on my servers. These are exactly "
           "the features I selected and configured; install nothing else. If you can't reach a server (no shell or SSH "
           "access from where you run), give me its commands to run myself, one server at a time.",
           "Rules, no exceptions:\n"
           "1. Before you connect to ANY server, ask me for access to that server (which user / key / jump host) and wait "
           "for my explicit yes. Ask again for each server; a yes for one server is not a yes for another.\n"
           "2. Before each command, show it and its undo line (every script prints its undo in its header) and wait for my yes.\n"
           "3. Never print, log or paste secrets or keys other than the public key below.\n"
           "4. Don't change anything else on those hosts. If a step doesn't fit (other distro, no rsyslog, different proxy, "
           "Windows without OpenSSH), stop and ask.\n"
           f"5. Scripts come from the release tarball {RELEASES}/releases/download/v{version()}/logwatch-dashboard-{version()}.tar.gz; "
           "read each script before you run it.\n"
           "6. Long installs: run them detached (`setsid nohup … &`) and poll the log, so a dropped session doesn't kill them.\n"
           "7. After each server, run its check line and show me the output. I'll mark it done in the installer.\n"
           f"8. More detail if a step fails: AGENT_INSTALL.md in the tarball ({RELEASES}).",
           f"The board's SSH public key (safe to share): {c['pub']}"]
    if not plan:
        out.append("\nNothing is pending: every server already has what the selected features need.")
    for e in plan:
        out.append(f"\n## {e['name']} ({e['address'] or 'address: ask me'}, {e['os']})")
        for i in e["items"]:
            if not i["done"]:
                out.append(f"- {i['title']}: {i['what']}\n  `{i['cmd']}`")
        done = [i["title"] for i in e["items"] if i["done"]]
        if done:
            out.append(f"- already installed, skip: {', '.join(done)}")
        if e["os"] == "linux":
            out.append(f"- check: `{_checkline(state, e)}` (from remote/ in the tarball, as root)")
    return "\n".join(out) + "\n"
