"""Proxmox discovery: nodes, VMs, containers (with their IPs) and disks, read with the PVEAuditor token.

Guest IPs come from, in order: the container's live interfaces, the QEMU guest agent (needs VM.GuestAgent.Audit on
PVE 9 / VM.Monitor on PVE 8; skipped quietly without it), then static ip= / ipconfigN= in the guest's config.
Nothing is changed on Proxmox.
"""
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

from .checks import _http, _secret


def _ok_ip(a):
    try:
        ip = ipaddress.ip_address(a.split("/")[0])
    except ValueError:
        return ""
    return "" if ip.is_loopback or ip.is_link_local or ip.version != 4 else str(ip)


def _cfg_ips(cfg):
    out = []
    for k, v in (cfg or {}).items():
        if re.fullmatch(r"(net|ipconfig)\d+", k):
            m = re.search(r"\bip=([0-9.]+)", str(v))
            if m and _ok_ip(m.group(1)):
                out.append(m.group(1))
    return out


def proxmox(state):
    """{nodes: [{name, ip, status}], guests: [{name, vmid, type, node, status, ips, tags}], disks: [...], warnings: []}."""
    v = state["values"]
    base = str(v.get("proxmox.url") or "").rstrip("/") + "/api2/json"
    kw = {"headers": {"Authorization": f"PVEAPIToken={_secret(state, 'PROXMOX_TOKEN')}"}, "verify": bool(v.get("proxmox.verify_tls"))}

    def get(path):
        r = _http("GET", base + path, **kw)
        r.raise_for_status()
        return r.json().get("data")

    out = {"nodes": [], "guests": [], "disks": [], "warnings": []}
    try:
        st = {n.get("name"): n for n in (get("/cluster/status") or []) if n.get("type") == "node"}
    except Exception:
        st = {}
    for n in get("/nodes") or []:
        out["nodes"].append({"name": n["node"], "ip": (st.get(n["node"]) or {}).get("ip", ""), "status": n.get("status", "")})
    res = [r for r in get("/cluster/resources?type=vm") or [] if not r.get("template")]
    agent_denied = []

    def guest(r):
        kind, node, vmid = r.get("type"), r.get("node"), r.get("vmid")
        g = {"name": r.get("name") or f"{kind}-{vmid}", "vmid": vmid, "type": "ct" if kind == "lxc" else "vm", "node": node,
             "status": r.get("status", ""), "tags": r.get("tags", ""), "ips": []}
        try:
            if kind == "lxc" and g["status"] == "running":
                for i in get(f"/nodes/{node}/lxc/{vmid}/interfaces") or []:
                    if i.get("name") != "lo":
                        g["ips"] += [x for x in [_ok_ip(i.get("inet") or "")] if x]
            elif kind == "qemu" and g["status"] == "running":
                try:
                    for i in (get(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces") or {}).get("result") or []:
                        if i.get("name") != "lo":
                            g["ips"] += [x for x in (_ok_ip(a.get("ip-address", "")) for a in i.get("ip-addresses") or []) if x]
                except Exception as e:  # no agent, or no permission for it
                    if "403" in str(e):
                        agent_denied.append(g["name"])
            if not g["ips"]:
                g["ips"] = _cfg_ips(get(f"/nodes/{node}/{kind}/{vmid}/config"))
        except Exception:
            pass
        g["ips"] = list(dict.fromkeys(g["ips"]))
        return g

    with ThreadPoolExecutor(8) as ex:
        out["guests"] = sorted(ex.map(guest, res), key=lambda g: (g["status"] != "running", g["name"]))
    for n in out["nodes"]:
        if n["status"] != "online":
            continue
        try:
            for d in get(f"/nodes/{n['name']}/disks/list") or []:
                out["disks"].append({"node": n["name"], "dev": d.get("devpath", ""), "model": d.get("model", ""), "type": d.get("type", ""),
                                     "size_gb": round((d.get("size") or 0) / 1e9), "health": d.get("health", ""), "used": d.get("used", "")})
        except Exception as e:
            out["warnings"].append(f"disks on {n['name']}: {str(e)[:80]} (needs Sys.Audit)")
    if agent_denied:
        out["warnings"].append(f"guest agent not readable for {len(agent_denied)} VM(s): IPs from their config only "
                               "(grant VM.GuestAgent.Audit on PVE 9, VM.Monitor on PVE 8, for live IPs)")
    no_ip = [g["name"] for g in out["guests"] if g["status"] == "running" and not g["ips"]]
    if no_ip:
        out["warnings"].append("no IP found for: " + ", ".join(no_ip[:12]) + (" …" if len(no_ip) > 12 else ""))
    return out


def merge_hosts(text, entries):
    """Append 'name address' lines for entries whose name isn't in the list yet."""
    have = {ln.split()[0] for ln in str(text or "").splitlines() if ln.strip()}
    add = [f"{n} {a}" for n, a in entries if n not in have]
    return "\n".join([x for x in str(text or "").splitlines() if x.strip()] + add), len(add)
