#!/usr/bin/env python3
"""Turns logs and checks into board items/events. Run every 10 min by the worker (and by "Run checks now").
Each collector is skipped when its module is off in config.yaml; a failing collector raises one info item."""
import datetime as dt
import fcntl
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import traceback

import httpx
from pathlib import Path

import db
import remote
from common import iso, ms_iso, vl, vl_push, vl_ts
from settings import CONFIG, DATA, VL, mod, secret, section, ssh_hosts

SYSLOG = section("syslog")
IGNORE_LOGIN_FROM = []
for _c in SYSLOG.get("ignore_login_from") or []:
    try:
        IGNORE_LOGIN_FROM.append(ipaddress.ip_network(str(_c), strict=False))
    except ValueError:
        pass


def ignored_ip(ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in IGNORE_LOGIN_FROM)
    except ValueError:
        return False


# --- collectors -------------------------------------------------------------------------------

def pull(con, start, end):
    """Hosts that can't push syslog (ssh.hosts with role logpull): fetch journal + CrowdSec event lines over the
    forced-command key and write them to VictoriaLogs like syslog records."""
    if not mod("pull"):
        return
    active = set()
    for h in ssh_hosts("logpull"):
        host = h["name"]
        st = db.kv_get(con, f"pull:{host}", {"cursor": "-", "offset": 0})
        try:
            lines = remote.json_lines(host, f"logpull {st['cursor']} {st['offset']}")
        except Exception as e:
            key = f"pull:{host}"
            active.add(key)
            db.upsert_item(con, key, "pull", f"Can't pull logs from {host}",
                           f"{type(e).__name__}: {e}"[:400] + f"\nCheck the board can reach {h.get('address') or host} on SSH "
                           f"port {h.get('port') or 22}, and that remote/linux/install-agent.sh ran there with --roles logpull.",
                           "error", kind="condition")
            continue
        now = iso(time.time())
        recs = []
        for x in lines:
            if x["k"] == "j":
                recs.append({"_time": iso(x["t"] / 1e6), "hostname": host, "app_name": x["app"], "severity": str(x["pri"]),
                             "unit": x.get("unit", ""), "_msg": x["msg"], "format": "pull"})
            elif x["k"] == "e":
                recs.append({"_time": now, "hostname": host, "app_name": "crowdsec-event", "_msg": x["line"], "format": "pull"})
        if recs:
            httpx.post(f"{VL}/insert/jsonline", timeout=120, params={"_stream_fields": "hostname,app_name"},
                       content="\n".join(json.dumps(r) for r in recs)).raise_for_status()
            try:  # make the batch searchable now: later collectors in this cycle (crowdsec, log rules) read it
                httpx.post(f"{VL}/internal/force_flush", timeout=30)
            except httpx.HTTPError:
                pass
        db.kv_set(con, f"pull:{host}", {"cursor": lines[-1]["cursor"], "offset": lines[-1]["offset"]})
        db.kv_set(con, f"pull_stats:{host}", {"at": time.time(), "records": len(recs)})
    db.clear_conditions(con, "pull", active)


def hosts(con, start, end):
    # 1 h lookback, not the window: pulled sources (UniFi API) land with past _time, behind the window start
    for r in vl("hostname:* -type:netflow -type:dns | stats by (hostname) count() n", iso(time.time() - 3600), end):
        name = (r.get("hostname") or "").strip()
        if not name or name == "-":
            continue
        con.execute("INSERT INTO hosts(name,last_seen,first_seen) VALUES(?,?,?) "
                    "ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen", (name, time.time(), time.time()))
    active = set()
    silent_h = float(SYSLOG.get("silent_hours") or 2)
    for h in con.execute("SELECT name,last_seen FROM hosts WHERE ignored=0"):
        if time.time() - h["last_seen"] > silent_h * 3600:
            key = f"host-silent:{h['name']}"
            active.add(key)
            db.upsert_item(con, key, "hosts", f"{h['name']} stopped sending logs",
                           f"No logs for over {silent_h:g} hours. Host down, network issue, or forwarding broken. "
                           "If the host was retired, use Mute.", "error", kind="condition")
    # running Proxmox guests/nodes that never sent anything (forwarding never set up)
    pv_cfg = mod("proxmox") or {}
    seen = {r["name"].lower() for r in con.execute("SELECT name FROM hosts")}
    exempt = {str(x).lower() for x in pv_cfg.get("no_logs_expected") or []}
    pve = db.kv_get(con, "proxmox") or {} if pv_cfg else {}
    expected = [(g["name"], f"{g['type']} {g['vmid']} on {g['node']}") for g in pve.get("guests", []) if g.get("running")]
    expected += [(n["name"], "Proxmox node") for n in pve.get("nodes", []) if n.get("online")]
    missing = []
    for name, what in expected:
        if name.lower() in seen or name.lower() in exempt:
            continue
        key = f"host-never:{name}"
        active.add(key)
        missing.append({"name": name, "what": what})
        db.upsert_item(con, key, "hosts", f"{name} has never sent logs",
                       f"{what} is running but nothing from it reached VictoriaLogs. Linux: remote/linux/logfwd.sh; "
                       "Windows: remote/windows. If it shouldn't send logs, Mute it (or add it to proxmox.no_logs_expected).",
                       "warning", kind="condition")
    db.kv_set(con, "hosts_missing", missing)
    db.clear_conditions(con, "hosts", active)


VOL_KINDS = {"winevt": "windows", "heartbeat": "windows", "unifi_flow": "unifi", "unifi_event": "unifi",
             "dns": "dns", "netflow": "netflow", "traffic": "traffic"}


def volume(con, start, end):
    """Hourly log volume (24h) per source kind and per host, for the board's charts."""
    now = time.time()
    hour0 = int(now // 3600) * 3600 - 23 * 3600
    slots = [hour0 + i * 3600 for i in range(24)]

    def slot(row):
        i = int((vl_ts(row) - hour0) // 3600)
        return i if 0 <= i < 24 else None

    kinds = {k: [0] * 24 for k in ("linux", "windows", "unifi", "dns", "netflow", "traffic")}
    for r in vl("* | stats by (_time:1h, type) count() n", iso(hour0), end, limit=1000):
        i = slot(r)
        if i is not None:
            kinds[VOL_KINDS.get(r.get("type") or "", "linux")][i] += int(r["n"])
    per_host = {}
    for r in vl("hostname:* -type:netflow -type:dns -type:heartbeat | stats by (hostname, _time:1h) count() n",
                iso(hour0), end, limit=5000):
        i, name = slot(r), (r.get("hostname") or "").strip()
        if i is not None and name and name != "-":
            per_host.setdefault(name, [0] * 24)[i] += int(r["n"])
    db.kv_set(con, "volume", {"at": now, "hours": slots, "kinds": kinds, "hosts": per_host})


SSH_FAIL = '("Failed password" OR "Invalid user" OR "authentication failure" OR "maximum authentication attempts")'


def linux(con, start, end):
    for r in vl(f"{SSH_FAIL} -type:netflow | stats by (hostname) count() n", start, end):
        n = int(r["n"])
        if n >= int(SYSLOG.get("ssh_fail_threshold") or 20):
            db.upsert_item(con, f"ssh-bruteforce:{r['hostname']}", "linux",
                           f"{n} failed SSH/auth attempts on {r['hostname']}",
                           "Burst of failed logins in the last check window. Check the source IPs in Logs "
                           f"(query: hostname:{r['hostname']} {SSH_FAIL}).", "warning")
        db.add_event(con, "linux", f"Failed logins on {r['hostname']}", severity="warning",
                     dedupe=f"sshfail:{r['hostname']}:{start}")

    pat = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
    for r in vl('"Accepted publickey" OR "Accepted password" OR "Accepted keyboard-interactive"', start, end):
        m = pat.search(r.get("_msg", ""))
        if not m or ignored_ip(m.group(3)):
            continue
        method, user, src = m.groups()
        sev = "warning" if method == "password" else "info"
        db.add_event(con, "linux", f"SSH login {user} → {r.get('hostname')} from {src}", severity=sev,
                     ts=vl_ts(r), dedupe=f"login:{r.get('hostname')}:{r['_time']}:{user}")

    for r in vl('"incorrect password attempt" OR "NOT in sudoers"', start, end):
        db.upsert_item(con, f"sudo-fail:{r.get('hostname')}", "linux", f"Failed sudo on {r.get('hostname')}",
                       r.get("_msg", "")[:400], "warning")

    for r in vl('"Failed with result" | stats by (hostname, app_name) count() n', start, end):
        db.add_event(con, "linux", f"Service failure on {r['hostname']}", severity="warning",
                     dedupe=f"svcfail:{r['hostname']}:{start}")


def log_rules(con, start, end):
    """config log_rules: [{name, query (LogsQL), threshold, severity, source}] → one item per rule and host."""
    for rule in CONFIG.get("log_rules") or []:
        if not isinstance(rule, dict) or not rule.get("query") or not rule.get("name") or rule.get("enabled") is False:
            continue
        thr, sev = int(rule.get("threshold") or 1), rule.get("severity") or "warning"
        src = rule.get("source") or "logs"
        for r in vl(f"({rule['query']}) | stats by (hostname) count() n", start, end):
            n, host = int(r["n"]), r.get("hostname") or "?"
            if n >= thr:
                db.upsert_item(con, f"rule:{rule['name']}:{host}", src, f"{rule['name']} on {host}",
                               f"{n} log lines matching the rule in the last window.\nQuery: {rule['query']}", sev)


UNIFI = mod("unifi") or {}
RISK = {"low": 1, "medium": 2, "high": 3, "very_high": 4}
UNIFI_LAG_MS = 5 * 60 * 1000  # the console writes flows a little after they happen
GW = UNIFI.get("gateway_name") or "unifi-gateway"


def unifi_get(path, body=None):
    """UniFi Network API (local console or Site Manager connector URL) with a read-only API key."""
    key = secret("UNIFI_API_KEY")
    if not key:
        raise RuntimeError("UNIFI_API_KEY missing in secrets.env")
    url = f"{UNIFI['url'].rstrip('/')}/proxy/network/{path.replace('{site}', UNIFI.get('site') or 'default')}"
    r = httpx.request("POST" if body is not None else "GET", url, json=body, headers={"X-API-KEY": key},
                      verify=bool(UNIFI.get("verify_tls", False)), timeout=60)
    r.raise_for_status()
    return r.json()


def unifi_pages(con, path, kv):
    """Records between the kv watermark and now - lag (ms). The watermark moves to the window end."""
    end = int(time.time() * 1000) - UNIFI_LAG_MS
    since = db.kv_get(con, kv) or end - 15 * 60 * 1000
    out, page = [], 0
    while since < end:
        d = unifi_get(f"v2/api/site/{{site}}/{path}",
                      {"timestampFrom": since, "timestampTo": end - 1, "pageNumber": page, "pageSize": 1000})
        out += d.get("data") or []
        page += 1
        if not d.get("has_next") or page >= 50:
            break
    db.kv_set(con, kv, max(since, end))
    return out


def ms_iso(ms):
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).isoformat(timespec="milliseconds")


def vl_push(rows):
    if rows:
        httpx.post(f"{VL}/insert/jsonline", params={"_stream_fields": "type,hostname", "_msg_field": "msg",
                                                    "_time_field": "time"},
                   content="\n".join(json.dumps(r) for r in rows), timeout=60).raise_for_status()


MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)


def unifi_ip_names():
    """IP → name for LAN clients (online now + fixed-IP reservations) and UniFi devices, so flow lines show who."""
    out = {}
    for path in ("api/s/{site}/rest/user", "api/s/{site}/stat/sta", "api/s/{site}/stat/device"):
        try:
            for c in unifi_get(path).get("data") or []:
                ip, name = c.get("fixed_ip") or c.get("ip") or c.get("last_ip"), c.get("name") or c.get("hostname")
                if ip and name and not MAC_RE.match(name):
                    out[ip] = name
        except Exception:
            pass
    return out


def side_name(x, names):
    n = x.get("client_name")
    if n and not MAC_RE.match(n):
        return n
    return names.get(x.get("ip")) or ",".join(x.get("domains") or []) or "unknown host"


def flow_row(f, names=None):
    names = names or {}
    s, d, ips = f.get("source") or {}, f.get("destination") or {}, f.get("ips") or {}
    pol = ", ".join(f"{p.get('type')}:{p.get('name', '')}" for p in f.get("policies") or [])
    row = {"time": ms_iso(f["time"]), "type": "unifi_flow", "hostname": GW, "action": f.get("action"),
           "risk": f.get("risk"), "policy": pol, "proto": f.get("protocol"), "service": f.get("service"),
           "src_ip": s.get("ip"), "src_port": s.get("port"), "src_name": side_name(s, names),
           "src_net": s.get("network_name"), "dst_ip": d.get("ip"), "dst_port": d.get("port"),
           "dst_name": side_name(d, names),
           "dst_net": d.get("network_name") or d.get("region"),
           "ips_signature": ips.get("signature"), "ips_id": ips.get("signature_id"),
           "ips_category": ips.get("category_name")}
    row["msg"] = (f"{row['action']} {row['proto']} {row['src_name']} ({row['src_ip']}:{row['src_port']}) → "
                  f"{row['dst_name']} ({row['dst_ip']}:{row['dst_port']}) "
                  f"{ips.get('signature') or pol}")
    return {k: v for k, v in row.items() if v not in (None, "")}


def render(e):
    p = e.get("parameters") or {}
    return re.sub(r"\{(\w+)\}", lambda m: str((p.get(m.group(1)) or {}).get("name") or m.group(0)),
                  e.get("message_raw") or "")


def unifi(con, start, end):
    if not UNIFI:
        return
    # Blocked, risky and IPS flows: stored in VictoriaLogs (type:unifi_flow), IPS hits go on the board.
    flows = [f for f in unifi_pages(con, "traffic-flows", "unifi_flow_ms")
             if f.get("action") == "blocked" or f.get("ips") or RISK.get(f.get("risk"), 0) >= 2]
    names = unifi_ip_names() if flows else {}
    vl_push([flow_row(f, names) for f in flows])
    min_risk = RISK.get(UNIFI.get("ips_item_min_risk") or "high", 3)
    for f in flows:
        ips = f.get("ips")
        if not ips:
            continue
        s, d = f.get("source") or {}, f.get("destination") or {}
        src = f"{side_name(s, names)} ({s.get('ip')}:{s.get('port')})"
        dst = f"{side_name(d, names)} ({d.get('ip')}:{d.get('port')})"
        sig = ips.get("signature") or "unknown signature"
        db.add_event(con, "unifi", f"IPS: {sig}", severity="warning", ts=f["time"] / 1000,
                     detail=f"{src} → {dst}, {f.get('action')}", dedupe=f"ips:{f['id']}")
        if RISK.get(f.get("risk"), 0) >= min_risk:
            db.upsert_item(con, f"ips:{sig}:{d.get('ip')}", "unifi", f"IPS alert: {sig}",
                           f"{src} → {dst}, {f.get('action')}, risk {f.get('risk')}. "
                           f"{ips.get('alarm_category_potential_risk', '')}\n"
                           f"Check whether the source is one of yours. False positive → suppress signature "
                           f"{ips.get('signature_id')} in UniFi.", "error")

    # Console system log: stored as type:unifi_event; new devices + admin activity on the board.
    known = {r["mac"] for r in con.execute("SELECT mac FROM known_macs")}
    if not known:  # first run: everything UniFi already knows is not "new"
        for c in unifi_get("api/s/{site}/rest/user").get("data") or []:
            con.execute("INSERT OR IGNORE INTO known_macs(mac,label,first_seen) VALUES(?,?,?)",
                        (c["mac"].lower(), c.get("name") or c.get("hostname") or "", c.get("first_seen") or time.time()))
        known = {r["mac"] for r in con.execute("SELECT mac FROM known_macs")}
    events = unifi_pages(con, "system-log/all", "unifi_event_ms")
    vl_push([{"time": ms_iso(e["timestamp"]), "type": "unifi_event", "hostname": GW,
              "category": e.get("category"), "key": e.get("key"), "severity": e.get("severity"),
              "title": e.get("title_raw"), "msg": render(e)} for e in events])
    for e in events:
        key, p, ts = e.get("key") or "", e.get("parameters") or {}, e["timestamp"] / 1000
        if "CONNECTED" in key and "DISCONNECTED" not in key:
            c = p.get("CLIENT") or {}
            mac = (c.get("id") or "").lower()
            if mac and mac not in known:
                known.add(mac)
                label = c.get("name") or c.get("hostname") or mac
                con.execute("INSERT OR IGNORE INTO known_macs(mac,label,first_seen) VALUES(?,?,?)", (mac, label, ts))
                via = (p.get("DEVICE_WITH_PORT") or p.get("DEVICE") or {}).get("name", "")
                db.upsert_item(con, f"new-device:{mac}", "unifi", f"New device on the network: {label}",
                               f"MAC {mac} · IP {c.get('ip', '?')} · network {(p.get('NETWORK') or {}).get('name', '?')} · "
                               f"{via} {(p.get('WLAN') or p.get('SSID') or {}).get('name', '')}\n"
                               "Resolve once you know what it is (name it in UniFi).", "warning")
        elif e.get("category") in ("AUDIT", "SOFTWARE_UPDATES") or (
                e.get("category") != "SECURITY" and e.get("severity") in ("HIGH", "VERY_HIGH")):
            db.add_event(con, "unifi", render(e)[:200] or e.get("title_raw", key),
                         severity="warning" if e.get("severity") in ("HIGH", "VERY_HIGH") else "info",
                         ts=ts, dedupe=f"ue:{e.get('id')}")


PRIV_GROUP_EVENTS = {"4728", "4732", "4756", "4729", "4733", "4757"}


def windows(con, start, end):
    w = mod("windows")
    if not w:
        return
    for r in vl("type:winevt EventID:in(1102,4720,4740,4728,4732,4756,4729,4733,4757,4719,4739)", start, end):
        eid, host, ts = str(r.get("EventID")), r.get("hostname"), vl_ts(r)
        msg = (r.get("Message") or r.get("_msg") or "")[:500]
        if eid == "1102":
            db.upsert_item(con, f"seclog-cleared:{host}:{r['_time']}", "windows", f"Security log CLEARED on {host}",
                           msg, "critical")
        elif eid == "4720":
            db.upsert_item(con, f"user-created:{r['_time']}", "windows", f"AD user created (on {host})", msg, "warning")
        elif eid in ("4719", "4739"):
            db.upsert_item(con, f"policy-change:{eid}:{r['_time']}", "windows",
                           f"{'Audit' if eid == '4719' else 'Domain'} policy changed on {host}", msg, "warning")
        elif eid == "4740":
            db.add_event(con, "windows", "Account lockout", severity="warning", ts=ts, detail=msg,
                         dedupe=f"4740:{r['_time']}")
        elif eid in PRIV_GROUP_EVENTS:
            db.add_event(con, "windows", "Security group membership changed", severity="warning", ts=ts,
                         detail=msg, dedupe=f"{eid}:{r['_time']}")
    for r in vl("type:winevt EventID:4625 | stats by (hostname) count() n", start, end):
        n = int(r["n"])
        db.add_event(con, "windows", f"Failed Windows logons on {r['hostname']}", severity="info",
                     dedupe=f"4625:{r['hostname']}:{start}")
        if n >= int(w.get("fail_threshold") or 30):
            db.upsert_item(con, f"win-bruteforce:{r['hostname']}", "windows",
                           f"{n} failed Windows logons on {r['hostname']}",
                           "Burst of 4625 events in one check window. Logs: "
                           f"type:winevt EventID:4625 hostname:{r['hostname']}", "warning")
    for r in vl("type:winevt EventID:4624 LogonType:10", start, end):
        db.add_event(con, "windows", f"RDP logon {r.get('TargetUserName', '?')} → {r.get('hostname')}",
                     ts=vl_ts(r), dedupe=f"rdp:{r['_time']}:{r.get('hostname')}")


def rdap_expiry(domain):
    r = httpx.get(f"https://rdap.org/domain/{domain}", follow_redirects=True, timeout=20)
    r.raise_for_status()
    ev = next(e for e in r.json().get("events", []) if e.get("eventAction") == "expiration")
    return dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00")).timestamp()


def tls_expiry(con, start, end):
    """TLS certs, registered domains (RDAP, once a day) and manual dates (config + added on the board).
    Everything lands in kv 'expiries' for the Infra tab; < expiry.warn_days raises an item."""
    ex = mod("expiry")
    if not ex:
        return
    active, cards = set(), []
    warn_days = int(ex.get("warn_days") or 30)

    def check(key, name, kind, exp, note=""):
        days = (exp - time.time()) / 86400
        cards.append({"key": key, "name": name, "kind": kind, "expires": exp, "days": days, "note": note})
        if days < warn_days:
            active.add(key)
            what = f"Certificate for {name}" if kind == "tls" else name
            db.upsert_item(con, key, "expiry", f"{what} expires in {max(0, int(days))} days",
                           note or f"expires {iso(exp)}", "error" if days < 7 else "warning", kind="condition")

    for target in db.targets(con, "tls"):
        host, port, sni = target["host"], int(target.get("port") or 443), target.get("sni") or target["host"]
        key = f"tls:{sni}:{port}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=sni) as t:
                der = t.getpeercert(binary_form=True)
            out = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-enddate"], input=der,
                                 capture_output=True, timeout=10)
            end_s = out.stdout.decode().strip().split("=", 1)[1]
            exp = dt.datetime.strptime(end_s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc).timestamp()
        except Exception as e:
            active.add(key)
            db.upsert_item(con, key, "expiry", f"Can't check certificate on {sni}:{port}", str(e)[:200], "info",
                           kind="condition")
            cards.append({"key": key, "name": sni, "kind": "tls", "expires": None, "days": None, "note": str(e)[:80]})
            continue
        check(key, sni, "tls", exp, f"{host}:{port}")

    cache = db.kv_get(con, "domain_expiry", {})
    for domain in ex.get("domains") or []:
        c = cache.get(domain) or {}
        if time.time() - c.get("at", 0) > 86400:
            try:
                c = {"at": time.time(), "exp": rdap_expiry(domain)}
            except Exception:
                c = {**c, "at": time.time() - 86400 + 3600}  # retry in an hour, keep the last good date
            cache[domain] = c
        if c.get("exp"):
            check(f"domain:{domain}", f"Domain {domain}", "domain", c["exp"], "Renew at the registrar.")
    db.kv_set(con, "domain_expiry", cache)

    for m in db.manual_expiries(con):
        check(f"manual:{m['name']}", m["name"], "manual", dt.datetime.fromisoformat(str(m["expires"])).timestamp(),
              m.get("note", ""))
    cards.sort(key=lambda c: c["days"] if c["days"] is not None else -1)
    db.kv_set(con, "expiries", cards)
    db.clear_conditions(con, "expiry", active)


def local_disk(con, start, end):
    """Disk under the board's data volume (VictoriaLogs normally shares it)."""
    path = section("victorialogs").get("disk_path") or str(DATA)
    total, used, _ = shutil.disk_usage(path)
    pct = used / total * 100
    active = set()
    if pct >= 80:
        active.add("disk:logwatch")
        db.upsert_item(con, "disk:logwatch", "logwatch-disk", f"Log disk {pct:.0f}% full",
                       f"{used / 2**30:.1f} of {total / 2**30:.1f} GB used. VictoriaLogs drops the oldest logs at its "
                       "size cap (victorialogs.max_disk); grow the disk or lower the cap/retention.",
                       "warning", kind="condition")
    db.clear_conditions(con, "logwatch-disk", active)


def trivy(con, start, end):
    """Results written weekly by the worker's image scan (see trivy.py)."""
    if not mod("trivy"):
        return
    p = DATA / "trivy.json"
    if not p.exists():
        return
    data = json.loads(p.read_text())
    if db.kv_get(con, "trivy_seen", 0) >= data["generated"]:
        return
    active = set()
    for f in data["findings"]:
        key = f"trivy:{f['host']}:{f['target']}"
        active.add(key)
        db.upsert_item(con, key, "trivy",
                       f"{f['crit']} critical / {f['high']} high fixable CVEs: {f['target']} on {f['host']}",
                       f["detail"], "error" if f["crit"] else "warning", kind="condition")
    for e in data.get("errors", []):
        db.add_event(con, "trivy", f"Scan error: {e[:120]}", severity="info", dedupe=f"trivyerr:{data['generated']}:{e[:80]}")
    db.clear_conditions(con, "trivy", active)
    db.kv_set(con, "trivy_seen", data["generated"])


def top_domains(con, start, end):
    """Hourly: top looked-up domains per client from the Windows DNS server log."""
    dns = (mod("windows") or {}).get("dns") or {}
    if not dns.get("enabled") or time.time() - db.kv_get(con, "top_domains_at", 0) < 3600:
        return
    rows = vl("type:dns | stats by (client, qname) count() n | sort by (n desc) | limit 3000",
              iso(time.time() - 7 * 86400), end)
    per = {}
    skip = re.compile(dns.get("noise_regex") or r"$^", re.I)
    for r in rows:
        q = r.get("qname", "")
        if skip.search(q):
            continue
        per.setdefault(r.get("client", "?"), []).append(q)
    names = db.kv_get(con, "client_names", {})
    out = {}
    for client, qs in sorted(per.items(), key=lambda kv: -len(kv[1])):
        if client not in names:
            try:
                names[client] = socket.gethostbyaddr(client)[0].split(".")[0].upper()
            except OSError:
                names[client] = client
        out[names[client]] = qs[:8]
    db.kv_set(con, "client_names", names)
    db.kv_set(con, "top_domains", dict(list(out.items())[:20]))
    db.kv_set(con, "top_domains_at", time.time())


CROWDSEC = mod("crowdsec") or {}
CS_TEST_NET = ipaddress.ip_network("203.0.113.0/24")  # documentation range, used for bouncer tests


def cs_json(row):
    try:
        return json.loads(row.get("_msg", "").strip())
    except ValueError:
        return None


def cs_short(scenario):
    return re.sub(r"^crowdsecurity/(http-)?", "", scenario or "?")


def cs_test_ip(ip):
    try:
        return ipaddress.ip_address(ip or "") in CS_TEST_NET
    except ValueError:
        return False


def crowdsec(con, start, end):
    """CrowdSec on the edge nodes: heartbeat health (remote/crowdsec/health.sh), bans/WAF blocks → events."""
    if not CROWDSEC:
        return
    active = set()
    beats = {}
    for r in vl("app_name:crowdsec-health", iso(time.time() - 1200), end, limit=200):
        d = cs_json(r)
        name = (d or {}).get("host") or r.get("hostname")
        if d and vl_ts(r) > beats.get(name, (0, None))[0]:
            beats[name] = (vl_ts(r), d)
    status = []
    for h in CROWDSEC.get("hosts") or []:
        name = h["name"]
        ts, d = beats.get(name, (0, None))
        problems = []
        checks = {"crowdsec": bool((d or {}).get("crowdsec")), "lapi": bool((d or {}).get("lapi"))}
        if d is None:
            problems.append("no heartbeat for 20 min (host down, timer stopped or log forwarding broken)")
        else:
            if not d.get("crowdsec") or not d.get("lapi"):
                problems.append("CrowdSec engine/LAPI is down: nothing new gets banned")
            pull = d.get("bouncer_last_pull") or ""
            try:
                age = ts - dt.datetime.fromisoformat(pull[:19] + "+00:00").timestamp()  # vs the heartbeat, not now: pulled logs arrive late
            except ValueError:
                age = 1e9
            if age > 600:
                problems.append("bouncer hasn't pulled decisions for 10+ min: bans aren't enforced")
            if d.get("waf") is not None:
                checks["waf"] = bool(d["waf"])
                if not d["waf"]:
                    problems.append("WAF (AppSec) listener is down: requests pass uninspected")
            for c, up in (d.get("containers") or {}).items():
                checks[c] = bool(up)
                if not up:
                    problems.append(f"container {c} is not running")
        if problems:
            key = f"crowdsec-health:{name}"
            active.add(key)
            db.upsert_item(con, key, "crowdsec", f"Edge protection degraded on {name}", "; ".join(problems),
                           "error", kind="condition")
        status.append({"name": name, "ok": not problems, "capi": (d or {}).get("capi", 0),
                       "local": sum(v for k, v in ((d or {}).get("decisions") or {}).items() if k != "CAPI"),
                       "seen": ts, "web": bool(h.get("web")), "problems": problems, "checks": checks,
                       "version": (d or {}).get("version"), "bouncer_pull": (d or {}).get("bouncer_last_pull"),
                       "bans": [b for b in ((d or {}).get("bans") or []) if not cs_test_ip(b.get("ip"))]})
    db.clear_conditions(con, "crowdsec", active)

    # new bans / WAF blocks in this window → events; CVE virtual-patch hits → one item per rule
    for r in vl("app_name:crowdsec-event", start, end, limit=2000):
        e = cs_json(r)
        if not e or not e.get("ip") or cs_test_ip(e.get("ip")):
            continue
        host, meta = r.get("hostname", "?"), e.get("meta") or {}
        sc = e.get("scenario", "")
        if e.get("decision"):
            db.add_event(con, "crowdsec", f"Banned on {host}: {cs_short(sc)}", severity="info",
                         ts=vl_ts(r), dedupe=f"csban:{host}:{e['ip']}:{e.get('ts')}")
        else:
            db.add_event(con, "crowdsec", f"WAF blocked on {host}", severity="info",
                         ts=vl_ts(r), dedupe=f"cswaf:{host}:{e['ip']}:{e.get('ts')}:{sc[:40]}")
        if "vpatch" in sc or re.search(r"CVE-\d{4}-\d+", sc, re.I):
            db.upsert_item(con, f"crowdsec-vpatch:{sc}", "crowdsec", f"Exploit attempt blocked: {cs_short(sc)}",
                           f"Latest: {e['ip']} ({e.get('cn') or '?'}, {e.get('as') or '?'}) → "
                           f"{meta.get('target_fqdn', host)}{meta.get('uri', '')}. Blocked by the WAF before reaching "
                           "the backend. Check you're patched for it, then Resolve (or Mute the rule).", "warning")

    recent = []
    for r in vl("app_name:crowdsec-event | sort by (_time desc)", iso(time.time() - 86400), end, limit=300):
        e = cs_json(r)
        if not e or cs_test_ip(e.get("ip")):
            continue
        meta = e.get("meta") or {}
        recent.append({"ts": vl_ts(r), "host": r.get("hostname", "?"), "ip": e.get("ip"), "cn": e.get("cn"),
                       "as": e.get("as"), "what": cs_short(e.get("scenario")),
                       "action": f"ban {e['duration']}" if e.get("decision") else "blocked",
                       "target": f"{meta.get('target_fqdn', '')}{meta.get('uri') or meta.get('http_path', '')}"[:80]})
    hour0 = int(time.time() // 3600) * 3600 - 23 * 3600
    hourly = {"ban": [0] * 24, "blocked": [0] * 24}
    for x in recent:
        i = int((x["ts"] - hour0) // 3600)
        if 0 <= i < 24:
            hourly["blocked" if x["action"] == "blocked" else "ban"][i] += 1
    db.kv_set(con, "crowdsec", {"status": status, "recent": recent[:40], "hourly": hourly, "hour0": hour0,
                                 "bans_24h": sum(1 for x in recent if x["action"] != "blocked"),
                                 "blocks_24h": sum(1 for x in recent if x["action"] == "blocked")})


# --- infra status (Infra tab) -----------------------------------------------------------------

PVE = mod("proxmox") or {}


def pve_get(path):
    tok = secret("PROXMOX_TOKEN")
    if not tok:
        raise RuntimeError("PROXMOX_TOKEN missing in secrets.env")
    r = httpx.get(f"{PVE['url'].rstrip('/')}/api2/json{path}", headers={"Authorization": f"PVEAPIToken={tok}"},
                  verify=bool(PVE.get("verify_tls", False)), timeout=60)
    r.raise_for_status()
    return r.json()["data"]


def proxmox(con, start, end):
    """Cluster nodes + guests via a read-only PVEAuditor token; failed vzdump jobs in 24h → item."""
    if not PVE:
        return
    res = pve_get("/cluster/resources")
    guests = [{"name": r.get("name") or str(r["vmid"]), "vmid": r["vmid"], "type": "VM" if r["type"] == "qemu" else "CT",
               "node": r.get("node"), "running": r.get("status") == "running"}
              for r in res if r["type"] in ("qemu", "lxc") and not r.get("template")]
    nodes = {}
    for r in res:
        if r["type"] == "node":
            nodes[r["node"]] = {"name": r["node"], "online": r.get("status") == "online",
                                "cpu": r.get("cpu", 0), "mem": r.get("mem", 0), "maxmem": r.get("maxmem", 1),
                                "uptime": r.get("uptime", 0), "vm_up": 0, "vm_down": 0, "ct_up": 0, "ct_down": 0,
                                "storage": []}
    for r in res:
        n = nodes.get(r.get("node"))
        if not n:
            continue
        if r["type"] in ("qemu", "lxc") and not r.get("template"):
            n[f"{'vm' if r['type'] == 'qemu' else 'ct'}_{'up' if r.get('status') == 'running' else 'down'}"] += 1
        elif r["type"] == "storage" and r.get("maxdisk") and r.get("status") == "available":
            if r.get("shared") and any(x["storage"] == r["storage"] for m in nodes.values() for x in m["storage"]):
                continue  # shared storage: show once
            n["storage"].append({"storage": r["storage"], "used": r.get("disk", 0), "max": r["maxdisk"]})
    active = set()
    for n in nodes.values():
        if not n["online"]:
            key = f"pve-node:{n['name']}"
            active.add(key)
            db.upsert_item(con, key, "proxmox", f"Proxmox node {n['name']} is offline",
                           "The cluster reports the node offline. Check its power and network.", "critical", kind="condition")
        for st in n["storage"]:
            pct = st["used"] / st["max"] * 100
            if pct >= float(PVE.get("storage_warn_pct") or 85):
                key = f"pve-storage:{n['name']}:{st['storage']}"
                active.add(key)
                db.upsert_item(con, key, "proxmox", f"Storage {st['storage']} on {n['name']} is {pct:.0f}% full",
                               f"{st['used'] / 2**30:.0f} of {st['max'] / 2**30:.0f} GiB used", "warning", kind="condition")
    failed = []
    for t in pve_get("/cluster/tasks"):
        if t.get("type") == "vzdump" and t.get("starttime", 0) > time.time() - 86400 and t.get("status") not in (None, "OK", ""):
            failed.append({"node": t.get("node"), "id": t.get("id") or "all", "status": t.get("status"),
                           "ts": t.get("starttime")})
            db.upsert_item(con, f"pve-backup:{t.get('upid')}", "proxmox",
                           f"Backup failed on {t.get('node')}: {t.get('id') or 'job'}",
                           f"{t.get('status')}\nTask {t.get('upid')}. See Datacenter → Tasks in Proxmox.", "error")
    db.clear_conditions(con, "proxmox", active)
    db.kv_set(con, "proxmox", {"at": time.time(), "nodes": sorted(nodes.values(), key=lambda n: n["name"]),
                               "guests": sorted(guests, key=lambda g: g["vmid"]), "backups_failed": failed})


def backups(con, start, end):
    """Backup jobs, newest backup per guest, guests no job covers. Items: no jobs / uncovered guests / stale backups."""
    if not PVE or not (PVE.get("backups", True)):
        return
    stale_h = float(PVE.get("backup_stale_hours") or 48)
    pv = db.kv_get(con, "proxmox") or {}
    guests = {g["vmid"]: dict(g, last=None, size=None, count=0) for g in pv.get("guests") or []}
    jobs = [{"id": j.get("id"), "enabled": j.get("enabled", 1) not in (0, "0"), "schedule": j.get("schedule") or j.get("starttime"),
             "storage": j.get("storage"), "all": bool(j.get("all")), "vmid": j.get("vmid") or "",
             "next": j.get("next-run")} for j in pve_get("/cluster/backup")]
    seen_shared = set()
    for st in pve_get("/storage"):
        if "backup" not in (st.get("content") or ""):
            continue
        for n in [x["name"] for x in pv.get("nodes") or [] if x["online"]]:
            if st.get("shared") and st["storage"] in seen_shared:
                break
            try:
                items = pve_get(f"/nodes/{n}/storage/{st['storage']}/content?content=backup")
            except httpx.HTTPStatusError:
                continue  # storage not on this node / not active
            seen_shared.add(st["storage"])
            for b in items:
                g = guests.get(b.get("vmid"))
                if g is None:
                    continue
                g["count"] += 1
                if (b.get("ctime") or 0) > (g["last"] or 0):
                    g["last"], g["size"], g["where"] = b["ctime"], b.get("size"), st["storage"]
    uncovered = {g["vmid"] for g in pve_get("/cluster/backup-info/not-backed-up")}
    for g in guests.values():
        g["covered"] = g["vmid"] not in uncovered
    active = set()
    if not [j for j in jobs if j["enabled"]]:
        active.add("backup:no-jobs")
        db.upsert_item(con, "backup:no-jobs", "backups", f"No Proxmox backup jobs: {len(uncovered)} guests never backed up",
                       "Datacenter → Backup has no enabled job. Add a vzdump job covering the guests.",
                       "warning", kind="condition")
    elif uncovered:
        active.add("backup:uncovered")
        names = ", ".join(sorted(guests[v]["name"] for v in uncovered if v in guests))
        db.upsert_item(con, "backup:uncovered", "backups", f"{len(uncovered)} guests aren't in any backup job",
                       names, "warning", kind="condition")
    for g in guests.values():
        if g["covered"] and (not g["last"] or g["last"] < time.time() - stale_h * 3600):
            key = f"backup:stale:{g['name']}"
            active.add(key)
            db.upsert_item(con, key, "backups", f"No backup of {g['name']} in {stale_h:g} h",
                           f"{g['type']} {g['vmid']} on {g['node']} is in a backup job but the newest backup is "
                           f"{'missing' if not g['last'] else dt.datetime.fromtimestamp(g['last']).strftime('%Y-%m-%d %H:%M')}.",
                           "warning", kind="condition")
    db.clear_conditions(con, "backups", active)
    db.kv_set(con, "backups", {"at": time.time(), "jobs": jobs,
                               "guests": sorted(guests.values(), key=lambda g: (g["covered"], g["last"] or 0, g["vmid"]))})


def disks(con, start, end):
    """SMART health + wearout per node disk, ZFS pool health, storage fill trend. Hourly."""
    if not PVE or not PVE.get("disks", True) or time.time() - (db.kv_get(con, "disks") or {}).get("at", 0) < 3300:
        return
    pv = db.kv_get(con, "proxmox") or {}
    out, active = [], set()
    for n in [x for x in pv.get("nodes") or [] if x["online"]]:
        for d in pve_get(f"/nodes/{n['name']}/disks/list"):
            wear = d.get("wearout")
            wear = int(wear) if str(wear).isdigit() else None  # PVE: % life left (100 = new)
            row = {"node": n["name"], "dev": d.get("devpath"), "model": (d.get("model") or d.get("vendor") or "").strip(),
                   "serial": d.get("serial"), "type": d.get("type"), "size": d.get("size"), "health": d.get("health") or "UNKNOWN",
                   "wear": wear, "used": d.get("used") or ""}
            out.append(row)
            name = f"{n['name']} {row['dev']}"
            if row["health"] not in ("PASSED", "OK", "UNKNOWN"):
                key = f"disk:smart:{n['name']}:{row['dev']}"
                active.add(key)
                db.upsert_item(con, key, "disks", f"SMART {row['health']} on {name}",
                               f"{row['model']} (serial {row['serial']}). Plan a replacement; check `smartctl -a {row['dev']}`.",
                               "error", kind="condition")
            if wear is not None and wear <= 10:
                key = f"disk:wear:{n['name']}:{row['dev']}"
                active.add(key)
                db.upsert_item(con, key, "disks", f"SSD {name} is {100 - wear}% worn",
                               f"{row['model']}: {wear}% life left.", "warning", kind="condition")
        pools = []
        for z in pve_get(f"/nodes/{n['name']}/disks/zfs"):
            pools.append({"node": n["name"], "name": z["name"], "health": z.get("health"), "size": z.get("size"),
                          "alloc": z.get("alloc"), "frag": z.get("frag")})
            if z.get("health") != "ONLINE":
                key = f"disk:zfs:{n['name']}:{z['name']}"
                active.add(key)
                db.upsert_item(con, key, "disks", f"ZFS pool {z['name']} on {n['name']} is {z.get('health')}",
                               "Run `zpool status -v` on the node.", "critical", kind="condition")
        out.extend(dict(p, kind="zfs") for p in pools)
    # storage fill history (hourly, 30 d) → linear trend over the last 7 days
    now = time.time()
    hist = db.kv_get(con, "storage_hist") or {}
    trend = []
    for n in pv.get("nodes") or []:
        for st in n["storage"]:
            k = f"{n['name']}/{st['storage']}"
            h = [p for p in hist.get(k, []) if p[0] > now - 30 * 86400] + [[round(now), st["used"] / st["max"] * 100]]
            hist[k] = h
            pts = [p for p in h if p[0] > now - 7 * 86400]
            days, slope = None, 0
            if len(pts) >= 24 and pts[-1][0] - pts[0][0] > 86400:
                mx = sum(p[0] for p in pts) / len(pts)
                my = sum(p[1] for p in pts) / len(pts)
                var = sum((p[0] - mx) ** 2 for p in pts)
                slope = sum((p[0] - mx) * (p[1] - my) for p in pts) / var if var else 0  # %/s
                if slope > 0:
                    days = (100 - pts[-1][1]) / slope / 86400
            trend.append({"key": k, "pct": h[-1][1], "days": days, "pts": [[p[0], round(p[1], 1)] for p in h[-24 * 7:]]})
            if days is not None and days < 14:
                key = f"disk:fill:{k}"
                active.add(key)
                db.upsert_item(con, key, "disks", f"Storage {k} full in ~{max(days, 0):.0f} days",
                               f"{h[-1][1]:.0f}% used, growing ~{slope * 86400:.1f}%/day over the last week.",
                               "warning", kind="condition")
    db.kv_set(con, "storage_hist", hist)
    db.clear_conditions(con, "disks", active)
    db.kv_set(con, "disks", {"at": now, "disks": [d for d in out if d.get("kind") != "zfs"],
                             "pools": [d for d in out if d.get("kind") == "zfs"], "trend": trend})


def wan(con, start, end):
    """UniFi gateway health (WAN, latency, clients) + IPS hits in 24h from the stored flows."""
    if not UNIFI or not UNIFI.get("wan", True):
        return
    h = {s["subsystem"]: s for s in unifi_get("api/s/{site}/stat/health").get("data") or []}
    w, www, lan, wl = h.get("wan", {}), h.get("www", {}), h.get("lan", {}), h.get("wlan", {})
    ws = (w.get("uptime_stats") or {}).get("WAN") or {}
    gw = w.get("gw_system-stats") or {}
    sigs = vl("type:unifi_flow ips_signature:* | stats by (ips_signature) count() n | sort by (n desc) | limit 5",
              iso(time.time() - 86400), end)
    ips_24h = sum(int(x.get("n", 0)) for x in vl("type:unifi_flow ips_signature:* | stats count() n",
                                                  iso(time.time() - 86400), end))
    up = w.get("status") == "ok"
    out = {"at": time.time(), "up": up, "isp": w.get("isp_name"), "wan_ip": w.get("wan_ip"),
           "latency": www.get("latency") or ws.get("latency_average"), "availability": ws.get("availability"),
           "drops": www.get("drops"), "down": www.get("xput_down"), "upl": www.get("xput_up"),
           "speedtest": {"down": www.get("xput_down"), "up": www.get("xput_up"), "ping": www.get("speedtest_ping"),
                         "at": www.get("speedtest_lastrun")},
           "clients": (lan.get("num_user") or 0) + (wl.get("num_user") or 0), "guests": (wl.get("num_guest") or 0),
           "gw_cpu": gw.get("cpu"), "gw_mem": gw.get("mem"), "gw_version": w.get("gw_version"),
           "gw_uptime": gw.get("uptime") or w.get("uptime"),
           "ips_24h": ips_24h, "ips_top": [{"sig": x.get("ips_signature"), "n": int(x.get("n", 0))} for x in sigs]}
    db.kv_set(con, "wan", out)
    if not up:
        db.upsert_item(con, "wan:down", "wan", f"WAN is down on {GW}",
                       f"UniFi health reports WAN status {w.get('status')!r}.", "critical", kind="condition")
    db.clear_conditions(con, "wan", {"wan:down"} if not up else set())


def action1(con, start, end):
    """Patch status per endpoint (missing updates, reboot pending). Hourly."""
    a = mod("action1")
    if not a or time.time() - (db.kv_get(con, "action1") or {}).get("at", 0) < 3300:
        return
    base, org = (a.get("base_url") or "https://app.action1.com/api/3.0").rstrip("/"), secret("ACTION1_ORG_ID")
    tok = httpx.post(f"{base}/oauth2/token", data={"client_id": secret("ACTION1_CLIENT_ID"),
                                                   "client_secret": secret("ACTION1_CLIENT_SECRET")}, timeout=30)
    tok.raise_for_status()
    hdr = {"Authorization": f"Bearer {tok.json()['access_token']}"}
    eps = httpx.get(f"{base}/endpoints/managed/{org}?limit=200", headers=hdr, timeout=60).json()["items"]
    rows = []
    for ep in eps:
        miss = httpx.get(f"{base}/endpoints/managed/{org}/{ep['id']}/missing-updates?limit=200", headers=hdr,
                         timeout=60).json().get("items") or []
        ups = []
        for x in miss:
            v = (x.get("versions") or [{}])[0]
            sev = v.get("security_severity") or "Unspecified"
            sec = v.get("update_type") == "Security Updates"
            lvl = {"Critical": "critical", "Important": "important"}.get(sev) or ("security" if sec or sev in ("Moderate", "Low") else "other")
            cves = [c.strip() for c in str(v.get("security_CVE") or "").replace(";", ",").split(",") if c.strip().upper().startswith("CVE-")]
            kb = x.get("kb_number") or ""
            ups.append({"name": x.get("name"), "kb": "" if kb in ("None", "Unknown") else kb, "lvl": lvl, "sev": sev,
                        "type": v.get("update_type") or "", "cve": cves[0] if cves else "", "ncve": len(cves),
                        "reboot": bool(x.get("reboot_needed")), "sla": v.get("update_sla_status") or "",
                        "ver": v.get("version") or ""})
        order = {"critical": 0, "important": 1, "security": 2, "other": 3}
        ups.sort(key=lambda u: (order[u["lvl"]], u["sla"] != "Overdue", u["name"] or ""))
        cnt = {k: sum(u["lvl"] == k for u in ups) for k in order}
        rows.append({"name": ep["name"], "online": ep.get("status") == "Connected", "os": ep.get("platform"),
                     "reboot": ep.get("reboot_required") == "Yes", "missing": len(miss),
                     "last_seen": ep.get("last_seen"), **cnt,
                     "overdue": sum(u["sla"] == "Overdue" for u in ups), "updates": ups[:40]})
    rows.sort(key=lambda r: (-r["critical"], -r["important"], -r["security"], -r["missing"], not r["reboot"], r["name"]))
    db.kv_set(con, "action1", {"at": time.time(), "endpoints": rows})


# --- Wazuh: agents + SCA + vulnerabilities (manager API / indexer), alerts into the log store ------------------------

def _wz_api(w):
    """Wazuh manager API (:55000): JWT from basic auth, valid 15 min by default."""
    base = (w.get("api_url") or "").rstrip("/")
    verify = bool(w.get("verify_tls", False))
    r = httpx.post(f"{base}/security/user/authenticate", auth=(secret("WAZUH_API_USER"), secret("WAZUH_API_PASSWORD")),
                   verify=verify, timeout=30)
    r.raise_for_status()
    hdr = {"Authorization": f"Bearer {r.json()['data']['token']}"}

    def get(path, **params):
        x = httpx.get(f"{base}{path}", headers=hdr, params=params, verify=verify, timeout=60)
        x.raise_for_status()
        return x.json().get("data") or {}
    return get


def _wz_idx(w):
    """Wazuh indexer (OpenSearch :9200) search, or None when no indexer is configured."""
    base = (w.get("indexer_url") or "").rstrip("/")
    if not base:
        return None
    auth, verify = (secret("WAZUH_INDEXER_USER"), secret("WAZUH_INDEXER_PASSWORD")), bool(w.get("verify_tls", False))

    def search(index, body):
        x = httpx.post(f"{base}/{index}/_search", json=body, auth=auth, verify=verify, timeout=90)
        x.raise_for_status()
        return x.json()
    return search


WZ_SEV = ["critical", "high", "medium", "low"]


def wazuh(con, start, end):
    """Agents (status, OS, SCA score, vulnerabilities, alerts 24h) for Hosts; alerts ≥ min level into the log store."""
    w = mod("wazuh")
    if not w:
        return
    idx = _wz_idx(w)
    st = db.kv_get(con, "wazuh") or {}
    if idx and (w.get("alerts") or "indexer") == "indexer":
        _wz_alerts(con, w, idx)
    if time.time() - st.get("at", 0) < 3300 and not st.get("err"):
        return _wz_items(con, w, st)  # agent/SCA/vuln view refreshes hourly; alerts every run
    get = _wz_api(w)
    info = get("/")
    agents = get("/agents", limit=2000, select="id,name,ip,status,os.name,os.platform,os.version,version,lastKeepAlive,group")
    rows = []
    for a in agents.get("affected_items") or []:
        osd = a.get("os") or {}
        rows.append({"id": a.get("id"), "name": a.get("name") or "", "ip": a.get("ip") or "", "status": a.get("status") or "",
                     "os": " ".join(x for x in (osd.get("name"), osd.get("version")) if x), "platform": osd.get("platform") or "",
                     "version": (a.get("version") or "").replace("Wazuh ", ""), "seen": a.get("lastKeepAlive") or "",
                     "groups": a.get("group") or [], "sca": [], "score": None,
                     **{k: 0 for k in WZ_SEV}, "cves": [], "alerts": 0, "alerts_hi": 0, "rules": []})
    by = {r["name"].lower(): r for r in rows}
    for r in rows:
        if r["status"] != "active":
            continue
        try:
            pol = get(f"/sca/{r['id']}").get("affected_items") or []
        except httpx.HTTPError:
            continue
        r["sca"] = [{"name": p.get("name"), "score": p.get("score"), "pass": p.get("pass"), "fail": p.get("fail"),
                     "total": p.get("total_checks"), "at": p.get("end_scan")} for p in pol]
        sc = [p["score"] for p in r["sca"] if isinstance(p.get("score"), (int, float))]
        r["score"] = round(sum(sc) / len(sc)) if sc else None
    if idx:
        vul = idx("wazuh-states-vulnerabilities-*", {"size": 0, "aggs": {"a": {"terms": {"field": "agent.name", "size": 2000},
                  "aggs": {"s": {"terms": {"field": "vulnerability.severity", "size": 8}}}}}})
        for b in vul.get("aggregations", {}).get("a", {}).get("buckets", []):
            r = by.get(str(b["key"]).lower())
            for s in (b.get("s") or {}).get("buckets", []) if r else []:
                k = str(s["key"]).lower()
                if k in WZ_SEV:
                    r[k] = s["doc_count"]
        top = idx("wazuh-states-vulnerabilities-*", {"size": 1000, "query": {"terms": {"vulnerability.severity": ["Critical", "High"]}},
                  "sort": [{"vulnerability.score.base": {"order": "desc", "unmapped_type": "float"}}],
                  "_source": ["agent.name", "vulnerability.id", "vulnerability.severity", "vulnerability.score.base", "package.name", "package.version"]})
        for h in top.get("hits", {}).get("hits", []):
            x = h.get("_source") or {}
            r = by.get(str((x.get("agent") or {}).get("name", "")).lower())
            if r is not None and len(r["cves"]) < 25:
                v, p = x.get("vulnerability") or {}, x.get("package") or {}
                r["cves"].append({"id": v.get("id"), "sev": str(v.get("severity", "")).lower(), "score": (v.get("score") or {}).get("base"),
                                  "pkg": p.get("name"), "ver": p.get("version")})
        hi = int(w.get("alert_item_level", 12))
        al = idx("wazuh-alerts-4.x-*", {"size": 0, "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-24h"}}},
                 {"range": {"rule.level": {"gte": int(w.get("min_level", 3))}}}]}},
                 "aggs": {"a": {"terms": {"field": "agent.name", "size": 2000}, "aggs": {
                     "hi": {"filter": {"range": {"rule.level": {"gte": hi}}}},
                     "r": {"terms": {"field": "rule.description", "size": 5}, "aggs": {"l": {"max": {"field": "rule.level"}}}}}}}})
        for b in al.get("aggregations", {}).get("a", {}).get("buckets", []):
            r = by.get(str(b["key"]).lower())
            if r is not None:
                r["alerts"], r["alerts_hi"] = b["doc_count"], (b.get("hi") or {}).get("doc_count", 0)
                r["rules"] = [{"d": x["key"], "n": x["doc_count"], "l": int((x.get("l") or {}).get("value") or 0)}
                              for x in (b.get("r") or {}).get("buckets", [])]
    rows.sort(key=lambda r: (r["status"] == "active", -r["critical"], -r["high"], -r["alerts_hi"], r["name"]))
    st = {"at": time.time(), "manager": {"version": info.get("api_version"), "host": info.get("hostname")},
          "indexer": bool(idx), "agents": rows}
    db.kv_set(con, "wazuh", st)
    _wz_items(con, w, st)


def _wz_items(con, w, st):
    keep = set()
    for r in st.get("agents") or []:
        if r["id"] == "000":
            continue
        if r["status"] == "disconnected":
            k = f"wazuh:agent:{r['name']}"
            keep.add(k)
            db.upsert_item(con, k, "wazuh", f"Wazuh agent {r['name']} is disconnected",
                           f"Last keep-alive {r['seen'] or 'unknown'}. Check the wazuh-agent service on the host.", "warning", kind="condition")
        if r["critical"] and w.get("vuln_items", True):
            k = f"wazuh:vuln:{r['name']}"
            keep.add(k)
            top = ", ".join(c["id"] for c in r["cves"] if c["sev"] == "critical")[:300]
            db.upsert_item(con, k, "wazuh", f"{r['critical']} critical vulnerabilit{'y' if r['critical'] == 1 else 'ies'} on {r['name']}",
                           f"Wazuh vulnerability detection. {top}", "info", kind="condition")
    db.clear_conditions(con, "wazuh", keep)


def _wz_alerts(con, w, idx):
    """New alerts since the last run → VictoriaLogs (type:wazuh); level ≥ alert_item_level also raises a board item."""
    cur = db.kv_get(con, "wazuh_cursor") or {}
    since = cur.get("ts") or iso(time.time() - 900)
    seen = set(cur.get("ids") or [])
    lo, hi = int(w.get("min_level", 3)), int(w.get("alert_item_level", 12))
    res = idx("wazuh-alerts-4.x-*", {"size": 5000, "sort": [{"timestamp": "asc"}],
              "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": since}}}, {"range": {"rule.level": {"gte": lo}}}]}}})
    rows, last, ids = [], since, seen
    for h in res.get("hits", {}).get("hits", []):
        if h["_id"] in seen:
            continue
        a = h.get("_source") or {}
        rule, ag, d = a.get("rule") or {}, a.get("agent") or {}, a.get("data") or {}
        ts = a.get("timestamp") or a.get("@timestamp")
        if ts != last:
            last, ids = ts, set()
        ids.add(h["_id"])
        lvl = int(rule.get("level") or 0)
        try:  # Wazuh writes +0000 offsets; VictoriaLogs wants RFC 3339
            t = dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except (TypeError, ValueError):
            t = ts
        rows.append({"time": t, "type": "wazuh", "hostname": ag.get("name") or "wazuh", "app": "wazuh",
                     "msg": f"[{lvl}] {rule.get('description', '')}" + (f" · {a['full_log'][:2000]}" if a.get("full_log") else ""),
                     "level": lvl, "rule_id": str(rule.get("id", "")), "groups": ",".join(rule.get("groups") or []),
                     "mitre": ",".join((rule.get("mitre") or {}).get("id") or []), "agent_ip": ag.get("ip", ""),
                     "srcip": d.get("srcip", ""), "location": a.get("location", "")})
        if lvl >= hi:
            db.upsert_item(con, f"wazuh:alert:{rule.get('id')}:{ag.get('name')}", "wazuh",
                           f"Wazuh level {lvl}: {rule.get('description', '')[:120]} on {ag.get('name')}",
                           (a.get("full_log") or "")[:500], "error" if lvl >= 14 else "warning")
    vl_push(rows)
    db.kv_set(con, "wazuh_cursor", {"ts": last, "ids": sorted(ids)[-500:]})


def _alert_lines(path):
    """The alert file's text: an SMB path (//server/share/dir/file) with ALERTFILE_SMB_* secrets, or a local path."""
    if not path.startswith(("//", "\\\\")):
        return Path(path).read_text(errors="replace")
    import smbclient
    unc = "\\\\" + path.lstrip("/\\").replace("/", "\\")
    with smbclient.open_file(unc, mode="r", encoding="utf-8-sig", errors="replace", share_access="rwd",
                             username=secret("ALERTFILE_SMB_USER") or None,
                             password=secret("ALERTFILE_SMB_PASSWORD") or None) as f:
        return f.read()


def alertfile(con, start, end):
    """Alerts another system already writes, one JSON per line: {id, severity (Error|Warning|Info), source, message}.
    Only ids above the last one seen are read; Error/Warning become items, the rest events."""
    cfg = mod("alertfile")
    label = re.sub(r"[^\w.-]", "", str(cfg.get("source") or "alerts"))[:40] or "alerts"
    last_id = db.kv_get(con, "queue_last_id", None)
    rows = []
    for line in _alert_lines(str(cfg.get("path") or "")).splitlines():
        try:
            a = json.loads(line)
            a["id"] = int(a["id"])
        except (ValueError, KeyError, TypeError):
            continue
        rows.append(a)
    newest = max([a["id"] for a in rows] + [last_id or 0])
    if last_id is None and not cfg.get("import_existing"):  # first run: start from now, don't replay history
        db.kv_set(con, "queue_last_id", newest)
        return
    for a in rows:
        if a["id"] <= (last_id or 0):
            continue
        sev = {"error": "error", "critical": "critical", "warning": "warning"}.get(str(a.get("severity", "")).lower(), "info")
        src, msg = str(a.get("source") or label)[:60], str(a.get("message") or "")
        key_msg = re.sub(r"\(\d{4}-\d\d-\d\d[^)]*\)", "", msg)  # same alert on a new date = same item
        if sev == "info":
            db.add_event(con, label, f"{src}: {msg[:120]}", ts=time.time(), dedupe=f"q:{a['id']}")
        else:
            db.upsert_item(con, f"queue:{src}:{key_msg[:200]}", label, f"{src}: {msg[:140]}", msg[:2000], sev)
    db.kv_set(con, "queue_last_id", newest)


def todos(con, start, end):
    """Own to-dos: overdue → error, due within a day → warning."""
    now = time.time()
    for r in con.execute("SELECT key, due, severity FROM items WHERE kind='todo' AND state='open' AND due IS NOT NULL").fetchall():
        sev = "error" if r["due"] < now else ("warning" if r["due"] < now + 86400 else "info")
        if sev != r["severity"]:
            con.execute("UPDATE items SET severity=? WHERE key=?", (sev, r["key"]))


ALL = [pull, hosts, volume, linux, log_rules, unifi, windows, tls_expiry, local_disk, trivy, top_domains, crowdsec,
       proxmox, backups, disks, wan, action1, wazuh, alertfile, todos]
NEEDS = {pull: "pull", unifi: "unifi", windows: "windows", tls_expiry: "expiry", trivy: "trivy", crowdsec: "crowdsec",
         proxmox: "proxmox", backups: "proxmox", disks: "proxmox", wan: "unifi", action1: "action1", wazuh: "wazuh",
         alertfile: "alertfile"}
COLLECTORS = [c for c in ALL if c not in NEEDS or mod(NEEDS[c])]
if not (mod("windows") or {}).get("dns", {}).get("enabled"):
    COLLECTORS.remove(top_domains)


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    lock = open(DATA / "collect.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # scheduled run vs "Run checks now" button
    except BlockingIOError:
        return
    now = time.time()
    with db.connect() as con:
        start = db.kv_get(con, "window_end", now - 900)
        start_s, end_s = iso(start), iso(now)
        failed = set()
        runs = {}
        for c in COLLECTORS:
            t0 = time.time()
            try:
                c(con, start_s, end_s)
                con.commit()
                runs[c.__name__] = {"ok": True, "secs": round(time.time() - t0, 1)}
            except Exception as e:
                con.rollback()
                runs[c.__name__] = {"ok": False, "secs": round(time.time() - t0, 1), "err": f"{type(e).__name__}: {e}"[:200]}
                failed.add(f"collector:{c.__name__}")
                db.upsert_item(con, f"collector:{c.__name__}", "logwatch", f"Board check '{c.__name__}' is failing",
                               f"{type(e).__name__}: {e}"[:500], "info", kind="condition")
                traceback.print_exc(file=sys.stderr)
        db.clear_conditions(con, "logwatch", failed)
        db.kv_set(con, "window_end", now)
        db.kv_set(con, "last_collect", time.time())  # end time: a "Run checks" request made mid-run counts as served
        db.kv_set(con, "collectors", runs)
        db.prune(con)
    try:  # expired Edge WAF bans leave Cloudflare too (its lists have no expiry)
        if mod("waf"):
            import waf
            waf.sweep()
    except Exception:
        traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    main()
