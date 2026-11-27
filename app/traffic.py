#!/usr/bin/env python3
"""All edge traffic → VictoriaLogs (type:traffic). Run every minute by the worker (module "traffic").

Pulls new lines from every ssh.hosts entry with role "trafficpull" (remote/linux: logwatch-remote trafficpull tails
the files in that host's TRAFFIC_GLOBS), parses them and adds GeoIP country + ASN. Formats are detected per line:
Nginx Proxy Manager proxy logs, nginx "combined", and the nftables lw-conn/lw-drop log lines from
remote/linux/nft-traffic-log.sh.
Read state only advances after VictoriaLogs accepted the batch, so a failed run is retried, not lost.
"""
import base64
import datetime as dt
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor

import db
import remote
from common import vl_push
from geo import geo
from settings import mod, ssh_hosts

TC = mod("traffic") or {}
DNAT_MAP = {str(k): str(v) for k, v in (TC.get("dnat_map") or {}).items()}  # DNAT target → the internal address behind it
FAILS_TO_ALERT = 10                          # one run a minute → ~10 min of failures
BLOCK_STATUS = {str(s) for s in TC.get("block_status") or ["403", "429", "444"]}  # answered by the edge itself

NPM_RE = re.compile(r'^\[([^\]]+)\] (\S+) (\S+) (\S+) - (\S+) (\S+) (\S+) "(.*?)" \[Client ([^\]]+)\] \[Length (\d+)\] '
                    r'\[Gzip ([^\]]+)\] \[Sent-to ([^\]]+)\] "(.*?)" "(.*?)"$')
COMBINED_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-) "(.*?)" "(.*?)"(?: "?(\S+?)"?)?')
NFT_RE = re.compile(r"^(\S+)\s+(?:\S+\s+\S+:\s+)?(lw-conn|lw-drop): (.*)$")
KV_RE = re.compile(r"(\w+)=(\S*)")


def service_names():
    """(address, port) → name from config traffic.service_names ({"192.0.2.60:443": "Web"})."""
    out = {}
    for k, v in (TC.get("service_names") or {}).items():
        a, _, p = str(k).rpartition(":")
        if a and p.isdigit():
            out[(a.strip("[]"), int(p))] = str(v)
    return out


def http_row(node, ts, ip, meth, scheme, host, uri, st, up, length, ua, ref):
    action = "blocked" if up in ("-", "") and st in BLOCK_STATUS else "allowed"
    cn, asn = geo(ip)
    path = uri.split("?", 1)[0]
    return {"_time": ts, "node": node, "src": ip, "cn": cn, "as": asn, "proto": scheme, "target": host, "path": path[:300],
            "method": meth[:16], "status": st, "upstream": up, "bytes": int(length) if str(length).isdigit() else 0,
            "ua": ua[:300], "ref": "" if ref == "-" else ref[:300], "action": action, "what": f"{host}{path[:120]}",
            "_msg": f"{meth} {host}{uri[:200]} → {st} ({action})"}


def parse_npm(node, line):
    m = NPM_RE.match(line)
    if not m:
        return None
    t, _cache, up, st, meth, scheme, host, uri, ip, length, _gz, _to, ua, ref = m.groups()
    ts = dt.datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    return http_row(node, ts, ip, meth, scheme, host, uri, st, up, length, ua, ref)


def parse_combined(node, line):
    """nginx/Apache combined log; an optional trailing field is used as the vhost (log_format ... "$host")."""
    m = COMBINED_RE.match(line)
    if not m:
        return None
    ip, t, meth, uri, st, length, ref, ua, host = m.groups()
    ts = dt.datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    # combined has no upstream field: edge-answered statuses count as blocked
    return http_row(node, ts, ip, meth, "http", host or node, uri, st, "-" if st in BLOCK_STATUS else "+", length, ua, ref)


def parse_nft(node, line, ports):
    m = NFT_RE.match(line)
    if not m:
        return None
    t, kind, rest = m.groups()
    try:
        ts = dt.datetime.fromisoformat(t).timestamp()
    except ValueError:
        return None
    f = dict(KV_RE.findall(rest))
    ip, proto, dport = f.get("SRC", ""), (f.get("PROTO") or "?").lower(), f.get("DPT", "")
    if not ip:
        return None
    port = int(dport) if dport.isdigit() else 0
    if kind == "lw-conn":
        nip = DNAT_MAP.get(f.get("DST", ""), f.get("DST", ""))
        server = ports.get((nip, port)) or ""
        target, action = server or f"{nip}:{port}", "allowed"
    else:
        server, target, action = "", f"{node}:{port}", "dropped"
    cn, asn = geo(ip)
    return {"_time": ts, "node": node, "src": ip, "cn": cn, "as": asn, "proto": proto, "target": target, "path": "",
            "method": "", "status": "", "bytes": int(f.get("LEN") or 0), "action": action, "dport": port,
            "server": server, "what": target, "_msg": f"{proto.upper()} {ip} → {target} ({action})"}


def parse(node, line, ports):
    if line.startswith("["):
        return parse_npm(node, line)
    if "lw-conn:" in line or "lw-drop:" in line:
        return parse_nft(node, line, ports)
    return parse_combined(node, line)


def fetch(host, state):
    arg = base64.b64encode(json.dumps(state).encode()).decode() if state else "-"
    return remote.json_lines(host, f"trafficpull {arg}", timeout=45)


def main():
    hosts = [h["name"] for h in ssh_hosts("trafficpull")]
    if not TC or not hosts:
        return
    with db.connect() as con:
        states = {h: db.kv_get(con, f"traffic:{h}") or {} for h in hosts}
        ports = service_names()
    with ThreadPoolExecutor(len(hosts)) as ex:
        futs = {h: ex.submit(fetch, h, states[h]) for h in hosts}
    results = {}
    for h, f in futs.items():
        try:
            results[h] = f.result()
        except Exception as e:
            results[h] = e
    with db.connect() as con:
        active = set()
        for h, res in results.items():
            fails = db.kv_get(con, f"traffic_fail:{h}") or 0
            if not isinstance(res, Exception):
                try:
                    recs, bad = [], 0
                    for x in res[:-1]:
                        r = parse(h, x.get("line") or "", ports)
                        if r:
                            r["_time"] = dt.datetime.fromtimestamp(r["_time"], dt.timezone.utc).isoformat(timespec="milliseconds")
                            r["type"] = "traffic"
                            recs.append(r)
                        else:
                            bad += 1
                    vl_push(recs, stream="type,node", msg="_msg", time_field="_time")
                    db.kv_set(con, f"traffic:{h}", res[-1]["state"])
                    db.kv_set(con, f"traffic_stats:{h}", {"at": time.time(), "rows": len(recs), "unparsed": bad,
                                                          "backlog": bool(res[-1].get("trunc"))})
                    db.kv_set(con, f"traffic_fail:{h}", 0)
                    continue
                except Exception as e:
                    res = e
            fails += 1
            db.kv_set(con, f"traffic_fail:{h}", fails)
            if fails >= FAILS_TO_ALERT:
                key = f"traffic:{h}"
                active.add(key)
                db.upsert_item(con, key, "traffic", f"Can't pull traffic logs from {h}",
                               f"{type(res).__name__}: {res}"[:400] + f"\n{fails} failed pulls in a row. Check SSH from the "
                               "board to the host and that its /etc/logwatch-remote.conf enables trafficpull.",
                               "error", kind="condition")
        db.clear_conditions(con, "traffic", active)


if __name__ == "__main__":
    main()
