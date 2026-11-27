#!/usr/bin/env python3
"""Uptime probes. Run every minute by the worker.

HTTP/TCP/UDP/ICMP targets live in the board DB (targets table: add/edit them on the Status tab; config uptime.targets
seeds it the first time). Every probe lands in the uptime table; two failures in a row raise "<name> is down"
(unless in maintenance).
"""
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

import db
from settings import BOARD, mod

UPTIME = mod("uptime") or {}
OK_REDIRECT = [str(h).lower() for h in BOARD.get("ok_redirect_hosts") or []]
FAILS_TO_ALERT = int(UPTIME.get("fails_to_alert") or 2)


def _auth(t):
    a = t.get("auth") or {}
    if a.get("type") == "basic":
        return httpx.BasicAuth(a.get("user", ""), a.get("password", ""))
    return None


def http_request(t):
    """One HTTP request as the target describes it (method, headers, body, auth). Raises on transport errors."""
    to = httpx.Timeout(t.get("timeout", 30), connect=10)
    headers = {"User-Agent": "logwatch-uptime/1", **{str(k): str(v) for k, v in (t.get("headers") or {}).items()}}
    a = t.get("auth") or {}
    if a.get("type") == "bearer" and a.get("token"):
        headers["Authorization"] = f"Bearer {a['token']}"
    body = t.get("body") or None
    return httpx.request((t.get("method") or "GET").upper(), t["url"], timeout=to, verify=bool(t.get("verify")),
                         follow_redirects=bool(t.get("follow")), headers=headers, content=body.encode() if body else None, auth=_auth(t))


def judge_http(t, r):
    """(ok, why-not) for a response: expected codes (default: below 400 or an allowed redirect), then 'body contains'."""
    loc = r.headers.get("location", "").lower()
    ok = r.status_code in t["expect"] if t.get("expect") else (r.status_code < 400 or any(h in loc for h in OK_REDIRECT))
    if not ok:
        return False, f"HTTP {r.status_code}"
    want = t.get("contains")
    if want and want not in r.text:
        return False, f"HTTP {r.status_code}, body lacks “{want[:40]}”"
    return True, ""


def probe_http(t):
    # connect 10 s, read 30 s (or the target "timeout"); a timeout gets one retry before it counts as a failure
    for attempt in (1, 2):
        t0 = time.time()
        try:
            r = http_request(t)
            break
        except httpx.TimeoutException as e:
            if attempt == 2:
                return False, None, None, f"{type(e).__name__}: {e}"[:200]
        except Exception as e:
            return False, None, None, f"{type(e).__name__}: {e}"[:200]
    ms = (time.time() - t0) * 1000
    ok, why = judge_http(t, r)
    return ok, ms, r.status_code, why


def probe_tcp(t):
    t0 = time.time()
    try:
        socket.create_connection((t["host"], t["port"]), t.get("timeout", 5)).close()
        return True, (time.time() - t0) * 1000, None, ""
    except Exception as e:
        return False, None, None, f"{type(e).__name__}: {e}"[:200]


def probe_udp(t):
    """Send the payload; up = any reply (and it contains "contains", if set). Without a payload or reply
    expectation, up = no ICMP port-unreachable within the timeout (UDP has no handshake)."""
    t0 = time.time()
    payload = (t.get("payload") or "").encode().decode("unicode_escape").encode("latin-1")
    try:
        info = socket.getaddrinfo(t["host"], t["port"], type=socket.SOCK_DGRAM)[0]
        with socket.socket(info[0], socket.SOCK_DGRAM) as s:
            s.settimeout(t.get("timeout", 3))
            s.connect(info[4])
            s.send(payload)
            try:
                data = s.recv(4096)
            except socket.timeout:
                if t.get("reply") or t.get("contains"):
                    return False, None, None, "no reply"
                return True, None, None, ""
        if t.get("contains") and t["contains"].encode() not in data:
            return False, None, None, "reply lacks the expected text"
        return True, (time.time() - t0) * 1000, None, ""
    except Exception as e:
        return False, None, None, f"{type(e).__name__}: {e}"[:200]


PING_MS = re.compile(r"time[=<]([\d.]+)\s*ms")


def probe_icmp(t):
    """Ping (3 tries, up = any reply). Uses the system ping, which needs no root on Debian/Ubuntu."""
    try:
        r = subprocess.run(["ping", "-n", "-c", "3", "-i", "0.3", "-W", str(int(t.get("timeout", 2))), t["host"]],
                           capture_output=True, text=True, timeout=15)
    except Exception as e:
        return False, None, None, f"{type(e).__name__}: {e}"[:200]
    ms = [float(x) for x in PING_MS.findall(r.stdout)]
    if not ms:
        return False, None, None, "no reply to ping"
    return True, sorted(ms)[len(ms) // 2], None, ""


PROBES = {"tcp": probe_tcp, "udp": probe_udp, "icmp": probe_icmp}


def probe(t):
    return PROBES.get(t.get("kind"), probe_http)(t)


def where(t):
    k = t.get("kind")
    if t.get("url"):
        return t["url"]
    return t["host"] if k == "icmp" else f"{k or 'tcp'}://{t['host']}:{t['port']}"


def main():
    with db.connect() as con:
        targets = db.targets(con, "uptime")
    now = time.time()
    with db.connect() as con:
        with ThreadPoolExecutor(16) as ex:
            res = list(ex.map(probe, targets))
        rows = [(t["name"], now, int(ok), ms, code, err) for t, (ok, ms, code, err) in zip(targets, res)]
        con.executemany("INSERT INTO uptime(target,ts,ok,ms,code,err) VALUES(?,?,?,?,?,?)", rows)

        maint = db.active_maint(con, now)
        active = set()
        watch = [(t["name"], where(t), t.get("alert", True)) for t in targets]
        for name, loc, alert in watch:
            if not alert:
                continue
            last = con.execute("SELECT ok, err FROM uptime WHERE target=? ORDER BY ts DESC LIMIT ?",
                               (name, FAILS_TO_ALERT)).fetchall()
            key = f"uptime:{name}"
            if len(last) == FAILS_TO_ALERT and not any(r["ok"] for r in last) and not db.in_maint(maint, key, "uptime"):
                active.add(key)
                db.upsert_item(con, key, "uptime", f"{name} is down",
                               f"{loc} failed {FAILS_TO_ALERT} checks in a row.\n{last[0]['err']}", "critical",
                               kind="condition")
        db.clear_conditions(con, "uptime", active)


if __name__ == "__main__":
    main()
