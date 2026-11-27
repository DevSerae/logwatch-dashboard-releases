#!/usr/bin/env python3
"""Background jobs in one process (the "worker" container): collect every 10 min (or when "Run checks now" sets
kv collect_requested), uptime + traffic every minute, trivy weekly, GeoIP monthly. One thread per job."""
import sys
import threading
import time
import traceback

import collect
import db
import geo
import traffic
import trivy
import updates
import uptime
from settings import mod


def collect_job():
    collect.main()


def collect_due():
    with db.connect() as con:
        req, last = db.kv_get(con, "collect_requested", 0), db.kv_get(con, "last_collect", 0)
    return req > last


def update_due():
    with db.connect() as con:
        return db.kv_get(con, "update_check_requested", 0) > db.kv_get(con, "job:updates", 0)


def geo_job():
    print(geo.update(), flush=True)


JOBS = [  # name, function, interval s, enabled, extra trigger
    ("collect", collect_job, 600, True, collect_due),
    ("uptime", uptime.main, 60, bool(mod("uptime")), None),
    ("traffic", traffic.main, 60, bool(mod("traffic")), None),
    ("trivy", trivy.main, 7 * 86400, bool(mod("trivy")), None),
    ("updates", updates.check, int(updates.CHECK_HOURS * 3600), updates.CHECK, update_due),
    ("geoip", geo_job, 30 * 86400, geo.provider() != "off" and bool(mod("traffic") or mod("crowdsec")), None),
]


def loop(name, fn, every, trigger):
    with db.connect() as con:
        last = db.kv_get(con, f"job:{name}", 0)
    while True:
        if time.time() - last >= every or (trigger and trigger()):
            last = time.time()
            try:
                fn()
            except Exception:
                print(f"[{name}] failed", file=sys.stderr, flush=True)
                traceback.print_exc()
            with db.connect() as con:
                db.kv_set(con, f"job:{name}", last)
        time.sleep(5)


def main():
    with db.connect():
        pass  # creates the schema before the threads start
    threads = []
    for name, fn, every, on, trig in JOBS:
        if on:
            t = threading.Thread(target=loop, args=(name, fn, every, trig), name=name, daemon=True)
            t.start()
            threads.append(t)
            print(f"worker: {name} every {every}s", flush=True)
    while all(t.is_alive() for t in threads):
        time.sleep(30)
    sys.exit("worker: a job thread died")


if __name__ == "__main__":
    main()
