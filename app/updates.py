"""Update checks against the public releases repo, and update requests for the host updater.

The board never updates itself: it writes /data/update-request.json ({version, at}) when an admin clicks Update (now or
scheduled), or when they allowed automatic updates. update.sh on the host (systemd logwatch-update.path/.timer, run as
root) picks the request up, downloads that release from the repo configured on the host (never from the request),
verifies its checksum, backs up, rebuilds and rolls back if the board doesn't come back. It reports in
/data/update-status.json and leaves a heartbeat in /data/updater.json.
"""
import datetime as dt
import json
import re
import time
from pathlib import Path

import httpx

import db
from settings import DATA, section

UPD = section("updates")
REPO = str(UPD.get("repo") or "DevSerae/logwatch-dashboard-releases").strip("/")
CHECK = UPD.get("check", True) is not False
CHECK_HOURS = float(UPD.get("check_hours") or 12)
AUTO_AT = str(UPD.get("auto_at") or "03:00")
REQUEST, STATUS, BEAT = DATA / "update-request.json", DATA / "update-status.json", DATA / "updater.json"
VER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def current():
    for p in (Path(__file__).with_name("VERSION"), Path(__file__).parent.parent / "VERSION"):
        if p.exists():
            return p.read_text().strip()
    return "0.0.0"


def vt(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3]) or (0,)


def _read(p):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def auto_on(con):
    v = db.kv_get(con, "update_auto", None)
    return bool(UPD.get("auto", False)) if v is None else bool(v)


def next_auto_at(now=None):
    """Next local AUTO_AT (HH:MM) as epoch seconds."""
    now = dt.datetime.fromtimestamp(now or time.time())
    try:
        h, m = (int(x) for x in AUTO_AT.split(":"))
    except ValueError:
        h, m = 3, 0
    t = now.replace(hour=h, minute=m, second=0, microsecond=0)
    return (t if t > now else t + dt.timedelta(days=1)).timestamp()


def check():
    """Worker job: ask GitHub for the latest release; queue it when automatic updates are allowed."""
    r = httpx.get(f"https://api.github.com/repos/{REPO}/releases/latest", timeout=20, follow_redirects=True,
                  headers={"Accept": "application/vnd.github+json", "User-Agent": "logwatch-dashboard/" + current()})
    r.raise_for_status()
    j = r.json()
    latest = str(j.get("tag_name") or "").lstrip("v")
    info = {"latest": latest if VER_RE.match(latest) else "", "url": j.get("html_url") or "",
            "notes": str(j.get("body") or "")[:4000], "published": j.get("published_at") or "", "checked": time.time()}
    with db.connect() as con:
        db.kv_set(con, "update", info)
        if info["latest"] and vt(info["latest"]) > vt(current()) and auto_on(con) and not REQUEST.exists() \
                and db.kv_get(con, "update_skip", "") != info["latest"]:
            request(info["latest"], next_auto_at(), "automatic")
    print(f"updates: running {current()}, latest {latest or '?'}", flush=True)


def request(version, at, by):
    if not VER_RE.match(version):
        raise ValueError("bad version")
    if vt(version) <= vt(current()):
        raise ValueError(f"{version} is not newer than {current()}")
    tmp = REQUEST.with_suffix(".tmp")
    tmp.write_text(json.dumps({"version": version, "at": int(at), "by": by, "requested": int(time.time())}))
    tmp.replace(REQUEST)


def cancel():
    REQUEST.unlink(missing_ok=True)


def state(con):
    info = db.kv_get(con, "update", {}) or {}
    beat = _read(BEAT) or {}
    status = _read(STATUS) or {}
    latest = info.get("latest") or ""
    return {"current": current(), "latest": latest, "available": bool(latest) and vt(latest) > vt(current()),
            "url": info.get("url", ""), "notes": info.get("notes", ""), "checked": info.get("checked", 0),
            "check": CHECK, "auto": auto_on(con), "auto_at": AUTO_AT, "repo": REPO,
            "skip": db.kv_get(con, "update_skip", ""), "later": db.kv_get(con, "update_later", 0),
            "request": _read(REQUEST), "status": status if status.get("at", 0) > time.time() - 7 * 86400 else {},
            "updater": bool(beat) and beat.get("at", 0) > time.time() - 3600}
