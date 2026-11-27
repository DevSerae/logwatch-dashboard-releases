"""GeoIP enrichment (country + ASN). Default: DB-IP Lite (CC BY 4.0, no account); optional MaxMind GeoLite2.
The worker downloads/refreshes the databases monthly into /data/geo; the board works without them ("?")."""
import datetime as dt
import gzip
import ipaddress
import shutil
import tarfile
import tempfile
from pathlib import Path

import httpx

from settings import DATA, section, secret

GEO = DATA / "geo"
COUNTRY, ASN = GEO / "country.mmdb", GEO / "asn.mmdb"
_db = {"at": None, "c": None, "a": None}
_cache = {}


def provider():
    return (section("board").get("geoip") or "dbip").lower()


def _open():
    mtime = max((p.stat().st_mtime for p in (COUNTRY, ASN) if p.exists()), default=None)
    if mtime == _db["at"]:
        return
    _db["at"] = mtime
    try:
        import maxminddb
        _db["c"] = maxminddb.open_database(str(COUNTRY)) if COUNTRY.exists() else None
        _db["a"] = maxminddb.open_database(str(ASN)) if ASN.exists() else None
    except Exception:
        _db["c"] = _db["a"] = None


def geo(ip):
    """(country ISO code | "LAN" | "?", "<asn> <org>" | "private" | "?")."""
    if ip in _cache:
        return _cache[ip]
    if not _cache:
        _open()
    cn, asn = "?", "?"
    try:
        a = ipaddress.ip_address(ip)
        if not a.is_global:
            cn, asn = "LAN", "private"
        else:
            c = (_db["c"].get(ip) if _db["c"] else None) or {}
            cn = (c.get("country") or c.get("registered_country") or {}).get("iso_code") or "?"
            s = (_db["a"].get(ip) if _db["a"] else None) or {}
            if s.get("autonomous_system_number"):
                asn = f"{s['autonomous_system_number']} {s.get('autonomous_system_organization') or ''}".strip()
    except ValueError:
        pass
    if len(_cache) > 50000:
        _cache.clear()
        _open()
    _cache[ip] = (cn, asn)
    return cn, asn


def _fetch(url, dest, auth=None):
    tmp = Path(tempfile.mkdtemp(dir=GEO))
    try:
        f = tmp / "dl"
        with httpx.stream("GET", url, auth=auth, follow_redirects=True, timeout=300) as r:
            r.raise_for_status()
            with f.open("wb") as out:
                for chunk in r.iter_bytes():
                    out.write(chunk)
        mm = tmp / "x.mmdb"
        if url.endswith(".gz") and not url.endswith(".tar.gz"):
            with gzip.open(f) as src, mm.open("wb") as out:
                shutil.copyfileobj(src, out)
        else:  # MaxMind: tar.gz with the .mmdb inside
            with tarfile.open(f) as t:
                m = next(x for x in t.getmembers() if x.name.endswith(".mmdb"))
                with t.extractfile(m) as src, mm.open("wb") as out:
                    shutil.copyfileobj(src, out)
        mm.replace(dest)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def update():
    """Download the current month's databases. Returns a short status string."""
    GEO.mkdir(parents=True, exist_ok=True)
    p = provider()
    if p == "off":
        return "geoip off"
    if p == "maxmind":
        acct, key = secret("MAXMIND_ACCOUNT_ID"), secret("MAXMIND_LICENSE_KEY")
        if not acct or not key:
            raise RuntimeError("geoip: maxmind needs MAXMIND_ACCOUNT_ID + MAXMIND_LICENSE_KEY")
        base = "https://download.maxmind.com/geoip/databases/{}/download?suffix=tar.gz"
        _fetch(base.format("GeoLite2-Country"), COUNTRY, (acct, key))
        _fetch(base.format("GeoLite2-ASN"), ASN, (acct, key))
        return "maxmind updated"
    month = dt.date.today().strftime("%Y-%m")
    prev = (dt.date.today().replace(day=1) - dt.timedelta(days=1)).strftime("%Y-%m")
    for m in (month, prev):  # the new month's file appears a day or two in
        try:
            _fetch(f"https://download.db-ip.com/free/dbip-country-lite-{m}.mmdb.gz", COUNTRY)
            _fetch(f"https://download.db-ip.com/free/dbip-asn-lite-{m}.mmdb.gz", ASN)
            return f"db-ip lite {m} updated"
        except httpx.HTTPStatusError:
            continue
    raise RuntimeError("geoip: DB-IP download failed")
