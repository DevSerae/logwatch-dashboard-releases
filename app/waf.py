"""Edge WAF: rules, bans and the CRS level kept in the board DB and pushed to every layer that can act on them.

One rule model (waf_policy) for every layer, from L2 to L7. A rule says where it acts and what it matches:
  web    websites, i.e. HTTP through the Cloudflare tunnels.
         · who is asking (IPs, countries, networks, sites) → Cloudflare custom rules (block / managed challenge / allow)
         · what is asked (path, headers, args, attacks)    → CrowdSec AppSec on the edge nodes (logwatch-wafctl, role waf)
  ports  raw TCP/UDP forwarded by the port proxies (logwatch-nfwafctl, role l4waf, nftables):
         L2 MAC/VLAN, L3 sources/TTL/size/fragments/bogons/spoofing, L4 protocol/ports/flags/MSS/state,
         limits (rate, bandwidth, concurrent connections per IP or /24), L7 fixed payload bytes.
Bans go to every layer; the OWASP CRS level is AppSec only. Every apply stores the full state in waf_audit; undo = put an
older state back. Rules from before 2.8.0 (waf_rules, waf_geo, waf_l4) are converted once; what can't be converted lands
in waf_legacy with all its details, raises an Edge WAF item, and the UI offers to recreate it.
CF has no log action on its Free plan: log-only website rules about sources are stored and simulated, not pushed.
"""
import datetime as dt
import importlib.machinery
import importlib.util
import ipaddress
import json
import math
import re
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import unquote

import httpx

import db
import remote
from settings import VL, mod, secret, ssh_hosts

HERE = Path(__file__).resolve().parent
WC = mod("waf") or {}
NODES = [h["name"] for h in ssh_hosts("waf")] if WC else []  # edge nodes with role waf; empty = nothing pushed
L4_NODES = [h["name"] for h in ssh_hosts("l4waf")] if WC else []  # port proxies with role l4waf (nftables)
L4_GROUPS = WC.get("port_groups") or []      # [{name: "Web", ports: "8000-8100"}, ...]: imported once as port lists
CF = WC.get("cloudflare") or {}              # {zone: id, account: id}; token = secret CLOUDFLARE_API_TOKEN
CF_API = "https://api.cloudflare.com/client/v4"
CF_PREFIX = "Logwatch - "
CF_LIST = "lw_bans"
CF_MAX_EXPR = 4096
MODEL = 2
LOCK = threading.Lock()

DURS = {"1h": 1, "4h": 4, "24h": 24, "168h": 168, "720h": 720, "permanent": None}
DUR_TXT = {"1h": "1 hour", "4h": "4 hours", "24h": "24 hours", "168h": "7 days", "720h": "30 days", "permanent": "good"}
# CRS exclusions suggested in the UI: authenticated admin areas that trip false positives, e.g.
# [{host: app.example.com, paths: [/admin/], auth: [bearer, "cookie:session"]}]
CRS_DEFAULT_EXCL = WC.get("crs_exclusions") or []
# zones the access log can answer for (simulation); everything else is checked on the edge only
SIM_ZONES = {"URI", "METHOD", "HEADERS"}
SIM_HEADERS = {"user-agent": "ua", "referer": "ref"}
# spec fields per layer
PORT_FIELDS = ("proto", "ports", "sports", "dst", "state", "family", "tcp_bad", "nosyn", "mss", "ttl", "len", "frag", "bogon",
               "spoof", "mac", "vlan", "payload", "limit", "nodes", "flags", "icmp", "invalid", "hours", "days", "dscp", "osf", "ban")
V3 = ("flags", "icmp", "invalid", "hours", "days", "dscp", "osf", "ban")   # need port proxy agent v3 (also rules on dynamic lists)
BOTH_OK = ("proto", "ports", "nodes")          # port fields that still make sense on a rule for websites + ports
FIELD_TXT = {"proto": "protocol", "ports": "ports", "sports": "source ports", "dst": "backend addresses", "state": "connection state",
             "family": "IP version", "tcp_bad": "bad TCP flags", "nosyn": "new TCP without SYN", "mss": "TCP MSS", "ttl": "TTL",
             "len": "packet size", "frag": "fragments", "bogon": "bogon sources", "spoof": "spoofed sources", "mac": "MAC addresses",
             "vlan": "VLANs", "payload": "payload bytes", "limit": "limits", "nodes": "port proxies", "flags": "TCP flags",
             "icmp": "ICMP types", "invalid": "invalid packets", "hours": "hours", "days": "days", "dscp": "DSCP", "osf": "OS fingerprint",
             "ban": "ban to a dynamic list", "cf": "Cloudflare fields", "rate": "rate limit"}
EARLY = ("frag", "tcp_bad", "mss", "ttl", "len", "bogon", "mac", "vlan", "flags", "icmp", "invalid", "osf", "dscp")
TCP_FLAGS = ("fin", "syn", "rst", "psh", "ack", "urg", "ecn", "cwr")
ICMP_TYPES = ("echo-request", "echo-reply", "destination-unreachable", "time-exceeded", "parameter-problem", "timestamp-request",
              "redirect", "router-advertisement", "router-solicitation", "nd-neighbor-solicit", "nd-neighbor-advert", "packet-too-big")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
# rate limits / response rules on the edge nodes (CrowdSec leaky buckets on the NPM access log)
RL_KEYS = ("ip", "ip_path", "ip_host", "net", "asn", "ua", "host")
RL_DURS = ("10m", "1h", "4h", "24h", "168h")
# Cloudflare fields a website rule can test besides sources and sites (all on the Free plan)
CF_FIELDS = {"continent": ("ip.src.continent", "str"), "eu": ("ip.src.is_in_european_union", "bool"),
             "http_version": ("http.request.version", "str"), "ssl": ("ssl", "bool"), "ext": ("http.request.uri.path.extension", "str"),
             "referer": ("http.referer", "str"), "query": ("http.request.uri.query", "str"), "cookie": ("http.cookie", "str"),
             "header": ("http.request.headers.names", "names"), "bot": ("cf.client.bot", "bool"), "path": ("http.request.uri.path", "str"),
             "ua": ("http.user_agent", "str"), "method": ("http.request.method", "str")}
CF_OPS = ("eq", "ne", "contains", "starts", "ends", "in", "notin", "is", "isnot")
# lists (Edge WAF → Lists): picked by name in rules as list:<id>
LIST_KINDS = ("ports", "addr", "hosts", "feed", "dynamic")
HOSTING_ASNS = (14061, 16276, 24940, 16509, 14618, 396982, 8075, 63949, 20473, 51167, 45102, 132203, 9009, 60781, 31898, 36352,
                202425, 213230, 50673, 47583, 62240, 197540, 12876, 35540, 136907, 37963, 55286, 53667, 46606, 8100)
FEEDS = {
    "spamhaus": {"name": "Spamhaus DROP", "url": ["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"],
                 "fmt": "ndjson", "hours": 12, "why": "hijacked and criminal networks: safe to drop everywhere"},
    "firehol1": {"name": "FireHOL level 1", "url": ["https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"],
                 "fmt": "lines", "hours": 12, "why": "attacks and malware sources from several lists, few false positives"},
    "tor": {"name": "Tor exit nodes", "url": ["https://check.torproject.org/torbulkexitlist"], "fmt": "lines", "hours": 6,
            "why": "anonymous traffic: many real people, many attackers"},
    "crowdsec": {"name": "CrowdSec community blocklist", "via": "capi", "hours": 6,
                 "why": "what the edge nodes already get from CrowdSec, for the port proxies too"},
    "hosting": {"name": "Hosting and cloud networks", "static": [f"as:{a}" for a in HOSTING_ASNS],
                "why": "datacenter ASNs (DigitalOcean, OVH, Hetzner, AWS, Azure, …): bots, rarely real visitors"},
    "bots": {"name": "Verified search bots (Google, Bing)", "url": ["https://developers.google.com/static/search/apis/ipranges/googlebot.json",
             "https://www.bing.com/toolbox/bingbot.json"], "fmt": "prefixes", "hours": 24,
             "why": "published crawler ranges: use as an exception, or to catch fake bots"},
}
DUMMY = {4: "192.0.2.0/24", 6: "2001:db8::/32"}  # stands in for countries/networks when only validating


class Bad(Exception):
    pass


def _script(name):
    """The engine scripts sit next to this file in the image (/app); in a checkout they're under remote/linux."""
    p = HERE / name
    return p if p.exists() else HERE.parent / "remote" / "linux" / name


# ---------------------------------------------------------------- rule spec

HOST_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def clean_src(v, what="sources", maxn=500, lists=True):
    """'1.2.3.4', '1.2.3.0/24', 'cn:DE', 'as:14061' (also 'DE', 'AS14061'), 'list:3' → normalised list."""
    out = []
    for x in v or []:
        x = str(x).strip()
        if not x:
            continue
        if lists and re.fullmatch(r"list:\d{1,6}", x):
            out.append(x)
            continue
        m = re.fullmatch(r"(?i)(?:cn:)?([a-z]{2})", x)
        if m or x.lower().startswith("cn:"):
            if not m:
                raise Bad(f"{what}: country must be a 2-letter code")
            out.append("cn:" + m[1].upper())
            continue
        m = re.fullmatch(r"(?i)(?:as:|as)\s*([1-9][0-9]{0,9})", x)
        if m:
            out.append(f"as:{int(m[1])}")
            continue
        try:
            n = ipaddress.ip_network(x, strict=False)
        except ValueError:
            raise Bad(f"{what}: {x[:40]!r} isn't an IP, range, country (DE) or network (AS14061)")
        out.append(str(n.network_address) if n.num_addresses == 1 else str(n))
    out = list(dict.fromkeys(out))
    if len(out) > maxn:
        raise Bad(f"{what}: up to {maxn} entries")
    return out


def clean_ports(v, what="ports"):
    parts = [p for p in re.sub(r"\s+", "", str(v or "")).split(",") if p]
    for p in parts:
        if re.fullmatch(r"list:\d{1,6}", p):
            continue
        if not PORT_RE.match(p) or not all(1 <= int(x) <= 65535 for x in p.split("-")) or int(p.split("-")[0]) > int(p.split("-")[-1]):
            raise Bad(f"{what}: {p[:20]!r} isn't a port or range like 443 or 8000-8100")
    return ", ".join(parts)


def clean_range(v, lo, hi, what):
    v = re.sub(r"\s+", "", str(v or ""))
    if not v:
        return ""
    m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", v)
    if not m or not lo <= int(m[1]) <= int(m[2] or m[1]) <= hi:
        raise Bad(f"{what}: a number or range within {lo}-{hi}, like 1-5")
    return v


def clean_conds(match):
    conds = []
    for c in match or []:
        conds.append({k: c[k] for k in ("zone", "var", "op", "value", "case", "measure") if c.get(k) not in (None, "")})
    return conds


def has(spec, k):
    v = spec.get(k)
    return bool(v) and v not in ("any", "")


def web_kind(spec):
    """'appsec' (looks at the request), 'cf' (who sends it + Cloudflare fields), 'rate' (CrowdSec buckets) or 'list' (feeds as
    CrowdSec decisions on the edge nodes). Set by clean_spec; rules saved before 2.9.0 don't carry it."""
    return spec.get("wk") or ("appsec" if spec.get("match") else "cf")


def cur_lists():
    """{id: list} from the board DB (rules name lists as list:<id>)."""
    with db.connect() as con:
        return {x["id"]: x for x in db.kv_get(con, "waf_lists", []) or []}


def list_refs(spec):
    """Every list:<id> a rule names, as (field, id)."""
    out = [(f, int(x[5:])) for f in ("src", "src_not", "hosts") for x in spec.get(f) or [] if str(x).startswith("list:")]
    out += [("ports", int(p.strip()[5:])) for p in str(spec.get("ports") or "").split(",") if p.strip().startswith("list:")]
    if spec.get("ban"):
        out.append(("ban", spec["ban"]["list"]))
    return out


def big_list(lst):
    """Feeds fetched from the internet: too big for a Cloudflare expression (they go to the edge nodes as CrowdSec decisions)."""
    return lst["kind"] == "feed" and not FEEDS.get(lst.get("feed"), {}).get("static")


def clean_rate(r):
    if not isinstance(r, dict):
        raise Bad("bad rate limit")
    kind, key = r.get("kind") or "rate", r.get("key") or "ip"
    if kind not in ("rate", "resp") or key not in RL_KEYS:
        raise Bad("rate limit: count requests (rate) or answers (resp), per " + " | ".join(RL_KEYS))
    try:
        n, secs = int(r.get("n") or 0), int(r.get("secs") or 0)
    except (TypeError, ValueError):
        raise Bad("rate limit: numbers only")
    if not 1 <= n <= 100000 or not 1 <= secs <= 3600:
        raise Bad("rate limit: 1-100000 requests within 1-3600 seconds")
    ban = r.get("ban") or "4h"
    if ban not in RL_DURS:
        raise Bad("rate limit: ban for " + " | ".join(RL_DURS))
    paths = [str(x).strip() for x in r.get("paths") or [] if str(x).strip()]
    if len(paths) > 10 or any(not x.startswith("/") or len(x) > 200 for x in paths):
        raise Bad("rate limit: up to 10 path prefixes like /login")
    meth = [str(m).strip().upper() for m in r.get("methods") or [] if str(m).strip()]
    if any(not re.fullmatch(r"[A-Z]{3,12}", m) for m in meth):
        raise Bad("rate limit: methods like POST")
    try:
        st = sorted({int(x) for x in r.get("statuses") or []})
    except (TypeError, ValueError):
        raise Bad("rate limit: statuses are numbers like 404")
    if any(not 100 <= x <= 599 for x in st):
        raise Bad("rate limit: statuses 100-599")
    if kind == "resp" and not st:
        raise Bad("a response rule needs the answers it counts, e.g. 404 or 401")
    return {"kind": kind, "key": key, "n": n, "secs": secs, "ban": ban, "paths": paths, "methods": meth, "statuses": st}


def clean_cf(conds):
    out = []
    for c in conds or []:
        f, op = c.get("f"), c.get("op") or "eq"
        if f not in CF_FIELDS or op not in CF_OPS:
            raise Bad("Cloudflare field: " + ", ".join(CF_FIELDS))
        typ = CF_FIELDS[f][1]
        if typ == "bool":
            if op not in ("is", "isnot"):
                raise Bad(f"{f} is yes/no")
            out.append({"f": f, "op": op})
            continue
        v = str(c.get("v") or "").strip()
        if not v or len(v) > 300 or any(ch in v for ch in '"\\\n'):
            raise Bad(f"{f}: a value (no quotes or backslashes)")
        if typ == "names" and op not in ("is", "isnot"):
            raise Bad("header: present or missing")
        if op in ("is", "isnot") and typ != "names":
            raise Bad(f"{f}: compare with equals, contains, …")
        out.append({"f": f, "op": op, "v": v.lower() if typ == "names" or f in ("ext", "continent") else v})
    if len(out) > 8:
        raise Bad("up to 8 Cloudflare conditions")
    return out


def clean_spec(s, lists=None):
    """Shape and check a rule from the UI (the engines' own check() does the last word)."""
    if not isinstance(s, dict):
        raise Bad("bad rule")
    L = cur_lists() if lists is None else lists
    where = [w for w in ("web", "ports") if w in (s.get("where") or [])]
    if not where:
        raise Bad("where should it act: websites, ports or both?")
    action = s.get("action") or "block"
    if action not in ("block", "challenge", "reject", "allow"):
        raise Bad("action block | challenge | reject | allow")
    x = {"where": where, "action": action, "src": clean_src(s.get("src")), "src_not": clean_src(s.get("src_not"), "exceptions")}
    hosts = [h.strip().lower() for h in s.get("hosts") or [] if str(h).strip()]
    if any(not HOST_RE.match(h) and not re.fullmatch(r"list:\d{1,6}", h) for h in hosts):
        raise Bad("bad site name")
    x["hosts"], x["match"] = hosts, clean_conds(s.get("match"))
    proto = s.get("proto") or "any"
    if proto not in ("any", "tcp", "udp", "icmp"):
        raise Bad("protocol tcp | udp | icmp | any")
    x["proto"], x["ports"], x["sports"] = proto, clean_ports(s.get("ports")), clean_ports(s.get("sports"), "source ports")
    if "list:" in x["sports"]:
        raise Bad("port lists are for destination ports")
    x["dst"] = []
    for d in s.get("dst") or []:
        try:
            x["dst"].append(str(ipaddress.ip_network(str(d).strip(), strict=False)))
        except ValueError:
            raise Bad(f"backend address {str(d)[:40]!r} isn't an IP or range")
    st = s.get("state") or ""
    if st not in ("", "new", "est", "any"):
        raise Bad("connection state new | est | any")
    fam = s.get("family") or "any"
    if fam not in ("any", "ip4", "ip6"):
        raise Bad("IP version any | ip4 | ip6")
    x["state"], x["family"] = st, fam
    for k in ("tcp_bad", "nosyn", "frag", "bogon", "spoof", "invalid"):
        x[k] = bool(s.get(k))
    x["mss"] = clean_range(s.get("mss"), 0, 65535, "TCP MSS")
    x["ttl"] = clean_range(s.get("ttl"), 0, 255, "TTL")
    x["len"] = clean_range(s.get("len"), 0, 65535, "packet size")
    x["mac"] = [str(m).strip().lower().replace("-", ":") for m in s.get("mac") or [] if str(m).strip()]
    if any(not MAC_RE.match(m) for m in x["mac"]):
        raise Bad("MAC addresses look like 02:00:00:aa:bb:cc")
    try:
        x["vlan"] = [int(v) for v in s.get("vlan") or [] if str(v).strip() != ""]
    except (TypeError, ValueError):
        raise Bad("VLAN ids are numbers 0-4095")
    if any(not 0 <= v <= 4095 for v in x["vlan"]):
        raise Bad("VLAN ids are numbers 0-4095")
    x["payload"] = []
    for p in s.get("payload") or []:
        hx = re.sub(r"[\s:]", "", str(p.get("hex") or "")).lower()
        if hx.startswith("0x"):
            hx = hx[2:]
        try:
            at = int(p.get("at") or 0)
        except (TypeError, ValueError):
            raise Bad("payload offset is a number")
        if not hx:
            continue
        if not re.fullmatch(r"([0-9a-f]{2}){1,16}", hx) or not 0 <= at <= 1400:
            raise Bad("payload: offset 0-1400 and 1-16 bytes of hex, like 16030100")
        x["payload"].append({"at": at, "hex": hx})
    lim = s.get("limit")
    x["limit"] = None
    if lim:
        try:
            x["limit"] = {"what": lim.get("what") or "conn", "n": int(lim.get("n") or 0), "per": lim.get("per") or "minute",
                          "burst": int(lim.get("burst") or 0), "by": lim.get("by") or "ip"}
        except (TypeError, ValueError):
            raise Bad("limit: numbers only")
        if x["limit"]["what"] not in ("conn", "pkt", "bytes", "concurrent") or x["limit"]["per"] not in ("second", "minute") \
                or x["limit"]["by"] not in ("ip", "net", "all") or not 1 <= x["limit"]["n"] <= 10 ** 7 or not 0 <= x["limit"]["burst"] <= 10 ** 6:
            raise Bad("limit: connections | packets | kbytes | concurrent, 1-10000000, per second | minute, per IP | /24 | all")
    x["nodes"] = [n for n in s.get("nodes") or [] if n in L4_NODES]
    # next-gen port checks (agent v3)
    fl = s.get("flags") or None
    x["flags"] = None
    if fl and (fl.get("mask") or fl.get("set")):
        mask, on = [f for f in TCP_FLAGS if f in (fl.get("mask") or [])], [f for f in TCP_FLAGS if f in (fl.get("set") or [])]
        mask = [f for f in TCP_FLAGS if f in set(mask) | set(on)]
        x["flags"] = {"mask": mask, "set": on}
    x["icmp"] = [t for t in ICMP_TYPES if t in (s.get("icmp") or [])]
    hr = re.sub(r"\s+", "", str(s.get("hours") or ""))
    if hr and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d", hr):
        raise Bad("hours like 08:00-18:00 (22:00-06:00 wraps over midnight)")
    x["hours"] = hr
    x["days"] = [d for d in DAYS if d in (s.get("days") or [])]
    if len(x["days"]) == 7:
        x["days"] = []
    try:
        x["dscp"] = sorted({int(d) for d in s.get("dscp") or [] if str(d).strip() != ""})
    except (TypeError, ValueError):
        raise Bad("DSCP values are numbers 0-63")
    if any(not 0 <= d <= 63 for d in x["dscp"]):
        raise Bad("DSCP values are numbers 0-63")
    x["osf"] = [str(o).strip() for o in s.get("osf") or [] if str(o).strip()]
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}", o) for o in x["osf"]):
        raise Bad("OS names like Linux, Windows, FreeBSD, unknown")
    bn = s.get("ban") or None
    x["ban"] = None
    if bn and bn.get("list"):
        try:
            x["ban"] = {"list": int(bn["list"]), "secs": int(bn.get("secs") or 3600)}
        except (TypeError, ValueError):
            raise Bad("ban: a dynamic list and seconds")
        if not 60 <= x["ban"]["secs"] <= 30 * 86400:
            raise Bad("ban: 1 minute to 30 days")
    x["cf"] = clean_cf(s.get("cf"))
    x["rate"] = clean_rate(s["rate"]) if s.get("rate") else None
    ex = s.get("expires")
    x["expires"] = None
    if ex:
        try:
            x["expires"] = float(ex)
        except (TypeError, ValueError):
            raise Bad("bad expiry")
        if x["expires"] <= time.time():
            raise Bad("the expiry is in the past")
    # lists: they must exist, and be the right kind for where they're named
    kinds = {"src": ("addr", "feed", "dynamic"), "src_not": ("addr", "feed"), "hosts": ("hosts",), "ports": ("ports",), "ban": ("dynamic",)}
    for f, lid in list_refs(x):
        lst = L.get(lid)
        if not lst:
            raise Bad(f"list #{lid} doesn't exist (any more)")
        if lst["kind"] not in kinds[f]:
            raise Bad(f"list '{lst['name']}' ({lst['kind']}) can't be used as {FIELD_TXT.get(f, f).replace('src_not', 'exceptions')}")
    refs = {f: [L[i] for g, i in list_refs(x) if g == f] for f in ("src", "src_not", "hosts")}
    dyn_src = [l for l in refs["src"] if l["kind"] == "dynamic"]
    big_src = [l for l in refs["src"] if big_list(l)]
    # what makes sense where
    used = [k for k in PORT_FIELDS if has(x, k)]
    if "web" in where:
        if dyn_src:
            raise Bad(f"dynamic list '{dyn_src[0]['name']}' lives on the port proxies: choose Ports only")
        if "ports" in where:
            bad = [k for k in used if k not in BOTH_OK]
            if bad:
                raise Bad(f"{', '.join(FIELD_TXT[k] for k in bad)} only work on port proxies: choose Ports only, or make two rules")
            if x["match"] or x["cf"] or x["rate"]:
                raise Bad("request checks, Cloudflare fields and rate limits only work on websites: choose Websites only, or make two rules")
        elif used:
            raise Bad(f"{', '.join(FIELD_TXT[k] for k in used)} only work on port proxies: website traffic reaches the board's "
                      "edge through Cloudflare tunnels as HTTP, without the original packets")
        if x["rate"]:
            if x["match"] or x["src"] or x["src_not"] or x["cf"]:
                raise Bad("a rate limit counts requests per key on the edge nodes: give it sites and paths, not sources or other checks")
            if action != "block":
                raise Bad("a rate limit bans (block), or logs in log mode")
            if len(x["hosts"]) > 10:
                raise Bad("a rate limit: up to 10 sites")
            x["wk"] = "rate"
        elif big_src:
            if len(big_src) != len(x["src"]) or x["src_not"] or x["hosts"] or x["match"] or x["cf"] or action != "block":
                raise Bad(f"'{big_src[0]['name']}' is too big for Cloudflare: it blocks on the edge nodes for every site, so the rule "
                          "can only be 'block these feeds' (no other sources, sites, exceptions or checks)")
            x["wk"] = "list"
        elif x["match"]:
            if x["src"] or x["src_not"] or x["cf"]:
                raise Bad("a website rule checks either who is asking and Cloudflare fields (Cloudflare) or what is asked "
                          "(paths, headers, sizes: the edge nodes), not both: make two rules")
            if action != "block":
                raise Bad("request checks can block (403) or log, not challenge or allow")
            x["wk"] = "appsec"
        else:
            if not (x["src"] or x["hosts"] or x["cf"]):
                raise Bad("pick who it's about (IPs, countries, networks, lists), Cloudflare fields or what is asked (path, headers, …)")
            if any(big_list(l) for l in refs["src_not"]):
                raise Bad("feeds are too big for a Cloudflare exception: for search bots use the field 'known good bot'")
            x["wk"] = "cf"
        if action == "reject":
            raise Bad("reject is for ports; websites block (403)")
    if "ports" in where:
        if action == "challenge":
            raise Bad("ports can't show a challenge (no browser): choose block or reject" + (", or Websites only" if "web" in where else ""))
        if x["hosts"] and "web" not in where:
            raise Bad("sites only apply to websites")
        if action == "allow" and not x["src"]:
            raise Bad("an allow rule needs the sources it lets through")
        if x["ban"] and action == "allow":
            raise Bad("an allow rule can't ban")
        if not (x["src"] or x["ports"] or x["limit"] or any(x[k] for k in EARLY + ("spoof", "nosyn")) or x["payload"] or x["dst"]):
            raise Bad("this would match every forwarded connection: pick sources, ports, a limit or a check")
        if (x["tcp_bad"] or x["mss"] or x["nosyn"] or x["flags"] or x["osf"]) and proto != "tcp":
            raise Bad("TCP flag / MSS / OS checks need protocol TCP")
        if x["icmp"] and proto != "icmp":
            raise Bad("ICMP types need protocol ICMP")
    return x


def clean_policy(p, avail=True, lists=None):
    """{name, mode, spec} from the UI → checked. avail: refuse layers that aren't set up (nothing saved that can't apply)."""
    if not isinstance(p, dict) or p.get("mode") not in ("log", "enforce"):
        raise Bad("mode must be log or enforce")
    spec = clean_spec(p.get("spec") or {}, lists)
    if avail:
        need(spec, p["mode"])
    return {"name": str(p.get("name") or "").strip()[:120] or describe(spec, short=True), "mode": p["mode"], "spec": spec}


def need(spec, mode):
    if "web" in spec["where"]:
        if web_kind(spec) in ("appsec", "rate", "list") and not NODES:
            raise Bad("request checks, rate limits and feeds need the WAF engine on an edge node (a host with role waf), and none is set up")
        if web_kind(spec) == "cf" and not cf_ready():
            raise Bad("website rules about IPs, countries and networks go to Cloudflare, which isn't set up (zone ID, account ID, "
                      "API token)" + (": choose Ports instead" if L4_NODES else ""))
    if "ports" in spec["where"] and not L4_NODES:
        raise Bad("no port proxy is set up (no host with role l4waf)")


def _srctxt(src, L=None):
    import geo
    out = []
    for s in src:
        if s.startswith("list:"):
            lst = (L or {}).get(int(s[5:]))
            out.append(f"list '{lst['name']}'" if lst else s)
        elif s.startswith("cn:"):
            out.append(geo.country_name(s[3:]) if hasattr(geo, "country_name") else s[3:])
        elif s.startswith("as:"):
            out.append("AS" + s[3:])
        else:
            out.append(s)
    return ", ".join(out[:6]) + (f" +{len(out) - 6}" if len(out) > 6 else "")


def describe(spec, short=False, L=None):
    """Plain-English summary (the UI has a richer one; this is for names, history and items)."""
    act = {"block": "Block", "challenge": "Challenge", "reject": "Reject", "allow": "Allow"}[spec["action"]]
    p = []
    rt = spec.get("rate")
    if rt:
        act = "Rate-limit" if rt["kind"] == "rate" else "Ban"
        p.append(f"over {rt['n']} " + ("requests" if rt["kind"] == "rate" else "/".join(map(str, rt["statuses"])) + " answers")
                 + f" in {rt['secs']} s per {rt['key'].replace('_', '+')}" + (" to " + ", ".join(rt["paths"][:3]) if rt["paths"] else ""))
    if spec.get("src"):
        p.append("from " + _srctxt(spec["src"], L))
    if spec.get("cf"):
        p.append("where " + "; ".join(f"{c['f']} {c['op']} {c.get('v', '')}".strip() for c in spec["cf"][:2]))
    if spec.get("match"):
        p.append("requests matching " + "; ".join(f"{c.get('zone')} {c.get('op')} {c.get('value', '')}".strip() for c in spec["match"][:2]))
    lim = spec.get("limit")
    if lim:
        p.append(f"over {lim['n']} {({'conn': 'new connections', 'pkt': 'packets', 'bytes': 'kB', 'concurrent': 'open connections'})[lim['what']]}"
                 + ("" if lim["what"] == "concurrent" else f"/{lim['per'][:3]}") + {"ip": " per IP", "net": " per /24", "all": " in total"}[lim["by"]])
    chk = [FIELD_TXT[k] for k in ("tcp_bad", "nosyn", "mss", "ttl", "len", "frag", "bogon", "spoof", "mac", "vlan", "payload", "flags",
                                  "icmp", "invalid", "dscp", "osf") if has(spec, k)]
    if chk:
        p.append("checks " + ", ".join(chk))
    if spec.get("ports"):
        pt = re.sub(r"list:(\d+)", lambda m: f"list '{(L or {}).get(int(m[1]), {}).get('name', m[1])}'", str(spec["ports"]))
        p.append(f"to {spec['proto'] if spec['proto'] != 'any' else ''} {pt}".replace("  ", " "))
    if spec.get("hosts"):
        p.append("on " + ", ".join(spec["hosts"][:3]))
    if spec.get("hours") or spec.get("days"):
        p.append(" ".join(x for x in (spec.get("hours"), "/".join(spec.get("days") or [])) if x))
    txt = f"{act} " + " ".join(p) if p else act
    return txt[:120] if short else txt


# ---------------------------------------------------------------- state

def _pol(r):
    return {"id": r[0], "name": r[1], "mode": r[2], "enabled": bool(r[3]), "spec": json.loads(r[4]), "created": r[5],
            "updated": r[6], "who": r[7], "origin": r[8]}


def seed_lists(con):
    """2.9.0: the config's port_groups become port lists, once (edited on the board from then on)."""
    if db.kv_get(con, "waf_lists_seeded"):
        return
    lists, n = db.kv_get(con, "waf_lists", []) or [], 0
    for g in L4_GROUPS:
        try:
            x = clean_list({"name": g.get("name"), "kind": "ports", "entries": str(g.get("ports") or ""), "note": "from config port_groups"},
                           {l["id"]: l for l in lists})
        except Bad:
            continue
        lists.append(x)
        n += 1
    db.kv_set(con, "waf_lists", lists)
    db.kv_set(con, "waf_lists_seeded", {"ts": time.time(), "ports": n})


def state(con):
    """Everything the layers should have, as plain JSON (also what waf_audit stores)."""
    ensure(con)
    seed_lists(con)
    pol = [_pol(r) for r in con.execute("SELECT id,name,mode,enabled,spec,created,updated,who,origin FROM waf_policy ORDER BY id")]
    bans = [{"id": r[0], "value": r[1], "expires": r[2], "note": r[3], "created": r[4], "who": r[5]}
            for r in con.execute("SELECT id,value,expires,note,created,who FROM waf_bans ORDER BY id")]
    return {"model": MODEL, "policies": pol, "bans": bans, "crs": db.kv_get(con, "waf_crs", None),
            "lists": db.kv_get(con, "waf_lists", []) or [], "trap": db.kv_get(con, "waf_trap", None)}


def put_state(con, st):
    """Replace the stored rule set with st (undo). Older-format states are converted the way the update converts them."""
    if st.get("model") != MODEL:
        pol, legacy = convert(st)
        for lg in legacy:
            add_legacy(con, *lg)
        st = {"model": MODEL, "policies": pol, "bans": st.get("bans") or [], "crs": st.get("crs"), "lists": st.get("lists"), "trap": st.get("trap")}
    con.execute("DELETE FROM waf_policy"); con.execute("DELETE FROM waf_bans")
    for p in st["policies"]:
        con.execute("INSERT INTO waf_policy(id,name,mode,enabled,spec,created,updated,who,origin) VALUES(?,?,?,?,?,?,?,?,?)",
                    (p["id"], p["name"], p["mode"], int(p["enabled"]), json.dumps(p["spec"]), p["created"], p["updated"], p["who"],
                     p.get("origin") or ""))
    for b in st["bans"]:
        con.execute("INSERT INTO waf_bans(id,value,expires,note,created,who) VALUES(?,?,?,?,?,?)",
                    (b["id"], b["value"], b["expires"], b["note"], b["created"], b["who"]))
    db.kv_set(con, "waf_crs", st["crs"])
    if "lists" in st and st["lists"] is not None:   # states from before 2.9.0 have no lists: keep today's
        db.kv_set(con, "waf_lists", st["lists"])
    if "trap" in st:
        db.kv_set(con, "waf_trap", st["trap"])


# ---------------------------------------------------------------- the update: old rules → this model

def _old_state(con):
    rules = [{"id": r[0], "mode": r[1], "desc": r[2], "hosts": json.loads(r[3]), "match": json.loads(r[4]),
              "enabled": bool(r[5]), "created": r[6], "updated": r[7], "who": r[8]}
             for r in con.execute("SELECT id,mode,desc,hosts,conds,enabled,created,updated,who FROM waf_rules ORDER BY id")]
    geo = [{"id": r[0], "kind": r[1], "value": r[2], "action": r[3], "mode": r[4], "note": r[5], "created": r[6], "who": r[7]}
           for r in con.execute("SELECT id,kind,value,action,mode,note,created,who FROM waf_geo ORDER BY id")]
    l4 = [{"id": r[0], "kind": r[1], "mode": r[2], "desc": r[3], "proto": r[4], "ports": r[5], "rate": r[6], "burst": r[7],
           "src": json.loads(r[8]), "enabled": bool(r[9]), "created": r[10], "updated": r[11], "who": r[12]}
          for r in con.execute("SELECT id,kind,mode,desc,proto,ports,rate,burst,src,enabled,created,updated,who FROM waf_l4 ORDER BY id")]
    return {"rules": rules, "geo": geo, "l4": l4}


def convert(old):
    """Old rules → policies. Returns (policies, legacy) with legacy = [(kind, old rule, reason, suggested policy or None)]."""
    pol, legacy, now = [], [], time.time()
    used = {r["id"] for r in old.get("rules") or []}
    nxt = [max(used | {0}) + 1]

    def new_id():
        while nxt[0] in used:
            nxt[0] += 1
        used.add(nxt[0])
        return nxt[0]

    def take(kind, o, p, origin):
        try:
            p = dict(p, **clean_policy({"name": p["name"], "mode": p["mode"], "spec": p["spec"]}, lists={}))
            ok, err = check({"model": MODEL, "policies": [dict(p, enabled=True)], "bans": [], "crs": None})
            if not ok:
                raise Bad(err)
        except Bad as e:
            legacy.append((kind, o, str(e), {"name": p["name"], "mode": p["mode"], "spec": p["spec"]}))
            return
        pol.append(dict(p, origin=origin))

    for r in old.get("rules") or []:
        take("rule", r, {"id": r["id"], "name": r["desc"], "mode": r["mode"], "enabled": r["enabled"], "created": r["created"],
                         "updated": r["updated"], "who": r["who"],
                         "spec": {"where": ["web"], "action": "block", "hosts": r["hosts"], "match": r["match"]}}, "web rule")
    groups = {}
    for g in old.get("geo") or []:
        groups.setdefault((g["action"], g["mode"]), []).append(g)
    for (action, mode), gs in groups.items():
        src = [("cn:" if g["kind"] == "cn" else "as:") + g["value"] for g in gs]
        o = {"countries_networks": [("" if g["kind"] == "cn" else "AS") + g["value"] for g in gs], "action": action, "mode": mode,
             "where": "Cloudflare (websites)", "ids": [g["id"] for g in gs]}
        p = {"id": new_id(), "name": f"{'Block' if action == 'block' else 'Challenge'} countries/networks", "mode": mode, "enabled": True,
             "created": min(g["created"] for g in gs), "updated": now, "who": gs[0]["who"],
             "spec": {"where": ["web"], "action": action, "src": src}}
        if not cf_ready():
            # never applied (Cloudflare isn't set up): the likely intent was the port proxy
            legacy.append(("geo", o, "this was a Cloudflare (websites) rule, and Cloudflare isn't set up, so it never applied",
                           {"name": p["name"], "mode": mode, "spec": {"where": ["ports"] if L4_NODES else ["web"],
                                                                      "action": "block", "src": src}}))
            continue
        take("geo", o, p, "country/network rule")
    for r in old.get("l4") or []:
        spec = {"where": ["ports"], "action": "block", "proto": r["proto"], "ports": r["ports"], "state": "new"}
        if r["kind"] == "rate":
            spec["limit"] = {"what": "conn", "n": r["rate"], "per": "minute", "burst": r["burst"] or 0, "by": "ip"}
        else:
            spec["src"] = [("cn:" if s["kind"] == "cn" else "as:") + s["value"] for s in r["src"]]
        take("l4", r, {"id": new_id(), "name": r["desc"] or "port-proxy rule", "mode": r["mode"], "enabled": r["enabled"],
                       "created": r["created"], "updated": r["updated"], "who": r["who"], "spec": spec}, "port-proxy rule")
    return pol, legacy


def add_legacy(con, kind, old, reason, suggest):
    j = json.dumps(old, sort_keys=True)
    if con.execute("SELECT 1 FROM waf_legacy WHERE old=?", (j,)).fetchone():
        return
    con.execute("INSERT INTO waf_legacy(ts,kind,old,reason,suggest,state) VALUES(?,?,?,?,?,'open')",
                (time.time(), kind, j, reason[:500], json.dumps(suggest) if suggest else None))


_ENSURED = set()


def ensure(con):
    """One-time update to the rule model of 2.8.0 (old tables are emptied, their rows kept in waf_legacy_src for reference)."""
    if id(con) in _ENSURED or db.kv_get(con, "waf_model", 1) == MODEL:
        _ENSURED.add(id(con))
        return
    old = _old_state(con)
    if old["rules"] or old["geo"] or old["l4"]:
        pol, legacy = convert(old)
        for p in pol:
            con.execute("INSERT OR REPLACE INTO waf_policy(id,name,mode,enabled,spec,created,updated,who,origin) VALUES(?,?,?,?,?,?,?,?,?)",
                        (p["id"], p["name"], p["mode"], int(p["enabled"]), json.dumps(p["spec"]), p["created"], p["updated"], p["who"],
                         "migrated " + p["origin"]))
        for lg in legacy:
            add_legacy(con, *lg)
        db.kv_set(con, "waf_legacy_src", old)
        con.execute("DELETE FROM waf_rules"); con.execute("DELETE FROM waf_geo"); con.execute("DELETE FROM waf_l4")
        db.add_event(con, "waf", f"Edge WAF: {len(pol)} rule{'s' if len(pol) != 1 else ''} moved to the new rule format"
                     + (f", {len(legacy)} need you" if legacy else ""), severity="warning" if legacy else "info",
                     detail="; ".join(f"{k}: {r}" for k, _, r, _ in legacy)[:500])
        db.kv_set(con, "waf_migrated", {"ts": time.time(), "moved": len(pol), "legacy": len(legacy), "pending_apply": True})
    db.kv_set(con, "waf_model", MODEL)
    refresh_items(con)


def legacy_rows(con, open_only=True):
    q = "SELECT id,ts,kind,old,reason,suggest,state FROM waf_legacy" + (" WHERE state='open'" if open_only else "") + " ORDER BY id"
    return [{"id": r[0], "ts": r[1], "kind": r[2], "old": json.loads(r[3]), "reason": r[4],
             "suggest": json.loads(r[5]) if r[5] else None, "state": r[6]} for r in con.execute(q)]


def legacy_txt(lg):
    o, k = lg["old"], lg["kind"]
    if k == "rule":
        return f"web rule #{o.get('id')} “{o.get('desc')}” ({o.get('mode')}) on {', '.join(o.get('hosts') or []) or 'every site'}: " + \
            "; ".join(f"{c.get('zone')}{'/' + c['var'] if c.get('var') else ''} {c.get('op')} {c.get('value', '')}".strip() for c in o.get("match") or [])
    if k == "geo":
        return f"{o.get('action')} {', '.join(o.get('countries_networks') or [])} on {o.get('where')} ({o.get('mode')})"
    return f"port-proxy rule #{o.get('id')} “{o.get('desc')}” ({o.get('mode')}): {o.get('proto')} {o.get('ports')}, " + \
        (f"over {o.get('rate')}/min new connections per IP (burst {o.get('burst') or 0})" if o.get("kind") == "rate"
         else "from " + ", ".join(("" if s["kind"] == "cn" else "AS") + s["value"] for s in o.get("src") or []))


def refresh_items(con):
    """Edge WAF items: old rules that still need recreating, port proxies on an old agent (count towards the Edge WAF tab)."""
    active = set()
    lg = legacy_rows(con)
    if lg:
        active.add("waf:legacy")
        db.upsert_item(con, "waf:legacy", "waf", f"{len(lg)} old WAF rule{'s' if len(lg) != 1 else ''} couldn't move to the new rule format",
                       "Open Edge WAF → WAF rules: each one is listed with all its details and a Fix button that opens it in the "
                       "builder.\n" + "\n".join(f"• {legacy_txt(x)} — {x['reason']}" for x in lg)[:1800], "warning", kind="condition")
    for n, a in (db.kv_get(con, "waf_agents", {}) or {}).items():
        if n in L4_NODES and a.get("v", 1) < 3:
            k = f"waf:agent:{n}"
            active.add(k)
            sk = a.get("skipped") or []
            db.upsert_item(con, k, "waf", f"Port proxy {n} runs an old WAF agent" + (f": {len(sk)} rule{'s' if len(sk) != 1 else ''} not applied" if sk else ""),
                           f"Re-run install-agent.sh on {n} (same roles) to update logwatch-nfwafctl. " +
                           ("Until then it only takes simple source and connection-rate rules, IPv4 only, and changes aren't confirmed "
                            "(no automatic revert)." if a.get("v", 1) < 2 else "Until then rules with TCP flags, ICMP types, schedules, DSCP, "
                            "OS fingerprints or dynamic lists, and the port-scan trap, don't apply there.")
                           + (f"\nNot applied there: rule #{', #'.join(str(i) for i in sk)}" if sk else ""),
                           "warning" if sk else "info", kind="condition")
    db.clear_conditions(con, "waf", active)


# ---------------------------------------------------------------- engine payloads

def ban_list(st, now=None):
    now = now or time.time()
    bans = []
    for b in st["bans"]:
        if b["expires"] and b["expires"] <= now:
            continue
        bans.append({"id": b["id"], "value": b["value"],
                     "dur": "permanent" if not b["expires"] else f"{max(1, math.ceil((b['expires'] - now) / 3600))}h"})
    return bans


def live(st, where):
    return [p for p in st["policies"] if p["enabled"] and where in p["spec"]["where"]]


# ---------------------------------------------------------------- lists + feeds

_FEED = {}   # feed key → {ts, values, err} (mirror of kv waf_feed:<key>)


def feed_values(key):
    f = FEEDS.get(key) or {}
    if f.get("static"):
        return list(f["static"])
    if key not in _FEED:
        with db.connect() as con:
            _FEED[key] = db.kv_get(con, f"waf_feed:{key}", {}) or {}
    return _FEED[key].get("values") or []


def _global_net(v):
    try:
        n = ipaddress.ip_network(v.strip(), strict=False)
    except ValueError:
        return None
    if not n.is_global or n.prefixlen < (8 if n.version == 4 else 19):
        return None
    return str(n.network_address) if n.num_addresses == 1 else str(n)


def fetch_feed(key):
    """Download one threat feed → sorted public networks (raises on failure; the last good copy stays)."""
    f = FEEDS[key]
    vals = set()
    if f.get("via") == "capi":
        if not NODES:
            raise Bad("needs an edge node with role waf (it holds the CrowdSec blocklist)")
        r = wafctl(NODES[0], "capi", timeout=150)
        if not r.get("ok"):
            raise Bad(r.get("err", "capi failed")[:200])
        raw = r.get("values") or []
    else:
        raw = []
        with httpx.Client(timeout=40, follow_redirects=True, headers={"User-Agent": "logwatch-dashboard"}) as cli:
            for u in f["url"]:
                t = cli.get(u)
                t.raise_for_status()
                if f["fmt"] == "lines":
                    raw += [ln.split("#")[0].split(";")[0].strip() for ln in t.text.splitlines()]
                elif f["fmt"] == "ndjson":
                    for ln in t.text.splitlines():
                        try:
                            raw.append(json.loads(ln).get("cidr") or "")
                        except ValueError:
                            pass
                else:
                    raw += [p.get("ipv4Prefix") or p.get("ipv6Prefix") or "" for p in t.json().get("prefixes") or []]
    for v in raw:
        g = _global_net(v) if v else None
        if g:
            vals.add(g)
    if not vals:
        raise Bad("the feed came back empty")
    return sorted(vals)


def refresh_feeds(con, force=None):
    """Feeds that a list uses, when older than their interval (or force=key). Returns the keys whose content changed."""
    used = {l.get("feed") for l in db.kv_get(con, "waf_lists", []) or [] if l["kind"] == "feed"}
    changed = []
    for key in sorted(k for k in used if k in FEEDS and not FEEDS[k].get("static")):
        cur = db.kv_get(con, f"waf_feed:{key}", {}) or {}
        if force != key and cur.get("tried", 0) > time.time() - FEEDS[key]["hours"] * 3600:
            continue
        try:
            vals = fetch_feed(key)
            new = {"ts": time.time(), "tried": time.time(), "values": vals, "err": ""}
            if vals != cur.get("values"):
                changed.append(key)
        except Exception as e:
            new = dict(cur, tried=time.time(), err=f"{type(e).__name__}: {e}"[:200])
        db.kv_set(con, f"waf_feed:{key}", new)
        _FEED[key] = new
    return changed


def feed_info(con):
    out = {}
    for k, f in FEEDS.items():
        c = {} if f.get("static") else db.kv_get(con, f"waf_feed:{k}", {}) or {}
        out[k] = {"name": f["name"], "why": f["why"], "static": bool(f.get("static")), "n": len(f.get("static") or c.get("values") or []),
                  "ts": c.get("ts"), "err": c.get("err", ""), "hours": f.get("hours")}
    return out


def clean_list(x, lists):
    """A list from the UI → checked. lists = {id: list} today (names are unique; a list's kind never changes)."""
    if not isinstance(x, dict):
        raise Bad("bad list")
    name = re.sub(r"\s+", " ", str(x.get("name") or "")).strip()[:60]
    if not name:
        raise Bad("give the list a name")
    lid = int(x.get("id") or 0)
    old = lists.get(lid)
    if lid and not old:
        raise Bad("no such list")
    kind = old["kind"] if old else x.get("kind")
    if kind not in LIST_KINDS:
        raise Bad("list kind: " + " | ".join(LIST_KINDS))
    if any(l["name"].lower() == name.lower() and l["id"] != lid for l in lists.values()):
        raise Bad(f"there's already a list called '{name}'")
    out = {"id": lid or max(list(lists) + [0]) + 1, "name": name, "kind": kind, "note": str(x.get("note") or "").strip()[:200],
           "updated": time.time()}
    ent = x.get("entries")
    if isinstance(ent, str):
        ent = [e for e in re.split(r"[\s,;]+", ent) if e]
    ent = ent or []
    if kind == "ports":
        out["entries"] = clean_ports(", ".join(str(e) for e in ent), name)
        if "list:" in out["entries"] or not out["entries"]:
            raise Bad("a port list holds ports and ranges like 443, 8000-8100")
    elif kind == "addr":
        out["entries"] = clean_src(ent, name, maxn=10000, lists=False)
        if not out["entries"]:
            raise Bad("an address list holds IPs, ranges, countries (DE) or networks (AS14061)")
    elif kind == "hosts":
        out["entries"] = list(dict.fromkeys(str(h).strip().lower() for h in ent if str(h).strip()))
        if not out["entries"] or any(not HOST_RE.match(h) for h in out["entries"]) or len(out["entries"]) > 200:
            raise Bad("a site list holds 1-200 site names like app.example.com or *.example.com")
    elif kind == "feed":
        out["feed"] = old["feed"] if old else x.get("feed")
        if out["feed"] not in FEEDS:
            raise Bad("feed: " + ", ".join(FEEDS))
    else:
        try:
            out["timeout"] = int(x.get("timeout") or 3600)
        except (TypeError, ValueError):
            raise Bad("timeout in seconds")
        if not 60 <= out["timeout"] <= 30 * 86400:
            raise Bad("timeout: 1 minute to 30 days")
        out["enforce"] = bool(x.get("enforce"))
        if sum(1 for l in lists.values() if l["kind"] == "dynamic" and l["id"] != lid) >= 16:
            raise Bad("up to 16 dynamic lists")
    return out


def list_users(st, lid):
    """Rules (and the trap) that use list lid."""
    out = [f"rule #{p['id']}" for p in st["policies"] if any(i == lid for _, i in list_refs(p["spec"]))]
    if (st.get("trap") or {}).get("list") == lid:
        out.append("the port-scan trap")
    return out


def clean_trap(t, lists):
    """Port-scan trap settings from the UI: {on, mode, list (a dynamic list), n closed ports a minute, secs, decoys}."""
    if not isinstance(t, dict):
        raise Bad("bad trap")
    lid = int(t.get("list") or 0)
    if t.get("on") and (lists.get(lid) or {}).get("kind") != "dynamic":
        raise Bad("the trap fills a dynamic list: pick or create one in Lists")
    mode = t.get("mode") or "log"
    if mode not in ("log", "enforce"):
        raise Bad("trap mode: log or enforce")
    try:
        n, secs = int(t.get("n") or 10), int(t.get("secs") or 3600)
    except (TypeError, ValueError):
        raise Bad("trap: numbers only")
    if not 2 <= n <= 1000 or not 60 <= secs <= 30 * 86400:
        raise Bad("trap: 2-1000 closed ports a minute, 60 s to 30 days on the list")
    dec = clean_ports(str(t.get("decoys") or ""), "decoy ports")
    if "list:" in dec:
        raise Bad("decoy ports: plain ports, not lists")
    if dec and len(dec.split(",")) > 32:
        raise Bad("up to 32 decoy ports")
    return {"on": bool(t.get("on")), "mode": mode, "list": lid or None, "n": n, "secs": secs, "decoys": dec}


def _L(st):
    return {l["id"]: l for l in st.get("lists") or []}


def x_src(src, L, family="any", expand=True):
    """Sources with list:<id> replaced by what the list holds (dynamic lists drop out: they're 'dyn' on the port proxy)."""
    out = []
    for v in src:
        if not v.startswith("list:"):
            out.append(v)
            continue
        lst = L.get(int(v[5:]))
        if not lst or lst["kind"] == "dynamic":
            continue
        if lst["kind"] == "addr":
            out += lst["entries"]
        elif expand:
            out += feed_values(lst["feed"])
        else:
            out += [x for x in feed_values(lst["feed"]) if x.startswith(("cn:", "as:"))][:3] or [DUMMY[4]]
    return list(dict.fromkeys(out))


def x_ports(ports, L):
    out = []
    for p in [p.strip() for p in str(ports or "").split(",") if p.strip()]:
        if p.startswith("list:"):
            lst = L.get(int(p[5:]))
            out += [q.strip() for q in (lst or {}).get("entries", "").split(",") if q.strip()]
        else:
            out.append(p)
    return ", ".join(dict.fromkeys(out))


def x_hosts(hosts, L):
    out = []
    for h in hosts:
        out += (L.get(int(h[5:])) or {}).get("entries", []) if h.startswith("list:") else [h]
    return list(dict.fromkeys(out))


def rate_doc(p, L):
    s, r = p["spec"], p["spec"]["rate"]
    return {"id": p["id"], "kind": r["kind"], "mode": p["mode"], "key": r["key"], "n": r["n"], "secs": r["secs"], "ban": r["ban"],
            "desc": p["name"], "hosts": x_hosts(s["hosts"], L)[:10], "paths": r["paths"], "methods": r["methods"], "statuses": r["statuses"]}


def edge_payload(st, now=None, v=2):
    L = _L(st)
    web = live(st, "web")
    p = {"rules": [{"id": p["id"], "mode": p["mode"], "desc": p["name"], "hosts": x_hosts(p["spec"]["hosts"], L), "match": p["spec"]["match"]}
                   for p in web if web_kind(p["spec"]) == "appsec"], "bans": ban_list(st, now)}
    if st["crs"]:
        p["crs"] = st["crs"]
    if v >= 2:
        p["scenarios"] = [rate_doc(x, L) for x in web if web_kind(x["spec"]) == "rate"]
        lids = sorted({int(s[5:]) for x in web if web_kind(x["spec"]) == "list" and x["mode"] == "enforce" for s in x["spec"]["src"]})
        p["lists"] = [{"id": i, "values": [v_ for v_ in feed_values(L[i]["feed"]) if not v_.startswith(("cn:", "as:"))]} for i in lids if i in L]
    return p


def expand_src(src, expand=True, family="any"):
    nets = [s for s in src if not s.startswith(("cn:", "as:"))]
    geo_ = [s for s in src if s.startswith(("cn:", "as:"))]
    if geo_:
        if expand:
            nets += geo_cidrs(geo_)
        else:
            nets += [DUMMY[v] for v in (4, 6) if family in ("any", f"ip{v}")]
    return nets


def l4_rule(p, st, expand=True):
    s, L = p["spec"], _L(st)
    lim = s.get("limit")
    r = {"id": p["id"], "mode": p["mode"], "action": s["action"], "proto": s["proto"], "ports": x_ports(s["ports"], L), "sports": s["sports"],
         "src": expand_src(x_src(s["src"], L, expand=expand), expand, s["family"]),
         "src_not": expand_src(x_src(s["src_not"], L, expand=expand), expand, s["family"]),
         "dst": s["dst"], "state": s["state"], "family": s["family"], "tcp_bad": s["tcp_bad"], "nosyn": s["nosyn"], "mss": s["mss"],
         "ttl": s["ttl"], "len": s["len"], "frag": s["frag"], "bogon": s["bogon"], "spoof": s["spoof"], "mac": s["mac"],
         "vlan": s["vlan"], "payload": s["payload"], "limit": dict(lim) if lim else None}
    dyn = [int(x[5:]) for x in s["src"] if x.startswith("list:") and (L.get(int(x[5:])) or {}).get("kind") == "dynamic"]
    for k in V3:
        if has(s, k):
            r[k] = s[k]
    if dyn:
        r["dyn"] = dyn
    return r


def needs_v3(r):
    return any(r.get(k) for k in V3 + ("dyn",))


def l4_payload(st, node=None, now=None, expand=True):
    """What a port proxy gets (agent v3): every ban, its enabled port rules (countries/networks/lists expanded to CIDRs here),
    the dynamic lists and the port-scan trap."""
    rules = [l4_rule(p, st, expand) for p in live(st, "ports") if not node or not p["spec"]["nodes"] or node in p["spec"]["nodes"]]
    dyn = [{"id": l["id"], "enforce": l["enforce"]} for l in st.get("lists") or [] if l["kind"] == "dynamic"]
    t = st.get("trap") or {}
    trap = {k: t[k] for k in ("mode", "list", "n", "secs", "decoys")} if t.get("on") and t.get("list") in {d["id"] for d in dyn} else None
    return {"v": 3, "bans": ban_list(st, now), "rules": rules, "dyn": dyn, "trap": trap}


def l4_payload_v2(st, node, now=None):
    """The same for an agent from 2.8.x: rules that need v3 (new checks, dynamic lists) are left out."""
    p = l4_payload(st, node, now)
    skipped = [r["id"] for r in p["rules"] if needs_v3(r)]
    return {"v": 2, "bans": p["bans"], "rules": [r for r in p["rules"] if not needs_v3(r)]}, skipped


def l4_payload_v1(st, node, now=None):
    """The same for an agent from before 2.8.0: only what its format can say (source sets, new-connection rate per IP, IPv4)."""
    rules, skipped = [], []
    L = _L(st)
    for p in live(st, "ports"):
        s = p["spec"]
        if s["nodes"] and node not in s["nodes"]:
            continue
        lim = s.get("limit")
        other = [k for k in PORT_FIELDS if has(s, k) and k not in ("proto", "ports", "limit", "nodes", "state")]
        simple_lim = lim and lim["what"] == "conn" and lim["per"] == "minute" and lim["by"] == "ip"
        if s["action"] != "block" or other or s["src_not"] or s["state"] not in ("", "new") or s["proto"] == "icmp" \
                or (lim and not simple_lim) or (lim and s["src"]) or not (lim or s["src"]) \
                or any((L.get(int(x[5:])) or {}).get("kind") == "dynamic" for x in s["src"] if x.startswith("list:")):
            skipped.append(p["id"])
            continue
        x = {"id": p["id"], "mode": p["mode"], "proto": s["proto"], "ports": x_ports(s["ports"], L)}
        if lim:
            x.update(kind="rate", rate=min(lim["n"], 100000), burst=min(lim["burst"], 100000))
        else:
            x.update(kind="geo", cidrs=[c for c in expand_src(x_src(s["src"], L)) if ":" not in c])
        rules.append(x)
    return {"bans": [b for b in ban_list(st, now) if ":" not in b["value"]], "l4": rules}, skipped


_GEO = {}   # (kind, value, mmdb mtime) → [CIDRs]


def geo_cidrs(src):
    """'cn:DE' / 'as:14061' → collapsed IPv4 + IPv6 CIDRs from the GeoIP databases (one pass over the database per miss, cached)."""
    import maxminddb
    import geo
    res = []
    for kind, fname, get in (("cn", geo.COUNTRY, lambda rec: ((rec or {}).get("country") or {}).get("iso_code")),
                             ("as", geo.ASN, lambda rec: str((rec or {}).get("autonomous_system_number") or ""))):
        want = {s[3:] for s in src if s.startswith(kind + ":")}
        if not want:
            continue
        mt = fname.stat().st_mtime
        miss = {v for v in want if (kind, v, mt) not in _GEO}
        if miss:
            found = {v: ([], []) for v in miss}
            with maxminddb.open_database(str(fname)) as rd:
                for net, rec in rd:
                    k = get(rec)
                    if k in found:
                        if net.version == 6 and net.subnet_of(ipaddress.ip_network("::ffff:0:0/96")):
                            continue      # IPv4-mapped copies of the IPv4 networks
                        found[k][net.version == 6].append(net)
            for v, (n4, n6) in found.items():
                _GEO[(kind, v, mt)] = [str(n) for n in ipaddress.collapse_addresses(n4)] + [str(n) for n in ipaddress.collapse_addresses(n6)]
        for v in want:
            res += _GEO[(kind, v, mt)]
    return res


# ---------------------------------------------------------------- Cloudflare expressions

def cf_src(src):
    ips = [s for s in src if not s.startswith(("cn:", "as:"))]
    cn = sorted(s[3:] for s in src if s.startswith("cn:"))
    asn = sorted(int(s[3:]) for s in src if s.startswith("as:"))
    parts = ([f"ip.src in {{{' '.join(ips)}}}"] if ips else []) + \
            ([f'ip.src.country in {{{" ".join(json.dumps(c) for c in cn)}}}'] if cn else []) + \
            ([f"ip.src.asnum in {{{' '.join(str(a) for a in asn)}}}"] if asn else [])
    return "(" + " or ".join(parts) + ")" if len(parts) > 1 else parts[0] if parts else ""


def cf_cond(c):
    f, typ = CF_FIELDS[c["f"]]
    op, v = c["op"], c.get("v", "")
    if typ == "bool":
        return f if op == "is" else f"not {f}"
    if typ == "names":
        e = f"any({f}[*] == {json.dumps(v)})"
        return e if op == "is" else f"not {e}"
    if op in ("in", "notin"):
        vals = [x.strip() for x in v.split(",") if x.strip()]
        e = f"{f} in {{{' '.join(json.dumps(x) for x in vals)}}}"
        return e if op == "in" else f"not {e}"
    return {"eq": f"{f} eq {json.dumps(v)}", "ne": f"{f} ne {json.dumps(v)}", "contains": f"{f} contains {json.dumps(v)}",
            "starts": f"starts_with({f}, {json.dumps(v)})", "ends": f"ends_with({f}, {json.dumps(v)})"}[op]


def cf_policy_expr(spec, L=None):
    p, L = [], L or {}
    src, src_not, hosts = x_src(spec["src"], L), x_src(spec["src_not"], L), x_hosts(spec["hosts"], L)
    if src:
        p.append(cf_src(src))
    if src_not:
        p.append(f"not {cf_src(src_not)}")
    if hosts:
        ex = [h for h in hosts if not h.startswith("*.")]
        hs = ([f'http.host in {{{" ".join(json.dumps(h) for h in ex)}}}'] if ex else []) + \
             [f'ends_with(http.host, {json.dumps(h[1:])})' for h in hosts if h.startswith("*.")]
        p.append("(" + " or ".join(hs) + ")" if len(hs) > 1 else hs[0])
    p += [cf_cond(c) for c in spec.get("cf") or []]
    return " and ".join(p)


def cf_rules(st, now=None):
    """[(description, action, expression)] in order: bans first (they always win), then allow, block, challenge."""
    now = now or time.time()
    bans = [b for b in st["bans"] if not b["expires"] or b["expires"] > now]
    out = [(CF_PREFIX + "banned IPs", "block", f"ip.src in ${CF_LIST}" if any(cf_item(b["value"]) for b in bans) else "")]
    pols = [p for p in live(st, "web") if web_kind(p["spec"]) == "cf" and p["mode"] == "enforce"]
    for action, cfa, name in (("allow", "skip", "allow rules"), ("block", "block", "block rules"), ("challenge", "managed_challenge", "challenge rules")):
        ex = [cf_policy_expr(p["spec"], _L(st)) for p in pols if p["spec"]["action"] == action]
        out.append((CF_PREFIX + name, cfa, " or ".join(f"({e})" for e in ex) if len(ex) > 1 else ex[0] if ex else ""))
    return [x for x in out if x[2]]


# ---------------------------------------------------------------- check / push

def _run_check(script, payload):
    r = subprocess.run(["python3", "-I", str(_script(script)), "check"], input=json.dumps(payload), capture_output=True, text=True, timeout=30)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "err": (r.stderr or "validator failed")[-300:]}


def check(st):
    """Validate with the engines' own code. Returns (ok, error)."""
    if any("ports" in p["spec"]["where"] for p in st["policies"]) or (st.get("trap") or {}).get("on"):
        out = _run_check("logwatch-nfwafctl", l4_payload(st, expand=False))
        if not out.get("ok"):
            return False, "port proxy: " + out.get("err", "")
    for desc, _, expr in cf_rules(st):
        if len(expr) > CF_MAX_EXPR:
            return False, f"Cloudflare: '{desc[len(CF_PREFIX):]}' would be {len(expr)} characters (limit {CF_MAX_EXPR}): use fewer IPs, or ranges"
    out = _run_check("logwatch-wafctl", edge_payload(st))
    return out.get("ok", False), out.get("err", "")


def wafctl(node, cmd, stdin=None, timeout=150, role="waf"):
    try:
        r = remote.run(node, f"{role} {cmd}", timeout=timeout, stdin=stdin)
        return json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else {"ok": False, "err": r.stderr.strip()[-300:]}
    except Exception as e:
        return {"ok": False, "err": f"{type(e).__name__}: {e}"[:300]}


def cf_token():
    return secret("CLOUDFLARE_API_TOKEN")


def cf_ready():
    """Cloudflare is a usable layer: zone + account IDs and the API token are all there."""
    return bool(CF.get("zone") and CF.get("account") and cf_token())


def needs(op, body):
    """Refuses changes for a layer that isn't set up (rules are checked per rule in clean_policy)."""
    if op == "crs_set" and not NODES:
        raise Bad("the WAF engine isn't on any edge node yet (no host with role waf): CRS settings can't apply")
    if op == "ban_add" and not (NODES or L4_NODES or cf_ready()):
        raise Bad("no layer to ban on: no edge node with role waf, no port proxy and no Cloudflare")


def cf_call(cli, method, path, **kw):
    r = cli.request(method, CF_API + path, **kw)
    d = r.json() if r.content else {}
    if not d.get("success", r.is_success):
        raise Bad(f"Cloudflare {method} {path.split('?')[0]}: " + ("; ".join(e.get("message", "") for e in d.get("errors") or []) or str(r.status_code)))
    return d.get("result")


def cf_item(value):
    """A ban as a CF list item, or None when CF can't hold it exactly (IPv6 prefixes longer than /64)."""
    net = ipaddress.ip_network(value, strict=False)
    if net.num_addresses == 1:
        return str(net.network_address)
    if net.version == 6 and net.prefixlen > 64:
        return None
    return str(net)


def cf_body(desc, action, expr):
    b = {"description": desc, "action": action, "expression": expr, "enabled": True}
    if action == "skip":
        b["action_parameters"] = {"ruleset": "current"}
        b["logging"] = {"enabled": True}
    return b


def push_cf(st, now=None):
    if not CF.get("zone") or not CF.get("account"):
        return {"ok": True, "skipped": "Cloudflare not configured"}
    tok = cf_token()
    if not tok:
        return {"ok": False, "err": "secret CLOUDFLARE_API_TOKEN missing"}
    now = now or time.time()
    z, a = CF["zone"], CF["account"]
    bans = [b for b in st["bans"] if not b["expires"] or b["expires"] > now]
    items = [(cf_item(b["value"]), b) for b in bans]
    skipped = [b["value"] for i, b in items if not i]
    want = cf_rules(st, now)
    done = []
    try:
        with httpx.Client(timeout=30, headers={"Authorization": f"Bearer {tok}"}) as cli:
            lists = cf_call(cli, "GET", f"/accounts/{a}/rules/lists") or []
            lst = next((x for x in lists if x["name"] == CF_LIST), None)
            if any(i for i, _ in items) and not lst:
                lst = cf_call(cli, "POST", f"/accounts/{a}/rules/lists",
                              json={"name": CF_LIST, "kind": "ip", "description": "Edge WAF bans (managed by the Logwatch board)"})
                done.append("created list")
            if lst:
                cf_call(cli, "PUT", f"/accounts/{a}/rules/lists/{lst['id']}/items",
                        json=[{"ip": i, "comment": f"lw-waf:{b['id']}"} for i, b in items if i])
                done.append(f"list {sum(1 for i, _ in items if i)} IPs")
            rs = cf_call(cli, "GET", f"/zones/{z}/rulesets/phases/http_request_firewall_custom/entrypoint")
            have = [r for r in rs.get("rules") or [] if (r.get("description") or "").startswith(CF_PREFIX)]
            if [r["description"] for r in have] == [d for d, _, _ in want]:
                for cur, (desc, action, expr) in zip(have, want):
                    if cur.get("expression") != expr or cur.get("action") != action or not cur.get("enabled"):
                        cf_call(cli, "PATCH", f"/zones/{z}/rulesets/{rs['id']}/rules/{cur['id']}", json=cf_body(desc, action, expr))
                        done.append(f"updated '{desc[len(CF_PREFIX):]}'")
            else:   # order matters (bans, allow, block, challenge): rebuild ours in order, other rules untouched
                for cur in have:
                    cf_call(cli, "DELETE", f"/zones/{z}/rulesets/{rs['id']}/rules/{cur['id']}")
                for desc, action, expr in want:
                    cf_call(cli, "POST", f"/zones/{z}/rulesets/{rs['id']}/rules", json=cf_body(desc, action, expr))
                done.append(f"rules rebuilt ({', '.join(d[len(CF_PREFIX):] for d, _, _ in want) or 'none'})")
    except (Bad, httpx.HTTPError, ValueError) as e:
        return {"ok": False, "err": str(e)[:300], "done": done}
    return {"ok": True, "done": done or ["no change"], "not_on_cf": skipped}


def push_l4(node, st, agents):
    """One port proxy: agent v2+ gets everything its format can say and must confirm the change over a new connection
    (else it reverts itself)."""
    s = wafctl(node, "status", timeout=30, role="l4waf")
    if not s.get("ok"):
        return {"ok": False, "err": "status: " + s.get("err", "unreachable")}
    v = int(s.get("v") or 1)
    if v >= 2:
        p, skipped = (l4_payload(st, node), []) if v >= 3 else l4_payload_v2(st, node)
        r = wafctl(node, "apply", json.dumps(p), role="l4waf")
        agents[node] = {"v": v, "skipped": skipped, "osf": bool(s.get("osf"))}
        if skipped:
            r["note"] = f"old agent: rule #{', #'.join(map(str, skipped))} not applied"
        if r.get("ok") and r.get("pending"):
            c = wafctl(node, f"confirm {r['pending']}", timeout=30, role="l4waf")
            if not c.get("ok"):
                return {"ok": False, "err": f"applied, but the confirmation didn't get through ({c.get('err', '')[:120]}): the port "
                                            f"proxy puts the previous rules back within {r.get('confirm_within', 120)} s"}
            r["confirmed"] = True
        return r
    p, skipped = l4_payload_v1(st, node)
    r = wafctl(node, "apply", json.dumps(p), role="l4waf")
    agents[node] = {"v": v, "skipped": skipped}
    r["old_agent"] = True
    if skipped:
        r["note"] = f"old agent: rule #{', #'.join(map(str, skipped))} not applied"
    return r


def apply(who, summary):
    """Push the stored state to every layer and record it (no DB lock held while pushing). Returns (ok, result)."""
    with LOCK:
        with db.connect() as con:
            st = state(con)
            agents = db.kv_get(con, "waf_agents", {}) or {}
        ok, err = check(st)
        res = {"edge": {}, "cf": {"ok": False, "err": "not pushed"}}
        if not ok:
            res["edge"]["_"] = {"ok": False, "err": err}
        else:
            res["cf"] = push_cf(st)
            ep = edge_payload(st)
            payload = json.dumps(ep)
            if not NODES:
                res["edge"]["_"] = {"ok": True, "skipped": "engine not deployed: saved on the board only"}
            for n in NODES:
                r = wafctl(n, "apply", payload)
                if r.get("ok") and int(r.get("v") or 1) < 2 and (ep.get("scenarios") or ep.get("lists")):
                    r["note"] = "old agent: rate limits and feeds not applied (re-run install-agent.sh)"
                res["edge"][n] = r
            for n in L4_NODES:
                try:
                    res["edge"][n + " (ports)"] = push_l4(n, st, agents)
                except Exception as e:   # GeoIP database missing/unreadable: the other layers still went out
                    res["edge"][n + " (ports)"] = {"ok": False, "err": f"port proxy: {type(e).__name__}: {e}"[:300]}
        good = bool(res["cf"].get("ok") and all(x.get("ok") for x in res["edge"].values()))
        with db.connect() as con:
            cur = con.execute("INSERT INTO waf_audit(ts,who,summary,state,result,ok) VALUES(?,?,?,?,?,?)",
                              (time.time(), who, summary[:300], json.dumps(st), json.dumps(res), int(good)))
            res["audit"] = cur.lastrowid
            db.kv_set(con, "waf_agents", agents)
            m = db.kv_get(con, "waf_migrated")
            if m and m.get("pending_apply") and ok:
                db.kv_set(con, "waf_migrated", dict(m, pending_apply=False))
            refresh_items(con)
            db.add_event(con, "waf", f"Edge WAF: {summary}"[:200], severity="info" if good else "warning",
                         detail=f"{who} · " + brief(res))
        return good, res


def stage(con, st=None):
    """Validate the state about to be committed (raises Bad, so the caller's transaction rolls back)."""
    st = st or state(con)
    ok, err = check(st)
    if not ok:
        raise Bad(err)


def brief(res):
    out = []
    for n, r in res.get("edge", {}).items():
        out.append(r.get("skipped") or f"{n}: " + ("ok" if r.get("ok") else r.get("err", "failed")) + (f" ({r['note']})" if r.get("note") else ""))
    cf = res.get("cf") or {}
    out.append("CF: " + (cf.get("skipped") or (", ".join(cf.get("done") or []) if cf.get("ok") else cf.get("err", "failed"))))
    return " · ".join(out)[:500]


def undo(audit_id, who):
    """Put back the state from before change #audit_id and apply it."""
    with db.connect() as con:
        if not con.execute("SELECT 1 FROM waf_audit WHERE id=?", (audit_id,)).fetchone():
            raise Bad("no such change")
        prev = con.execute("SELECT state FROM waf_audit WHERE id<? ORDER BY id DESC LIMIT 1", (audit_id,)).fetchone()
        st = json.loads(prev[0]) if prev else {"model": MODEL, "policies": [], "bans": [], "crs": None}
        put_state(con, st)
        refresh_items(con)
    return apply(who, f"undo change #{audit_id}")


def sweep():
    """Runs after every check run:
    · expired bans leave the board (CrowdSec and nftables expire them themselves; Cloudflare lists don't)
    · rules past their expiry are switched off · threat feeds are refreshed · Under Attack follows its timer/schedule
    · auto-escalation (when on) bans repeat offenders for longer · suggested rules are refreshed every 30 min
    Also pushes once after the update converted old rules, so the layers get the new format."""
    now, why = time.time(), []
    with db.connect() as con:
        state(con)
        n = con.execute("DELETE FROM waf_bans WHERE expires IS NOT NULL AND expires<=?", (now,)).rowcount
        if n:
            why.append(f"{n} expired ban{'s' if n != 1 else ''} removed")
        for pid, name, spec in con.execute("SELECT id,name,spec FROM waf_policy WHERE enabled=1").fetchall():
            ex = json.loads(spec).get("expires")
            if ex and ex <= now:
                con.execute("UPDATE waf_policy SET enabled=0, updated=?, who='board' WHERE id=?", (now, pid))
                why.append(f"rule #{pid} expired ({name})")
        m = db.kv_get(con, "waf_migrated") or {}
        try:
            ch = refresh_feeds(con)
        except Exception:
            ch = []
        if ch:
            st = state(con)
            used = {l["id"] for l in st["lists"] if l["kind"] == "feed" and l.get("feed") in ch}
            if any(i in used for p in st["policies"] if p["enabled"] for _, i in list_refs(p["spec"])):
                why.append("threat feeds refreshed (" + ", ".join(FEEDS[k]["name"] for k in ch) + ")")
        try:
            esc = escalate(con)
        except Exception:
            esc = 0
        if esc:
            why.append(f"{esc} repeat offender{'s' if esc != 1 else ''} banned longer (auto-escalation)")
    try:
        ua_tick()
    except Exception:
        pass
    try:
        with db.connect() as con:
            suggestions(con)      # cached 30 min
    except Exception:
        pass
    if why:
        apply("board", "; ".join(why))
    elif m.get("pending_apply") and (NODES or L4_NODES or cf_ready()):
        apply("board", f"rules moved to the new format ({m.get('moved', 0)} rules)")
    return n


# ---------------------------------------------------------------- auto-escalation

ESC_DEFAULT = {"on": False, "times": 3, "days": 7, "dur": "168h"}


def escalate(con):
    """An IP that got banned again and again (CrowdSec on the edge nodes, dynamic lists on the port proxies) within `days`
    is banned by the board for `dur` on every layer. Off until switched on."""
    cfg = dict(ESC_DEFAULT, **(db.kv_get(con, "waf_escalate", {}) or {}))
    if not cfg["on"]:
        return 0
    now = time.time()
    cur = set()
    for st_ in (db.kv_get(con, "crowdsec", {}) or {}).get("status", []):
        cur |= {b.get("ip") for b in st_.get("bans") or [] if b.get("ip") and not str(b.get("why") or "").startswith(("lw-list", "lw-waf"))}
    for members in ((db.kv_get(con, "waf_hits", {}) or {}).get("dyn") or {}).values():
        cur |= {m["ip"] for m in members}
    seen = db.kv_get(con, "waf_esc_seen", {}) or {}
    have = {r[0] for r in con.execute("SELECT value FROM waf_bans")}
    added = 0
    for ip in cur:
        if not ip or ip in have or not _global_net(ip):
            continue
        rec = seen.get(ip) or {"n": 0, "last": 0, "first": now}
        if now - rec["first"] > cfg["days"] * 86400:
            rec = {"n": 0, "last": 0, "first": now}
        if now - rec["last"] > 1800:      # gone for half an hour = a new ban
            rec["n"] += 1
        rec["last"] = now
        seen[ip] = rec
        if rec["n"] >= cfg["times"]:
            con.execute("INSERT INTO waf_bans(value,expires,note,created,who) VALUES(?,?,?,?,?) ON CONFLICT(value) DO NOTHING",
                        (ip, None if DURS[cfg["dur"]] is None else now + DURS[cfg["dur"]] * 3600,
                         f"auto-escalated: banned {rec['n']} times in {cfg['days']} days", now, "board"))
            added += 1
            seen.pop(ip, None)
    seen = {k: v for k, v in seen.items() if now - v["last"] < cfg["days"] * 86400}
    db.kv_set(con, "waf_esc_seen", dict(sorted(seen.items(), key=lambda kv: -kv[1]["last"])[:5000]))
    return added


# ---------------------------------------------------------------- Under Attack (Cloudflare security level)

def _ua_level(cli, level=None):
    z = CF["zone"]
    if level:
        return cf_call(cli, "PATCH", f"/zones/{z}/settings/security_level", json={"value": level})["value"]
    return cf_call(cli, "GET", f"/zones/{z}/settings/security_level")["value"]


def ua_set(on, who, mins=0, sched=None):
    """Turn Cloudflare's Under Attack mode on (optionally for mins) or back to the level it had before. sched = {hours, days}
    keeps it on during those times (board time). Needs the API token to have Zone Settings: Edit."""
    if not cf_ready():
        raise Bad("Cloudflare isn't set up (zone ID, account ID, API token)")
    with db.connect() as con:
        cur = db.kv_get(con, "waf_ua", {}) or {}
    if sched is not None:
        hr = re.sub(r"\s+", "", str(sched.get("hours") or ""))
        if hr and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d", hr):
            raise Bad("hours like 22:00-06:00")
        sched = {"hours": hr, "days": [d for d in DAYS if d in (sched.get("days") or [])]} if hr or sched.get("days") else None
        cur["sched"] = sched
    try:
        with httpx.Client(timeout=20, headers={"Authorization": f"Bearer {cf_token()}"}) as cli:
            level = _ua_level(cli)
            if on and level != "under_attack":
                cur["prev"] = level
                level = _ua_level(cli, "under_attack")
            elif not on and level == "under_attack":
                level = _ua_level(cli, cur.get("prev") or "medium")
    except Bad as e:
        if "auth" in str(e).lower() or "permission" in str(e).lower() or "9109" in str(e) or "10000" in str(e):
            raise Bad(f"{e} — the API token needs the permission Zone → Zone Settings → Edit")
        raise
    except httpx.HTTPError as e:
        raise Bad(f"Cloudflare: {e}")
    cur.update(on=level == "under_attack", level=level, until=time.time() + mins * 60 if on and mins else None, ts=time.time(), who=who)
    with db.connect() as con:
        db.kv_set(con, "waf_ua", cur)
        db.add_event(con, "waf", f"Cloudflare Under Attack mode {'on' if cur['on'] else 'off'}"
                     + (f" for {mins} min" if on and mins else ""), severity="warning" if cur["on"] else "info", detail=who)
    return cur


def _in_sched(sc, t=None):
    t = time.localtime(t or time.time())
    if sc.get("days") and DAYS[t.tm_wday] not in sc["days"]:
        return False
    if sc.get("hours"):
        a, b = sc["hours"].split("-")
        hm = f"{t.tm_hour:02d}:{t.tm_min:02d}"
        return a <= hm < b if a < b else hm >= a or hm < b
    return True


def ua_tick():
    with db.connect() as con:
        cur = db.kv_get(con, "waf_ua", {}) or {}
    if not cur or not cf_ready():
        return
    want = None
    if cur.get("on") and cur.get("until") and cur["until"] <= time.time():
        want = False
    if cur.get("sched"):
        inside = _in_sched(cur["sched"])
        if inside != bool(cur.get("on")) and (inside or not cur.get("until")) and cur.get("sched_state") != inside:
            want = inside
        cur["sched_state"] = inside
        with db.connect() as con:
            db.kv_set(con, "waf_ua", dict(db.kv_get(con, "waf_ua", {}) or {}, sched_state=inside))
    if want is not None:
        ua_set(want, "board (schedule)" if cur.get("sched") else "board (timer)")


def hits(con, max_age=60):
    """Per-rule hit counts (24 h) from every node, cached. Keys: AppSec rule names, 'l4:<id>' / 'l4:ban' for port proxies."""
    c = db.kv_get(con, "waf_hits", {})
    if c.get("ts", 0) > time.time() - max_age or not (NODES or L4_NODES):
        return c
    rules = {}
    for n, role in [(n, "waf") for n in NODES] + [(n, "l4waf") for n in L4_NODES]:
        r = wafctl(n, "hits 24", timeout=40, role=role)
        for k, v in (r.get("rules") or {}).items():
            k = f"l4:{k}" if role == "l4waf" else k
            x = rules.setdefault(k, {"hits": 0, "ips": 0, "last": "", "packets": 0})
            x["hits"] += v["hits"]; x["ips"] += v["ips"]; x["last"] = max(x["last"], v["last"] or ""); x["packets"] += v.get("packets") or 0
    dyn = {}
    for n in L4_NODES:   # dynamic list members (agent v3)
        r = wafctl(n, "list", timeout=30, role="l4waf")
        for lid, members in (r.get("lists") or {}).items():
            dyn.setdefault(lid, []).extend(dict(m, node=n) for m in members)
    c = {"ts": time.time(), "rules": rules, "dyn": dyn}
    db.kv_set(con, "waf_hits", c)
    agents_check(con)
    return c


def agents_check(con):
    """Port proxy agent versions were only stored at apply time: re-read them so an updated agent clears its warning without a push."""
    agents, changed = db.kv_get(con, "waf_agents", {}) or {}, False
    for n in L4_NODES:
        s = wafctl(n, "status", timeout=30, role="l4waf")
        if not s.get("ok"):
            continue
        v = int(s.get("v") or 1)
        if (agents.get(n) or {}).get("v") != v:
            agents[n] = {"v": v, "skipped": (agents.get(n) or {}).get("skipped", []) if v < 3 else [], "osf": bool(s.get("osf"))}
            changed = True
    if changed:
        db.kv_set(con, "waf_agents", agents)
        refresh_items(con)


# ---------------------------------------------------------------- input from the UI (bans, CRS)

def clean_ban(value, dur):
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise Bad("not an IP or CIDR range")
    if net.is_private or net.is_loopback or net.is_reserved or net.is_multicast or net.is_link_local or net.is_unspecified:
        raise Bad("only public addresses can be banned")
    if (net.version == 4 and net.prefixlen < 16) or (net.version == 6 and net.prefixlen < 32):
        raise Bad("range too wide (smallest /16 IPv4, /32 IPv6)")
    if dur not in DURS:
        raise Bad("bad duration")
    return (str(net.network_address) if net.num_addresses == 1 else str(net)), \
        (None if DURS[dur] is None else time.time() + DURS[dur] * 3600)


def clean_crs(c):
    if not c:
        return None
    if c.get("mode") not in ("log", "enforce") or c.get("pl") not in (1, 2, 3, 4):
        raise Bad("CRS: mode log|enforce, level 1-4")
    return {"mode": c["mode"], "pl": c["pl"], "exclusions": c.get("exclusions") if c.get("exclusions") is not None else CRS_DEFAULT_EXCL}


# ---------------------------------------------------------------- preview: what each engine would get

def _load(name):
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_"), str(_script(name)))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def preview(p):
    """The rule as each layer would run it: nftables text (+ stage), AppSec hub rule, Cloudflare expression."""
    lists = cur_lists()
    p = clean_policy(p, avail=False, lists=lists)
    s = p["spec"]
    out = {"name": p["name"], "sentence": describe(s, L=lists)}
    pol = {"id": 1, "mode": p["mode"], "enabled": True, **p}
    st = {"model": MODEL, "policies": [pol], "bans": [], "crs": None, "lists": list(lists.values()), "trap": None}
    if "web" in s["where"]:
        if web_kind(s) == "list":
            out["edge"] = "the feed's addresses go to every edge node as CrowdSec ban decisions (all sites)" + \
                ("" if p["mode"] == "enforce" else ": not while the rule is log-only")
        elif web_kind(s) in ("appsec", "rate"):
            r = subprocess.run(["python3", "-I", str(_script("logwatch-wafctl")), "check"], capture_output=True, text=True, timeout=20,
                               input=json.dumps(dict(edge_payload(st), preview=True)))
            try:
                o = json.loads(r.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                o = {"ok": False, "err": (r.stderr or "validator failed")[-300:]}
            doc = (o.get("docs") or {}).get("1") or (o.get("scen") or {}).get("1")
            out["appsec"] = json.dumps(doc, indent=1) if o.get("ok") else "error: " + o.get("err", "")
        else:
            out["cf"] = {"expression": cf_policy_expr(s, _L({"lists": list(lists.values())})), "action": {"block": "block", "challenge": "managed_challenge", "allow": "skip"}[s["action"]],
                         "pushed": p["mode"] == "enforce"}
    if "ports" in s["where"]:
        nf = _load("logwatch-nfwafctl")
        try:
            r1 = l4_rule(pol, st, expand=False)
            v = nf.check_payload({"v": 3, "bans": [], "rules": [r1], "dyn": [{"id": i, "enforce": False} for i in
                                  set(r1.get("dyn") or []) | ({r1["ban"]["list"]} if r1.get("ban") else set())]})
            sets = []
            text = "\n".join(nf.rule_lines(v["rules"][0], sets))
            geo_ = [x for x in s["src"] + s["src_not"] if x.startswith(("cn:", "as:"))]
            out["nft"] = {"stage": v["rules"][0]["stage"], "rule": text.strip(), "chain": nf.action_chain(v["rules"][0]).strip(),
                          "sets": [x.strip() for x in sets],
                          "note": f"{', '.join(geo_)} expand to their address ranges on apply (shown as {DUMMY[4]} / {DUMMY[6]} here)" if geo_ else ""}
        except nf.Bad as e:
            out["nft"] = {"error": str(e)}
    return out


# ---------------------------------------------------------------- simulation against the logs

def _vl(query, hours, limit=200000):
    end = time.time()
    r = httpx.post(f"{VL}/select/logsql/query", timeout=60,
                   data={"query": query, "start": str(int(end - hours * 3600)), "end": str(int(end)), "limit": str(limit)})
    r.raise_for_status()
    return [json.loads(x) for x in r.text.splitlines() if x.strip()]


_SEEN = {"ts": 0, "v": {}}


def seen():
    """Hosts, countries, networks and ports in the last 24 h (websites and port proxies apart), for the builder's picks. Cached 10 min."""
    if time.time() - _SEEN["ts"] < 600:
        return _SEEN["v"]
    v = {"hosts": [], "cn": [], "as": [], "pcn": [], "pas": [], "dports": []}
    try:
        for k, q, f in (("hosts", "method:*", "target"), ("cn", "method:*", "cn"), ("as", "method:*", "as"),
                        ("pcn", "-proto:http", "cn"), ("pas", "-proto:http", "as"), ("dports", "-proto:http", "dport")):
            rows = _vl(f'type:traffic {q} | stats by ({f}) count() n | sort by (n desc) | limit 40', 24, 100)
            v[k] = [[r.get(f) or "", int(r.get("n") or 0)] for r in rows if (r.get(f) or "") not in ("", "?", "-", "0")]
    except Exception:
        pass
    _SEEN.update(ts=time.time(), v=v)
    return v


def _cond_fn(c):
    zone, op = c.get("zone"), c.get("op")
    if zone not in SIM_ZONES or op.startswith("libinjection"):
        return None
    if zone == "HEADERS":
        f = SIM_HEADERS.get(str(c.get("var") or "").lower())
        if not f:
            return None
    else:
        f = {"URI": "path", "METHOD": "method"}[zone]
    case = bool(c.get("case")) or zone == "METHOD"
    val = str(c.get("value") or "")
    val = val.upper() if zone == "METHOD" else val if case else val.lower()
    if op == "regex":
        try:
            rx = re.compile(val)
        except re.error:
            return None

    def norm(s):
        s = s or ""
        if zone == "METHOD":
            return s.upper()
        return unquote(s if case else s.lower())
    if op == "regex":
        return lambda row: bool(rx.search(norm(row.get(f))))
    return {"contains": lambda row: val in norm(row.get(f)), "equals": lambda row: norm(row.get(f)) == val,
            "startsWith": lambda row: norm(row.get(f)).startswith(val),
            "endsWith": lambda row: norm(row.get(f)).endswith(val)}.get(op)


def _host_fn(hosts):
    if not hosts:
        return lambda row: True
    ex = {h for h in hosts if not h.startswith("*.")}
    wild = tuple(h[1:] for h in hosts if h.startswith("*."))
    return lambda row: (row.get("target") or "").lower() in ex or (row.get("target") or "").lower().endswith(wild or ("\0",))


def _src_fn(src):
    """'cn:DE' / 'as:N' / CIDRs → row matcher (None = no sources given)."""
    if not src:
        return None
    nets = [ipaddress.ip_network(s, strict=False) for s in src if not s.startswith(("cn:", "as:"))]
    cn = {s[3:] for s in src if s.startswith("cn:")}
    asn = {s[3:] for s in src if s.startswith("as:")}

    def fn(row):
        if cn and (row.get("cn") or "").upper() in cn:
            return True
        if asn and str(row.get("as") or "").split(" ")[0] in asn:
            return True
        if nets:
            try:
                ip = ipaddress.ip_address(row.get("src") or "")
            except ValueError:
                return False
            return any(ip.version == n.version and ip in n for n in nets)
        return False
    return fn


def _port_fn(ports):
    rs = [(int(a), int(b or a)) for a, _, b in (p.partition("-") for p in ports.replace(" ", "").split(",") if p)]
    return (lambda row: any(a <= int(row.get("dport") or 0) <= b for a, b in rs)) if rs else (lambda row: True)


def _summary(rows, hit, scanned, line, unsupported, extra=None):
    ips, top, blocked = {}, {}, 0
    for r, k in hit:
        ips[r.get("src")] = ips.get(r.get("src"), 0) + 1
        top[k] = top.get(k, 0) + 1
        blocked += r.get("action") in ("blocked", "dropped")
    return dict({"scanned": scanned, "matched": len(hit), "ips": len(ips), "already_blocked": blocked, "unsupported": unsupported,
                 "top_ips": sorted(ips.items(), key=lambda x: -x[1])[:5], "top": sorted(top.items(), key=lambda x: -x[1])[:5],
                 "sample": [{"ts": r.get("_time"), "ip": r.get("src"), "cn": r.get("cn"), "line": line(r), "status": r.get("status") or r.get("action")}
                            for r, _ in hit[-8:][::-1]]}, **(extra or {}))


def sim_web(s, hours):
    fields = "| fields _time, src, cn, as, target, path, method, ua, ref, status, action"
    unsupported, q = [f"Cloudflare field {c['f']}" for c in s.get("cf") or []], "type:traffic method:*"
    if s["match"]:
        fns = []
        for c in s["match"]:
            f = _cond_fn(c)
            if f:
                fns.append(f)
            else:
                unsupported.append(f'{c.get("zone")}{"/" + c["var"] if c.get("var") else ""} {c.get("op")}')
        base = (lambda row: all(f(row) for f in fns)) if fns else (lambda row: False)
    else:
        sf, nf = _src_fn(s["src"]), _src_fn(s["src_not"])
        base = lambda row: (sf is None or sf(row)) and not (nf and nf(row))
        if len(s["src"]) == 1 and s["src"][0].startswith("cn:"):
            q += f' cn:="{s["src"][0][3:]}"'
        elif len(s["src"]) == 1 and s["src"][0].startswith("as:"):
            q += f' as:"{s["src"][0][3:]} "*'
    hf = _host_fn(s["hosts"])
    rows = _vl(q + " " + fields, hours)
    hit = [(r, (r.get("target") or "") + (r.get("path") or "")) for r in rows if hf(r) and base(r)]
    scanned = len(rows) if q == "type:traffic method:*" else sum(int(x.get("n") or 0) for x in _vl("type:traffic method:* | stats count() n", hours))
    return _summary(rows, hit, scanned, lambda r: f'{r.get("method", "")} {r.get("target", "")}{r.get("path", "")}', unsupported)


def sim_ports(s, hours):
    """Against the port proxies' connection log (one line per new connection): sources, protocol, ports, node, connection rate."""
    fields = "| fields _time, node, src, cn, as, proto, dport, target, action"
    q = "type:traffic -proto:http" + (f" proto:{s['proto']}" if s["proto"] in ("tcp", "udp") else "")
    unsupported = [FIELD_TXT[k] for k in ("sports", "dst", "tcp_bad", "nosyn", "mss", "ttl", "len", "frag", "bogon", "spoof", "mac", "vlan", "payload")
                   + V3 if has(s, k)] + s.get("_unsup", [])
    if s["state"] == "est":
        unsupported.append("established connections")
    lim = s.get("limit")
    if lim and lim["what"] != "conn":
        unsupported.append({"pkt": "packet rate", "bytes": "bandwidth", "concurrent": "open connections"}[lim["what"]])
    if s["proto"] == "icmp":
        unsupported.append("ICMP")
    rows = _vl(q + " " + fields, hours)
    sf, nf, pf = _src_fn(s["src"]), _src_fn(s["src_not"]), _port_fn(s["ports"])
    nodes = set(s["nodes"])
    fam = s["family"]
    m = [r for r in rows if (not nodes or r.get("node") in nodes) and pf(r) and (sf is None or sf(r)) and not (nf and nf(r))
         and (fam == "any" or (":" in (r.get("src") or "")) == (fam == "ip6"))]
    extra = {}
    if lim and lim["what"] == "conn":   # tokens: n per interval + burst; whatever is above it in a bucket would be over
        per = 60 if lim["per"] == "minute" else 1
        key = (lambda r: r.get("src")) if lim["by"] == "ip" else (lambda r: ".".join((r.get("src") or "").split(".")[:3]) + ".0/24"
                                                                    if ":" not in (r.get("src") or "") else ":".join((r.get("src") or "").split(":")[:4]) + "::/64") \
            if lim["by"] == "net" else (lambda r: "all")
        buckets = {}
        for r in m:
            buckets.setdefault((key(r), int(float(r.get("_time") if isinstance(r.get("_time"), (int, float)) else _ts(r.get("_time"))) // per)), []).append(r)
        over = []
        for rs in buckets.values():
            over += rs[lim["n"] + lim["burst"]:]
        over.sort(key=lambda r: str(r.get("_time")))
        extra["estimate"] = "connection rate is estimated per " + lim["per"] + " bucket from logged new connections"
        m = over
    hit = [(r, f'{(r.get("proto") or "").upper()} {r.get("dport") or ""}') for r in m]
    return _summary(rows, hit, len(rows), lambda r: f'{(r.get("proto") or "").upper()} → {r.get("target") or r.get("dport")} via {r.get("node")}',
                    unsupported, extra)


def sim_rate(s, hours):
    """Rate limit / response rule: requests per key in the rule's window (tumbling windows, close to CrowdSec's leaky bucket)."""
    r = s["rate"]
    q = "type:traffic method:*" + (" status:in(" + ",".join(map(str, r["statuses"])) + ")" if r["statuses"] else "")
    rows = _vl(q + " | fields _time, src, cn, as, target, path, method, ua, status, action", hours)
    hf = _host_fn(s["hosts"])
    meth = set(r["methods"])
    m = [x for x in rows if hf(x) and (not r["paths"] or (x.get("path") or "").startswith(tuple(r["paths"])))
         and (not meth or (x.get("method") or "").upper() in meth)]
    key = {"ip": lambda x: x.get("src"), "ip_path": lambda x: (x.get("src"), x.get("path")), "ip_host": lambda x: (x.get("src"), x.get("target")),
           "net": lambda x: ".".join((x.get("src") or "").split(".")[:3]), "asn": lambda x: str(x.get("as") or "").split(" ")[0],
           "ua": lambda x: (x.get("src"), x.get("ua")), "host": lambda x: x.get("target")}[r["key"]]
    buckets = {}
    for x in m:
        t = x.get("_time")
        t = float(t) if isinstance(t, (int, float)) else _ts(t)
        buckets.setdefault((key(x), int(t // r["secs"])), []).append(x)
    over = []
    for rs in buckets.values():
        if len(rs) > r["n"]:
            over += rs[r["n"]:]
    over.sort(key=lambda x: str(x.get("_time")))
    hit = [(x, (x.get("target") or "") + (x.get("path") or "")) for x in over]
    return _summary(rows, hit, len(rows), lambda x: f'{x.get("method", "")} {x.get("target", "")}{x.get("path", "")}', [],
                    {"estimate": f"counted in {r['secs']} s windows per {r['key'].replace('_', '+')}; the first request over the limit bans"})


def _ts(v):
    try:
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0


def simulate(kind, spec, hours=24):
    """What a rule or ban would have matched in the last `hours` of edge traffic: {web: …, ports: …}."""
    hours = max(1, min(int(hours), 168))
    if kind == "ban":
        s = {"where": ["web"] + (["ports"] if L4_NODES else []), "src": [spec["value"]], "src_not": [], "hosts": [], "match": [],
             "proto": "any", "ports": "", "nodes": [], "state": "", "family": "any", "limit": None}
        s.update({k: "" for k in ("sports", "mss", "ttl", "len")}, **{k: False for k in ("tcp_bad", "nosyn", "frag", "bogon", "spoof")},
                 dst=[], mac=[], vlan=[], payload=[])
    else:
        L = cur_lists()
        s = clean_spec(spec, L)
        dyn = [x for x in s["src"] if x.startswith("list:") and L[int(x[5:])]["kind"] == "dynamic"]
        s = dict(s, src=x_src(s["src"], L), src_not=x_src(s["src_not"], L), hosts=x_hosts(s["hosts"], L), ports=x_ports(s["ports"], L))
        if dyn:
            s["_unsup"] = ["dynamic list members"]
    out = {"hours": hours}
    if "web" in s["where"] and s.get("rate"):
        out["web"] = sim_rate(s, hours)
    elif "web" in s["where"]:
        out["web"] = sim_web(s, hours)
    if "ports" in s["where"]:
        out["ports"] = sim_ports(s, hours)
    return out


# ---------------------------------------------------------------- suggested rules (never applied by themselves)

SCAN_RE = r"(?i)(/\.env|/\.git/|/wp-login\.php|/xmlrpc\.php|/phpmyadmin|/wp-admin/|/cgi-bin/|/\.aws/|/actuator|/vendor/phpunit|/boaform|/HNAP1)"
BOT_RE = r"(?i)(googlebot|bingbot)"


def _fcrdns(ip):
    """Forward-confirmed reverse DNS for a search bot: PTR in the bot's domain and back to the same IP."""
    import socket
    try:
        name = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
        if not name.endswith((".googlebot.com", ".google.com", ".googleusercontent.com", ".search.msn.com")):
            return False
        return ip in socket.gethostbyname_ex(name)[2] or ip in {a[4][0] for a in socket.getaddrinfo(name, None)}
    except OSError:
        return False


def _in_nets(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in nets)


def suggestions(con, force=False):
    """Heuristics over the last 24 h of edge traffic → rules or bans to consider. Cached 30 min; dismissed ones stay hidden."""
    c = db.kv_get(con, "waf_sugg", {}) or {}
    if not force and c.get("ts", 0) > time.time() - 1800:
        return c
    st = state(con)
    out, errs = [], []
    banned = {b["value"] for b in st["bans"]}
    pol = st["policies"]

    def add(key, title, why, **kw):
        out.append(dict({"key": key, "title": title, "why": why}, **kw))
    try:
        rows = _vl("type:traffic method:* status:404 | stats by (src) count() n | sort by (n desc) | limit 10", 24, 10)
        for r in rows:
            ip, n = r.get("src") or "", int(r.get("n") or 0)
            if n >= 200 and ip not in banned and _global_net(ip):
                add(f"404:{ip}", f"Ban {ip}: {n} not-found answers in 24 h", "Probing for files that don't exist is how scanners work.",
                    ban={"value": ip, "dur": "24h"})
        if not any(web_kind(p["spec"]) == "rate" and (p["spec"]["rate"]["statuses"] or [0])[0] == 404 for p in pol) and rows \
                and int(rows[0].get("n") or 0) >= 200:
            add("resp404", "Ban IPs that collect many 404s", "One rule catches the next scanner by itself: 50 not-found answers in 5 minutes "
                "per IP → 4 h ban (starts in log mode).",
                rule={"name": "404 burst → ban", "mode": "log", "spec": {"where": ["web"], "action": "block",
                      "rate": {"kind": "resp", "key": "ip", "n": 50, "secs": 300, "ban": "4h", "statuses": [404], "paths": [], "methods": []}}})
    except Exception as e:
        errs.append(f"404s: {e}")
    try:
        rows = _vl(f'type:traffic method:* path:~"{SCAN_RE}" | stats by (path) count() n, count_uniq(src) ips | sort by (n desc) | limit 8', 24, 8)
        tot = sum(int(r.get("n") or 0) for r in rows)
        if tot >= 20 and not any(any("wp-login" in str(c.get("value")) or ".env" in str(c.get("value")) for c in p["spec"].get("match") or [])
                                 for p in pol):
            add("scanpaths", f"Block scanner paths ({tot} requests in 24 h)", "Requests for .env, .git, wp-login.php and the like: "
                "nothing legitimate asks for them here. Top: " + ", ".join(f"{r.get('path')} ×{r.get('n')}" for r in rows[:4]),
                rule={"name": "Scanner paths", "mode": "log", "spec": {"where": ["web"], "action": "block", "match": [
                      {"zone": "URI", "op": "regex", "value": SCAN_RE[4:]}]}})
    except Exception as e:
        errs.append(f"scanner paths: {e}")
    try:
        rows = _vl("type:traffic method:* | stats by (src, target) count() n | sort by (n desc) | limit 5", 1, 5)
        hot = [r for r in rows if int(r.get("n") or 0) >= 1500 and r.get("src") not in banned]
        if hot and not any(web_kind(p["spec"]) == "rate" and p["spec"]["rate"]["kind"] == "rate" for p in pol):
            h = hot[0]
            add("rate", f"Rate-limit requests: {h.get('src')} sent {h.get('n')} to {h.get('target')} in the last hour",
                "A per-IP limit stops floods and brute force without touching normal visitors (a page load is 20-80 requests).",
                rule={"name": "Request flood → ban", "mode": "log", "spec": {"where": ["web"], "action": "block",
                      "rate": {"kind": "rate", "key": "ip", "n": 600, "secs": 60, "ban": "1h", "statuses": [], "paths": [], "methods": []}}})
    except Exception as e:
        errs.append(f"rates: {e}")
    try:
        rows = _vl("type:traffic method:* status:in(401,403) | stats by (target, path) count() n, count_uniq(src) ips | sort by (n desc) | limit 3", 24, 3)
        for r in rows:
            if int(r.get("n") or 0) >= 300 and not any(web_kind(p["spec"]) == "rate" and 401 in p["spec"]["rate"]["statuses"] for p in pol):
                add(f"auth:{r.get('target')}{r.get('path')}", f"Login failures on {r.get('target')}{r.get('path')}: {r.get('n')} in 24 h",
                    "Ban an IP after 20 refused logins in 10 minutes (brute force).",
                    rule={"name": f"Login brute force {r.get('target')}", "mode": "log", "spec": {"where": ["web"], "action": "block",
                          "hosts": [r.get("target")] if HOST_RE.match(str(r.get("target") or "")) else [],
                          "rate": {"kind": "resp", "key": "ip", "n": 20, "secs": 600, "ban": "4h", "statuses": [401, 403], "paths": [], "methods": []}}})
                break
    except Exception as e:
        errs.append(f"logins: {e}")
    try:
        rows = _vl(f'type:traffic method:* ua:~"{BOT_RE}" | stats by (src) count() n | sort by (n desc) | limit 20', 24, 20)
        if rows:
            nets = [ipaddress.ip_network(v) for v in feed_values("bots")]
            fake = []
            for r in rows[:12]:
                ip = r.get("src") or ""
                if ip and ip not in banned and _global_net(ip) and not _in_nets(ip, nets) and not _fcrdns(ip):
                    fake.append((ip, int(r.get("n") or 0)))
            for ip, n in fake[:5]:
                add(f"fakebot:{ip}", f"Ban {ip}: claims to be Googlebot/Bingbot but isn't ({n} requests)",
                    "Not in the published crawler ranges and its reverse DNS doesn't confirm it.", ban={"value": ip, "dur": "168h"})
    except Exception as e:
        errs.append(f"bots: {e}")
    if L4_NODES and not (st.get("trap") or {}).get("on"):
        add("trap", "Turn on the port-scan trap", "Sources that knock on many closed ports of the port proxies go on a dynamic list and are "
            "dropped for an hour. Starts in log mode.", trap=True)
    if not any(l["kind"] == "feed" and l.get("feed") == "spamhaus" for l in st["lists"]):
        add("spamhaus", "Block Spamhaus DROP everywhere", "Hijacked and criminal networks; no legitimate traffic comes from them. "
            "Creates the feed list and a rule (log mode first).", feed="spamhaus")
    gone = set(db.kv_get(con, "waf_sugg_dismissed", []) or [])
    c = {"ts": time.time(), "items": [x for x in out if x["key"] not in gone], "errs": errs}
    db.kv_set(con, "waf_sugg", c)
    return c

