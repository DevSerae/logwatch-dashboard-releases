"""SQLite state for the board: action items, events, host check-ins, uptime, maintenance, AI runs."""
import fnmatch
import json
import sqlite3
import time
from contextlib import contextmanager

from settings import DATA

DB_PATH = str(DATA / "board.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    key TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'event',      -- 'event' (stays until handled) | 'condition' (auto-closes when gone)
    severity TEXT NOT NULL DEFAULT 'warning',
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL DEFAULT 'open',      -- open | snoozed | resolved | muted | cleared
    snooze_until REAL,
    closed_at REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    dedupe TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS hosts (
    name TEXT PRIMARY KEY,
    last_seen REAL NOT NULL,
    first_seen REAL NOT NULL,
    ignored INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS known_macs (mac TEXT PRIMARY KEY, label TEXT, first_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS item_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    ts REAL NOT NULL,
    action TEXT NOT NULL,                    -- fired | reopened | cleared | resolved | snoozed | muted | added | ...
    note TEXT NOT NULL DEFAULT '',
    who TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS uptime (target TEXT NOT NULL, ts REAL NOT NULL, ok INTEGER NOT NULL, ms REAL, code INTEGER, err TEXT);
CREATE TABLE IF NOT EXISTS maint (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,                    -- 'all' | item source (uptime, proxmox, ...) | name matched in item keys
    start REAL NOT NULL,
    end REAL NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    who TEXT NOT NULL DEFAULT '',
    instatus_id TEXT,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_runs (
    id TEXT PRIMARY KEY,                     -- = the agent session id (also used in ai.chat_url)
    key TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued',    -- queued | running | done | failed
    outcome TEXT NOT NULL DEFAULT '',        -- fixed | not_fixed | unknown
    summary TEXT NOT NULL DEFAULT '',
    log TEXT NOT NULL DEFAULT '[]',          -- JSON steps: [{t: text|tool, ...}]
    err TEXT NOT NULL DEFAULT '',
    who TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL,
    started REAL,
    finished REAL
);
CREATE INDEX IF NOT EXISTS ai_runs_key ON ai_runs(key, created);
CREATE TABLE IF NOT EXISTS ai_briefs (      -- short AI summaries of a panel's data, typed out in the panel
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                      -- the series it summarises (edge | traffic)
    prompt TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued',    -- queued | running | done | failed
    text TEXT NOT NULL DEFAULT '',
    err TEXT NOT NULL DEFAULT '',
    who TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS uptime_t ON uptime(target, ts);
CREATE INDEX IF NOT EXISTS item_history_key ON item_history(key, ts);
CREATE TABLE IF NOT EXISTS waf_rules (       -- Edge WAF custom rules (CrowdSec AppSec via logwatch-wafctl)
    id INTEGER PRIMARY KEY,
    mode TEXT NOT NULL,                      -- log | enforce
    desc TEXT NOT NULL DEFAULT '',
    hosts TEXT NOT NULL DEFAULT '[]',        -- JSON list; empty = every host
    conds TEXT NOT NULL,                     -- JSON list of {zone, var, op, value, case}
    enabled INTEGER NOT NULL DEFAULT 1,
    created REAL NOT NULL,
    updated REAL NOT NULL,
    who TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS waf_bans (        -- IP/CIDR bans: CrowdSec on every node + Cloudflare list
    id INTEGER PRIMARY KEY,
    value TEXT NOT NULL UNIQUE,
    expires REAL,                            -- NULL = permanent
    note TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL,
    who TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS waf_geo (         -- country / network rules (Cloudflare only)
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,                      -- cn | as
    value TEXT NOT NULL,
    action TEXT NOT NULL,                    -- block | challenge
    mode TEXT NOT NULL,                      -- log (stored, not pushed) | enforce
    note TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL,
    who TEXT NOT NULL DEFAULT '',
    UNIQUE(kind, value)
);
CREATE TABLE IF NOT EXISTS waf_l4 (          -- port-proxy rules (L4, nftables via logwatch-nfwafctl)
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,                      -- rate | geo
    mode TEXT NOT NULL,                      -- log | enforce
    desc TEXT NOT NULL DEFAULT '',
    proto TEXT NOT NULL DEFAULT 'any',       -- tcp | udp | any
    ports TEXT NOT NULL,                     -- "21000-21999, 8401"
    rate INTEGER,                            -- rate: new connections per minute per source IP
    burst INTEGER,
    src TEXT NOT NULL DEFAULT '[]',          -- geo: JSON list of {kind: cn|as, value}
    enabled INTEGER NOT NULL DEFAULT 1,
    created REAL NOT NULL,
    updated REAL NOT NULL,
    who TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS waf_policy (      -- Edge WAF rules since 2.8.0 (one model for websites + port proxies, L2-L7)
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL,                      -- log | enforce
    enabled INTEGER NOT NULL DEFAULT 1,
    spec TEXT NOT NULL,                      -- JSON: where, action, src, src_not, hosts, match, proto, ports, ... (waf.clean_spec)
    created REAL NOT NULL,
    updated REAL NOT NULL,
    who TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL DEFAULT ''          -- "migrated web rule" etc. for rules converted by the 2.8.0 update
);
CREATE TABLE IF NOT EXISTS waf_legacy (      -- old rules the 2.8.0 update couldn't convert (shown with a Fix button)
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,                      -- rule | geo | l4
    old TEXT NOT NULL,                       -- JSON of the old rule
    reason TEXT NOT NULL,
    suggest TEXT,                            -- JSON {name, mode, spec} prefilled in the builder
    state TEXT NOT NULL DEFAULT 'open'       -- open | fixed | dismissed
);
CREATE TABLE IF NOT EXISTS waf_audit (       -- every apply: full state after it (undo puts the previous one back)
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    who TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL,
    state TEXT NOT NULL,
    result TEXT NOT NULL,
    ok INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS knowns (          -- facts from the operator: "Brimstone is down on purpose", "no backups wanted"
    id INTEGER PRIMARY KEY,
    text TEXT NOT NULL,                      -- the fact, in the operator's words; goes into AI runs and briefs
    match TEXT NOT NULL DEFAULT '',          -- optional: items it covers (like a maintenance target) move to Expected
    who TEXT NOT NULL DEFAULT '',
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (         -- what the board checks (uptime, tls); config.yaml only seeds the first run
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,                      -- uptime | tls
    name TEXT NOT NULL,
    spec TEXT NOT NULL,                      -- JSON: uptime {name,url|host+port,kind,group,expect} · tls {host,port,sni}
    created REAL NOT NULL,
    who TEXT NOT NULL DEFAULT '',
    UNIQUE(kind, name)
);
"""
MIGRATIONS = [("items", "note", "TEXT NOT NULL DEFAULT ''"), ("items", "due", "REAL"),
              ("ai_runs", "grp", "TEXT NOT NULL DEFAULT ''")]   # grp: bulk "Resolve with AI" = one agent run for all its items (= the lead run's id)


@contextmanager
def connect(path=DB_PATH):
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    for table, col, decl in MIGRATIONS:
        if col not in {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def kv_get(con, k, default=None):
    row = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    return json.loads(row["v"]) if row else default


def kv_set(con, k, v):
    con.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v)))


def history(con, key, action, note="", who="board"):
    con.execute("INSERT INTO item_history(key,ts,action,note,who) VALUES(?,?,?,?,?)",
                (key, time.time(), action, note[:500], who[:120]))


def upsert_item(con, key, source, title, detail="", severity="warning", kind="event"):
    """Raise or refresh an action item. Resolved/cleared items reopen when they fire again; muted never do."""
    now = time.time()
    row = con.execute("SELECT state FROM items WHERE key=?", (key,)).fetchone()
    if row is None:
        con.execute(
            "INSERT INTO items(key,source,kind,severity,title,detail,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)",
            (key, source, kind, severity, title, detail, now, now),
        )
        history(con, key, "fired")
        return
    state = row["state"]
    if state in ("resolved", "cleared"):
        state = "open"
        history(con, key, "reopened", "fired again")
    con.execute(
        "UPDATE items SET title=?, detail=?, severity=?, last_seen=?, count=count+1, state=?, "
        "closed_at=CASE WHEN ?='open' THEN NULL ELSE closed_at END WHERE key=?",
        (title, detail, severity, now, state, state, key),
    )


def clear_conditions(con, source, active_keys):
    """Auto-close condition items of a source that weren't reported this run."""
    now = time.time()
    rows = con.execute(
        "SELECT key FROM items WHERE source=? AND kind='condition' AND state IN ('open','snoozed')", (source,)
    ).fetchall()
    for r in rows:
        if r["key"] not in active_keys:
            con.execute("UPDATE items SET state='cleared', closed_at=? WHERE key=?", (now, r["key"]))
            history(con, r["key"], "cleared", "condition went away")


def add_event(con, source, title, detail="", severity="info", ts=None, dedupe=None):
    con.execute(
        "INSERT OR IGNORE INTO events(ts,source,severity,title,detail,dedupe) VALUES(?,?,?,?,?,?)",
        (ts or time.time(), source, severity, title, detail, dedupe),
    )


def active_maint(con, at=None):
    at = at or time.time()
    return [dict(r) for r in con.execute("SELECT * FROM maint WHERE start<=? AND end>? ORDER BY end", (at, at))]


def in_maint(windows, key, source):
    """True if an item/target falls inside one of the given maintenance windows."""
    for w in windows:
        t = w["target"].lower()
        if t == "all" or t == source.lower() or t in key.lower():
            return True
    return False


def knowns(con):
    return [dict(r) for r in con.execute("SELECT id, text, match, who, created FROM knowns ORDER BY id")]


def known_for(knowns, key, source, title=""):
    """The first known whose match covers an item: a source name, part of the item key or title (case-insensitive),
    or a glob with * / ? on the key. None when no known matches (knowns without a match only inform the AI)."""
    k, s, t = key.lower(), source.lower(), (title or "").lower()
    for kn in knowns:
        m = (kn.get("match") or "").strip().lower()
        if not m:
            continue
        if m == s or m in k or m in t or (("*" in m or "?" in m) and fnmatch.fnmatchcase(k, m)):
            return kn
    return None


def knowns_text(knowns):
    """Markdown list for prompts (AI runs, briefs); empty string when there are none."""
    return "\n".join(f"- {kn['text']}" + (f" (covers board items matching `{kn['match']}`)" if kn.get("match") else "")
                     for kn in knowns)


def prune(con, days=30):
    cutoff = time.time() - days * 86400
    con.execute("DELETE FROM uptime WHERE ts < ?", (cutoff,))
    con.execute("DELETE FROM maint WHERE end < ?", (cutoff,))
    con.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    con.execute("DELETE FROM items WHERE state IN ('resolved','cleared') AND closed_at < ?", (cutoff,))
    con.execute("DELETE FROM item_history WHERE ts < ? AND key NOT IN (SELECT key FROM items)", (cutoff,))
    con.execute("DELETE FROM ai_runs WHERE created < ? AND key NOT IN (SELECT key FROM items)", (cutoff,))
    con.execute("DELETE FROM ai_briefs WHERE created < ?", (time.time() - 86400,))


TARGET_SEED = {"uptime": ("uptime", "targets"), "tls": ("expiry", "tls")}


def target_name(kind, spec):
    return spec["name"] if kind == "uptime" else f"{spec.get('sni') or spec['host']}:{spec.get('port', 443)}"


def _seed(module, key):
    from settings import CONFIG
    return ((CONFIG.get(module) or {}) if isinstance(CONFIG.get(module), dict) else {}).get(key) or []


def targets(con, kind):
    """Checks the board runs. The board DB owns them; config.yaml only seeds them the first time."""
    if not kv_get(con, f"targets_seeded:{kind}"):
        for s in _seed(*TARGET_SEED[kind]):
            con.execute("INSERT OR IGNORE INTO targets(kind,name,spec,created,who) VALUES(?,?,?,?,?)",
                        (kind, target_name(kind, s), json.dumps(s), time.time(), "config.yaml"))
        kv_set(con, f"targets_seeded:{kind}", True)
        con.commit()
    return [dict(json.loads(r["spec"]), id=r["id"]) for r in
            con.execute("SELECT id, spec FROM targets WHERE kind=? ORDER BY id", (kind,))]


def manual_expiries(con):
    """Hand-tracked expiry dates; the ones from config.yaml move into the board the first time so they can be removed too."""
    if not kv_get(con, "manual_expiries_seeded"):
        cur = kv_get(con, "manual_expiries", [])
        names = {m["name"] for m in cur}
        kv_set(con, "manual_expiries", cur + [dict(m, expires=str(m["expires"])) for m in _seed("expiry", "manual")
                                              if m.get("name") and m["name"] not in names])
        kv_set(con, "manual_expiries_seeded", True)
        con.commit()
    return kv_get(con, "manual_expiries", [])
