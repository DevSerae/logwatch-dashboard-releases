"""Board accounts: users with a role (admin | auditor), PBKDF2 passwords, TOTP MFA with recovery codes, and the
sign-in policy (require MFA, board URL for SSO). Stored in board.db; the first start imports the admin from
secrets.env (BOARD_ADMIN_USER / BOARD_ADMIN_PASSWORD_HASH, written by setup.py set-password and the web setup).

Roles: admin = everything. auditor = view only (every page and log, no changes); they can still manage their own
password and MFA. Each user has a session version (sv): bumping it signs that user out everywhere."""
import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time

import db
from settings import secret

ROLES = ("admin", "auditor")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
MIN_PW = 12

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    name TEXT PRIMARY KEY COLLATE NOCASE,
    email TEXT NOT NULL DEFAULT '',          -- lower case; SSO sign-ins match on it
    role TEXT NOT NULL DEFAULT 'auditor',    -- admin | auditor
    pw_hash TEXT NOT NULL DEFAULT '',        -- empty = SSO only
    totp_secret TEXT NOT NULL DEFAULT '',
    totp_on INTEGER NOT NULL DEFAULT 0,
    totp_last INTEGER NOT NULL DEFAULT 0,    -- last accepted time step (no replays)
    recovery TEXT NOT NULL DEFAULT '[]',     -- JSON list of sha256 hashes, each usable once
    disabled INTEGER NOT NULL DEFAULT 0,
    sv INTEGER NOT NULL DEFAULT 1,           -- session version: +1 signs the user out everywhere
    created REAL NOT NULL,
    last_login REAL,
    last_ip TEXT NOT NULL DEFAULT '',
    last_via TEXT NOT NULL DEFAULT ''        -- password | password+mfa | sso:<provider>
);
"""


class UserError(ValueError):
    pass


def ensure(con):
    con.executescript(SCHEMA)
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        h = secret("BOARD_ADMIN_PASSWORD_HASH")
        if h:
            con.execute("INSERT INTO users(name, role, pw_hash, created) VALUES(?, 'admin', ?, ?)",
                        (secret("BOARD_ADMIN_USER", "admin"), h, time.time()))


# --- passwords --------------------------------------------------------------------------------------------------

def hash_password(pw, iterations=600_000):
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(dk).decode()}"


def check_password(pw, stored):
    try:
        algo, it, salt, h = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), int(it))
        return hmac.compare_digest(base64.b64encode(dk).decode(), h)
    except (ValueError, AttributeError):
        return False


_DUMMY = hash_password(secrets.token_hex(8), 600_000)


def password_ok(pw):
    if len(pw or "") < MIN_PW:
        raise UserError(f"use at least {MIN_PW} characters")
    return pw


# --- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ---------------------------------------------------------------------

def totp_new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(sec, counter):
    key = base64.b32decode(sec + "=" * (-len(sec) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7fffffff) % 1_000_000:06d}"


def totp_match(sec, code, last=0, at=None):
    """The accepted time step for a 6-digit code (±1 step of drift, never one at or before `last`), else None."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code) or not sec:
        return None
    step = int((at or time.time()) // 30)
    for s in (step - 1, step, step + 1):
        if s > last and hmac.compare_digest(_hotp(sec, s), code):
            return s
    return None


def otpauth_uri(sec, name, issuer):
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(name)}?secret={sec}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def qr_svg(text):
    try:
        import io
        import segno
        buf = io.BytesIO()
        segno.make(text, error="m").save(buf, kind="svg", scale=5, border=2, dark="#000", light="#fff", xmldecl=False,
                                         svgns=True)
        return buf.getvalue().decode()
    except Exception:
        return ""


def _rc_hash(code):
    return hashlib.sha256(re.sub(r"[^a-z0-9]", "", code.lower()).encode()).hexdigest()


def new_recovery_codes(con, name):
    alpha = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = ["".join(secrets.choice(alpha) for _ in range(4)) + "-" + "".join(secrets.choice(alpha) for _ in range(4))
             for _ in range(10)]
    con.execute("UPDATE users SET recovery=? WHERE name=?", (json.dumps([_rc_hash(c) for c in codes]), name))
    return codes


def check_second_factor(con, name, code):
    """True if code is the user's current TOTP or an unused recovery code (which is then used up)."""
    u = get(con, name)
    if not u or not u["totp_on"]:
        return False
    s = totp_match(u["totp_secret"], code, u["totp_last"])
    if s:
        con.execute("UPDATE users SET totp_last=? WHERE name=?", (s, u["name"]))
        return True
    left = json.loads(u["recovery"] or "[]")
    h = _rc_hash(code or "")
    if h in left:
        left.remove(h)
        con.execute("UPDATE users SET recovery=? WHERE name=?", (json.dumps(left), u["name"]))
        db.add_event(con, "auth", f"{u['name']} used a recovery code", f"{len(left)} left", "warning")
        return True
    return False


# --- users ------------------------------------------------------------------------------------------------------

def get(con, name):
    r = con.execute("SELECT * FROM users WHERE name=?", (name or "",)).fetchone()
    return dict(r) if r else None


def by_email(con, emails):
    emails = [e.lower() for e in emails if e]
    for e in emails:
        r = con.execute("SELECT * FROM users WHERE email=? AND email!=''", (e,)).fetchone()
        if r:
            return dict(r)
    return None


def all_users(con):
    out = []
    for r in con.execute("SELECT * FROM users ORDER BY role, name"):
        u = dict(r)
        u["recovery_left"] = len(json.loads(u.pop("recovery") or "[]"))
        u["has_pw"] = bool(u.pop("pw_hash"))
        u.pop("totp_secret")
        out.append(u)
    return out


def _admins_left(con, without):
    return con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0 AND name!=?",
                       (without,)).fetchone()[0]


def create(con, name, role="auditor", email="", password=""):
    name = (name or "").strip()
    if not NAME_RE.fullmatch(name):
        raise UserError("username: letters, digits, . _ @ - (up to 64)")
    if role not in ROLES:
        raise UserError(f"role must be one of: {', '.join(ROLES)}")
    email = (email or "").strip().lower()
    if email and not EMAIL_RE.fullmatch(email):
        raise UserError("that isn't an e-mail address")
    if get(con, name):
        raise UserError(f"{name} already exists")
    if email and by_email(con, [email]):
        raise UserError(f"another user already has {email}")
    if not password and not email:
        raise UserError("give a password, or an e-mail for SSO sign-in (or both)")
    con.execute("INSERT INTO users(name, email, role, pw_hash, created) VALUES(?,?,?,?,?)",
                (name, email, role, hash_password(password_ok(password)) if password else "", time.time()))
    return get(con, name)


def update(con, name, *, role=None, email=None, disabled=None):
    u = get(con, name)
    if not u:
        raise UserError(f"no user {name}")
    if role is not None:
        if role not in ROLES:
            raise UserError(f"role must be one of: {', '.join(ROLES)}")
        if u["role"] == "admin" and role != "admin" and not _admins_left(con, u["name"]):
            raise UserError("that's the last admin: make another admin first")
        con.execute("UPDATE users SET role=?, sv=sv+1 WHERE name=?", (role, u["name"]))
    if email is not None:
        email = email.strip().lower()
        if email and not EMAIL_RE.fullmatch(email):
            raise UserError("that isn't an e-mail address")
        other = by_email(con, [email]) if email else None
        if other and other["name"] != u["name"]:
            raise UserError(f"{other['name']} already has {email}")
        if not email and not u["pw_hash"]:
            raise UserError("this user signs in with SSO only: set a password before removing the e-mail")
        con.execute("UPDATE users SET email=? WHERE name=?", (email, u["name"]))
    if disabled is not None:
        if disabled and u["role"] == "admin" and not _admins_left(con, u["name"]):
            raise UserError("that's the last admin: make another admin first")
        con.execute("UPDATE users SET disabled=?, sv=sv+1 WHERE name=?", (1 if disabled else 0, u["name"]))
    return get(con, u["name"])


def set_password(con, name, pw):
    u = get(con, name)
    if not u:
        raise UserError(f"no user {name}")
    con.execute("UPDATE users SET pw_hash=?, sv=sv+1 WHERE name=?", (hash_password(password_ok(pw)), u["name"]))


def rename(con, old, new):
    u = get(con, old)
    new = (new or "").strip()
    if not u:
        raise UserError(f"no user {old}")
    if not NAME_RE.fullmatch(new):
        raise UserError("username: letters, digits, . _ @ - (up to 64)")
    if new.lower() != u["name"].lower() and get(con, new):
        raise UserError(f"{new} already exists")
    con.execute("UPDATE users SET name=?, sv=sv+1 WHERE name=?", (new, u["name"]))


def delete(con, name):
    u = get(con, name)
    if not u:
        raise UserError(f"no user {name}")
    if u["role"] == "admin" and not _admins_left(con, u["name"]):
        raise UserError("that's the last admin: make another admin first")
    con.execute("DELETE FROM users WHERE name=?", (u["name"],))


def reset_mfa(con, name):
    con.execute("UPDATE users SET totp_on=0, totp_secret='', totp_last=0, recovery='[]', sv=sv+1 WHERE name=?", (name,))


def sign_out_everywhere(con, name):
    con.execute("UPDATE users SET sv=sv+1 WHERE name=?", (name,))


def verify_password(con, name, pw):
    """The user if name + password are right and the account is enabled, else None (constant-ish time)."""
    u = get(con, (name or "").strip())
    ok = check_password(pw or "", u["pw_hash"] if u and u["pw_hash"] else _DUMMY)
    return u if ok and u and u["pw_hash"] and not u["disabled"] else None


def touch_login(con, name, ip, via):
    con.execute("UPDATE users SET last_login=?, last_ip=?, last_via=? WHERE name=?", (time.time(), ip, via, name))


# --- sign-in policy ---------------------------------------------------------------------------------------------

def policy(con):
    p = db.kv_get(con, "auth_policy", {}) or {}
    return {"mfa_required": bool(p.get("mfa_required")), "public_url": str(p.get("public_url") or "")}


def set_policy(con, **kw):
    p = policy(con)
    p.update({k: v for k, v in kw.items() if v is not None})
    db.kv_set(con, "auth_policy", p)
    return p
