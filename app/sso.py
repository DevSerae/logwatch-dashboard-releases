"""Sign in with Google, Microsoft, Discord, GitHub or any OpenID Connect provider (Authentik, Keycloak, Authelia,
Entra ID…). Authorization code flow with PKCE + state; the board talks to the provider's token and userinfo endpoints
over HTTPS itself, so no token from the browser is trusted.

A provider only signs in someone whose verified e-mail belongs to a board user, unless auto-create is on for it
(optionally limited to e-mail domains), which creates the user with the provider's default role. Providers live in
board.db (Settings → Users & sign-in); the client secret never goes back to the browser."""
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import urlencode

import httpx

import users

PRESETS = {
    "google": {"label": "Google", "auth": "https://accounts.google.com/o/oauth2/v2/auth",
               "token": "https://oauth2.googleapis.com/token",
               "userinfo": "https://openidconnect.googleapis.com/v1/userinfo", "scope": "openid email profile",
               "console": "https://console.cloud.google.com/apis/credentials"},
    "microsoft": {"label": "Microsoft", "issuer_tpl": "https://login.microsoftonline.com/{tenant}/v2.0",
                  "scope": "openid email profile",
                  "console": "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"},
    "discord": {"label": "Discord", "auth": "https://discord.com/oauth2/authorize",
                "token": "https://discord.com/api/oauth2/token", "userinfo": "https://discord.com/api/users/@me",
                "scope": "identify email", "console": "https://discord.com/developers/applications"},
    "github": {"label": "GitHub", "auth": "https://github.com/login/oauth/authorize",
               "token": "https://github.com/login/oauth/access_token", "userinfo": "https://api.github.com/user/emails",
               "scope": "read:user user:email", "console": "https://github.com/settings/developers"},
    "oidc": {"label": "OpenID Connect", "scope": "openid email profile", "console": ""},
}
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
SCHEMA = """
CREATE TABLE IF NOT EXISTS sso_providers (
    id TEXT PRIMARY KEY,                     -- in the redirect URI: /auth/sso/<id>/callback
    kind TEXT NOT NULL,                      -- google | microsoft | discord | github | oidc
    label TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    issuer TEXT NOT NULL DEFAULT '',         -- oidc: issuer URL · microsoft: tenant ID or domain
    auto_role TEXT NOT NULL DEFAULT '',      -- '' = only existing users · auditor | admin = create on first sign-in
    domains TEXT NOT NULL DEFAULT '',        -- auto-create only for these e-mail domains (comma list, empty = any)
    trust_email INTEGER NOT NULL DEFAULT 0,  -- oidc: accept e-mails without email_verified
    enabled INTEGER NOT NULL DEFAULT 1,
    created REAL NOT NULL
);
"""
_disc = {}


class SSOError(ValueError):
    pass


def ensure(con):
    con.executescript(SCHEMA)


def providers(con, enabled_only=False):
    q = "SELECT * FROM sso_providers" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY label"
    return [dict(r) for r in con.execute(q)]


def public(p):
    """A provider without its client secret (safe for pages)."""
    return {k: v for k, v in p.items() if k != "client_secret"} | {"has_secret": bool(p.get("client_secret"))}


def get(con, pid):
    r = con.execute("SELECT * FROM sso_providers WHERE id=?", (pid,)).fetchone()
    return dict(r) if r else None


def save(con, f):
    kind = f.get("kind", "")
    if kind not in PRESETS:
        raise SSOError("pick a provider type")
    pid = (f.get("id") or kind).strip().lower()
    if not ID_RE.fullmatch(pid):
        raise SSOError("ID: lower-case letters, digits and - (it goes in the redirect URI)")
    old = get(con, pid)
    cid, csec = (f.get("client_id") or "").strip(), (f.get("client_secret") or "").strip()
    csec = csec or (old or {}).get("client_secret", "")
    if not cid or not csec:
        raise SSOError("client ID and client secret are required")
    issuer = (f.get("issuer") or "").strip().rstrip("/")
    if kind == "oidc" and not re.match(r"https://[^\s/]+", issuer):
        raise SSOError("issuer must be an https:// URL (the part before /.well-known/openid-configuration)")
    if kind == "microsoft" and (not re.fullmatch(r"[A-Za-z0-9.-]+", issuer or "")
                                or issuer.lower() in ("common", "organizations", "consumers")):
        raise SSOError("tenant: your directory (tenant) ID or domain, so only your organisation can sign in")
    role = f.get("auto_role") or ""
    if role not in ("",) + users.ROLES:
        raise SSOError("bad auto-create role")
    domains = ",".join(d.strip().lower().lstrip("@") for d in (f.get("domains") or "").split(",") if d.strip())
    label = (f.get("label") or "").strip()[:40] or PRESETS[kind]["label"]
    con.execute("INSERT INTO sso_providers(id, kind, label, client_id, client_secret, issuer, auto_role, domains, "
                "trust_email, enabled, created) VALUES(?,?,?,?,?,?,?,?,?,1,?) ON CONFLICT(id) DO UPDATE SET "
                "kind=excluded.kind, label=excluded.label, client_id=excluded.client_id, client_secret=excluded.client_secret, "
                "issuer=excluded.issuer, auto_role=excluded.auto_role, domains=excluded.domains, trust_email=excluded.trust_email",
                (pid, kind, label, cid, csec, issuer, role, domains, 1 if f.get("trust_email") else 0, time.time()))
    _disc.pop(pid, None)
    return get(con, pid)


def endpoints(p):
    kind = p["kind"]
    if kind in ("google", "discord", "github"):
        return PRESETS[kind]
    issuer = PRESETS["microsoft"]["issuer_tpl"].format(tenant=p["issuer"]) if kind == "microsoft" else p["issuer"]
    hit = _disc.get(p["id"])
    if not hit or time.time() - hit[0] > 3600:
        r = httpx.get(issuer + "/.well-known/openid-configuration", timeout=10)
        r.raise_for_status()
        d = r.json()
        hit = (time.time(), {"auth": d["authorization_endpoint"], "token": d["token_endpoint"],
                             "userinfo": d.get("userinfo_endpoint", ""), "scope": PRESETS[kind]["scope"]})
        _disc[p["id"]] = hit
    return hit[1]


def redirect_uri(base, pid):
    return f"{base.rstrip('/')}/auth/sso/{pid}/callback"


# --- the flow: state lives in a short-lived signed cookie -------------------------------------------------------

def _sign(key, body):
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def start(p, base, key, nxt):
    """(provider URL to send the browser to, cookie value)."""
    ep = endpoints(p)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    st = {"p": p["id"], "s": secrets.token_urlsafe(24), "v": verifier, "n": nxt, "e": int(time.time()) + 600}
    body = base64.urlsafe_b64encode(json.dumps(st).encode()).decode()
    q = {"response_type": "code", "client_id": p["client_id"], "redirect_uri": redirect_uri(base, p["id"]),
         "scope": ep["scope"], "state": st["s"], "code_challenge": challenge, "code_challenge_method": "S256"}
    if p["kind"] == "google":
        q["prompt"] = "select_account"
    return ep["auth"] + "?" + urlencode(q), f"{body}.{_sign(key, body)}"


def read_state(cookie, key, pid, state):
    try:
        body, sig = (cookie or "").rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(key, body)):
            return None
        st = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if st["p"] != pid or st["e"] < time.time() or not hmac.compare_digest(st["s"], state or ""):
            return None
        return st
    except (ValueError, KeyError, TypeError):
        return None


def finish(p, base, code, verifier):
    """The verified e-mail addresses the provider vouches for (may be empty)."""
    ep = endpoints(p)
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(base, p["id"]),
            "client_id": p["client_id"], "client_secret": p["client_secret"], "code_verifier": verifier}
    r = httpx.post(ep["token"], data=data, headers={"Accept": "application/json"}, timeout=15)
    if r.status_code != 200:
        raise SSOError(f"{p['label']} refused the sign-in code ({r.status_code})")
    tok = r.json().get("access_token")
    if not tok:
        raise SSOError(f"{p['label']} sent no access token")
    h = {"Authorization": f"Bearer {tok}", "Accept": "application/json"}
    if p["kind"] == "github":
        r = httpx.get(ep["userinfo"], headers=h | {"X-GitHub-Api-Version": "2022-11-28"}, timeout=15)
        r.raise_for_status()
        return [e["email"] for e in r.json() if e.get("verified") and e.get("email")]
    if not ep.get("userinfo"):
        raise SSOError(f"{p['label']} has no userinfo endpoint")
    r = httpx.get(ep["userinfo"], headers=h, timeout=15)
    r.raise_for_status()
    u = r.json()
    email = u.get("email") or ""
    if p["kind"] == "discord":
        return [email] if email and u.get("verified") else []
    verified = u.get("email_verified")
    if isinstance(verified, str):
        verified = verified.lower() == "true"
    # Microsoft: no email_verified claim, but the provider is locked to one tenant whose admins own the addresses
    trusted = p["kind"] == "microsoft" or (p["kind"] == "oidc" and p["trust_email"])
    return [email] if email and (verified or trusted) else []


def match_or_create(con, p, emails):
    """The board user for these e-mails, creating one if the provider allows it; else None."""
    u = users.by_email(con, emails)
    if u or not p["auto_role"] or not emails:
        return u
    allowed = [d for d in p["domains"].split(",") if d]
    email = next((e.lower() for e in emails if not allowed or e.lower().rsplit("@", 1)[-1] in allowed), None)
    if not email:
        return None
    base = re.sub(r"[^A-Za-z0-9._-]", "", email.split("@")[0])[:40] or "user"
    name, n = base, 1
    while users.get(con, name):
        n += 1
        name = f"{base}{n}"
    return users.create(con, name, p["auto_role"], email)
