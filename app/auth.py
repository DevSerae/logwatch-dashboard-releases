"""Built-in login: board users (users.py: roles, PBKDF2, TOTP), HMAC-signed session cookie bound to the user's session
version, login rate limit, optional source allow-list, and the real client IP from X-Forwarded-For only when the peer
is a trusted proxy. SSO sign-in is in sso.py.

Behind a reverse proxy or Cloudflare Tunnel that isn't in board.trusted_proxies, every visitor looks like the connector:
open_cidrs never applies to such forwarded requests (they could come from anywhere), and the board notes the proxy so
an admin can trust it (Features → Board access). board.proxy_public: true lets visitors through the trusted proxies in
without matching allow_cidrs (a public tunnel, usually with Cloudflare Access in front).

Optional: open_cidrs skip the login (trusted LAN, dashboard iframes), and board.cf_access accepts a valid Cloudflare
Access JWT instead of the login (required: true also rejects anything from the trusted proxies without one). Both get
board.open_role / cf_access.role (default admin) unless the Access e-mail belongs to a board user, who keeps theirs."""
import hashlib
import hmac
import ipaddress
import secrets
import time

import httpx
import jwt

import db
import users
from settings import BOARD, nets, secret

COOKIE = "lw_session"
PENDING = "lw_mfa"        # password checked, second factor still due (5 min)
SSO_COOKIE = "lw_sso"
SESSION_HOURS = float(BOARD.get("session_hours") or 12)
TRUSTED = nets("trusted_proxies")
ALLOW = nets("allow_cidrs")
OPEN = nets("open_cidrs")
CF = BOARD.get("cf_access") if isinstance(BOARD.get("cf_access"), dict) else {}
CF_TEAM = str(CF.get("team") or "").removeprefix("https://").strip("/")
CF_AUD = str(CF.get("aud") or "").strip()
CF_REQUIRED = bool(CF.get("required")) and bool(CF_TEAM and CF_AUD)
OPEN_ROLE = BOARD.get("open_role") if BOARD.get("open_role") in users.ROLES else "admin"
CF_ROLE = CF.get("role") if CF.get("role") in users.ROLES else "admin"
PROXY_PUBLIC = bool(BOARD.get("proxy_public"))
FWD = ("cf-connecting-ip", "cf-ray", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "forwarded")
_jwks = {"at": 0.0, "keys": {}}
_fails = {}  # ip -> [timestamps]
MAX_FAILS, FAIL_WINDOW = 10, 900


hash_password, check_password = users.hash_password, users.check_password


def _key():
    k = secret("SESSION_SECRET")
    if len(k) < 32:
        raise RuntimeError("SESSION_SECRET missing or too short in secrets.env (run setup.py init)")
    return k.encode()


def key():
    return _key()


def _signed(body, hours):
    exp = int(time.time() + hours * 3600)
    body = f"{body}|{exp}"
    return f"{body}|{hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()}"


def _unsign(cookie, parts):
    try:
        f = (cookie or "").split("|")
        if len(f) != parts + 2:
            return None
        body = "|".join(f[:-1])
        good = hmac.new(_key(), body.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(f[-1], good) and int(f[-2]) > time.time():
            return f[:parts]
    except (ValueError, RuntimeError):
        pass
    return None


def make_session(u, kind="s"):
    """Cookie for a user signed in with a password (kind s) or SSO (kind o), or one who still owes the second factor
    (kind m, 5 minutes)."""
    return _signed(f"{kind}|{u['name']}|{u['sv']}", 5 / 60 if kind == "m" else SESSION_HOURS)


def read_session(cookie, kinds=("s", "o")):
    """The user (dict with role, via = cookie kind) if the cookie is valid, unexpired, current and the account
    enabled, else None."""
    f = _unsign(cookie, 3)
    if not f or f[0] not in kinds:
        return None
    with db.connect() as con:
        u = users.get(con, f[1])
    if u and not u["disabled"] and str(u["sv"]) == f[2]:
        return u | {"via": f[0]}
    return None


def external_user(email, default_role):
    """Who a Cloudflare Access / open_cidrs visitor is: the board user with that e-mail, else a stand-in."""
    if email:
        with db.connect() as con:
            u = users.by_email(con, [email])
        if u and not u["disabled"]:
            return u
    return {"name": email or "open-access", "role": default_role, "external": True}


def client_ip(request):
    """Socket peer, or the right-most untrusted X-Forwarded-For hop when the peer is a trusted proxy."""
    peer = request.client.host if request.client else "0.0.0.0"
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(ip in n for n in TRUSTED):
        return peer
    hops = [h.strip() for h in (request.headers.get("x-forwarded-for") or "").split(",") if h.strip()]
    for h in reversed(hops):
        try:
            a = ipaddress.ip_address(h)
        except ValueError:
            continue
        if not any(a in n for n in TRUSTED):
            return str(a)
    return peer


def allowed(ip):
    if not ALLOW:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in ALLOW)


def _in(ip, nets_):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets_)


def open_access(ip, request=None):
    """Client in board.open_cidrs: no login (never true for clients behind a trusted proxy unless listed, nor for
    requests an untrusted proxy or tunnel forwarded: the peer is the connector, the visitor could be anyone)."""
    if request is not None and untrusted_proxy(request):
        return False
    return bool(OPEN) and _in(ip, OPEN)


def via_proxy(request):
    peer = request.client.host if request.client else ""
    return _in(peer, TRUSTED)


def forwarded(request):
    return any(request.headers.get(h) for h in FWD)


def untrusted_proxy(request):
    """Forwarded by a reverse proxy / tunnel connector that isn't in trusted_proxies."""
    return forwarded(request) and not via_proxy(request)


def is_https(request):
    """The browser used HTTPS (directly, or as a proxy/tunnel says). Only used to make cookies stricter."""
    if request.url.scheme == "https":
        return True
    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    return proto == "https" or '"https"' in (request.headers.get("cf-visitor") or "")


def allowed_request(request, ip):
    """allow_cidrs, except that board.proxy_public lets everyone through the trusted proxies in, and the container's own
    loopback (healthcheck, docker compose exec) is always let in."""
    peer = request.client.host if request.client else ""
    if peer in ("127.0.0.1", "::1") and not forwarded(request):
        return True
    return allowed(ip) or (PROXY_PUBLIC and via_proxy(request))


def _cf_key(kid):
    if kid not in _jwks["keys"] and time.time() - _jwks["at"] > 60:
        r = httpx.get(f"https://{CF_TEAM}/cdn-cgi/access/certs", timeout=10)
        r.raise_for_status()
        _jwks["keys"] = {k["kid"]: jwt.PyJWK(k).key for k in r.json().get("keys", []) if k.get("kid")}
        _jwks["at"] = time.time()
    return _jwks["keys"].get(kid)


def cf_user(request):
    """E-mail from a valid Cloudflare Access JWT (Cf-Access-Jwt-Assertion), else None."""
    token = request.headers.get("cf-access-jwt-assertion")
    if not (CF_TEAM and CF_AUD and token):
        return None
    try:
        key = _cf_key(jwt.get_unverified_header(token).get("kid"))
        if key is None:
            return None
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=CF_AUD, issuer=f"https://{CF_TEAM}")
        return claims.get("email") or claims.get("common_name") or "cloudflare-access"
    except Exception:
        return None


def rate_limited(ip):
    now = time.time()
    _fails[ip] = [t for t in _fails.get(ip, []) if now - t < FAIL_WINDOW]
    return len(_fails[ip]) >= MAX_FAILS


def fail(ip):
    _fails.setdefault(ip, []).append(time.time())


def bearer_ok(request, name):
    """Machine endpoints (AI runner, webhook ingest): Authorization: Bearer <secret NAME>."""
    want = secret(name)
    got = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
    return bool(want) and len(want) >= 24 and hmac.compare_digest(got, want)
