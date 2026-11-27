# Reverse proxy, HTTPS and remote access

The board listens on plain HTTP (`BOARD_PORT`, 8080). For access from outside the LAN, or to use the AI runner across
networks, put it behind HTTPS.

1. Keep `board.cookie_secure: true` (a board set up for plain http still marks cookies Secure for HTTPS visitors).
2. Add the proxy's address to `board.trusted_proxies`, e.g. `[192.0.2.5/32]`. Only then does the board trust
   `X-Forwarded-For` for the lockout, `allow_cidrs` and logs. For a proxy on the same Docker host, use the Docker
   network's gateway, e.g. `172.17.0.1/32`.
3. Optionally bind the board to localhost (`BOARD_BIND=127.0.0.1` in `.env`) when the proxy runs on the same host.

Then pick one of these:

**Caddy**
```
logwatch.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**nginx / Nginx Proxy Manager**
```
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
    proxy_read_timeout 120s;
}
```

**Traefik**: a router for `Host(\`logwatch.example.com\`)` pointing to the board service on port 8080.

**Cloudflare Tunnel / Tailscale Serve / other tunnels**: point the tunnel at `http://<board>:8080`. In that case the
"proxy" is the tunnel connector, so put the connector's address in `trusted_proxies`. An identity layer in front
(Cloudflare Access, Authelia, authentik, Tailscale ACLs) is a good extra.

A board installed for plain http on the LAN works through a tunnel as it is: cookies turn Secure by themselves for
visitors who came in over HTTPS, and a tunnel that rewrites `Host` (cloudflared `httpHostHeader`) is fine. Two
settings still matter:

- `board.allow_cidrs`: if it's set, the connector's address must be in it, or the tunnel gets "not allowed". Visitors
  are matched against it too once the connector is in `trusted_proxies`. For a public tunnel, set
  `board.proxy_public: true` so allow_cidrs only limits direct access.
- `board.open_cidrs` never applies to requests a proxy that isn't in `trusted_proxies` forwarded, because the visitor
  behind it could be anyone.

When the board sees traffic from a proxy it doesn't trust, Features shows **Board access** with the connector's address.
Fix it there with **Edit settings** (Board → Reverse proxies).

**Cloudflare Access** can replace the board's login for people coming through it: set `board.cf_access.team`
(`yourteam.cloudflareaccess.com`) and `board.cf_access.aud` (the Access application's AUD tag). A valid Access JWT
then signs you in. With `required: true`, everything arriving from `trusted_proxies` must carry one; there's no
password fallback there. Anyone else still gets the login page.

Avoid exposing the board directly to the internet without HTTPS. `board.allow_cidrs` is an extra lock for the login
page.

**Embedding** in a dashboard (Homarr, Homepage, Heimdall iframes): add the dashboard's origin to
`board.frame_ancestors`. A narrow viewport gets a compact layout.

Browsers block the login cookie inside a cross-site iframe. If the dashboard runs on your LAN, `board.open_cidrs`
lets those networks in without the login. Keep it narrow: anyone in them gets full access.
