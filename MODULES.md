# Modules

Turn modules on or off in the web setup (`sudo bash install.sh`, Features step) or with
`python3 setup.py modules --enable a,b --disable c`. Settings live in
`config/config.yaml`, under the section with the module's name. Secrets go in `python3 setup.py secret NAME`.
After changes, run `python3 setup.py check && python3 setup.py render && docker compose up -d && docker compose restart board worker`.
`up -d` alone doesn't restart running containers, and they read `config.yaml` only at start.
From the board: **Features** in the sidebar (or **Install** on a grayed-out tab) switches a module on and restarts
(through the host update helper, about a minute); its tab then shows that module's setup steps until you mark it done.

A disabled module runs no collectors and makes no outbound calls. Its tabs, cards and KPIs are hidden, and it
needs no secrets.

## Apps

`setup.py wizard` groups modules into apps. A board tab is grayed out (with the modules it needs) when none of its
modules are on.

| App | Modules |
|---|---|
| network | `unifi`, `netflow` |
| logs | `syslog`, `pull`, `windows`, `alertfile`, `webhook` |
| edge | `crowdsec`, `traffic`, `waf` |
| infra | `uptime`, `expiry`, `proxmox`, `trivy`, `action1`, `wazuh` |
| extras | `instatus`, `ai` |

The setup groups the same modules into areas: Logs, Edge WAF, Network, Hosts (Action1, Wazuh, trivy), Services,
Infra and Extras.

## Checking a host

`remote/linux/check-host.sh --board <addr> [--syslog] [--roles …] [--crowdsec]` (as root, on the host) lists what is
set up and what is missing for those modules; add `--pubkey "…" --fix` to install the missing pieces. The setup's
checks also log in as the board would and run the always-allowed `hello` role, which reports the host's enabled roles
and whether the tools they need are present.

## Modules

| Module | What you get | Needs on the board | Needs elsewhere |
|---|---|---|---|
| `syslog` (default on) | Log intake (RFC3164/5424, TCP+UDP), "host stopped sending logs", SSH brute-force and new-login items, custom `log_rules`, the Logs explorer | port `syslog.port` published | `remote/linux/logfwd.sh` on Linux hosts; syslog settings on network gear (`docs/network-gear.md`) |
| `pull` | Same as syslog for hosts that can't push: the board pulls new journal lines over SSH every minute | `ssh.hosts` with role `logpull` | `remote/linux/install-agent.sh --roles logpull` |
| `uptime` | HTTP(S)/TCP probes every minute, Services tab, response-time history | checks are added/removed on the Services tab (`uptime.targets` seeds the first run) | — |
| `expiry` | TLS certificate, domain (RDAP) and manual expiry dates, warns `warn_days` ahead | `expiry.tls/domains/manual` | — |
| `proxmox` | Node/guest/storage status, backup freshness per guest, SMART + ZFS health, "guest never sent logs" | `PROXMOX_TOKEN` (`user@realm!tokenid=uuid`; role **PVEAuditor** on `/`), `proxmox.url` | — |
| `trivy` | Weekly scan of running container images for fixable HIGH/CRITICAL CVEs | built with Trivy (render sets `WITH_TRIVY=1`); `ssh.hosts` role `images` | install-agent `--roles images` (lists `docker ps` images only) |
| `windows` | Windows event log: failed logons, service crashes, disk/NTFS errors, reboots, heartbeat; optional DNS top domains per device | Fluent Bit forward port (`windows.forward_port`) published | `remote/windows/install.ps1` (Fluent Bit service) |
| `unifi` | IPS/IDS alerts, firewall flows on the Edge tab, gateway events, WAN health | `UNIFI_API_KEY` (UniFi Network → Integrations; the board only reads, see [UniFi API calls](#unifi-api-calls)), `unifi.url` | — |
| `netflow` | Flows from any NetFlow v5/v9/IPFIX exporter on the Edge tab | goflow2 container, UDP `netflow.port` | flow export on the router (`docs/network-gear.md`) |
| `crowdsec` | Engine/LAPI/WAF/bouncer health, bans + WAF blocks, repeat offenders, Ban/Unban from the board | `crowdsec.hosts`; role `csctl` on a host for Ban/Unban | `remote/crowdsec/setup.sh` on each edge host |
| `traffic` | Every HTTP request (NPM or nginx combined logs) and every new connection (nftables) through edge hosts, with GeoIP | `ssh.hosts` role `trafficpull` | install-agent `--roles trafficpull [--traffic-globs …]`; `remote/linux/nft-traffic-log.sh` |
| `waf` | Edge WAF tab: one rule format for websites and port traffic, L2 to L7: sources (IP/CIDR, country, ASN), HTTP request checks (URI, args, headers, body, method, libinjection SQLi/XSS), ports/protocol/source ports/backends/state, packet checks (bad TCP flags, MSS, TTL, size, fragments, bogons, reverse-path spoofing), MAC/VLAN, payload bytes, rate/concurrent limits per IP or /24. Simple mode (goals) and Advanced mode (every field), preview of the generated nftables/AppSec/Cloudflare rule, IP/CIDR bans with expiry, OWASP CRS paranoia level. Every change starts log-only, can be simulated against the last 24h of traffic, and is undoable from History; port-proxy changes revert themselves unless the board confirms them. Rules from before 2.8.0 are converted once; any that can't be are listed above the rules with a Fix button and raise an Edge WAF item | `ssh.hosts` role `waf`; optional `waf.cloudflare` zone/account IDs + `CLOUDFLARE_API_TOKEN` (Zone WAF Edit, Account Filter Lists Edit) to push country/ASN rules and bans to Cloudflare too | `remote/crowdsec/setup.sh --bouncer npm` (AppSec), install-agent `--roles waf`. Port proxies (hosts that DNAT raw TCP/UDP; the board filters, the DNAT stays yours): role `l4waf` (nftables tables `netdev lw_waf_in` for first-packet checks and `inet lw_waf`; re-run install-agent after updating to 2.8.0), with `waf.port_groups` for one-click ports in the rule builder |
| `wazuh` | Wazuh agents (status, version, SCA score, critical/high vulnerabilities, alerts 24h) merged into Hosts; alerts into Logs; items for disconnected agents, high-level alerts and critical vulnerabilities | `wazuh.api_url` + `WAZUH_API_USER`/`WAZUH_API_PASSWORD` (role readonly); optional `wazuh.indexer_url` + `WAZUH_INDEXER_USER`/`WAZUH_INDEXER_PASSWORD` (read on `wazuh-alerts-*`, `wazuh-states-vulnerabilities-*`) for vulnerabilities and alerts. Wazuh 4.8+ | `wazuh.alerts: syslog` instead: the manager forwards alerts to the syslog port |
| `action1` | Missing patches and reboot-pending endpoints from Action1 | `ACTION1_CLIENT_ID`, `ACTION1_CLIENT_SECRET`, `ACTION1_ORG_ID` (API credentials with read-only role) | — |
| `alertfile` | Alerts another system already writes as JSON lines (`{id, severity, source, message}`): Error/Warning become items, the rest events; only new ids are read | `alertfile.path` (`//server/share/…` with `ALERTFILE_SMB_USER`/`ALERTFILE_SMB_PASSWORD`, or a file inside the container) | — |
| `instatus` | Maintenance windows on the board also post/resolve maintenance on an Instatus page | `INSTATUS_API_KEY`, `instatus.page_id` | — |
| `webhook` | `POST /api/ingest` raises, updates or clears items from anything (scripts, Uptime Kuma, Grafana, cron jobs) | `INGEST_TOKEN` (`setup.py secret INGEST_TOKEN --generate`) | `docs/webhook.md` |
| `ai` | "Resolve with AI" on incidents: your agent CLI works the incident, live transcript on the board | `AI_RUNNER_TOKEN` (`setup.py runner-env` creates it) | `ai-runner/runner.py` on a machine with the agent |

Always on:

- **Updates**: `updates.check` (default on) asks the releases repo every `check_hours`; the board prompts, and the
  host's `update.sh` applies only what an admin approved (now, scheduled, or automatically if `updates.auto` /
  the checkbox in the prompt is on). See the README.
- **Proxmox discovery** (installer): with the Proxmox module's URL and token filled in, *Discover from Proxmox* lists
  nodes, VMs and containers with their IPs (container interfaces, the QEMU guest agent, or static config) and disk
  health, and adds the ones you pick to the syslog, pull and trivy host lists. Live VM IPs need
  `VM.GuestAgent.Audit` (PVE 9) or `VM.Monitor` (PVE 8) on top of PVEAuditor.

- **Board**: items, snooze/mute/resolve, to-dos, notes, history, maintenance windows, views, CSV export.
- **VictoriaLogs and board disk checks**.
- **GeoIP**: `board.geoip`.
  - `dbip`: DB-IP Lite. The worker downloads it monthly, no account needed. Attribution goes on the Edge tab, as
    the CC BY 4.0 licence requires.
  - `maxmind`: GeoLite2. Needs the `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` secrets.
  - `off`

### UniFi API calls

The `unifi` module never changes anything on the console. Every call goes to `<unifi.url>/proxy/network/…` with the
`X-API-KEY` header:

| Method | Endpoint | What for |
|---|---|---|
| GET | `api/s/{site}/stat/health` | WAN health |
| GET | `api/s/{site}/stat/sta`, `api/s/{site}/stat/device`, `api/s/{site}/rest/user` | client and device names for IPs |
| POST | `v2/api/site/{site}/traffic-flows` | firewall flows (search query: time window + page in the JSON body) |
| POST | `v2/api/site/{site}/system-log/all` | IPS/IDS alerts and gateway events (same kind of search query) |

The two POSTs are searches: UniFi's v2 API takes the filter as a JSON body, the way a GET takes a query string. A
proxy or firewall in front of the console has to allow POST to those two paths. A UniFi API key has the permissions
of the admin who created it, so create it as an admin with a View Only role for Network.

## Custom log rules

`log_rules` in `config.yaml` turns any LogsQL query into board items, one per rule and host, when the count in the
5-minute window reaches `threshold`. Use it for anything the built-in collectors don't know about. Examples:

- switch port flaps
- NAS disk warnings
- firewall admin logins
- app errors

See `docs/network-gear.md`. Test a query on the **Logs** tab first.

## Security notes

- The board has a single admin account. Passwords are stored as PBKDF2-SHA256 hashes. Sessions are signed cookies:
  HttpOnly, SameSite=Lax, and Secure unless `cookie_secure: false`. Ten failed logins within 15 minutes lock an IP for 15
  minutes. `board.allow_cidrs` limits who can even see the login page.
- Machine endpoints (`/api/ingest`, `/api/runner/*`) use separate Bearer tokens and do nothing while their module is off.
- The board's SSH key can only run `/usr/local/sbin/logwatch-remote`. That dispatcher allows only the roles in
  each host's `/etc/logwatch-remote.conf`, and validates every argument.
- The containers run as a non-root user with config and secrets mounted read-only.
