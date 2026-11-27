# Logwatch Dashboard: installation guide for AI agents

You are an AI agent installing Logwatch Dashboard for a user on their network. This file is your playbook. Read
it fully, together with `MODULES.md`, before you touch anything. The user should not have to read anything else.

**Access you need.** A shell on the board VM with sudo (Claude Code / CloudCLI running on it, or SSH into it), and,
for section 4, SSH with sudo to each server you'll set up, or the user running the commands you give them. If you
can't reach a server, print its steps for the user instead; never ask for their passwords in chat.

**The user may prefer the web setup.** `sudo bash install.sh` from the install dir does sections 2–5 in the browser.
Its Servers step gives the user a prompt to paste into any agent (also saved as `installer-prompts/servers.md`). If
they start you with it, do exactly that list, ask for access to each server before connecting, and show every command before running it.

## Ground rules

1. **Ask before you act.** Interview the user first (section 2). Confirm every change to a machine other than the board
   host before making it: installing agents, firewall rules, router/switch config, API keys, CrowdSec bouncers.
2. **Secrets stay in `secrets/`.** Never put a password, token or API key in `config/config.yaml`, in a command line
   that ends up in shell history, or in your chat output. Use `python3 setup.py secret NAME` (it prompts) or
   `--stdin` from a pipe. Ask the user to type secrets into the prompt themselves when possible.
3. **Least privilege.** API keys should be read-only or audit-only wherever the vendor allows it; `MODULES.md` lists the
   minimum each module needs. The board's SSH key only runs the forced command on each host.
4. **Don't change the app.** You may adapt *deployment* to the user's environment: a reverse proxy, a different host
   path, systemd instead of compose restart policies, an existing VictoriaLogs. Keep the app code, the remote scripts'
   behaviour and the security model as shipped. If something really needs a code change, explain it and ask first.
5. **Be reversible.** Every remote script has an uninstall/undo line in its header. Before running a remote script,
   tell the user how to undo it.
6. **Verify each step** (section 5) before you move on.

## 1. What this is

A self-hosted "what needs doing" board for a homelab or small network. Logs land in a bundled VictoriaLogs. A worker
turns them into board items: hosts gone silent, SSH brute force, failed backups, expiring certs, IPS alerts, CrowdSec
bans, down services, missing patches, and so on. The UI has tabs for events, edge traffic, infrastructure, services and logs.

It runs as Docker Compose on one Linux host:

- `board`: web UI with built-in login
- `worker`: collectors and timers
- `victorialogs`: log store and syslog receiver
- `fluent-bit` (optional, profile `collector`): Windows and NetFlow intake
- `goflow2` (optional, profile `netflow`): NetFlow/IPFIX collector

Everything beyond plain syslog is a **module** you switch on or off in `config/config.yaml`.

## 2. Interview the user

Ask these in plain language, a few at a time, and record the answers. Skip questions that don't apply.

**Hosting**
- Which machine will host the board? It needs Linux, Docker Engine and the Compose plugin, at least 2 CPU, 2 GB RAM,
  and disk for logs (20 GB default cap, 30 days retention). A VM or LXC with nesting works.
- How will they open it?
  - LAN only, plain HTTP: set `cookie_secure: false`.
  - HTTPS tunnel *and* plain-HTTP LAN access: also `cookie_secure: false`. Visitors who come in over HTTPS still get
    Secure cookies; with `true`, LAN logins over http can't keep a session.
  - Behind their existing reverse proxy or tunnel with HTTPS: see `docs/reverse-proxy.md`.
- Which networks may reach the login page (`board.allow_cidrs`)? Requests from the Docker host itself (curl
  127.0.0.1) and a same-host reverse proxy arrive from the Docker gateway (e.g. 172.18.0.1), so list it too if needed.
- Which port? 8080 by default.
- Time zone?
- Retention and disk cap?

**What to watch.** Walk through `MODULES.md` and ask which modules they want. Useful prompts:

| Ask | Module |
|---|---|
| Which Linux machines can send syslog? | `syslog` (default on) |
| Which can't push and need pulling? | `pull` |
| Websites or services to probe for uptime? | `uptime` |
| Certificates, domains or licences to track for expiry? | `expiry` |
| Proxmox VE? | `proxmox` |
| Docker image vulnerability scans? | `trivy` |
| Windows servers or PCs? Windows DNS servers? | `windows` |
| UniFi gateway? | `unifi` |
| Another router that exports NetFlow/IPFIX? | `netflow` |
| Edge/reverse-proxy hosts? With CrowdSec? Should every request/connection show up? | `crowdsec`, `traffic` |
| Action1 patch management? | `action1` |
| Should the edge block attacks itself (custom L7 rules, bans, country/ASN rules, OWASP CRS)? Is the zone on Cloudflare too? | `waf` (needs CrowdSec AppSec on the edge hosts) |
| An Instatus status page? | `instatus` |
| Other tools that should raise items via HTTP? | `webhook` |
| Network gear (switches, firewalls, APs, NAS) that can send syslog? | `syslog` + `log_rules`, see `docs/network-gear.md` |
| Want "Resolve with AI"? Which agent CLI, on which machine? How much autonomy should it get? | `ai`, see `ai-runner/README.md` |

**Constraints**
- Anything that must not be touched or restarted without asking (production systems)?
- How does the board VM reach the servers: same LAN/routed VLANs, Tailscale, NetBird, Cloudflare One (WARP), or
  another VPN (WireGuard, ZeroTier, ...)? Don't assume; everyone's setup differs. `docs/remote-access.md` has what
  each one needs on the VM and the servers. Install or join a VPN on the VM only after the user says so, with a key
  they type in. The board only needs plain IP reachability:
  - SSH out to pull hosts
  - inbound syslog, Fluent Bit forward or NetFlow from senders
  - HTTPS out to APIs

  Use whatever path the user already has, overlay addresses included.

Summarise the plan back to the user (modules, hosts, ports, what gets installed where) and get a yes before section 3.

## 3. Install the board

On the board host:

```bash
# 1. code + prerequisites + the update helper, without the web setup (asks before installing Docker; --yes skips that)
curl -fsSL https://github.com/DevSerae/logwatch-dashboard-releases/releases/latest/download/install.sh -o install.sh
less install.sh                                   # show the user what it does
sudo bash install.sh --no-setup                    # → /opt/logwatch-dashboard, owned by the system user logwatch
cd /opt/logwatch-dashboard                        # run setup.py below with sudo (the dir is root/logwatch only)

# 2. config, session secret, the board's SSH key, data dir, .env + override
python3 setup.py init

# 3. admin login (the user types the password; or pipe it with --stdin)
python3 setup.py set-password --user admin

# 4. modules
python3 setup.py modules --enable uptime,expiry,proxmox        # whatever the user chose
python3 setup.py modules --disable syslog                      # only if they really don't want it
```

With Proxmox enabled, the user doesn't have to list hosts by hand: the PVEAuditor token can read every node, VM and
container with its IPs (`GET /api2/json/cluster/resources?type=vm`, then `/nodes/<n>/lxc/<id>/interfaces` or
`/nodes/<n>/qemu/<id>/agent/network-get-interfaces`). Offer that, and let them pick which ones go into the host
lists. The web setup's *Discover hosts from Proxmox* does exactly this.

Then edit `config/config.yaml` for every enabled module. The example comments show each key. Replace or delete all the
documentation addresses (`example.com`, `192.0.2.x`, `203.0.113.x`). Store each module's secrets with
`python3 setup.py secret NAME`:

- `--generate` for tokens the board itself issues: `INGEST_TOKEN`, `AI_RUNNER_TOKEN`.
- Plain prompt or `--stdin` for vendor keys.

```bash
python3 setup.py check     # must print "ok"; fix every FAIL, read every warn
python3 setup.py render    # writes .env and docker-compose.override.yml (ports/profiles from config.yaml)
docker compose up -d --build
docker compose ps          # board healthy, worker + victorialogs running
```

Then:

- Set `TZ`, `BOARD_BIND`, `BOARD_PORT`, `VL_RETENTION` and `VL_MAX_DISK` in `.env`. `render` keeps them.
- After any config or module change, run `python3 setup.py render && docker compose up -d && docker compose restart board worker`.
  `up -d` alone doesn't restart running containers, and they read `config.yaml` only at start.
- After a secret change, run `docker compose restart board worker`.
- If the board host's firewall has a `forward` policy of drop (common on hardened nftables setups), Docker's bridges
  need to be allowed out, or the containers hang on every outbound call (APIs, SSH, GeoIP, image builds). Check with
  `nft list chain inet filter forward`, and ask before adding e.g. `iifname { "docker0", "br-*" } accept` plus
  `ct state established,related accept`.
- Open the firewall on the board host for the ports the user's senders need: syslog (514 tcp/udp), Fluent Bit
  forward (24224 tcp), NetFlow (2055 udp) and the board port. Restrict each to the sending networks.

## 4. Connect the sources

Do these only for enabled modules, and confirm each host with the user first.

| Source | What to run | Where |
|---|---|---|
| Linux syslog | `remote/linux/logfwd.sh <board-address> [514] [tcp]` | each Linux host (root) |
| Pull hosts (`pull`, `traffic`, `trivy`, CrowdSec ban/unban) | `remote/linux/install-agent.sh --roles … --pubkey "$(python3 setup.py pubkey)" --from <board-ip>`, then add the host to `ssh.hosts` with the same roles | each host (root) |
| Connection logging on port-forwarding hosts (`traffic`) | `remote/linux/nft-traffic-log.sh [--input-ports …]` | edge/firewall host |
| Edge WAF (`waf`) | `remote/crowdsec/setup.sh --bouncer npm` (AppSec), then install-agent with role `waf`; optional `waf.cloudflare` zone/account IDs + `setup.py secret CLOUDFLARE_API_TOKEN`. Ask before the first change: Cloudflare pushes are live zone changes | edge host |
| HTTP edge logs (`traffic`) | `--traffic-globs` on install-agent: NPM proxy logs or nginx combined logs | edge host |
| CrowdSec (`crowdsec`) | `remote/crowdsec/setup.sh [--install] [--bouncer none\|nftables\|npm] …`, then add the host to `crowdsec.hosts` | each edge host |
| Windows (`windows`) | `remote/windows/install.ps1 -Board <addr> [-Dns]` (elevated) or `remote/windows/deploy.sh` over OpenSSH | each Windows host |
| Network gear | `docs/network-gear.md` | the device's UI/CLI |
| Webhook senders | `docs/webhook.md` | wherever |
| AI runner | `python3 setup.py runner-env --url <board-url> --out runner.env`, copy `runner.py` + `runner.env` (mode 600), add `AGENT`/`AGENT_CWD`/`AGENT_EXTRA_ARGS`, then keep it running (systemd unit, or a session hook that starts it; it holds `runner.env.lock`, so extra starts exit). See `ai-runner/README.md` | the machine with the agent CLI |

Notes:
- `ssh.hosts[].name` must match the host's syslog hostname so pulled and pushed data line up.
- Pull roles:
  - `logpull`: journal lines
  - `trafficpull`: tails `TRAFFIC_GLOBS`
  - `csctl`: CrowdSec ban/unban from the board
  - `images`: `docker ps` image list for trivy
- `--from` is the address the board's SSH connection **arrives from** as the host sees it: the board VM's LAN IP,
  its overlay IP (Tailscale/NetBird/WireGuard) when it reaches that host over the overlay, or the NAT address in
  between. A wrong `--from` looks exactly like a wrong key ("Permission denied").
- If sshd uses `AllowUsers`/`AllowGroups`, the `logwatch` user is locked out. install-agent prints a warning; with
  `--sshd-allow` it joins the first AllowGroups group or adds an `AllowUsers logwatch` drop-in (validated with
  `sshd -t`, then sshd reloads). Ask before using it on hosts with a hand-tuned sshd. Also check that sshd listens on
  the port in `ssh.hosts[].port`.
- install-agent **replaces** the `logwatch` user's `authorized_keys` and `/etc/logwatch-remote.conf`. Re-run it with
  every role the host needs, not only the new one.
- The first SSH connection pins the host key (`data/ssh/known_hosts`). If a host is rebuilt, delete its line there.
- CrowdSec's allow-list defaults to private ranges. Ask the user for their own admin IPs and pass them with `--allow`.
- NPM bouncer mode downloads the CrowdSec OpenResty bouncer from GitHub and edits NPM's custom nginx config. Tell the
  user, and make sure NPM keeps working afterwards.
- CrowdSec heartbeat: `setup.sh` installs `logwatch-crowdsec-health.timer` (every 5 min) and writes
  `/etc/logwatch-crowdsec.conf`:
  - `LAPI`: host:port the LAPI listens on, e.g. `127.0.0.1:8080`, or the Docker gateway (`172.18.0.1:8080`) in NPM mode.
  - `APPSEC`: host:port of the AppSec listener (`…:7422`). **Leave it empty on hosts without AppSec** (nftables-only
    gateways), or their card reports "WAF (AppSec) listener is down".
  - `CONTAINERS`: Docker containers whose running state goes on the card (e.g. `npm cloudflared`).
  - `BOUNCER_MATCH`: regex for the bouncer name whose last pull counts (`openresty`, `firewall|nftables`).

  Check it with `sudo /usr/local/sbin/logwatch-crowdsec-health` and `journalctl -t crowdsec-health -n 1`.

### Hosts that already run CrowdSec, nftables logging or a home-made heartbeat

The package uses fixed names. When the user's edge hosts were set up by hand before, line them up (ask first, back up
each file first, e.g. `cp f /root/f.bak-lw`):

- **AppSec acquisition**: the WAF manages `/etc/crowdsec/acquis.d/logwatch-appsec.yaml`. `setup.sh --bouncer npm`
  moves any other `source: appsec` file aside (`.bak-lw`), and `logwatch-wafctl` adopts a single existing one when
  ours is missing. With several, keep one and rename it to `logwatch-appsec.yaml`. It needs `listen_addr` and an
  `appsec_configs` list.
- **nftables log prefixes**: the traffic parser reads only `lw-conn` (new connections) and `lw-drop` (drops). Rename
  other prefixes in `/etc/nftables.conf`, in the live ruleset (`nft -a list ruleset`, then `nft replace rule …`) and in
  any rsyslog filter that routes them to the file in `TRAFFIC_GLOBS`. `remote/linux/nft-traffic-log.sh` does this
  for new setups.
- **Port proxies (`l4waf`)**: the board owns the nftables table `inet lw_waf` (`/etc/logwatch-waf/lw-waf.nft`, loaded
  at boot by `logwatch-nft.service`). It only filters (bans, rate and country rules) traffic that the host's own DNAT
  already forwards. It never creates DNAT, so **the host's DNAT/port forwarding must stay** where it is (iptables,
  nft or anything else). Once the board has applied its table, you can remove older hand-made *ban or filter* rules
  for the same ports, never the DNAT.
- **nftables at boot**: the agent and `nft-traffic-log.sh` don't use `/etc/nftables.conf` or enable `nftables.service`.
  On Debian/Ubuntu its stock config starts with `flush ruleset`, which also clears the DNAT that
  `netfilter-persistent` restores. If the host already has `nftables.service` enabled with that line, both scripts
  print a warning: leave the user's config alone and tell them.
- **Heartbeats**: disable any older timer/cron that also logs with tag `crowdsec-health`. The board takes the newest
  heartbeat per host, so a stale one wins half the time.
- **Cloudflare**: the board only touches objects it created: custom rules named `Logwatch - …` and the IP list
  `lw_bans`. Rules the user made by hand stay; ask before you remove overlapping ones.
- **Re-apply** after a migration so every engine gets the current files. Making any change on the Edge WAF tab does it,
  or run `docker compose exec board python3 -c "import waf; print(waf.apply('admin', 're-apply'))"`.

### Running commands on other hosts

- Run long jobs (package installs, CrowdSec hub updates, image builds) detached: `setsid nohup … >/tmp/x.log 2>&1 &`,
  then poll the log. A dropped SSH session shouldn't kill them.
- If SSH connection multiplexing (`ControlMaster`) hangs, use `ssh -o ControlMaster=no -o ControlPath=none …` and
  `</dev/null` for non-interactive commands.
- Never `pkill -f` a pattern that also appears in your own command line. It kills your shell. Kill by PID.
- Don't hand-edit the board DB. Use the board UI or `setup.py`.

## 5. Verify

On each connected Linux host, `remote/linux/check-host.sh --board <board-ip> [--syslog] [--roles …] [--crowdsec]` (root)
lists what's set up and what's missing; `--pubkey "…" --fix` installs the missing pieces.

- `docker compose ps`: all services up. `docker compose logs worker --tail 50` shows no tracebacks.
- Log in to the board.
  - **Logs** tab: lines from each syslog host within a minute or two.
  - **Infra** tab: Proxmox, UniFi, Windows and similar data after the next collector run (≤ 5 min).
- Pull hosts:

  ```bash
  docker compose exec worker ssh -i /secrets/ssh/id_ed25519 -o UserKnownHostsFile=/data/ssh/known_hosts \
    logwatch@<host> logpull -
  ```

  This should print JSON lines ending in `{"k": "end"…}`.
  The always-allowed `hello` role (`… logwatch@<host> hello`) prints the host's enabled roles and whether their tools
  are present. The web setup's checks run exactly that.
- CrowdSec / Edge WAF: each edge host's card shows all checks OK (engine, LAPI, AppSec where configured, bouncer), and
  the Edge WAF tab lists every engine as ok. Traffic should show requests/connections from each edge within minutes.
- Webhook: run the curl example from `docs/webhook.md`. An item should appear.
- AI: run `runner.py --once` while a run is queued. The `/ai/<id>` page should show the transcript. The board's
  "runner not seen" warning clears once the permanent runner polls.
- Expected at first: a burst of items (old certs, silent hosts, missing logs). Walk the user through them. Mute
  what they don't care about, and use `proxmox.no_logs_expected` for guests that never log. Test lines you write
  to VictoriaLogs while debugging can't be deleted (the bundled instance has no `-delete.enable`) and show up as a
  new host, later "stopped sending logs": mute that host.

## 6. Hand-over

Tell the user, briefly:

- **URL and login**:
  - change the password: `python3 setup.py set-password`
  - lockout: 10 failed logins within 15 minutes lock that IP out
- **Where things live**:
  - config: `config/config.yaml`
  - secrets: `secrets/secrets.env` + `secrets/ssh/`, mode 600; back these up, never share them
  - data: `data/` (board DB) + docker volume `logwatch_vlogs`
- **Updating**: the board prompts when a release is out (Update now / Schedule / Remind / Skip); nothing updates
  without a click unless they enable automatic updates. Backups land in `/var/backups/logwatch-dashboard`, with
  rollback if the board doesn't come back. Without systemd: `sudo bash install.sh` again.
- **Undo lines** for everything you installed on other hosts, and the `.bak-lw` backups you made.
- **Their choices**: what you enabled, and what's left optional.
