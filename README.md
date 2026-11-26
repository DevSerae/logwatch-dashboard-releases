<p align="center">
  <img src="assets/banner.svg" alt="Logwatch Dashboard" width="100%">
</p>

<p align="center">
  <a href="https://github.com/DevSerae/logwatch-dashboard-releases/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/DevSerae/logwatch-dashboard-releases?style=for-the-badge&color=9085e9&labelColor=17142b"></a>
  <img alt="Linux amd64 | arm64" src="https://img.shields.io/badge/linux-amd64%20%7C%20arm64-9085e9?style=for-the-badge&labelColor=17142b&logo=linux&logoColor=white">
  <img alt="Docker Compose" src="https://img.shields.io/badge/docker-compose%20v2-9085e9?style=for-the-badge&labelColor=17142b&logo=docker&logoColor=white">
  <img alt="Tested on Debian 12 and 13" src="https://img.shields.io/badge/tested-Debian%2012%20%7C%2013-9085e9?style=for-the-badge&labelColor=17142b&logo=debian&logoColor=white">
</p>

<p align="center">
  <b>A self-hosted "what needs doing" board for homelabs and small networks.</b><br>
  Logs, API data and edge traffic come in. A short list of things to act on comes out.
</p>

<p align="center">
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-what-you-get">What you get</a> ·
  <a href="#-prerequisites">Prerequisites</a> ·
  <a href="#-runs-on">Runs on</a> ·
  <a href="#-updates">Updates</a> ·
  <a href="#-uninstall">Uninstall</a>
</p>

---

## ⚡ Quick start

On the Linux VM that will host the board:

```bash
curl -fsSL https://github.com/DevSerae/logwatch-dashboard-releases/releases/latest/download/install.sh | sudo bash
```

That's it. The script installs what's missing (it **asks** before installing Docker), puts the board in
`/opt/logwatch-dashboard` and starts the web setup on the board's port. Open the link it prints (it carries a one-time
token); when you're done, the same page turns into the board at `http://<vm>:8080`.

<details>
<summary><b>Prefer to read it first?</b> (recommended)</summary>

```bash
curl -fsSLO https://github.com/DevSerae/logwatch-dashboard-releases/releases/latest/download/install.sh
less install.sh
sudo bash install.sh            # --dir <path> · --version <x.y.z> · --yes · --no-setup
```

Or download the tarball from [Releases](https://github.com/DevSerae/logwatch-dashboard-releases/releases/latest),
check it against `SHA256SUMS`, unpack and run `sudo bash logwatch-dashboard/install.sh`.
</details>

<details>
<summary><b>Let your AI agent do it</b> (Claude Code, CloudCLI, Codex, Gemini CLI, OpenCode…)</summary>

Give the agent a shell on the board VM (and SSH to the servers it should set up), then say:

> Install Logwatch Dashboard from https://github.com/DevSerae/logwatch-dashboard-releases: run its install.sh with
> `--no-setup`, then follow AGENT_INSTALL.md in /opt/logwatch-dashboard.

The playbook makes it interview you first, ask before touching any machine, keep secrets out of the chat, and give you
an undo line for everything it installs.
</details>

## ✨ What you get

**🧾 The board, always on.** One list of things that need a person, each with history, notes, snooze, mute and
resolve. Also: an **Events** timeline, a **Hosts** view of log ingest per host, a **Logs** explorer on VictoriaLogs
(any query can become an alert rule), maintenance windows that silence what they cover, GeoIP, and updates you approve.

Everything else is a **module**. The setup groups modules into **monitors**; pick only what you use. A module that's
off runs no collectors, makes no outbound calls and needs no secrets.

### 🔎 Logs

| Module | Turn it on and you get |
|---|---|
| **Syslog intake** (on by default) | Linux hosts and network gear push syslog (TCP/UDP). Alerts for hosts that go silent, SSH brute force, new logins and your own log rules |
| **SSH pull** | The same for hosts that can't push: the board pulls their journal over SSH every minute |
| **Windows events** | Failed logons, service crashes, disk/NTFS errors, reboots and a heartbeat from Windows hosts via Fluent Bit; optional DNS top domains |
| **Alert file** | Picks up alerts another system already writes as JSON lines (SMB share or local file) |
| **Webhook** | `POST /api/ingest`: scripts, Uptime Kuma, Grafana or cron jobs raise and clear items |

### 🛡️ Edge WAF

| Module | Turn it on and you get |
|---|---|
| **CrowdSec** | A health card per edge host (engine, LAPI, AppSec, bouncer), bans and WAF blocks, repeat offenders, Ban/Unban from the board |
| **Request / connection log** | Every HTTP request (Nginx Proxy Manager / nginx) and every new connection (nftables) through your edge, on a world map with filters |
| **Edge WAF** | Custom layer-7 rules from a rule builder, IP/CIDR bans with expiry, country/ASN rules, OWASP CRS level, and **port proxies** for raw TCP/UDP (game servers…). Every change starts log-only, can be simulated against the last 24 h of traffic, and can be undone. Optional push to Cloudflare |

### 📡 Network

| Module | Turn it on and you get |
|---|---|
| **UniFi** | IPS/IDS alerts, firewall flows, gateway events and WAN health |
| **NetFlow / IPFIX** | Flows from any NetFlow v5/v9/IPFIX exporter |

### 🖥️ Hosts

| Module | Turn it on and you get |
|---|---|
| **Action1** | Missing patches and reboot-pending endpoints, per host |
| **Wazuh** | Agent status, SCA score, critical/high vulnerabilities and alerts merged into Hosts; alerts into Logs |
| **Container image CVEs** | A weekly Trivy scan of the images your containers run, with alerts for fixable HIGH/CRITICAL CVEs |

### ⏱️ Services

| Module | Turn it on and you get |
|---|---|
| **Uptime** | A Status tab with HTTP(S)/TCP probes every minute and response-time history. Add checks right on the tab |
| **Expiry** | TLS certificates, domain registrations (RDAP) and manual dates, warned about ahead of time |

### 🏗️ Infra

| Module | Turn it on and you get |
|---|---|
| **Proxmox VE** | Nodes, guests, storage, backup freshness per guest, SMART and ZFS health, guests that never sent logs. In the setup, **Discover** fills every host list from your cluster |

### 🧪 Extras

| Module | Turn it on and you get |
|---|---|
| **Instatus** | Board maintenance windows also post and resolve maintenance on your Instatus page |
| **Resolve with AI** | Your agent CLI (Claude Code, Codex, Gemini, OpenCode) works an incident while you watch the live transcript on the board |

## 🧭 The web setup

Five steps in your browser, everything optional, every feature expands to exactly the inputs it needs. It runs on the
board's port behind a one-time token from the terminal and hands the port to the board when it's done.

| | |
|---|---|
| **1 · Board** | Port, login, who may reach the board, retention, GeoIP, updates |
| **2 · Access** | How this VM reaches your servers: direct, **Tailscale**, **NetBird**, **Cloudflare One** or another VPN. Lists exactly which ports and paths must be open, can install and join Tailscale/NetBird for you, and tests every server you enter |
| **3 · Features** | Turn areas and sources on, each with its inputs, steps and live checks. With Proxmox, **Discover** finds your nodes, VMs and containers |
| **4 · Servers** | Only what your picks need on each server. **Without AI**: one copy-paste line per server. **With AI**: a prompt to paste into any AI agent (Claude Code, CloudCLI, Codex, Gemini, OpenCode…), on the VM or anywhere that reaches your servers; it must ask you for access to every server and show every command first |
| **5 · Install** | Run every check, save, build and start; the page turns into the board's login |

Turn on more features later from the board's **Settings → Install features**; only the new pieces show up.

<p align="center">
  <img src="assets/setup-servers.png" alt="Servers step: one copy-paste line per server for the features you picked" width="88%">
</p>

<details>
<summary><b>More screenshots</b></summary>
<br>
<p align="center">
  <img src="assets/setup-access.png" alt="Access step: direct access with the exact ports and paths to open" width="88%"><br><br>
  <img src="assets/setup-ai.png" alt="Servers step with AI: the agent CLIs found on the VM and the prompt to start one" width="88%">
</p>
</details>

## 📋 Prerequisites

| | Minimum | Notes |
|---|---|---|
| **CPU / RAM** | 2 vCPU · 2 GB | 4 GB if you enable many modules or keep long retention |
| **Disk** | ~30 GB | logs are capped at 20 GB by default (30 days) |
| **Docker** | Engine 24+ with Compose v2 | `install.sh` offers to install it from get.docker.com |
| **Python** | 3.9+ | for the installer and `setup.py`; `python3-venv` is installed if missing |
| **systemd** | recommended | needed for one-click updates from the board |
| **Network** | outbound HTTPS | GitHub (updates), GeoIP downloads, the APIs you enable |
| **Reachability** | board ⇄ servers | SSH out to pulled hosts; syslog/NetFlow in from senders. LAN, VPN or overlay all fine |
| **Firewall** | Docker can forward | if the VM's firewall drops forwarded traffic, allow Docker's bridges out or the containers can't reach anything |

API access is read-only wherever the vendor allows it (Proxmox PVEAuditor, UniFi read-only key, Wazuh readonly role…).

## 🐧 Runs on

| Platform | Status |
|---|---|
| **Debian 13** (trixie) | ✅ Tested |
| **Debian 12** (bookworm) | ✅ Tested |
| Ubuntu 22.04 / 24.04 LTS | 🟡 Should work, untested |
| Rocky Linux / AlmaLinux 9, RHEL 9 | 🟡 Should work, untested (dnf) |
| Fedora (current) | 🟡 Should work, untested (dnf) |
| Proxmox LXC container | 🟡 Should work, untested: enable **nesting** (and **keyctl** for unprivileged CTs) |
| arm64 (Raspberry Pi 4/5, Ampere…) | 🟡 Should work, untested |
| Arch, Alpine, openSUSE, others | ⚙️ Manual: install Docker + Compose and Python 3.9+ yourself, then run `install.sh` |
| macOS, Windows, WSL | ❌ Not supported |

A VM is the smoothest option. Running the board on a Proxmox host itself isn't recommended: use a VM or CT.

## 🌐 Remote servers

Not everyone's network looks the same, so the installer asks instead of assuming:

| Way | What the installer does |
|---|---|
| **Direct** (same LAN, routed VLANs, site-to-site VPN) | nothing to install; tests the routes and SSH ports |
| **Tailscale** | installs and joins this VM with a one-off auth key (never stored); explains ACLs and subnet routers |
| **NetBird** | installs and joins with a setup key, self-hosted management URL supported; explains policies and routes |
| **Cloudflare One** | WARP client steps with headless service-token enrolment and private network routes |
| **Other** (WireGuard, ZeroTier, OpenVPN…) | checks the interface and shows which one reaches each server |

## 🔄 Updates

- The board checks this repo every 12 hours (turn it off with `updates.check: false`).
- When a release is out, it asks: **Update now**, **Schedule** for a time you pick, **Remind me tomorrow**, or
  **Skip this version**. Nothing changes until you click.
- Optional: tick *install new releases automatically* to get them at 03:00.
- The host helper (`update.sh` via systemd) downloads only from the repo set on the host, verifies `SHA256SUMS`, backs
  up code and config, rebuilds, and **rolls back** if the board isn't healthy within 3 minutes.

Manual update any time: run the one-liner again. Your config, secrets and data are never touched.

## 🔐 Security

- Single admin account, PBKDF2 password hashes, signed HttpOnly cookies, login lockout, optional `allow_cidrs`.
- The board's SSH key can only run one dispatcher on each host, which allows only the roles you enabled there and
  validates every argument.
- Containers run as an unprivileged user with config and secrets mounted read-only.
- Secrets live in `secrets/` (mode 600) on your VM and never leave it. VPN join keys are used once and never stored.

## 🧹 Uninstall

```bash
cd /opt/logwatch-dashboard && sudo docker compose down -v
sudo systemctl disable --now logwatch-update.path logwatch-update.timer
sudo rm -rf /opt/logwatch-dashboard /etc/systemd/system/logwatch-update.* /etc/default/logwatch-dashboard /var/backups/logwatch-dashboard
sudo userdel logwatch
```

Scripts installed on monitored hosts each print their own undo line in their header.

---

<p align="center"><sub>Releases only: this repo holds the installer and release assets.</sub></p>
