"""Everything the installer asks, in one place: monitors (board tabs) → modules → fields.

Field keys:
  "a.b.c"          a config.yaml path
  "secret:NAME"    a secrets.env entry (never shown again once stored)
  "ssh:<role>"     hosts list ("name address [port]" per line); merged into ssh.hosts with that role
Kinds: text, int, bool, choice, secret, list (one item per line), csv (comma separated), lines (custom parser in configio).
"""
from dataclasses import dataclass, field


@dataclass
class F:
    key: str
    label: str
    kind: str = "text"
    default: object = None
    help: str = ""
    required: bool = False
    options: tuple = ()
    placeholder: str = ""


@dataclass
class Module:
    id: str
    title: str
    what: str
    fields: list = field(default_factory=list)
    checks: tuple = ()          # check ids in checks.py
    default_on: bool = False


@dataclass
class Monitor:
    id: str
    title: str
    what: str
    modules: list


SSH_HELP = "One host per line: name address [port]. The name must match the host's syslog hostname."

MONITORS = [
    Monitor("logs", "Logs", "Central log search, silent hosts, SSH brute force, custom log rules.", [
        Module("syslog", "Syslog intake", "Linux hosts and network gear push syslog to this VM.", [
            F("syslog.port", "Syslog port (TCP+UDP)", "int", 514),
            F("syslog.silent_hours", "Hours of silence before a host counts as gone", "int", 2),
            F("syslog.ssh_fail_threshold", "Failed SSH logins per host per 15 min before an item", "int", 20),
            F("syslog.ignore_login_from", "Don't report successful logins from (CIDRs)", "csv", [], placeholder="192.0.2.0/24"),
            F("hosts:syslog", "Linux hosts that will send syslog (for the setup steps)", "list", [],
              help="One per line: name address. Only used to write the steps and checks below.", placeholder="web-1 192.0.2.21"),
        ], checks=("port:syslog.port:tcp", "port:syslog.port:udp"), default_on=True),
        Module("pull", "SSH pull", "The board pulls journal lines over SSH from hosts that can't push syslog.", [
            F("ssh:logpull", "Hosts to pull from", "list", [], SSH_HELP, True, placeholder="nas-1 192.0.2.22"),
        ], checks=("ssh:logpull",)),
        Module("windows", "Windows events", "Event logs from Windows hosts via Fluent Bit (failed logons, crashes, disk errors, reboots).", [
            F("windows.forward_port", "Fluent Bit forward port (TCP)", "int", 24224),
            F("windows.fail_threshold", "Failed logons per host per window before an item", "int", 30),
            F("windows.dns.enabled", "Windows DNS server debug log → top domains per device", "bool", False),
            F("hosts:windows", "Windows hosts (for the setup steps)", "list", [], placeholder="dc-1 192.0.2.30"),
        ], checks=("port:windows.forward_port:tcp",)),
        Module("alertfile", "Alert file", "Alerts another system already writes (JSON lines on an SMB share or a local file): Error/Warning become items.", [
            F("alertfile.path", "File", "text", "", "SMB: //server/share/path/alerts.jsonl · local: a path inside the container (/data/...).",
              True, placeholder="//files.example.com/it$/Alerts/alerts.jsonl"),
            F("secret:ALERTFILE_SMB_USER", "SMB user (DOMAIN\\user), read-only", "secret"),
            F("secret:ALERTFILE_SMB_PASSWORD", "SMB password", "secret"),
            F("alertfile.source", "Source name on the board", "text", "alerts"),
        ], checks=("alertfile",)),
        Module("webhook", "Webhook", "POST /api/ingest: scripts, Uptime Kuma, Grafana or cron jobs raise and clear items.", [
            F("secret:INGEST_TOKEN", "Ingest token", "secret", help="Leave blank to generate one."),
        ]),
    ]),
    Monitor("edge", "Edge WAF", "Edge proxies: CrowdSec, every request/connection, custom WAF rules, bans, country/ASN rules.", [
        Module("crowdsec", "CrowdSec", "Engine/bouncer health, bans and WAF blocks, repeat offenders, Ban/Unban from the board.", [
            F("lines:crowdsec.hosts", "CrowdSec hosts", "list", [], "One per line: name [web]. web = it fronts HTTP sites (WAF expected).",
              True, placeholder="edge-1 web"),
            F("ssh:csctl", "Hosts the board may Ban/Unban on (SSH)", "list", [], SSH_HELP, placeholder="edge-1 192.0.2.21"),
        ], checks=("ssh:csctl",)),
        Module("traffic", "Request / connection log", "Every HTTP request (NPM/nginx logs) and new connection (nftables) through edge hosts, with GeoIP.", [
            F("ssh:trafficpull", "Edge hosts to pull traffic logs from", "list", [], SSH_HELP, True, placeholder="edge-1 192.0.2.21"),
            F("traffic.block_status", "Statuses the edge answers when blocking", "csv", [403, 429, 444]),
            F("tglobs", "Access log paths on the edge hosts (for the setup steps)", "text",
              "/data/logs/proxy-host-*_access.log", help="NPM: /data/logs/proxy-host-*_access.log · nginx: /var/log/nginx/access.log"),
        ], checks=("ssh:trafficpull",)),
        Module("waf", "Edge WAF", "Custom layer-7 rules, IP/CIDR bans, country/ASN rules, OWASP CRS level. Log-only first, undoable.", [
            F("ssh:waf", "Edge proxies with CrowdSec AppSec", "list", [], SSH_HELP, placeholder="edge-1 192.0.2.21"),
            F("ssh:l4waf", "Port proxies (nftables, raw TCP/UDP ports)", "list", [], SSH_HELP + " Optional.", placeholder="ports-1 192.0.2.25"),
            F("lines:waf.port_groups", "Port groups (become port lists on first start)", "list", [], "One per line: name: ports. Edited under Edge WAF → Lists afterwards", placeholder="App servers: 8000-8100"),
            F("cf", "Also push bans and country/ASN rules to Cloudflare", "bool", False),
            F("waf.cloudflare.zone", "Cloudflare zone ID", "text", "", "Zone ID (32 hex), not the domain name.", placeholder="0123456789abcdef0123456789abcdef"),
            F("waf.cloudflare.account", "Cloudflare account ID", "text", "", placeholder="0123456789abcdef0123456789abcdef"),
            F("secret:CLOUDFLARE_API_TOKEN", "Cloudflare API token", "secret", help="Permissions: Zone WAF Edit + Account Filter Lists Edit."),
        ], checks=("ssh:waf", "ssh:l4waf", "cloudflare")),
    ]),
    Monitor("network", "Network", "Gateway IPS alerts, firewall flows, WAN health, NetFlow.", [
        Module("unifi", "UniFi", "IPS/IDS alerts, firewall flows, gateway events, WAN health.", [
            F("unifi.url", "Console URL", "text", "", "The console address or a Site Manager connector URL.", True, placeholder="https://192.0.2.1"),
            F("unifi.site", "Site", "text", "default"),
            F("unifi.verify_tls", "Verify TLS", "bool", False),
            F("unifi.gateway_name", "Gateway name (as it appears in logs)", "text", "gateway"),
            F("unifi.ips_item_min_risk", "IPS alerts that raise an item", "choice", "high", options=("low", "medium", "high", "very_high")),
            F("unifi.wan", "WAN health", "bool", True),
            F("secret:UNIFI_API_KEY", "API key", "secret", help="UniFi Network → Settings → Control Plane → Integrations, created by a View Only admin. The board only reads (two of its searches are POSTs, see MODULES.md).", required=True),
        ], checks=("unifi",)),
        Module("netflow", "NetFlow / IPFIX", "Flows from any NetFlow v5/v9/IPFIX exporter.", [
            F("netflow.port", "NetFlow port (UDP)", "int", 2055),
            F("hosts:netflow", "Exporters (for the setup steps)", "list", [], placeholder="router-1 192.0.2.1"),
        ], checks=("port:netflow.port:udp",)),
    ]),
    Monitor("hosts", "Hosts", "Per-host patch, agent and vulnerability status next to the log view.", [
        Module("action1", "Action1", "Missing patches and reboot-pending endpoints.", [
            F("action1.base_url", "API base URL", "text", "https://app.action1.com/api/3.0",
              help="EU: https://app.eu.action1.com/api/3.0 · AU: https://app.au.action1.com/api/3.0"),
            F("secret:ACTION1_CLIENT_ID", "Client ID", "secret", required=True),
            F("secret:ACTION1_CLIENT_SECRET", "Client secret", "secret", required=True),
            F("secret:ACTION1_ORG_ID", "Organization ID", "secret", required=True,
              help="Action1 → Configuration → API Credentials (role: read-only). The org ID is in the console URL."),
        ], checks=("action1",)),
        Module("wazuh", "Wazuh", "Agents (status, SCA score, vulnerabilities, alerts 24h) merged into Hosts; alerts into Logs.", [
            F("wazuh.api_url", "Manager API URL", "text", "", "Port 55000 on the Wazuh manager.", True, placeholder="https://wazuh.example.com:55000"),
            F("secret:WAZUH_API_USER", "API user", "secret", required=True, help="A read-only API user (role readonly)."),
            F("secret:WAZUH_API_PASSWORD", "API password", "secret", required=True),
            F("wazuh.indexer_url", "Indexer URL (vulnerabilities + alerts)", "text", "", "Port 9200. Empty = agents and SCA only.",
              placeholder="https://wazuh.example.com:9200"),
            F("secret:WAZUH_INDEXER_USER", "Indexer user", "secret", help="Read on wazuh-alerts-* and wazuh-states-vulnerabilities-*."),
            F("secret:WAZUH_INDEXER_PASSWORD", "Indexer password", "secret"),
            F("wazuh.verify_tls", "Verify TLS", "bool", False, "Wazuh ships self-signed certificates."),
            F("wazuh.alerts", "Alerts into Logs", "choice", "indexer", options=("indexer", "syslog", "off"),
              help="indexer = the board pulls them · syslog = the manager forwards them (no indexer access needed) · off"),
            F("wazuh.min_level", "Lowest rule level kept in Logs", "int", 3),
            F("wazuh.alert_item_level", "Rule level that raises a board item", "int", 12),
            F("wazuh.vuln_items", "An item per agent with critical vulnerabilities", "bool", True),
        ], checks=("wazuh",)),
        Module("trivy", "Container image CVEs", "Weekly scan of running container images for fixable HIGH/CRITICAL CVEs.", [
            F("ssh:images", "Docker hosts", "list", [], SSH_HELP, True, placeholder="apps-1 192.0.2.23"),
        ], checks=("ssh:images",)),
    ]),
    Monitor("services", "Services", "Uptime probes and everything that expires.", [
        Module("uptime", "Uptime", "HTTP(S)/TCP probes every minute with response-time history.", [
            F("lines:uptime.targets", "Checks", "list", [], "One per line: name url  ·  or: name tcp host:port. More can be added on the board.",
              placeholder="Website https://www.example.com"),
            F("uptime.fails_to_alert", "Failed probes in a row before an item", "int", 2),
            F("board.ok_redirect_hosts", "Redirects to these count as up (SSO login pages)", "csv", [], placeholder="sso.example.com"),
        ], checks=("uptime",), default_on=True),
        Module("expiry", "Expiry", "TLS certificates, domain registrations (RDAP), manual dates.", [
            F("lines:expiry.tls", "TLS endpoints", "list", [], "One per line: host[:port] [sni]", placeholder="www.example.com:443"),
            F("expiry.domains", "Domains", "csv", [], placeholder="example.com"),
            F("expiry.warn_days", "Warn this many days ahead", "int", 30),
        ], checks=("expiry",), default_on=True),
    ]),
    Monitor("infra", "Infra", "Hypervisor, storage, backups and disk health.", [
        Module("proxmox", "Proxmox VE", "Nodes, guests, storage, backup freshness, SMART + ZFS, guests that never sent logs.", [
            F("proxmox.url", "API URL", "text", "", "Any cluster node.", True, placeholder="https://192.0.2.40:8006"),
            F("secret:PROXMOX_TOKEN", "API token", "secret", help="user@realm!tokenid=uuid with role PVEAuditor on /.", required=True),
            F("proxmox.verify_tls", "Verify TLS", "bool", False),
            F("proxmox.backups", "Backup freshness", "bool", True),
            F("proxmox.backup_stale_hours", "Backup counts as stale after (hours)", "int", 48),
            F("proxmox.disks", "SMART + ZFS health", "bool", True),
            F("proxmox.storage_warn_pct", "Storage warning at (%)", "int", 85),
            F("proxmox.no_logs_expected", "Guests that never send logs on purpose", "csv", []),
        ], checks=("proxmox",)),
    ]),
    Monitor("extras", "Extras", "Status page maintenance and Resolve with AI.", [
        Module("instatus", "Instatus", "Board maintenance windows also post maintenance on an Instatus page.", [
            F("instatus.page_id", "Page ID", "text", "", required=True),
            F("secret:INSTATUS_API_KEY", "API key", "secret", required=True),
            F("instatus.public_text", "Public maintenance text", "text", "We're carrying out scheduled maintenance."),
        ], checks=("instatus",)),
        Module("ai", "Resolve with AI", "Your AI agent CLI works incidents, live transcript on the board (ai-runner/).", [
            F("ai.agent_label", "Agent name shown on the board", "text", "AI agent", placeholder="Claude Code"),
            F("ai.chat_url", "Link to the agent's chat UI ({run_id} is replaced)", "text", ""),
        ]),
    ]),
]

BOARD_FIELDS = [
    F("board.title", "Board title", "text", "Logwatch Dashboard"),
    F("board.host_label", "Label in the top bar", "text", "", placeholder="logwatch-1"),
    F("addr", "This VM's address (how other machines reach it)", "text", "", required=True),
    F("env:BOARD_PORT", "Board port", "int", 8080),
    F("board.cookie_secure", "Board is served over HTTPS (reverse proxy / tunnel)", "bool", False,
      "Off = plain http on the LAN. On = cookies are Secure; see docs/reverse-proxy.md."),
    F("board.allow_cidrs", "Networks that may open the login page", "csv", [], "Empty = anyone who can reach the port.",
      placeholder="192.0.2.0/24, 198.51.100.0/24"),
    F("board.trusted_proxies", "Reverse proxies / tunnel connectors (X-Forwarded-For trusted)", "csv", [],
      "The address the proxy or cloudflared connects to the board from (cloudflared in Docker on this VM: the Docker "
      "network's gateway, e.g. 172.17.0.1/32).", placeholder="192.0.2.5/32"),
    F("board.proxy_public", "Let visitors through those proxies in from anywhere", "bool", False,
      "For a public tunnel (Cloudflare Tunnel): allowed networks then only limit direct access. Put Cloudflare Access "
      "in front, or rely on the board's login + MFA."),
    F("board.open_cidrs", "Networks that skip the login", "csv", [],
      "Trusted LAN or a dashboard that embeds the board. Anyone in them gets full access.", placeholder="192.0.2.0/24"),
    F("board.cf_access.team", "Cloudflare Access team domain", "text", "",
      "Only if Cloudflare Access protects the board: a valid Access login signs you in.", placeholder="yourteam.cloudflareaccess.com"),
    F("board.cf_access.aud", "Cloudflare Access application AUD tag", "text", ""),
    F("board.cf_access.required", "Require Cloudflare Access for traffic from the reverse proxies", "bool", False),
    F("board.geoip", "GeoIP", "choice", "dbip", options=("dbip", "maxmind", "off"), help="dbip needs no account."),
    F("secret:MAXMIND_ACCOUNT_ID", "MaxMind account ID (geoip: maxmind)", "secret"),
    F("secret:MAXMIND_LICENSE_KEY", "MaxMind licence key", "secret"),
    F("env:TZ", "Time zone", "text", "UTC", placeholder="America/Toronto"),
    F("env:VL_RETENTION", "Log retention", "text", "30d"),
    F("env:VL_MAX_DISK", "Log disk cap", "text", "20GiB"),
    F("updates.check", "Check for new releases", "bool", True, "The board asks before installing anything."),
    F("updates.auto", "Install new releases automatically", "bool", False, "At the time below, with backup + rollback. Can be changed on the board."),
    F("updates.auto_at", "Automatic update time (HH:MM, this VM's time zone)", "text", "03:00"),
    F("board.min_password_length", "Minimum password length", "int", 12,
      "For every board user, 4 to 128. Below 12 only if the board isn't reachable from the internet."),
    F("admin_user", "Admin user", "text", "admin", required=True),
    F("admin_pw", "Admin password (at least the minimum length above)", "secret"),
    F("admin_pw2", "Admin password again", "secret"),
]


# How this VM reaches the servers (installer-only answers, kept in data/installer.json; once_* are never stored)
METHODS = {
    "direct": "Direct (same LAN, routed VLANs or a site-to-site VPN on the router)",
    "tailscale": "Tailscale",
    "netbird": "NetBird (cloud or self-hosted)",
    "cfone": "Cloudflare One (WARP client / WARP Connector)",
    "other": "Another VPN on this VM (WireGuard, ZeroTier, OpenVPN, …)",
}

ACCESS_FIELDS = [
    F("acc_direct", METHODS["direct"], "bool", True),
    F("acc_tailscale", METHODS["tailscale"], "bool", False),
    F("once_ts_authkey", "Tailscale auth key (used once to join, not stored)", "secret",
      help="admin console → Settings → Keys → Generate auth key (reusable off, pre-approved on)."),
    F("acc_ts_hostname", "Name of this VM in the tailnet", "text", "logwatch"),
    F("acc_netbird", METHODS["netbird"], "bool", False),
    F("once_nb_setup_key", "NetBird setup key (used once to join, not stored)", "secret",
      help="NetBird dashboard → Setup Keys → Create (one-off). Put the peer in a group your access policy lets reach the servers."),
    F("acc_nb_management", "NetBird management URL (self-hosted only)", "text", "", placeholder="https://netbird.example.com"),
    F("acc_cfone", METHODS["cfone"], "bool", False),
    F("acc_cf_team", "Zero Trust team name", "text", "", placeholder="example (from example.cloudflareaccess.com)"),
    F("acc_other", METHODS["other"], "bool", False),
    F("acc_other_iface", "Its interface on this VM", "text", "", placeholder="wg0"),
]

ALL_MODULES = {m.id: m for mon in MONITORS for m in mon.modules}
MONITOR_OF = {m.id: mon.id for mon in MONITORS for m in mon.modules}
SSH_ROLES = ("logpull", "trafficpull", "csctl", "images", "waf", "l4waf")
