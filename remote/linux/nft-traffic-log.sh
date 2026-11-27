#!/bin/bash
# Logwatch Dashboard (module "traffic"): log new connections on a port-forwarding / firewall host so the board's
# Edge tab shows them. Adds a separate nftables table (doesn't touch your ruleset), loaded at boot by
# logwatch-nft.service, and an rsyslog rule that writes the lines to /var/log/logwatch-traffic.log, which the
# trafficpull role tails.
# Run as root:  ./nft-traffic-log.sh [--input-ports "25565,27015"] [--rate 50]
#   forward chain: every NEW forwarded (DNAT'd) connection → "lw-conn:"
#   input chain:   NEW connections to --input-ports on this host → "lw-conn:"
# Optional dropped-probe logging ("lw-drop:"): in YOUR input chain, right before the final drop, add
#   limit rate 20/second log prefix "lw-drop: " level info
# Undo: nft delete table inet logwatch; rm /etc/nftables.d/logwatch.nft /etc/rsyslog.d/10-logwatch-traffic.conf
#   (and systemctl disable logwatch-nft unless the host also has role l4waf)
set -euo pipefail
PORTS=""; RATE=50
while [ $# -gt 0 ]; do case "$1" in --input-ports) PORTS=$2; shift 2 ;; --rate) RATE=$2; shift 2 ;; *) exit 2 ;; esac; done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v nft >/dev/null || { echo "nftables is required" >&2; exit 1; }
# Load the board's own nft tables at boot from their own unit: never via /etc/nftables.conf, whose stock Debian/Ubuntu
# "flush ruleset" would also clear the DNAT that netfilter-persistent restores. Each file only (re)defines its own table.
lw_nft_unit() {
  cat > /etc/systemd/system/logwatch-nft.service <<'UNIT'
[Unit]
Description=Logwatch Dashboard nftables tables (inet logwatch, inet lw_waf)
After=nftables.service netfilter-persistent.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'rc=0; for f in /etc/nftables.d/logwatch.nft /etc/logwatch-waf/lw-waf.nft; do [ -f "$$f" ] && { nft -f "$$f" || rc=1; }; done; exit $$rc'

[Install]
WantedBy=multi-user.target
UNIT
  [ -f /etc/nftables.conf ] && sed -i '\#include "/etc/nftables.d/logwatch.nft"#d; \#include "/etc/logwatch-waf/lw-waf.nft"#d' /etc/nftables.conf
  systemctl daemon-reload && systemctl enable logwatch-nft >/dev/null 2>&1 || echo "NOTE: enable logwatch-nft.service or the board's nft tables are gone after a reboot"
  if systemctl is-enabled nftables >/dev/null 2>&1 && grep -qE '^[[:space:]]*flush ruleset' /etc/nftables.conf 2>/dev/null; then
    echo "WARNING: nftables.service is enabled and /etc/nftables.conf starts with 'flush ruleset': at boot that also clears" >&2
    echo "  rules other tools restore (iptables-persistent DNAT). Comment it out if this host relies on them." >&2
  fi
}
mkdir -p /etc/nftables.d
{
  echo "table inet logwatch"
  echo "delete table inet logwatch"
  echo "table inet logwatch {"
  echo "  chain lwconn { type filter hook forward priority -5; policy accept;"
  echo "    ct state new limit rate $RATE/second log prefix \"lw-conn: \" level info"
  echo "  }"
  if [ -n "$PORTS" ]; then
    echo "  chain lwinp { type filter hook input priority -5; policy accept;"
    echo "    ct state new meta l4proto { tcp, udp } th dport { $PORTS } limit rate $RATE/second log prefix \"lw-conn: \" level info"
    echo "  }"
  fi
  echo "}"
} > /etc/nftables.d/logwatch.nft
nft -c -f /etc/nftables.d/logwatch.nft || { echo "nft rejected /etc/nftables.d/logwatch.nft (nft $(nft --version 2>/dev/null))" >&2; exit 1; }
nft -f /etc/nftables.d/logwatch.nft
lw_nft_unit

cat > /etc/rsyslog.d/10-logwatch-traffic.conf <<'CONF'
# Logwatch Dashboard: nftables lw-conn/lw-drop lines → /var/log/logwatch-traffic.log (pulled by the board), not forwarded.
template(name="LwTraffic" type="string" string="%timereported:::date-rfc3339% %msg:R,ERE,1,FIELD:(lw-(conn|drop): .*)--end%\n")
:msg, ereregex, "lw-(conn|drop): " { action(type="omfile" file="/var/log/logwatch-traffic.log" template="LwTraffic") stop }
CONF
cat > /etc/logrotate.d/logwatch-traffic <<'CONF'
/var/log/logwatch-traffic.log {
    daily
    rotate 2
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog 2>/dev/null || true
    endscript
}
CONF
rsyslogd -N1 >/dev/null 2>&1 || { rsyslogd -N1; exit 1; }
systemctl restart rsyslog
echo "ok: add /var/log/logwatch-traffic.log to TRAFFIC_GLOBS (install-agent.sh --traffic-globs) and role trafficpull"
