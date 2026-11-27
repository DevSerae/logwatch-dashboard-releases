#!/bin/bash
# Logwatch Dashboard: check that a Linux host is set up for the modules you want, and optionally fix it.
# Run as root ON THE HOST, from this directory. Read-only unless --fix is given.
#   ./check-host.sh --board 192.0.2.10 [--syslog] [--roles logpull,trafficpull,csctl,images,waf,l4waf]
#                   [--pubkey "ssh-ed25519 AAAA... logwatch"] [--crowdsec] [--fix]
#   --board     the board's address (syslog target, and the SSH source the agent key is limited to)
#   --syslog    this host should forward its syslog to the board (module syslog)
#   --roles     what the board may run here over SSH (modules pull, traffic, crowdsec Ban/Unban, trivy, waf, port-proxy l4waf)
#   --crowdsec  this is an edge host: CrowdSec heartbeat + events file expected (module crowdsec)
#   --fix       run logfwd.sh / install-agent.sh for whatever is missing (needs --pubkey for roles)
# Exit code: 0 all good, 1 something missing (after --fix: still missing).
set -uo pipefail
cd "$(dirname "$0")"
BOARD=""; SYSLOG=0; ROLES=""; PUB=""; CS=0; FIX=0
while [ $# -gt 0 ]; do
  case "$1" in
    --board) BOARD=$2; shift 2 ;;
    --syslog) SYSLOG=1; shift ;;
    --roles) ROLES=$2; shift 2 ;;
    --pubkey) PUB=$2; shift 2 ;;
    --crowdsec) CS=1; shift ;;
    --fix) FIX=1; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -n "$BOARD" ] || { echo "need --board <address>" >&2; exit 2; }
BAD=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
miss() { printf '  \033[31mmiss\033[0m  %s\n' "$*"; BAD=1; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$*"; }
has()  { case ",$ROLES," in *,"$1",*) return 0 ;; esac; return 1; }

check() {
  BAD=0
  echo "host $(hostname) → board $BOARD"
  command -v python3 >/dev/null && ok "python3" || miss "python3 (the agent needs it)"
  if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qx yes; then ok "clock synced"; else warn "clock not NTP-synced: log times may drift"; fi

  if [ $SYSLOG = 1 ]; then
    if [ -f /etc/rsyslog.d/90-logwatch.conf ] && grep -q "target=\"$BOARD\"" /etc/rsyslog.d/90-logwatch.conf; then
      systemctl is-active -q rsyslog && ok "syslog forwarding to $BOARD" || miss "rsyslog not running"
    else miss "syslog forwarding to $BOARD (logfwd.sh)"; fi
  fi

  if [ -n "$ROLES" ]; then
    if [ -x /usr/local/sbin/logwatch-remote ] && [ -f /etc/logwatch-remote.conf ]; then
      have=$(sed -n 's/^ROLES=//p' /etc/logwatch-remote.conf)
      for r in ${ROLES//,/ }; do
        case ",$have," in *,"$r",*) ok "agent role $r" ;; *) miss "agent role $r (installed: ${have:-none})" ;; esac
      done
      H=$(getent passwd logwatch | cut -d: -f6)
      if [ -n "$H" ] && grep -q 'logwatch-remote' "$H/.ssh/authorized_keys" 2>/dev/null; then ok "board key (forced command)"
      else miss "board key in ~logwatch/.ssh/authorized_keys"; fi
      [ -f /etc/sudoers.d/logwatch-remote ] && ok "sudoers rule" || miss "sudoers rule /etc/sudoers.d/logwatch-remote"
    else miss "remote agent (install-agent.sh)"; fi
    has csctl || has waf && { command -v cscli >/dev/null && ok "cscli" || miss "CrowdSec (cscli) for roles csctl/waf"; }
    has waf && { cscli appsec-configs list 2>/dev/null | grep -q . && ok "CrowdSec AppSec" || miss "CrowdSec AppSec (crowdsec/setup.sh --bouncer npm)"; }
    has waf && { [ -x /usr/local/sbin/logwatch-wafctl ] && ok "logwatch-wafctl" || miss "logwatch-wafctl (install-agent.sh with role waf)"; }
    has l4waf && { command -v nft >/dev/null && ok "nftables" || miss "nftables (apt install nftables) for role l4waf"; }
    has l4waf && { [ -x /usr/local/sbin/logwatch-nfwafctl ] && ok "logwatch-nfwafctl" || miss "logwatch-nfwafctl (install-agent.sh with role l4waf)"; }
    { has l4waf || [ -f /etc/nftables.d/logwatch.nft ]; } && { systemctl is-enabled logwatch-nft >/dev/null 2>&1 && ok "logwatch-nft.service (board nft tables at boot)" || miss "logwatch-nft.service not enabled: board nft tables are gone after a reboot (re-run install-agent.sh / nft-traffic-log.sh)"; }
    { has l4waf || [ -f /etc/nftables.d/logwatch.nft ]; } && systemctl is-enabled nftables >/dev/null 2>&1 && grep -qE '^[[:space:]]*flush ruleset' /etc/nftables.conf 2>/dev/null && warn "nftables.service runs 'flush ruleset' at boot: also clears iptables-persistent DNAT"
    has images && { command -v trivy >/dev/null && ok "trivy" || miss "trivy for role images"; }
    has trafficpull && {
      g=$(sed -n 's/^TRAFFIC_GLOBS=//p' /etc/logwatch-remote.conf 2>/dev/null)
      if [ -n "$g" ]; then n=0; for x in ${g//,/ }; do compgen -G "$x" >/dev/null && n=1; done
        [ $n = 1 ] && ok "traffic logs ($g)" || miss "no file matches TRAFFIC_GLOBS=$g"
      else warn "TRAFFIC_GLOBS not set: default access-log paths are used"; fi; }
  fi

  if [ $CS = 1 ]; then
    command -v cscli >/dev/null && ok "CrowdSec" || miss "CrowdSec (crowdsec/setup.sh --install)"
    systemctl is-active -q crowdsec 2>/dev/null && ok "crowdsec running" || miss "crowdsec service not running"
    [ -e /var/log/crowdsec-lw-events.json ] && ok "events file" || miss "events file (crowdsec/setup.sh)"
  fi
  return $BAD
}

check && exit 0
[ $FIX = 1 ] || { echo "missing items: rerun with --fix, or see AGENT_INSTALL.md"; exit 1; }
echo "fixing…"
if [ $SYSLOG = 1 ] && ! grep -qs "target=\"$BOARD\"" /etc/rsyslog.d/90-logwatch.conf; then ./logfwd.sh "$BOARD"; fi
if [ -n "$ROLES" ]; then
  [ -n "$PUB" ] || { echo "--fix with --roles needs --pubkey (python3 setup.py pubkey on the board host)" >&2; exit 1; }
  ./install-agent.sh --roles "$ROLES" --pubkey "$PUB" --from "$BOARD"
fi
[ $CS = 1 ] && ! command -v cscli >/dev/null && echo "CrowdSec is not installed: run ../crowdsec/setup.sh --install (choose a bouncer) yourself"
check
