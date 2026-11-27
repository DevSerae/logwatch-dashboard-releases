#!/bin/bash
# Logwatch Dashboard: install the remote agent on a Linux host the board pulls from over SSH.
# Run as root ON THE HOST, from this directory:
#   ./install-agent.sh --roles logpull,trafficpull,csctl,images,waf,l4waf --pubkey "ssh-ed25519 AAAA... logwatch" \
#                      [--from 192.0.2.10] [--traffic-globs "/var/log/nginx/access.log,/var/log/logwatch-traffic.log"] \
#                      [--wan eth0] [--sshd-allow]
# --sshd-allow: when sshd restricts logins with AllowUsers/AllowGroups, let the agent user in too (joins the first
# AllowGroups group, or adds /etc/ssh/sshd_config.d/10-logwatch.conf with AllowUsers; validated, then sshd reloads).
# Role l4waf (port proxies that DNAT raw TCP/UDP): nftables table inet lw_waf, only for forwarded traffic arriving
# on --wan (the public interface; default = the interface of the default route).
# Pubkey: on the board host, `python3 setup.py pubkey`. --from limits the key to the board's source address.
# Undo: ./install-agent.sh --uninstall
set -euo pipefail
cd "$(dirname "$0")"
ROLES=""; PUB=""; FROM=""; GLOBS=""; WAN=""; USER_=logwatch; SSHD_ALLOW=0
while [ $# -gt 0 ]; do
  case "$1" in
    --roles) ROLES=$2; shift 2 ;;
    --pubkey) PUB=$2; shift 2 ;;
    --from) FROM=$2; shift 2 ;;
    --traffic-globs) GLOBS=$2; shift 2 ;;
    --user) USER_=$2; shift 2 ;;
    --wan) WAN=$2; shift 2 ;;
    --sshd-allow) SSHD_ALLOW=1; shift ;;
    --uninstall)
      if [ -f /etc/ssh/sshd_config.d/10-logwatch.conf ]; then
        rm -f /etc/ssh/sshd_config.d/10-logwatch.conf
        sshd -t && { systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; }
      fi
      rm -f /usr/local/sbin/logwatch-remote /usr/local/sbin/logwatch-wafctl /usr/local/sbin/logwatch-nfwafctl /etc/sudoers.d/logwatch-remote /etc/logwatch-remote.conf
      if [ -f /etc/systemd/system/logwatch-osf.service ]; then
        systemctl disable --now logwatch-osf >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/logwatch-osf.service; systemctl daemon-reload || true
      fi
      if [ -f /etc/logwatch-waf/lw-waf.nft ]; then
        nft delete table inet lw_waf 2>/dev/null || true
        sed -i '\#include "/etc/logwatch-waf/lw-waf.nft"#d' /etc/nftables.conf 2>/dev/null || true
        rm -rf /etc/logwatch-waf
      fi
      if [ ! -f /etc/nftables.d/logwatch.nft ] && [ -f /etc/systemd/system/logwatch-nft.service ]; then
        systemctl disable logwatch-nft >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/logwatch-nft.service; systemctl daemon-reload || true
      fi
      id "$USER_" >/dev/null 2>&1 && userdel -r "$USER_" 2>/dev/null || true
      echo "removed"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
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
# OS fingerprints for the port proxy's "OS" rule field: nft's osf needs the pf.os database in the kernel (nfnl_osf, from
# the iptables package). Optional: without it, OS rules simply never match and the board says so.
lw_osf_unit() {
  install -m 644 -o root -g root pf.os /etc/logwatch-waf/pf.os
  if ! command -v nfnl_osf >/dev/null; then
    echo "NOTE: nfnl_osf not found (apt install iptables): OS fingerprint rules won't match until it's installed and this is re-run"
    return 0
  fi
  cat > /etc/systemd/system/logwatch-osf.service <<UNIT
[Unit]
Description=Logwatch Dashboard: OS fingerprints (pf.os) for nftables osf
Before=logwatch-nft.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/sbin/modprobe nfnetlink_osf
ExecStart=/bin/sh -c '$(command -v nfnl_osf) -f /etc/logwatch-waf/pf.os && touch /run/logwatch-osf.loaded'
ExecStop=/bin/rm -f /run/logwatch-osf.loaded

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload && systemctl enable logwatch-osf >/dev/null 2>&1 && systemctl restart logwatch-osf \
    || echo "NOTE: logwatch-osf.service failed (systemctl status logwatch-osf): OS fingerprint rules won't match"
}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -n "$ROLES" ] && [ -n "$PUB" ] || { echo "need --roles and --pubkey" >&2; exit 2; }
for r in ${ROLES//,/ }; do case $r in logpull|trafficpull|csctl|images|waf|l4waf) ;; *) echo "bad role $r" >&2; exit 2 ;; esac; done
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v sudo >/dev/null || { echo "sudo is required" >&2; exit 1; }

id "$USER_" >/dev/null 2>&1 || useradd --system --create-home --shell /bin/sh "$USER_"
passwd -l "$USER_" >/dev/null 2>&1 || true
install -m 755 -o root -g root logwatch-remote /usr/local/sbin/logwatch-remote
case ",$ROLES," in
  *,waf,*)
    command -v cscli >/dev/null || { echo "role waf needs CrowdSec with AppSec (remote/crowdsec/setup.sh --bouncer npm sets it up)" >&2; exit 1; }
    install -m 755 -o root -g root logwatch-wafctl /usr/local/sbin/logwatch-wafctl ;;
  *) rm -f /usr/local/sbin/logwatch-wafctl ;;
esac
case ",$ROLES," in
  *,l4waf,*)
    command -v nft >/dev/null || { echo "role l4waf needs nftables (apt install nftables)" >&2; exit 1; }
    [ -n "$WAN" ] || WAN=$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") {print $(i+1); exit}}')
    [ -n "$WAN" ] || { echo "role l4waf: no default route, pass --wan <public interface>" >&2; exit 1; }
    install -m 755 -o root -g root logwatch-nfwafctl /usr/local/sbin/logwatch-nfwafctl
    install -d -m 755 /etc/logwatch-waf
    [ -f /etc/logwatch-waf/lw-waf.nft ] || echo "# managed by logwatch-nfwafctl (empty until the board's first apply)" > /etc/logwatch-waf/lw-waf.nft
    lw_nft_unit
    lw_osf_unit ;;
  *) rm -f /usr/local/sbin/logwatch-nfwafctl ;;
esac

EVENTS=/var/log/crowdsec-lw-events.json
if [ -f /etc/logwatch-remote.conf ]; then
  cp -a /etc/logwatch-remote.conf /etc/logwatch-remote.conf.bak
  E=$(sed -n 's/^EVENTS=//p' /etc/logwatch-remote.conf | tail -1)     # a hand-set events file survives re-runs
  [ -n "$E" ] && EVENTS=$E
fi
{
  echo "# Logwatch Dashboard remote agent. Roles the board's key may run on this host."
  echo "ROLES=$ROLES"
  [ -n "$GLOBS" ] && echo "TRAFFIC_GLOBS=$GLOBS"
  [ -n "$WAN" ] && echo "L4_WAN=$WAN"
  echo "EVENTS=$EVENTS"
} > /etc/logwatch-remote.conf
chmod 644 /etc/logwatch-remote.conf

echo "$USER_ ALL=(root) NOPASSWD: /usr/local/sbin/logwatch-remote *" > /etc/sudoers.d/logwatch-remote
chmod 440 /etc/sudoers.d/logwatch-remote
visudo -cf /etc/sudoers.d/logwatch-remote >/dev/null

H=$(getent passwd "$USER_" | cut -d: -f6)
install -d -m 700 -o "$USER_" -g "$USER_" "$H/.ssh"
opts='restrict,command="sudo -n /usr/local/sbin/logwatch-remote \"$SSH_ORIGINAL_COMMAND\""'
[ -n "$FROM" ] && opts="from=\"$FROM\",$opts"
echo "$opts $PUB" > "$H/.ssh/authorized_keys"
chown "$USER_:$USER_" "$H/.ssh/authorized_keys"; chmod 600 "$H/.ssh/authorized_keys"

# sshd must allow the user (AllowUsers/AllowGroups setups)
sshd_allowed() {
  local t; t=$(sshd -T 2>/dev/null) || return 0
  if echo "$t" | grep -qi '^allowusers '; then
    echo "$t" | awk 'tolower($1)=="allowusers"{print $2}' | grep -qE "^${USER_}(@|$)" || return 1
  fi
  if echo "$t" | grep -qi '^allowgroups '; then
    local g ok=1
    for g in $(echo "$t" | awk 'tolower($1)=="allowgroups"{print $2}'); do id -nG "$USER_" | tr ' ' '\n' | grep -qx "$g" && ok=0; done
    return $ok
  fi
  return 0
}
if ! sshd_allowed; then
  if [ "$SSHD_ALLOW" = 1 ]; then
    T=$(sshd -T 2>/dev/null)
    G=$(echo "$T" | awk 'tolower($1)=="allowgroups"{print $2; exit}')
    [ -n "$G" ] && getent group "$G" >/dev/null && usermod -aG "$G" "$USER_"
    if echo "$T" | grep -qi '^allowusers ' && ! sshd_allowed; then
      install -d -m 755 /etc/ssh/sshd_config.d
      echo "AllowUsers $USER_" > /etc/ssh/sshd_config.d/10-logwatch.conf
      if ! sshd -t; then rm -f /etc/ssh/sshd_config.d/10-logwatch.conf; echo "sshd rejected the drop-in; not changed" >&2; fi
    fi
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    sshd_allowed || echo "WARNING: sshd still doesn't allow $USER_ (no 'Include /etc/ssh/sshd_config.d/*.conf'?); add it to AllowUsers/AllowGroups by hand."
  else
    echo "WARNING: sshd's AllowUsers/AllowGroups don't include $USER_, so the board can't log in."
    echo "         Re-run with --sshd-allow, or add it there by hand and reload sshd."
  fi
fi
echo "ok $(hostname) roles=$ROLES user=$USER_"
