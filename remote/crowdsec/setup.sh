#!/bin/bash
# Logwatch Dashboard (module "crowdsec"): wire CrowdSec on an edge host into the board. Run as root from this directory.
#
#   ./setup.sh [--install] [--bouncer none|nftables|npm] [--containers "npm cloudflared"] [--allow "<cidrs>"]
#              [--npm-data /opt/npm/data] [--npm-container npm] [--no-capi-enforce]
#
# Always: escalating ban profiles (4h, 8h, 12h ... per repeat), the lw_events notification (every alert → one JSON line
# the board reads), a 5-min heartbeat (health.sh) and an allow-list (default: loopback, RFC1918, CGNAT 100.64/10).
#   --install          install CrowdSec from the official packagecloud repo (Debian/Ubuntu) when missing
#   --bouncer nftables firewall bouncer (host + forwarded/DNAT'd traffic); --no-capi-enforce = only local + manual bans
#                      (recommended for game/CGNAT-heavy traffic: the community list catches shared IPs)
#   --bouncer npm      OpenResty bouncer + AppSec WAF inside an Nginx Proxy Manager container (downloads v1.2.5);
#                      LAPI + AppSec listen on the NPM docker network gateway so only NPM reaches them
#   --containers       docker containers the heartbeat reports on (board shows them as checks)
# Pull hosts (role logpull) need nothing else; syslog hosts forward the events file with rsyslog (added here).
set -euo pipefail
cd "$(dirname "$0")"
INSTALL=0; BOUNCER=none; CONTAINERS=""; ALLOW="127.0.0.1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10"
NPM_DATA=/opt/npm/data; NPM_CT=npm; CAPI=1; OPENRESTY_BOUNCER=1.2.5
while [ $# -gt 0 ]; do
  case "$1" in
    --install) INSTALL=1; shift ;;
    --bouncer) BOUNCER=$2; shift 2 ;;
    --containers) CONTAINERS=$2; shift 2 ;;
    --allow) ALLOW=$2; shift 2 ;;
    --npm-data) NPM_DATA=$2; shift 2 ;;
    --npm-container) NPM_CT=$2; shift 2 ;;
    --no-capi-enforce) CAPI=0; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

pkgs="jq"
if ! command -v cscli >/dev/null; then
  [ $INSTALL = 1 ] || { echo "CrowdSec isn't installed: rerun with --install (or install it yourself)" >&2; exit 1; }
  if [ ! -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
    install -d -m755 /etc/apt/keyrings
    curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey | gpg --dearmor -o /etc/apt/keyrings/crowdsec.gpg
    echo "deb [signed-by=/etc/apt/keyrings/crowdsec.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main" \
      > /etc/apt/sources.list.d/crowdsec_crowdsec.list
    apt-get update -qq
  fi
  pkgs="$pkgs crowdsec"
fi
[ "$BOUNCER" = nftables ] && pkgs="$pkgs crowdsec-firewall-bouncer-nftables"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $pkgs >/dev/null
cscli collections install crowdsecurity/linux crowdsecurity/sshd crowdsecurity/whitelist-good-actors >/dev/null 2>&1 || true

# --- profiles + notification ---
[ -f /etc/crowdsec/profiles.yaml ] && cp -an /etc/crowdsec/profiles.yaml /etc/crowdsec/profiles.yaml.pre-logwatch
install -m 644 profiles.yaml /etc/crowdsec/profiles.yaml
install -m 600 lw_events.yaml /etc/crowdsec/notifications/lw_events.yaml
touch /var/log/crowdsec-lw-events.json
chown nobody:nogroup /var/log/crowdsec-lw-events.json 2>/dev/null || chown nobody:nobody /var/log/crowdsec-lw-events.json
chmod 640 /var/log/crowdsec-lw-events.json   # notification plugins run as nobody

# --- allow-list ---
cscli allowlists create logwatch-trusted -d "Logwatch: trusted ranges" >/dev/null 2>&1 || true
cscli allowlists add logwatch-trusted $ALLOW -d "Logwatch trusted" >/dev/null 2>&1 || true

# --- bouncer ---
LAPI=127.0.0.1:8080; APPSEC=""; MATCH="."
case "$BOUNCER" in
  none) ;;
  nftables)
    b=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
    if [ $CAPI = 0 ]; then grep -q '^origins:' "$b" || printf 'origins:\n  - crowdsec\n  - cscli\n' >> "$b"; fi
    if grep -q '^api_key: <API_KEY>' "$b"; then  # the package can't self-register when crowdsec was installed in the same run
      k=$(cscli bouncers add "lw-nftables-$(hostname -s)" -o raw) && sed -i "s|^api_key: .*|api_key: $k|" "$b" && chmod 600 "$b"
    fi
    MATCH="nftables|firewall"
    systemctl enable -q --now crowdsec-firewall-bouncer ;;
  npm)
    command -v docker >/dev/null || { echo "docker is required for --bouncer npm" >&2; exit 1; }
    net=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$NPM_CT" | awk '{print $1}')
    GW=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$net")
    [ -n "$GW" ] || { echo "can't find the gateway of $NPM_CT's network" >&2; exit 1; }
    LAPI=$GW:8080; APPSEC=$GW:7422; MATCH="openresty|npm"
    echo 'net.ipv4.ip_nonlocal_bind = 1' > /etc/sysctl.d/90-logwatch-crowdsec.conf && sysctl -q -p /etc/sysctl.d/90-logwatch-crowdsec.conf
    printf 'api:\n  server:\n    listen_uri: %s\n' "$LAPI" > /etc/crowdsec/config.yaml.local
    sed -i "s#^url:.*#url: http://$LAPI/#" /etc/crowdsec/local_api_credentials.yaml
    cscli collections install crowdsecurity/nginx-proxy-manager crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-crs >/dev/null 2>&1 || true
    cat > /etc/crowdsec/acquis.d/logwatch-npm.yaml <<YAML
filenames:
  - $NPM_DATA/logs/proxy-host-*_access.log
  - $NPM_DATA/logs/proxy-host-*_error.log
  - $NPM_DATA/logs/default-host_access.log
  - $NPM_DATA/logs/fallback_http_access.log
labels:
  type: nginx-proxy-manager
YAML
    # an AppSec listener set up before Logwatch would clash with ours on the same port: park it (kept as .bak-lw)
    for f in /etc/crowdsec/acquis.d/*.y*ml; do
      [ -f "$f" ] && [ "$f" != /etc/crowdsec/acquis.d/logwatch-appsec.yaml ] && grep -qE '^source:[[:space:]]*appsec[[:space:]]*$' "$f" \
        && { mv "$f" "$f.bak-lw"; echo "moved existing AppSec acquisition $f to $f.bak-lw"; }
    done
    cat > /etc/crowdsec/acquis.d/logwatch-appsec.yaml <<YAML
appsec_configs:
  - crowdsecurity/appsec-default
  - crowdsecurity/crs
labels:
  type: appsec
listen_addr: $APPSEC
source: appsec
name: logwatch_npm_appsec
YAML
    T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
    curl -fsSL "https://github.com/crowdsecurity/cs-openresty-bouncer/releases/download/v$OPENRESTY_BOUNCER/crowdsec-openresty-bouncer.tgz" | tar xz -C "$T"
    S=$(find "$T" -maxdepth 1 -mindepth 1 -type d | head -1); D=$NPM_DATA/crowdsec
    install -d -m 700 "$D"; rm -rf "$D/lua" "$D/templates"; cp -r "$S/lua" "$D/lua"; cp -r "$S/templates" "$D/templates"
    systemctl restart crowdsec; sleep 4
    if [ ! -s "$D/bouncer.conf" ]; then
      cscli bouncers delete npm-openresty >/dev/null 2>&1 || true
      KEY=$(cscli bouncers add npm-openresty -o raw)
      sed -e "s#^API_URL=.*#API_URL=http://$LAPI#" -e "s#^API_KEY=.*#API_KEY=$KEY#" -e "s#^MODE=.*#MODE=stream#" \
          -e "s#^BAN_TEMPLATE_PATH=.*#BAN_TEMPLATE_PATH=/data/crowdsec/templates/ban.html#" \
          -e "s#^CAPTCHA_TEMPLATE_PATH=.*#CAPTCHA_TEMPLATE_PATH=/data/crowdsec/templates/captcha.html#" \
          -e "s#^APPSEC_URL=.*#APPSEC_URL=http://$APPSEC#" -e "s#^SSL_VERIFY=.*#SSL_VERIFY=false#" \
          "$S/config/config_example.conf" > "$D/bouncer.conf"
      chmod 600 "$D/bouncer.conf"
    fi
    install -d "$NPM_DATA/nginx/custom"
    install -m 644 http_top.conf "$NPM_DATA/nginx/custom/http_top.conf"
    docker exec "$NPM_CT" nginx -t 2>&1 | tail -1
    docker exec "$NPM_CT" nginx -s reload ;;
  *) echo "bad --bouncer $BOUNCER" >&2; exit 2 ;;
esac

# --- heartbeat ---
printf 'LAPI=%s\nAPPSEC=%s\nCONTAINERS="%s"\nBOUNCER_MATCH="%s"\n' "$LAPI" "$APPSEC" "$CONTAINERS" "$MATCH" > /etc/logwatch-crowdsec.conf
install -m 755 health.sh /usr/local/sbin/logwatch-crowdsec-health
cat > /etc/systemd/system/logwatch-crowdsec-health.service <<'U'
[Unit]
Description=Logwatch Dashboard CrowdSec heartbeat
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/logwatch-crowdsec-health
U
cat > /etc/systemd/system/logwatch-crowdsec-health.timer <<'U'
[Unit]
Description=Logwatch Dashboard CrowdSec heartbeat every 5 min
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
U

# --- syslog hosts: forward the events file (pull hosts read it directly) ---
if [ -f /etc/rsyslog.d/90-logwatch.conf ]; then
  {
    grep -rqs 'load="imfile"' /etc/rsyslog.conf /etc/rsyslog.d/ --exclude=89-logwatch-crowdsec.conf || echo 'module(load="imfile")'
    echo 'input(type="imfile" File="/var/log/crowdsec-lw-events.json" Tag="crowdsec-event:" Facility="local5" Severity="notice")'
  } > /etc/rsyslog.d/89-logwatch-crowdsec.conf
  rsyslogd -N1 >/dev/null 2>&1 || { rsyslogd -N1; exit 1; }
  systemctl restart rsyslog
fi

systemctl daemon-reload
systemctl enable -q --now logwatch-crowdsec-health.timer
systemctl restart crowdsec
sleep 4
systemctl is-active crowdsec
/usr/local/sbin/logwatch-crowdsec-health && echo "ok: heartbeat sent; add '- name: $(hostname)' under crowdsec.hosts in config.yaml"
