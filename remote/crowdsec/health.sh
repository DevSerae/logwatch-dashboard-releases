#!/bin/bash
# Logwatch Dashboard: CrowdSec heartbeat (systemd timer, every 5 min) → syslog tag "crowdsec-health" → the board.
# Settings: /etc/logwatch-crowdsec.conf (written by setup.sh): LAPI, APPSEC, CONTAINERS, BOUNCER_MATCH.
LAPI=127.0.0.1:8080; APPSEC=""; CONTAINERS=""; BOUNCER_MATCH="."
[ -f /etc/logwatch-crowdsec.conf ] && . /etc/logwatch-crowdsec.conf
j(){ systemctl is-active -q "$1" && echo true || echo false; }
port(){ ss -lnt | awk '{print $4}' | grep -qE ":${1##*:}\$" && echo true || echo false; }
cs=$(j crowdsec)
bp=$(cscli bouncers list -o json 2>/dev/null | jq -r --arg m "$BOUNCER_MATCH" '[.[] | select(.name|test($m))] | max_by(.last_pull) | .last_pull // ""')
lapi=$(port "$LAPI")
waf=null; [ -n "$APPSEC" ] && waf=$(port "$APPSEC")
dec=$(cscli decisions list -o json -a 2>/dev/null | jq '[.[]?.decisions[]?] | group_by(.origin) | map({key: .[0].origin, value: length}) | from_entries' 2>/dev/null || echo '{}')
capi=$(cscli metrics show decisions -o json 2>/dev/null | jq '[.. | objects | select(has("CAPI")) | .CAPI | .. | numbers] | add // 0' 2>/dev/null || echo 0)
ctrs='{}'
for c in $CONTAINERS; do
  up=$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo false)
  ctrs=$(jq -c --arg c "$c" --argjson u "$([ "$up" = true ] && echo true || echo false)" '. + {($c): $u}' <<<"$ctrs")
done
bans=$(cscli decisions list -o json 2>/dev/null | jq -c '[.[]? | .decisions[]? | select(.origin != "CAPI" and .origin != "lists") | {ip: .value, why: (.scenario | sub("^crowdsecurity/(http-)?"; "")), until: .until}] | sort_by(.until) | reverse | .[:15]' 2>/dev/null || echo '[]')
[ -n "$dec" ] || dec='{}'; [ -n "$bans" ] || bans='[]'; [ -n "$capi" ] || capi=0
ver=$(cscli version 2>&1 | awk '/^version:/{print $2}')
jq -cn --arg host "$(hostname)" --argjson cs "$cs" --arg bp "$bp" --argjson lapi "$lapi" --argjson waf "$waf" \
  --argjson dec "$dec" --argjson capi "$capi" --argjson ctrs "$ctrs" --arg ver "$ver" --argjson bans "$bans" \
  '{host:$host, crowdsec:$cs, lapi:$lapi, waf:$waf, bouncer_last_pull:$bp, decisions:$dec, capi:$capi,
    containers:$ctrs, version:$ver, bans:$bans}' | logger -t crowdsec-health -p local5.info
