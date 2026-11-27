#!/bin/bash
# Logwatch Dashboard: forward this host's syslog to the board's VictoriaLogs syslog listener (module "syslog").
# Run as root on the host:  ./logfwd.sh <board-address> [port=514] [tcp|udp=tcp]
# Env:  JOURNAL_CAP=500M   cap the journal at this size; empty = leave the journal alone. Never applied when the journal
#                          is already bigger (it would delete history) or when you set SystemMaxUse yourself.
#       CONTAINER_FIX=1    LXC/containers where AppArmor blocks journald → rsyslog: allow it in the rsyslogd profile's
#                          local override and read the journal directly (imjournal).
# rsyslog keeps a 100 MB disk queue so a board outage never blocks local logging.
# Undo: rm /etc/systemd/journald.conf.d/logwatch-size.conf /etc/rsyslog.d/90-logwatch.conf
#       /etc/rsyslog.d/05-logwatch-imjournal.conf; restart journald + rsyslog.
set -euo pipefail
T=${1:?usage: logfwd.sh <board-address> [port] [tcp|udp]}; P=${2:-514}; PROTO=${3:-tcp}
CAP=${JOURNAL_CAP-500M}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

bytes() {  # 500M / 1.5G / 2048 → bytes
  awk -v s="$1" 'BEGIN { n = s + 0; u = toupper(substr(s, length(s))); m = 1
    if (u == "K") m = 1024; else if (u == "M") m = 1024^2; else if (u == "G") m = 1024^3; else if (u == "T") m = 1024^4
    printf "%.0f", n * m }'
}

ours=/etc/systemd/journald.conf.d/logwatch-size.conf
if [ -z "$CAP" ]; then
  echo "journal: left as is (JOURNAL_CAP empty)"
elif grep -qsE '^\s*SystemMaxUse=' /etc/systemd/journald.conf $(ls /etc/systemd/journald.conf.d/*.conf 2>/dev/null | grep -v "^$ours$"); then
  echo "journal: SystemMaxUse is already set on this host, keeping yours"
else
  used=$(du -sb /var/log/journal /run/log/journal 2>/dev/null | awk '{ s += $1 } END { print s + 0 }')
  if [ "$used" -gt "$(bytes "$CAP")" ] && [ ! -f "$ours" ]; then
    echo "warn: journal: not capped at $CAP: it already holds $((used / 1048576)) MB and journald would delete" \
         "$(((used - $(bytes "$CAP")) / 1048576)) MB of history. Set JOURNAL_CAP=<size> to cap it anyway." >&2
  else
    mkdir -p /etc/systemd/journald.conf.d
    printf '[Journal]\nSystemMaxUse=%s\n' "$CAP" > "$ours"
    systemctl restart systemd-journald
  fi
fi

if ! command -v rsyslogd >/dev/null; then
  if command -v apt-get >/dev/null; then
    apt-get update -q >/dev/null 2>&1 || true; DEBIAN_FRONTEND=noninteractive apt-get install -y -q rsyslog >/dev/null
  elif command -v dnf >/dev/null; then dnf install -y -q rsyslog
  elif command -v apk >/dev/null; then apk add -q rsyslog
  else echo "install rsyslog first" >&2; exit 1; fi
fi

if [ "${CONTAINER_FIX:-}" = 1 ]; then
  if [ -d /etc/apparmor.d ] && [ -f /etc/apparmor.d/usr.sbin.rsyslogd ]; then
    mkdir -p /etc/apparmor.d/local
    loc=/etc/apparmor.d/local/usr.sbin.rsyslogd
    grep -qs "logwatch" "$loc" || cat >> "$loc" <<'AA'
# Logwatch Dashboard (logfwd.sh CONTAINER_FIX=1): let rsyslog get the journal inside containers
/run/systemd/journal/syslog rw,
/run/systemd/journal/dev-log rw,
/var/log/journal/ r,
/var/log/journal/** r,
/run/log/journal/ r,
/run/log/journal/** r,
/etc/machine-id r,
/var/spool/rsyslog/** rw,
AA
    command -v apparmor_parser >/dev/null && apparmor_parser -r /etc/apparmor.d/usr.sbin.rsyslogd 2>/dev/null || true
  fi
  echo 'module(load="imjournal" StateFile="imjournal.state" IgnorePreviousMessages="on")' > /etc/rsyslog.d/05-logwatch-imjournal.conf
fi

cat > /etc/rsyslog.d/90-logwatch.conf <<CONF
# Logwatch Dashboard: forward everything to the board (VictoriaLogs syslog listener).
*.* action(type="omfwd" target="$T" port="$P" protocol="$PROTO"
           template="RSYSLOG_SyslogProtocol23Format"
           queue.type="LinkedList" queue.filename="logwatch_fwd" queue.maxDiskSpace="100m"
           queue.saveOnShutdown="on" action.resumeRetryCount="-1" action.resumeInterval="30")
CONF
rsyslogd -N1 >/dev/null 2>&1 || { rsyslogd -N1; exit 1; }
systemctl enable -q rsyslog
systemctl restart rsyslog

# Does local logging actually reach rsyslog? (In unprivileged LXC, AppArmor can silently block journald → rsyslog.)
probe="logwatch-probe-$$-$RANDOM"
logger -t logwatch "forwarding test from $(hostname) $probe"
files=$(ls /var/log/syslog /var/log/messages 2>/dev/null || true)
seen=""
if [ -n "$files" ]; then
  for _ in 1 2 3 4 5 6; do
    sleep 1
    if grep -qs "$probe" $files; then seen=1; break; fi
  done
fi
if [ -n "$seen" ]; then
  echo "ok $(hostname) → $T:$P/$PROTO"
elif [ -z "$files" ]; then
  echo "ok $(hostname) → $T:$P/$PROTO (couldn't confirm locally: no /var/log/syslog or /var/log/messages; check the board's Logs)"
else
  echo "warn: rsyslog didn't get a local test message within 6 s, so nothing from this host will reach the board." >&2
  if command -v systemd-detect-virt >/dev/null && systemd-detect-virt -cq; then
    echo "      This is a container ($(systemd-detect-virt -c)): AppArmor usually blocks journald → rsyslog here" \
         "(dmesg on the hypervisor shows apparmor=\"DENIED\" profile=\"rsyslogd\"). Re-run with CONTAINER_FIX=1." >&2
  else
    echo "      Check: systemctl status rsyslog; journalctl -u rsyslog; dmesg | grep -i apparmor" >&2
  fi
  exit 2
fi
