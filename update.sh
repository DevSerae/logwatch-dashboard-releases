#!/usr/bin/env bash
# Logwatch Dashboard host updater: applies an update only when the board asked for it (an admin clicked Update or
# Schedule, or allowed automatic updates). Run as root by systemd (logwatch-update.path / .timer, set up by install.sh).
#
# Reads   data/update-request.json  {version, at}   written by the board
#         data/feature-request.json, data/installer-request.json, data/restart-request.json (feature installs,
#         Edit settings, Restart dashboard)
# Writes  data/update-status.json   {state, version, message, at}
#         data/updater.json         heartbeat (the board disables its Update button without it)
#         /var/log/logwatch-update-<version>.log, backups in /var/backups/logwatch-dashboard (last 3)
# The release always comes from LW_RELEASES in /etc/default/logwatch-dashboard (default: the public releases repo),
# never from the request, and must match its SHA256SUMS. Before updating, code + config are backed up to
# /var/backups/logwatch-dashboard; if the board isn't healthy within 3 minutes the backup is restored and rebuilt.
#
# Manual run: sudo ./update.sh            (applies a due request, else just heartbeats)
#             sudo ./update.sh --version 2.1.0   (update now without a request)
# Remove:     systemctl disable --now logwatch-update.path logwatch-update.timer
#             rm /etc/systemd/system/logwatch-update.*
set -euo pipefail

DIR="${LW_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
if [ -z "${LW_UPD_COPY:-}" ]; then   # run from a copy: the update replaces this file
  c="$(mktemp)"; cp "$0" "$c"
  LW_UPD_COPY="$c" LW_DIR="$DIR" exec bash "$c" "$@"
fi
trap 'rm -f "$LW_UPD_COPY"' EXIT
[ -r /etc/default/logwatch-dashboard ] && . /etc/default/logwatch-dashboard
REPO="${LW_RELEASES:-https://github.com/DevSerae/logwatch-dashboard-releases}"
DATA="$DIR/data"
REQ="$DATA/update-request.json"
STATUS="$DATA/update-status.json"
OWNER="$(stat -c %u:%g "$DIR")"
PY=python3
FORCE=""
[ "${1:-}" = --version ] && FORCE="${2:-}"

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
mkdir -p "$DATA"
cur="$(cat "$DIR/VERSION")"

jget() { $PY -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2], ""))' "$1" "$2" 2>/dev/null || true; }
put() {  # put <file> <json>: data/ is writable by the containers, so never follow a planted symlink there
  local t; t="$(mktemp "$DATA/.upd.XXXXXX")"
  printf '%s\n' "$2" > "$t" && chown "$OWNER" "$t" && chmod 644 "$t" && mv -fT "$t" "$1"
}
status() {  # status <state> <version> <message>
  put "$STATUS" "$($PY -c 'import json,sys,time; print(json.dumps({"state": sys.argv[1], "version": sys.argv[2], "from": sys.argv[3], "message": sys.argv[4][-400:], "at": int(time.time())}))' "$1" "$2" "$cur" "$3")"
}
newer() { $PY -c 'import sys,re; t=lambda v: tuple(int(x) for x in re.findall(r"\d+", v)[:3]); sys.exit(0 if t(sys.argv[1]) > t(sys.argv[2]) else 1)' "$1" "$2"; }

put "$DATA/updater.json" "{\"at\": $(date +%s), \"version\": \"$cur\", \"repo\": \"$REPO\"}"

port="$(awk -F= '$1=="BOARD_PORT"{print $2}' "$DIR/.env" 2>/dev/null || true)"; port="${port:-8080}"
healthy() {
  for _ in $(seq 1 36); do
    curl -fsS -m 4 "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && return 0
    sleep 5
  done
  return 1
}
SPY="$PY"; [ -x "$DIR/.venv/bin/python" ] && SPY="$DIR/.venv/bin/python"
rebuild() {
  cd "$DIR"
  chown -R "$OWNER" "$DIR"   # before render: it takes the containers' UID/GID from the install dir
  $SPY setup.py render
  chown -R "$OWNER" "$DIR"
  docker compose up -d --build --remove-orphans
}

# Feature installs (Install on the board's Settings): data/feature-request.json {enable: [module ids]} switches those
# modules on in config.yaml, renders and restarts; data/feature-status.json reports. config.yaml is restored on failure.
FREQ="$DATA/feature-request.json"
fstatus() {  # fstatus <state> <modules csv> <message>
  put "$DATA/feature-status.json" "$($PY -c 'import json,sys,time; print(json.dumps({"state": sys.argv[1], "modules": [m for m in sys.argv[2].split(",") if m], "message": sys.argv[3][-400:], "at": int(time.time())}))' "$1" "$2" "$3")"
}
unit=/etc/systemd/system/logwatch-update.path   # installs from before 2.1.5 only watch update-request.json
if [ -f "$unit" ] && ! grep -q feature-request "$unit"; then
  sed -i "/^PathChanged=.*update-request.json/a PathChanged=$FREQ" "$unit" && systemctl daemon-reload && systemctl restart logwatch-update.path || true
fi
if [ -z "$FORCE" ] && [ -f "$FREQ" ]; then
  exec 9>/run/logwatch-update.lock
  flock -n 9 || exit 0                             # an update is running: the timer comes back
  mods="$($PY -c 'import json,re,sys; d=json.load(open(sys.argv[1])); print(",".join(x for x in d.get("enable", []) if isinstance(x, str) and re.fullmatch(r"[a-z0-9]+", x)))' "$FREQ" 2>/dev/null || true)"
  rm -f "$FREQ"
  if [ -n "$mods" ]; then
    flog=/var/log/logwatch-features.log
    fstatus running "$mods" "switching on and restarting"
    cp -p "$DIR/config/config.yaml" "$DIR/config/.config.yaml.bak-features"
    if { echo "== $(date -Is) installing $mods"
         (cd "$DIR" && $SPY setup.py modules --enable "$mods") && rebuild && docker compose restart board worker && healthy; } >>"$flog" 2>&1; then
      fstatus "done" "$mods" "installed"
      (cd "$DIR" && "$DIR/.venv/bin/python" -m installer pending) >/dev/null 2>&1 || true
    else
      cp -p "$DIR/config/.config.yaml.bak-features" "$DIR/config/config.yaml"
      { echo "!! install of $mods failed: restoring config.yaml"; rebuild && docker compose restart board worker && healthy; } >>"$flog" 2>&1 || true
      fstatus failed "$mods" "install failed, nothing changed (log: $flog)"
    fi
    rm -f "$DIR/config/.config.yaml.bak-features"
  fi
  exec 9>&-
fi

# Restart dashboard (three-dots menu): data/restart-request.json restarts every container of the stack.
RREQ="$DATA/restart-request.json"
if [ -f "$unit" ] && ! grep -q restart-request "$unit"; then   # installs from before 2.5.0
  sed -i "/^PathChanged=.*feature-request.json/a PathChanged=$RREQ" "$unit" && systemctl daemon-reload && systemctl restart logwatch-update.path || true
fi
if [ -z "$FORCE" ] && [ -f "$RREQ" ]; then
  exec 9>/run/logwatch-update.lock
  if flock -n 9; then                              # else an update is running: it restarts the board anyway
    rm -f "$RREQ"
    ( echo "== $(date -Is) restart requested from the board"; cd "$DIR" && docker compose restart ) >>/var/log/logwatch-restart.log 2>&1 || true
  fi
  exec 9>&-
fi

# Edit settings on the board: data/installer-request.json {token} starts the web installer in edit mode on
# data/installer.sock (the board proxies /setup/ to it). It saves, restarts the board and exits; 30 minutes at most.
IREQ="$DATA/installer-request.json"
if [ -f "$unit" ] && ! grep -q installer-request "$unit"; then   # installs from before 2.4.0
  sed -i "/^PathChanged=.*feature-request.json/a PathChanged=$IREQ" "$unit" && systemctl daemon-reload && systemctl restart logwatch-update.path || true
fi
if [ -z "$FORCE" ] && [ -f "$IREQ" ]; then
  tokf=/run/logwatch-installer.token
  if [ ! -L "$IREQ" ] && [ -x "$DIR/.venv/bin/python" ] && ! systemctl is-active -q logwatch-installer \
     && (umask 077; $PY -c 'import json,sys; t=json.load(open(sys.argv[1])).get("token", ""); assert len(t) >= 20 and t.isascii(); print(t)' "$IREQ" > "$tokf") 2>/dev/null; then
    systemctl reset-failed logwatch-installer 2>/dev/null || true
    systemd-run --unit logwatch-installer --collect -p RuntimeMaxSec=1800 -p WorkingDirectory="$DIR" \
      "$DIR/.venv/bin/python" -m installer --edit --socket "$DATA/installer.sock" --token-file "$tokf" >/dev/null || rm -f "$tokf"
  fi
  rm -f "$IREQ"
fi

# What's still left to set up (servers not marked installed, empty required settings), for the board's Features page.
# Refreshed when config or the installer's state changed, so work from an older installer or board carries over.
pend="$DATA/setup-pending.json"
if [ -z "$FORCE" ] && [ -x "$DIR/.venv/bin/python" ] && [ -f "$DIR/config/config.yaml" ] \
   && { [ ! -f "$pend" ] || [ "$DIR/config/config.yaml" -nt "$pend" ] || [ "$DATA/installer.json" -nt "$pend" ]; }; then
  (cd "$DIR" && "$DIR/.venv/bin/python" -m installer pending) >/dev/null 2>&1 || true
fi

if [ -n "$FORCE" ]; then
  ver="$FORCE"
else
  [ -f "$REQ" ] || exit 0
  ver="$(jget "$REQ" version)"; at="$(jget "$REQ" at)"
  [[ "$at" =~ ^[0-9]+$ ]] || at=0
  [ "$at" -le "$(date +%s)" ] || exit 0          # scheduled for later: the timer comes back
fi
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { status failed "$ver" "bad version in the request"; rm -f "$REQ"; exit 1; }
newer "$ver" "$cur" || { status failed "$ver" "not newer than $cur"; rm -f "$REQ"; exit 1; }

exec 9>/run/logwatch-update.lock
flock -n 9 || exit 0
rm -f "$REQ"
status running "$ver" "downloading"
log="/var/log/logwatch-update-$ver.log"
exec > >(tee -a "$log") 2>&1
echo "== $(date -Is) updating $cur -> $ver from $REPO"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp" "$LW_UPD_COPY"' EXIT
base="$REPO/releases/download/v$ver"
fail() { echo "!! $*"; status failed "$ver" "$*"; exit 1; }
curl -fsSL -o "$tmp/lw.tar.gz" "$base/logwatch-dashboard-$ver.tar.gz" || fail "download failed"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || fail "no SHA256SUMS in the release"
want="$(awk -v f="logwatch-dashboard-$ver.tar.gz" '$2 == f || $2 == "*"f {print $1}' "$tmp/SHA256SUMS")"
[ -n "$want" ] && [ "$(sha256sum "$tmp/lw.tar.gz" | cut -d' ' -f1)" = "$want" ] || fail "checksum mismatch"
tar xzf "$tmp/lw.tar.gz" -C "$tmp"
[ "$(cat "$tmp/logwatch-dashboard/VERSION" 2>/dev/null)" = "$ver" ] || fail "tarball doesn't contain $ver"

status running "$ver" "backing up"
BK=/var/backups/logwatch-dashboard   # root-only: the backups hold secrets.env
install -d -m 700 "$BK"
bk="$BK/code-$cur-$(date +%Y%m%d-%H%M%S).tgz"
tar -C "$DIR" --exclude=./data --exclude=./.venv -czf "$bk" .   # code + config + secrets + .env (root-only file)
chmod 600 "$bk"
ls -1t "$BK"/code-*.tgz | tail -n +4 | xargs -r rm -f   # keep the last 3

status running "$ver" "installing"
tar -C "$tmp/logwatch-dashboard" --exclude=./.venv -cf - . | tar -C "$DIR" --no-same-owner --no-overwrite-dir -xf -
if [ -x "$DIR/.venv/bin/pip" ] && [ -f "$DIR/installer/requirements.txt" ]; then
  "$DIR/.venv/bin/pip" install -q --disable-pip-version-check -r "$DIR/installer/requirements.txt" || true
fi
status running "$ver" "rebuilding containers"
if rebuild && healthy; then
  echo "== $(date -Is) $ver is up"
  status "done" "$ver" "updated from $cur"
  [ -x "$DIR/.venv/bin/python" ] && (cd "$DIR" && "$DIR/.venv/bin/python" -m installer pending) >/dev/null 2>&1 || true
  put "$DATA/updater.json" "{\"at\": $(date +%s), \"version\": \"$ver\", \"repo\": \"$REPO\"}"
  exit 0
fi

echo "!! $ver didn't come up: rolling back to $cur"
tar -C "$DIR" -xzf "$bk"
rebuild || true
healthy && msg="board didn't come back on $ver; rolled back to $cur (log: $log)" \
        || msg="board didn't come back on $ver and the rollback didn't either: docker compose logs board (backup: $bk)"
status failed "$ver" "$msg"
exit 1
