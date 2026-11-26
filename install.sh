#!/usr/bin/env bash
# Logwatch Dashboard: install or update on this VM, then open the web setup on the board's port.
#
#   curl -fsSL https://github.com/DevSerae/logwatch-dashboard-releases/releases/latest/download/install.sh | sudo bash
#   (or download it, read it, then: sudo bash install.sh)
#
# Options: --dir /opt/logwatch-dashboard   install directory
#          --version 2.0.0                 a specific release (default: latest)
#          --yes                           install Docker without asking if it's missing
#          --no-setup                      install/update only (don't start the web setup)
# Re-running updates the code in place; config/, secrets/, data/ and .env are never touched.
# Undo: cd <dir> && docker compose down -v; systemctl disable --now logwatch-update.path logwatch-update.timer
#       rm -rf <dir> /etc/systemd/system/logwatch-update.* /etc/default/logwatch-dashboard /var/backups/logwatch-dashboard
#       userdel logwatch
set -euo pipefail

REPO="${LW_RELEASES:-https://github.com/DevSerae/logwatch-dashboard-releases}"
DIR=/opt/logwatch-dashboard
VERSION=latest
YES=0
SETUP=1
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --version) VERSION="${2#v}"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    --no-setup|--no-tui) SETUP=0; shift ;;
    -h|--help) sed -n '2,14p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }
ask() {  # ask "question" → 0 = yes; reads the terminal even when piped from curl
  [ "$YES" = 1 ] && return 0
  [ -r /dev/tty ] || return 1
  printf '%s [y/N] ' "$1" > /dev/tty
  read -r a < /dev/tty || return 1
  [ "$a" = y ] || [ "$a" = Y ] || [ "$a" = yes ]
}

[ "$(id -u)" = 0 ] || die "run as root: sudo bash install.sh (Docker and the install directory need it)"
[ "$(uname -s)" = Linux ] || die "Linux only"
case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) die "unsupported CPU $(uname -m): amd64 or arm64 only" ;; esac

# read os-release in a subshell: it defines VERSION, which would clobber ours
OS_NAME="$( { [ -r /etc/os-release ] && . /etc/os-release && echo "${PRETTY_NAME:-${ID:-unknown}}"; } || echo unknown)"
pm=""
command -v apt-get >/dev/null && pm=apt
command -v dnf >/dev/null && pm=${pm:-dnf}
say "System: $OS_NAME ($(uname -m)), package manager: ${pm:-none found}"

pkg() {  # pkg <apt names> -- <dnf names>
  local apt_names=() dnf_names=() side=apt
  for p in "$@"; do
    if [ "$p" = -- ]; then side=dnf; elif [ $side = apt ]; then apt_names+=("$p"); else dnf_names+=("$p"); fi
  done
  case "$pm" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${apt_names[@]}" ;;
    dnf) dnf install -y -q "${dnf_names[@]}" ;;
    *) die "install these yourself, then re-run: ${apt_names[*]}" ;;
  esac
}

# --- prerequisites -------------------------------------------------------------------------------------------------
need=()
command -v curl >/dev/null || need+=(curl)
command -v tar >/dev/null || need+=(tar)
command -v ssh >/dev/null || need+=(ssh)
command -v python3 >/dev/null || need+=(python3)
if [ ${#need[@]} -gt 0 ]; then
  say "Installing: ${need[*]}"
  a=(); d=()
  for n in "${need[@]}"; do
    case $n in ssh) a+=(openssh-client); d+=(openssh-clients) ;; *) a+=("$n"); d+=("$n") ;; esac
  done
  pkg "${a[@]}" -- "${d[@]}"
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "Python 3.9+ needed (found $(python3 -V 2>&1))"
if ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
  say "Installing python3-venv"
  pkg python3-venv -- python3
fi

if ! command -v docker >/dev/null; then
  echo "Docker is not installed. The board runs as a few containers (board, worker, VictoriaLogs, Fluent Bit)."
  if ask "Install Docker Engine now from Docker's official script (get.docker.com)?"; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker 2>/dev/null || true
  else
    echo "Skipping. Install Docker + the compose plugin (https://docs.docker.com/engine/install/), then re-run this."
  fi
elif ! docker compose version >/dev/null 2>&1; then
  say "Docker is here but the compose plugin isn't"
  if ask "Install docker-compose-plugin?"; then pkg docker-compose-plugin -- docker-compose-plugin; fi
fi

# --- code ----------------------------------------------------------------------------------------------------------
id logwatch >/dev/null 2>&1 || { say "Creating system user logwatch (owns $DIR; the containers run as it)"
  useradd --system --home-dir "$DIR" --no-create-home --shell /usr/sbin/nologin logwatch; }

here="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd || true)"
if [ -n "$here" ] && [ -f "$here/installer/web.py" ] && [ -f "$here/VERSION" ]; then
  src="$here"   # run from an unpacked release
  say "Using the unpacked release in $src ($(cat "$src/VERSION"))"
else
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  if [ "$VERSION" = latest ]; then base="$REPO/releases/latest/download"; else base="$REPO/releases/download/v$VERSION"; fi
  say "Downloading $base/logwatch-dashboard.tar.gz"
  curl -fsSL -o "$tmp/lw.tar.gz" "$base/logwatch-dashboard.tar.gz" || die "download failed (no internet, or no such version?)"
  if curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" 2>/dev/null; then
    want="$(awk '$2 ~ /logwatch-dashboard.tar.gz$/ && $2 !~ /-[0-9]/ {print $1}' "$tmp/SHA256SUMS")"
    [ -z "$want" ] || [ "$(sha256sum "$tmp/lw.tar.gz" | cut -d' ' -f1)" = "$want" ] || die "checksum mismatch: not installing"
  fi
  tar xzf "$tmp/lw.tar.gz" -C "$tmp"
  src="$tmp/logwatch-dashboard"
  [ -f "$src/VERSION" ] || die "unexpected tarball layout"
fi

if [ "$src" != "$DIR" ]; then
  if [ -f "$DIR/VERSION" ]; then
    say "Updating $DIR: $(cat "$DIR/VERSION") → $(cat "$src/VERSION") (config, secrets and data stay)"
  else
    say "Installing $(cat "$src/VERSION") into $DIR"
  fi
  mkdir -p "$DIR"
  # Code only: the release has no config.yaml, secrets/, data/, .env or override, so nothing of yours is replaced.
  tar -C "$src" --exclude=./.venv --exclude=./secrets --exclude=./data --exclude=./.env -cf - . | tar -C "$DIR" -xf -
fi
chown -R logwatch:logwatch "$DIR"
chmod 750 "$DIR"

if [ -d /run/systemd/system ]; then
  say "Setting up the update helper (applies only updates you approve on the board)"
  [ -f /etc/default/logwatch-dashboard ] || printf '# Releases repo the host updater downloads from\nLW_RELEASES=%s\n' "$REPO" > /etc/default/logwatch-dashboard
  mkdir -p "$DIR/data" && chown logwatch:logwatch "$DIR/data"
  cat > /etc/systemd/system/logwatch-update.service <<UNIT
[Unit]
Description=Logwatch Dashboard updater (applies updates approved on the board)
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$DIR/update.sh
UNIT
  cat > /etc/systemd/system/logwatch-update.path <<UNIT
[Unit]
Description=Logwatch Dashboard update requests

[Path]
PathChanged=$DIR/data/update-request.json
PathChanged=$DIR/data/feature-request.json
Unit=logwatch-update.service

[Install]
WantedBy=multi-user.target
UNIT
  cat > /etc/systemd/system/logwatch-update.timer <<UNIT
[Unit]
Description=Logwatch Dashboard scheduled updates + heartbeat

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now logwatch-update.path logwatch-update.timer >/dev/null 2>&1 || echo "  (couldn't enable the units; updates from the board stay off)"
else
  echo "No systemd: updates from the board are off. Update with: sudo bash $DIR/install.sh"
fi

say "Preparing the installer's Python environment ($DIR/.venv)"
[ -x "$DIR/.venv/bin/python" ] || python3 -m venv "$DIR/.venv"
"$DIR/.venv/bin/pip" install -q --disable-pip-version-check -r "$DIR/installer/requirements.txt"

echo
echo "Installed in $DIR. Open the setup again any time (web page on the board's port, or the next free one):"
echo "  sudo bash $DIR/install.sh        or: cd $DIR && sudo .venv/bin/python -m installer"
[ "$SETUP" = 1 ] || exit 0
cd "$DIR"
say "Starting the web setup: open the URL below in your browser (Ctrl+C stops it)"
exec "$DIR/.venv/bin/python" -m installer
