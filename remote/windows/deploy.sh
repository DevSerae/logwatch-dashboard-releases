#!/bin/bash
# Optional: push the Windows agent over OpenSSH from a Linux box (Windows OpenSSH server, admin account, cmd default shell).
# Usage: deploy.sh <ssh-target> <board-address> [--dns] [--port 24224]
set -euo pipefail
h=$1; board=$2; shift 2; extra=""
while [ $# -gt 0 ]; do case "$1" in --dns) extra="$extra -Dns"; shift ;; --port) extra="$extra -Port $2"; shift 2 ;; *) exit 2 ;; esac; done
d=$(dirname "$0")
ssh "$h" 'if not exist C:\ProgramData\lw-agent mkdir C:\ProgramData\lw-agent' >/dev/null
scp -q "$d/logwatch.lua" "$d/agent.yaml" "$d/agent-dns.yaml" "$d/install.ps1" "$h:C:/ProgramData/lw-agent/"
ssh "$h" "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\ProgramData\\lw-agent\\install.ps1 -Board $board $extra" 2>&1 \
  | grep -v '^#< CLIXML' | sed 's/<[^>]*>//g' | tail -8
ssh "$h" 'rmdir /s /q C:\ProgramData\lw-agent' >/dev/null
