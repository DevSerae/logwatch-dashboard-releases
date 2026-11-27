#!/usr/bin/env bash
# Build the release assets into dist/: logwatch-dashboard-<ver>.tar.gz, logwatch-dashboard.tar.gz (same file, stable
# name for install.sh), install.sh and SHA256SUMS. Only files git tracks (or would track) go in: never secrets/,
# data/, config.yaml, .env or the override (see .gitignore).
#   tools/release.sh            then: gh release create v<ver> dist/* -R <releases repo>
set -euo pipefail
cd "$(dirname "$0")/.."
ver="$(cat VERSION)"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "bad VERSION: $ver" >&2; exit 1; }
rm -rf dist && mkdir -p dist/stage/logwatch-dashboard
git ls-files -co --exclude-standard -z | grep -zv '^dist/' | grep -zv '^assets/' | tar --null -T - -cf - | tar -C dist/stage/logwatch-dashboard -xf -
for f in secrets data config/config.yaml .env docker-compose.override.yml; do
  [ ! -e "dist/stage/logwatch-dashboard/$f" ] || { echo "refusing: $f is in the release" >&2; exit 1; }
done
tar -C dist/stage --owner=0 --group=0 --sort=name -czf "dist/logwatch-dashboard-$ver.tar.gz" logwatch-dashboard
cp "dist/logwatch-dashboard-$ver.tar.gz" dist/logwatch-dashboard.tar.gz
cp install.sh dist/install.sh
rm -rf dist/stage
(cd dist && sha256sum logwatch-dashboard-"$ver".tar.gz logwatch-dashboard.tar.gz install.sh > SHA256SUMS)
ls -la dist
