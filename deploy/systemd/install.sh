#!/usr/bin/env bash
# Install the bwpool edge-agent systemd unit, binary, and example config (T-504).
#
# Idempotent: re-running updates the binary and unit, preserves any existing
# /etc/bwpool/*.env (only writes the example if absent). Run as root on the
# target edge.
#
# Usage:
#   deploy/systemd/install.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINDIR=/usr/local/bin
UNITDIR=/etc/systemd/system
CFGDIR=/etc/bwpool

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
command -v go >/dev/null || { echo "go toolchain required to build binaries" >&2; exit 1; }

install -d "$CFGDIR"

echo "building + installing edge-agent"
( cd "$REPO_ROOT" && go build -o "$BINDIR/bwpool-edge-agent" ./cmd/edge-agent )
install -m 0644 "$REPO_ROOT/deploy/systemd/bwpool-edge-agent.service" "$UNITDIR/"
[[ -f "$CFGDIR/edge-agent.env" ]] || install -m 0644 "$REPO_ROOT/deploy/systemd/edge-agent.env" "$CFGDIR/edge-agent.env"

systemctl daemon-reload
echo
echo "Installed. Next:"
echo "  edit $CFGDIR/edge-agent.env (set BWPOOL_EDGE_ID), then:"
echo "  systemctl enable --now bwpool-edge-agent.service"
