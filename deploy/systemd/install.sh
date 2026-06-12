#!/usr/bin/env bash
# Install the bwpool systemd units, binaries, and example config (T-504).
#
# Idempotent: re-running updates binaries and units, preserves any existing
# /etc/bwpool/*.env (only writes the examples if absent). Run as root on the
# target edge (agent) or control host (controller).
#
# Usage:
#   deploy/systemd/install.sh [edge|controller|both]   (default: both)
set -euo pipefail

ROLE="${1:-both}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINDIR=/usr/local/bin
UNITDIR=/etc/systemd/system
CFGDIR=/etc/bwpool

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
command -v go >/dev/null || { echo "go toolchain required to build binaries" >&2; exit 1; }

install -d "$CFGDIR"

install_edge() {
  echo "building + installing edge-agent"
  ( cd "$REPO_ROOT" && go build -o "$BINDIR/bwpool-edge-agent" ./cmd/edge-agent )
  install -m 0644 "$REPO_ROOT/deploy/systemd/bwpool-edge-agent.service" "$UNITDIR/"
  [[ -f "$CFGDIR/edge-agent.env" ]] || install -m 0644 "$REPO_ROOT/deploy/systemd/edge-agent.env" "$CFGDIR/edge-agent.env"
}

install_controller() {
  echo "building + installing controller"
  ( cd "$REPO_ROOT" && go build -o "$BINDIR/bwpool-controller" ./cmd/controller )
  install -m 0644 "$REPO_ROOT/deploy/systemd/bwpool-controller.service" "$UNITDIR/"
  [[ -f "$CFGDIR/controller.env" ]] || install -m 0644 "$REPO_ROOT/deploy/systemd/controller.env" "$CFGDIR/controller.env"
}

case "$ROLE" in
  edge)       install_edge ;;
  controller) install_controller ;;
  both)       install_edge; install_controller ;;
  *) echo "unknown role: $ROLE (want edge|controller|both)" >&2; exit 1 ;;
esac

systemctl daemon-reload
echo
echo "Installed. Next:"
echo "  edit $CFGDIR/edge-agent.env (set BWPOOL_EDGE_ID), then:"
echo "  systemctl enable --now bwpool-edge-agent.service"
echo "  systemctl enable --now bwpool-controller.service"
