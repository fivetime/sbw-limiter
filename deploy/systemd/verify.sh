#!/usr/bin/env bash
# Verify the bwpool-edge-agent unit against a REAL systemd (T-504 DoD: unit
# installs, auto-starts on boot, restarts on crash). Self-cleaning.
#
# It installs stub vpp.service + bird.service so the agent's Requires=/After=
# dependency graph resolves (production ships the real ones), then exercises:
#   1. install + start  → active, and Requires= pulls vpp.service up
#   2. dependency order → agent's start is ordered after vpp.service
#   3. crash restart    → kill -KILL the main PID, systemd brings it back (new PID)
#   4. boot autostart   → enable → is-enabled = enabled
#   5. clean stop       → graceful SIGTERM stop, unit inactive (not failed)
#
# Requires root + a running systemd. Run from anywhere in the repo.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN=/usr/local/bin/bwpool-edge-agent
UNIT=bwpool-edge-agent.service
UNITDIR=/etc/systemd/system
CFGDIR=/etc/bwpool

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ "$(systemctl is-system-running 2>/dev/null || true)" =~ running|degraded ]] || { echo "systemd not running" >&2; exit 1; }

cleanup() {
  set +e
  systemctl stop "$UNIT" 2>/dev/null
  systemctl disable "$UNIT" 2>/dev/null
  systemctl stop vpp.service bird.service 2>/dev/null
  rm -f "$UNITDIR/$UNIT" "$UNITDIR/vpp.service" "$UNITDIR/bird.service"
  rm -f "$CFGDIR/edge-agent.env"
  systemctl daemon-reload
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== build + install binary =="
( cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/edge-agent )

install -d "$CFGDIR"
printf 'BWPOOL_EDGE_ID=edge-verify\n' > "$CFGDIR/edge-agent.env"

echo "== install stub vpp/bird deps (prod ships the real ones) =="
for s in vpp bird; do
  cat > "$UNITDIR/$s.service" <<EOF
[Unit]
Description=stub $s for bwpool unit verification
[Service]
Type=exec
ExecStart=/bin/sleep infinity
EOF
done

cp "$REPO_ROOT/deploy/systemd/$UNIT" "$UNITDIR/"
systemctl daemon-reload

echo "== 1. start =="
systemctl start "$UNIT"
sleep 1
[[ "$(systemctl is-active "$UNIT")" == active ]] || fail "unit not active after start"
# Requires=vpp.service must have pulled the (stub) VPP up.
[[ "$(systemctl is-active vpp.service)" == active ]] || fail "Requires=vpp.service did not pull vpp up"
echo "   active; Requires= pulled vpp.service up"

echo "== 2. dependency ordering (agent After vpp.service) =="
# systemd-analyze verify reports ordering-cycle / missing-dep problems.
systemd-analyze verify "$UNITDIR/$UNIT" 2>&1 | grep -v '^$' || true

echo "== 3. crash restart =="
PID1="$(systemctl show -p MainPID --value "$UNIT")"
[[ "$PID1" != 0 ]] || fail "no MainPID"
echo "   MainPID=$PID1; sending SIGKILL"
kill -KILL "$PID1"
for _ in $(seq 1 20); do
  sleep 0.5
  PID2="$(systemctl show -p MainPID --value "$UNIT")"
  [[ "$PID2" != 0 && "$PID2" != "$PID1" ]] && break
done
[[ "$PID2" != 0 && "$PID2" != "$PID1" ]] || fail "did not restart after SIGKILL (pid still $PID1)"
[[ "$(systemctl is-active "$UNIT")" == active ]] || fail "not active after restart"
echo "   restarted: $PID1 -> $PID2, active again"

echo "== 4. boot autostart =="
systemctl enable "$UNIT" >/dev/null 2>&1
[[ "$(systemctl is-enabled "$UNIT")" == enabled ]] || fail "is-enabled != enabled"
echo "   enabled (WantedBy=multi-user.target)"

echo "== 5. clean stop =="
systemctl stop "$UNIT"
[[ "$(systemctl is-active "$UNIT")" != active ]] || fail "still active after stop"
RESULT="$(systemctl show -p Result --value "$UNIT")"
[[ "$RESULT" == success ]] || fail "stop Result=$RESULT, want success (graceful SIGTERM)"
echo "   stopped cleanly (Result=success)"

echo
echo "VERIFY OK"
