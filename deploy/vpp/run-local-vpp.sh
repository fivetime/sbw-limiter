#!/usr/bin/env bash
# Run a VPP instance from a build tree for local functional testing, then point
# the T-401 integration test at its socket. No DPDK / hugepages (4K pages).
#
#   VPP_BUILD=<vpp-src>/build-root/install-vpp-native/vpp scripts/run-local-vpp.sh
#
# Leaves VPP running in the foreground; Ctrl-C to stop. In another shell:
#   BWPOOL_TEST_VPP_SOCKET=/run/vpp/api.sock \
#     go test -tags integration -run TestReal ./internal/vpp/
set -euo pipefail

VPP_BUILD="${VPP_BUILD:?set VPP_BUILD to <vpp-src>/build-root/install-vpp-native/vpp}"
CONF="$(dirname "$0")/startup.conf"

export LD_LIBRARY_PATH="$VPP_BUILD/lib/x86_64-linux-gnu:$VPP_BUILD/lib:${LD_LIBRARY_PATH:-}"
export VPP_PLUGIN_PATH="$VPP_BUILD/lib/x86_64-linux-gnu/vpp_plugins:$VPP_BUILD/lib/vpp_plugins"

mkdir -p /run/vpp /var/log/vpp
groupadd -f vpp 2>/dev/null || true

echo "Starting VPP from $VPP_BUILD"
echo "  binary API socket: /run/vpp/api.sock"
echo "  CLI socket:        /run/vpp/cli.sock  (vppctl -s /run/vpp/cli.sock)"
exec "$VPP_BUILD/bin/vpp" -c "$CONF"
