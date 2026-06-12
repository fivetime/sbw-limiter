//go:build integration

package vpp

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// T-410 acceptance against real VPP: create an lcp pair (Go API) mirroring a
// VPP interface to a tap in a netns, write routes into that netns's Linux RIB
// (as BIRD would), and confirm linux-cp mirrors them into the VPP FIB —
// including ECMP expansion (§4.6) — and withdraws them on delete.
//
// Requires: VPP started with linux_cp + linux_nl plugins and a "dataplane"
// netns (deploy/vpp/startup.conf), plus BWPOOL_TEST_VPPCTL and the dataplane
// netns reachable as root.
const lcpNetns = "dataplane"

// nsExec runs `ip netns exec <ns> ip <args...>` — i.e. an iproute2 command
// inside the dataplane netns.
func nsExec(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"netns", "exec", lcpNetns, "ip"}, args...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v\n%s", full, err, out)
	}
	return string(out)
}

func nsTry(args ...string) {
	full := append([]string{"netns", "exec", lcpNetns, "ip"}, args...)
	_ = exec.Command("ip", full...).Run()
}

func TestRealLcpRouteMirror(t *testing.T) {
	if os.Getenv("BWPOOL_TEST_VPPCTL") == "" || os.Geteuid() != 0 {
		t.Skip("needs root + BWPOOL_TEST_VPPCTL + a real VPP with linux_nl + dataplane netns")
	}
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)

	// Create a VPP loopback with an address and pair it to a tap in the netns.
	vppctl(t, "loopback", "create-interface")
	swIf := loopbackIndex(t)
	t.Cleanup(func() { vppctl(t, "loopback", "delete-interface", "intfc", "loop0") })
	vppctl(t, "set", "interface", "state", "loop0", "up")
	vppctl(t, "set", "interface", "ip", "address", "loop0", "10.77.0.1/24")

	lcp := NewLcpPairs(ch)
	if err := lcp.Create(swIf, "bwtap0", lcpNetns); err != nil {
		t.Fatalf("lcp Create: %v", err)
	}
	t.Cleanup(func() { _ = lcp.Delete(swIf) })

	// Bring the tap up with a peer address (so nexthops resolve).
	nsTry("addr", "add", "10.77.0.2/24", "dev", "bwtap0")
	nsExec(t, "link", "set", "bwtap0", "up")
	time.Sleep(300 * time.Millisecond)

	// Single-hop route added AFTER the pair exists → mirrors to the FIB.
	nsTry("route", "del", "203.0.113.0/24")
	nsExec(t, "route", "add", "203.0.113.0/24", "via", "10.77.0.2")
	t.Cleanup(func() { nsTry("route", "del", "203.0.113.0/24") })

	// ECMP route (two nexthops) → both paths must appear (§4.6).
	nsTry("route", "del", "198.51.100.0/24")
	nsExec(t, "route", "add", "198.51.100.0/24",
		"nexthop", "via", "10.77.0.2", "nexthop", "via", "10.77.0.3")
	t.Cleanup(func() { nsTry("route", "del", "198.51.100.0/24") })

	waitFIB(t, "203.0.113.0/24", 1)
	waitFIB(t, "198.51.100.0/24", 2)

	// Withdraw the single-hop route → it must leave the FIB.
	nsExec(t, "route", "del", "203.0.113.0/24")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fibPathCount(t, "203.0.113.0/24") == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("203.0.113.0/24 still in FIB after withdrawal")
}

func loopbackIndex(t *testing.T) uint32 {
	t.Helper()
	out := vppctl(t, "show", "interface")
	m := loopIdxRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no loopback in:\n%s", out)
	}
	idx, _ := strconv.ParseUint(m[1], 10, 32)
	return uint32(idx)
}

// fibPathCount counts resolved nexthop paths for a prefix in the VPP FIB.
func fibPathCount(t *testing.T, prefix string) int {
	t.Helper()
	out := vppctl(t, "show", "ip", "fib", prefix)
	// If the prefix isn't present, VPP prints the covering route (e.g. 0.0.0.0/0).
	if !strings.Contains(out, prefix+" ") {
		return 0
	}
	return strings.Count(out, "arp-ipv4: via")
}

func waitFIB(t *testing.T, prefix string, wantPaths int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fibPathCount(t, prefix) >= wantPaths {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	out := vppctl(t, "show", "ip", "fib", prefix)
	t.Fatalf("%s did not mirror with %d path(s) into the VPP FIB:\n%s", prefix, wantPaths, out)
}
