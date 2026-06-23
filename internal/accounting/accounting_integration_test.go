//go:build integration

package accounting

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// T-502 acceptance against real components (DESIGN.md §5.1): drive routes into a
// netns Linux RIB, let linux-cp mirror them into the real VPP FIB, and confirm
// the three-way accounting (a) reads real counts off both, (b) stays healthy
// while the mirror tracks, (c) DEVIATES when a route lands in the kernel but not
// the FIB — the observable signature of silent netlink loss — and (d) clears
// once the kernel and FIB agree again (the converged state a re-export reaches).
//
// The re-export ACTION (BIRD configure → kernel re-push → re-mirror) is covered
// by the agent audit unit test plus the bird/lcp integration tests; this test
// proves the detection half against live route tables.
//
// Requires root, a real VPP with linux_cp + linux_nl and a "dataplane" netns
// (deploy/vpp/startup.conf), and BWPOOL_TEST_VPPCTL set to the vppctl invocation.
const netns = "dataplane"

func vc(t *testing.T, args ...string) string {
	t.Helper()
	fields := append(strings.Fields(os.Getenv("BWPOOL_TEST_VPPCTL")), args...)
	out, err := exec.Command(fields[0], fields[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("vppctl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func ns(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"netns", "exec", netns, "ip"}, args...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v\n%s", full, err, out)
	}
	return string(out)
}

func nsTry(args ...string) {
	full := append([]string{"netns", "exec", netns, "ip"}, args...)
	_ = exec.Command("ip", full...).Run()
}

func TestRealThreeWayAccounting(t *testing.T) {
	if os.Getenv("BWPOOL_TEST_VPPCTL") == "" || os.Geteuid() != 0 {
		t.Skip("needs root + BWPOOL_TEST_VPPCTL + real VPP with linux_nl + dataplane netns")
	}

	// Pair a VPP loopback to a tap in the netns so kernel routes mirror to the FIB.
	vc(t, "loopback", "create-interface")
	t.Cleanup(func() { vc(t, "loopback", "delete-interface", "intfc", "loop0") })
	vc(t, "lcp", "create", "loop0", "host-if", "acctap0", "netns", netns)
	t.Cleanup(func() { vc(t, "lcp", "delete", "loop0") })
	vc(t, "set", "interface", "state", "loop0", "up")
	vc(t, "set", "interface", "ip", "address", "loop0", "10.67.0.1/24")
	nsTry("addr", "add", "10.67.0.2/24", "dev", "acctap0")
	ns(t, "link", "set", "acctap0", "up")
	time.Sleep(400 * time.Millisecond)

	ctx := context.Background()
	vppctl := strings.Fields(os.Getenv("BWPOOL_TEST_VPPCTL"))
	linux := NewKernelCounterIn(netns)
	vpp := NewVPPFIBCounter(vppctl)

	// A handful of mirrored routes: present in BOTH the kernel and the FIB.
	mirrored := []string{"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"}
	for _, p := range mirrored {
		nsTry("route", "del", p)
		ns(t, "route", "add", p, "via", "10.67.0.2")
		pp := p
		t.Cleanup(func() { nsTry("route", "del", pp) })
	}
	waitMirror(t, vppctl, "203.0.113.0/24")

	// The trigger is the BIRD↔VPP mirror. This is a route-B linux_nl test with no
	// BIRD process, but in route B BIRD mirrors the kernel (BIRD → kernel → VPP),
	// so a route in the kernel is a route in BIRD: aliasing the BIRD leg to the
	// Linux counter faithfully simulates BIRD ≈ kernel, and a netlink loss (route
	// in kernel+BIRD, missing from VPP) shows up as BIRD running ahead of VPP.
	// Calibrate the baseline at the healthy steady state — the VPP FIB sits
	// structurally above (connected/local/receive entries), so the gap is a stable
	// negative number, not zero.
	chk := Checker{
		BIRD:  linux, // route B: BIRD mirrors the kernel
		Linux: linux,
		VPP:   vpp,
	}
	baseline, err := chk.CalibrateBaseline(ctx)
	if err != nil {
		t.Fatal(err)
	}
	chk.BaselineGap = baseline
	chk.Tolerance = 1 // a single un-mirrored route must break it
	lc, _ := linux.Count(ctx)
	vcnt, _ := vpp.Count(ctx)
	t.Logf("healthy: bird≈linux=%d vpp=%d baseline-gap=%d", lc, vcnt, baseline)
	if lc < uint64(len(mirrored)) || vcnt < uint64(len(mirrored)) {
		t.Fatalf("counts too low to be real (linux=%d vpp=%d)", lc, vcnt)
	}
	if rep, err := chk.Check(ctx); err != nil || rep.Deviated {
		t.Fatalf("healthy state should not deviate at its own baseline: %s (err %v)", rep, err)
	}

	// Inject netlink loss: routes that land in the kernel but cannot reach the
	// FIB. A dummy interface has no lcp pair, so linux-cp can't realize routes
	// out of it — the kernel RIB grows while the VPP FIB does not, pushing the
	// gap positive (drift past tolerance), the netlink-loss signature.
	ns(t, "link", "add", "dummy0", "type", "dummy")
	t.Cleanup(func() { nsTry("link", "del", "dummy0") })
	ns(t, "addr", "add", "10.88.0.1/24", "dev", "dummy0")
	ns(t, "link", "set", "dummy0", "up")
	lost := []string{"10.90.0.0/24", "10.91.0.0/24", "10.92.0.0/24"}
	for _, p := range lost {
		ns(t, "route", "add", p, "dev", "dummy0")
	}
	time.Sleep(400 * time.Millisecond)

	rep, err := chk.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("after injection: %s", rep)
	if !rep.Deviated {
		t.Fatalf("kernel-only routes must drift the mirror past tolerance: %s", rep)
	}
	if rep.Drift <= 0 {
		t.Fatalf("kernel-only routes should drift the gap positive: %s", rep)
	}

	// Recovery: remove the un-mirrorable routes (and their interface) → the
	// kernel returns to its baseline relationship with the FIB and the audit
	// clears. This is the converged state a re-export drives the system back to.
	ns(t, "link", "del", "dummy0")
	time.Sleep(300 * time.Millisecond)
	if rep, err := chk.Check(ctx); err != nil || rep.Deviated {
		t.Fatalf("after withdrawal the audit should clear: %s (err %v)", rep, err)
	}
}

func waitMirror(t *testing.T, vppctl []string, prefix string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, err := execRunner{}.Run(context.Background(), vppctl[0], append(vppctl[1:], "show", "ip", "fib", prefix)...)
		if err == nil && strings.Contains(string(out), prefix+" ") {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("%s did not mirror into the VPP FIB", prefix)
}
