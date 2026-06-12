//go:build integration

package vpp

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// T-405 acceptance: attach a classify chain head to an interface for
// policer-classify (DESIGN.md §5.2 — ingress uplink / egress core), verified
// against real VPP via policer_classify_dump. The loopback is created via
// vppctl (test scaffolding; the agent will resolve interface names→indexes via
// sw_interface_dump, a separate concern). Run with both:
//
//	BWPOOL_TEST_VPP_SOCKET=/run/vpp/api.sock
//	BWPOOL_TEST_VPPCTL="<vpp>/bin/vppctl -s /run/vpp/cli.sock"   (LD_LIBRARY_PATH set)

func vppctl(t *testing.T, args ...string) string {
	t.Helper()
	cmdline := os.Getenv("BWPOOL_TEST_VPPCTL")
	if cmdline == "" {
		t.Skip("BWPOOL_TEST_VPPCTL not set")
	}
	fields := strings.Fields(cmdline)
	full := append(fields, args...)
	out, err := exec.Command(full[0], full[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("vppctl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

var loopIdxRe = regexp.MustCompile(`(?m)^loop\d+\s+(\d+)\s`)

// makeLoopback creates a loopback via vppctl and returns its sw_if_index.
func makeLoopback(t *testing.T) uint32 {
	t.Helper()
	vppctl(t, "loopback", "create-interface")
	out := vppctl(t, "show", "interface")
	m := loopIdxRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("could not find loopback index in:\n%s", out)
	}
	idx, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vppctl(t, "loopback", "delete-interface", "intfc", "loop0") })
	return uint32(idx)
}

func TestRealPolicerClassifyAttach(t *testing.T) {
	if os.Getenv("BWPOOL_TEST_VPPCTL") == "" {
		t.Skip("BWPOOL_TEST_VPPCTL not set")
	}
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	cl := NewClassify(ch)

	swIf := makeLoopback(t)

	// Ingress chain head: ip4-dst-32. Egress would attach the src tables; here
	// one table is enough to verify the attach mechanism.
	ti, err := cl.AddTable(TableSpec{Mask: model.MaskIP4Dst32})
	if err != nil {
		t.Fatalf("AddTable: %v", err)
	}
	t.Cleanup(func() { _ = cl.DeleteTable(ti) })

	// Attach.
	if err := cl.SetPolicerInterface(swIf, ti, NoTable, true); err != nil {
		t.Fatalf("SetPolicerInterface attach: %v", err)
	}

	att, err := cl.DumpPolicerClassify(model.FamilyIPv4)
	if err != nil {
		t.Fatalf("DumpPolicerClassify: %v", err)
	}
	if !hasAttachment(att, swIf, ti) {
		t.Fatalf("attach not registered: dump=%+v, want sw_if=%d table=%d", att, swIf, ti)
	}

	// The ip4-policer-classify feature must be enabled on the interface arc.
	feat := vppctl(t, "show", "interface", "features", "loop0")
	if !strings.Contains(feat, "ip4-policer-classify") {
		t.Errorf("ip4-policer-classify feature not enabled on loop0:\n%s", feat)
	}

	// Detach: VPP identifies what to remove by table index, so detach must pass
	// the attached table index (NoTable would be a silent no-op).
	if err := cl.SetPolicerInterface(swIf, ti, NoTable, false); err != nil {
		t.Fatalf("SetPolicerInterface detach: %v", err)
	}
	att, err = cl.DumpPolicerClassify(model.FamilyIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if hasAttachment(att, swIf, ti) {
		t.Errorf("attach still present after detach: %+v", att)
	}
}

func hasAttachment(att []PolicerClassifyAttachment, swIf, table uint32) bool {
	for _, a := range att {
		if a.SwIfIndex == swIf && a.TableIndex == table {
			return true
		}
	}
	return false
}
