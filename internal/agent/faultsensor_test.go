package agent

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/fivetime/sbw-contract/model"

	"github.com/fivetime/sbw-limiter/internal/vpp"
)

func discardSensor(healthy func() bool, dump func() ([]vpp.Interface, error), ifaces ...string) *FaultSensor {
	return &FaultSensor{
		healthy:       healthy,
		dumpIfaces:    dump,
		policerIfaces: ifaces,
		log:           slog.New(slog.DiscardHandler),
	}
}

func upList(names ...string) func() ([]vpp.Interface, error) {
	return func() ([]vpp.Interface, error) {
		out := make([]vpp.Interface, len(names))
		for i, n := range names {
			out[i] = vpp.Interface{Name: n, Up: true, LinkUp: true}
		}
		return out, nil
	}
}

func TestLinkDownAmong(t *testing.T) {
	list := []vpp.Interface{
		{Name: "host-macc", Up: true, LinkUp: false},   // admin-up, carrier down → FAULT
		{Name: "host-data0", Up: true, LinkUp: true},   // fully up → not a fault
		{Name: "host-admin", Up: false, LinkUp: false}, // admin-down → operator intent, excluded
	}
	// Only host-macc among the watched set is a link-down fault.
	got := linkDownAmong(list, []string{"host-macc", "host-data0", "host-admin"})
	if len(got) != 1 || got[0] != "host-macc" {
		t.Fatalf("linkDownAmong = %v, want [host-macc]", got)
	}
	// A watched name missing from the dump is undetermined (not reported here).
	if got := linkDownAmong(list, []string{"absent"}); len(got) != 0 {
		t.Fatalf("missing iface must not be link-down, got %v", got)
	}
	// All carriers up → nothing.
	if got := linkDownAmong([]vpp.Interface{{Name: "a", Up: true, LinkUp: true}}, []string{"a"}); len(got) != 0 {
		t.Fatalf("healthy carrier must not be link-down, got %v", got)
	}
}

func TestFaultSensorVPPGone(t *testing.T) {
	s := discardSensor(func() bool { return false }, func() ([]vpp.Interface, error) {
		t.Fatal("must not dump when the connection is unhealthy")
		return nil, nil
	}, "host-macc")
	if fk, _ := s.Fault(); fk != model.FaultVPPGone {
		t.Fatalf("unhealthy connection = %v, want vpp-gone", fk)
	}
}

func TestFaultSensorLinkDown(t *testing.T) {
	s := discardSensor(func() bool { return true }, func() ([]vpp.Interface, error) {
		return []vpp.Interface{{Name: "host-macc", Up: true, LinkUp: false}}, nil
	}, "host-macc")
	fk, reason := s.Fault()
	if fk != model.FaultLinkDown {
		t.Fatalf("carrier-down policer iface = %v, want link-down", fk)
	}
	if reason == "" {
		t.Fatal("link-down must carry a reason")
	}
}

func TestFaultSensorHealthy(t *testing.T) {
	s := discardSensor(func() bool { return true }, func() ([]vpp.Interface, error) {
		return []vpp.Interface{{Name: "host-macc", Up: true, LinkUp: true}}, nil
	}, "host-macc")
	if fk, _ := s.Fault(); fk != model.FaultNone {
		t.Fatalf("all up = %v, want none", fk)
	}
}

// A dump error while the connection is still healthy leaves the fault UNTYPED (the
// reconcile pass classifies it) — the sensor must not guess link-down.
func TestFaultSensorDumpErrorUndetermined(t *testing.T) {
	s := discardSensor(func() bool { return true }, func() ([]vpp.Interface, error) {
		return nil, errors.New("channel busy")
	}, "host-macc")
	if fk, _ := s.Fault(); fk != model.FaultNone {
		t.Fatalf("healthy+dump-error = %v, want none (undetermined)", fk)
	}
}

// A dump error caused by VPP racing DOWN between the health check and the dump is
// vpp-gone, not undetermined.
func TestFaultSensorDumpErrorRacedDown(t *testing.T) {
	calls := 0
	healthy := func() bool { calls++; return calls == 1 } // up on the first check, down after
	s := discardSensor(healthy, func() ([]vpp.Interface, error) {
		return nil, errors.New("connection closed")
	}, "host-macc")
	if fk, _ := s.Fault(); fk != model.FaultVPPGone {
		t.Fatalf("dump error with connection now down = %v, want vpp-gone", fk)
	}
}

type fakeFault struct {
	fk     model.FaultKind
	reason string
}

func (f fakeFault) Fault() (model.FaultKind, string) { return f.fk, f.reason }

// The reporter overlays a DETERMINATE fault onto the report and forces DataPlaneDown so
// SoftDead() is true (the server's typed-fault path keys off healthDead).
func TestReporterOverlaysDeterminateFault(t *testing.T) {
	hc := NewHealthChecker("l1", fakeLive{healthy: true}, WithClock(func() int64 { return 1 }))
	hc.Observe(model.EdgeDesiredState{Generation: 3}, Result{}, nil) // clean pass → Healthy
	r := NewReporter("l1", hc, WithFault(fakeFault{model.FaultLinkDown, "link down on host-data0"}))

	rep, ok := r.Build()
	if !ok {
		t.Fatal("Build not ready")
	}
	if rep.Health.FaultKind != model.FaultLinkDown {
		t.Fatalf("fault_kind = %v, want link-down", rep.Health.FaultKind)
	}
	if rep.Health.State != model.HealthDataPlaneDown {
		t.Fatalf("a determinate fault must force DataPlaneDown, got %v", rep.Health.State)
	}
	if !rep.Health.SoftDead() {
		t.Fatal("overlaid determinate fault must be SoftDead() so the server acts")
	}
	if rep.Health.Reason != "link down on host-data0" {
		t.Fatalf("reason not overlaid: %q", rep.Health.Reason)
	}
}

// FaultNone leaves the reconcile-derived health untouched (no false soft-death).
func TestReporterFaultNoneLeavesHealthy(t *testing.T) {
	hc := NewHealthChecker("l1", fakeLive{healthy: true}, WithClock(func() int64 { return 1 }))
	hc.Observe(model.EdgeDesiredState{Generation: 3}, Result{}, nil)
	r := NewReporter("l1", hc, WithFault(fakeFault{model.FaultNone, ""}))

	rep, _ := r.Build()
	if rep.Health.FaultKind != model.FaultNone || rep.Health.State != model.HealthHealthy {
		t.Fatalf("FaultNone must not alter health: kind=%v state=%v", rep.Health.FaultKind, rep.Health.State)
	}
}

// ③ forwarding-broken: VPP healthy + links up, but the probe reports the path broken.
func TestFaultForwardingBroken(t *testing.T) {
	s := discardSensor(func() bool { return true }, upList("host-macc"), "host-macc")
	s.broken = func() bool { return true }
	if fk, reason := s.Fault(); fk != model.FaultForwardingBroken || reason == "" {
		t.Fatalf("healthy device + broken probe = %v, want forwarding-broken", fk)
	}
}

// ③ is ranked LAST: an unambiguous link-down explains the probe failure and wins.
func TestLinkDownOutranksForwardingBroken(t *testing.T) {
	dump := func() ([]vpp.Interface, error) {
		return []vpp.Interface{{Name: "host-macc", Up: true, LinkUp: false}}, nil
	}
	s := discardSensor(func() bool { return true }, dump, "host-macc")
	s.broken = func() bool { return true }
	if fk, _ := s.Fault(); fk != model.FaultLinkDown {
		t.Fatalf("link-down must outrank forwarding-broken, got %v", fk)
	}
}

// A healthy probe leaves the sensor at FaultNone.
func TestForwardingProbeHealthyNone(t *testing.T) {
	s := discardSensor(func() bool { return true }, upList("host-macc"), "host-macc")
	s.broken = func() bool { return false }
	if fk, _ := s.Fault(); fk != model.FaultNone {
		t.Fatalf("healthy probe = %v, want none", fk)
	}
}
