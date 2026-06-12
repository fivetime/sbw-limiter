package accounting

import (
	"context"
	"errors"
	"testing"
)

type fakeCounter struct {
	name string
	n    uint64
	err  error
}

func (f fakeCounter) Name() string                          { return f.name }
func (f fakeCounter) Count(context.Context) (uint64, error) { return f.n, f.err }

func TestCheckerHealthyAtBaseline(t *testing.T) {
	// VPP FIB sits structurally above the kernel main table: baseline gap is the
	// negative steady-state surplus. At baseline the drift is zero → healthy.
	c := Checker{
		BIRD:        fakeCounter{name: "bird", n: 215},
		Linux:       fakeCounter{name: "linux", n: 208},
		VPP:         fakeCounter{name: "vpp", n: 218}, // +10 connected/local surplus
		BaselineGap: -10,
		Tolerance:   3,
	}
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Gap != -10 || r.Drift != 0 {
		t.Fatalf("gap=%d drift=%d, want -10/0", r.Gap, r.Drift)
	}
	if r.Deviated {
		t.Errorf("at baseline should be healthy: %s", r)
	}
}

func TestCheckerNetlinkLossDriftsPositive(t *testing.T) {
	// Routes land in the kernel but not the FIB: Linux rises toward VPP, the gap
	// moves positive relative to baseline → drift past tolerance → deviation.
	c := Checker{
		BIRD:        fakeCounter{name: "bird", n: 220},
		Linux:       fakeCounter{name: "linux", n: 220}, // +12 kernel-only routes
		VPP:         fakeCounter{name: "vpp", n: 218},
		BaselineGap: -10,
		Tolerance:   3,
	}
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Gap != 2 || r.Drift != 12 {
		t.Fatalf("gap=%d drift=%d, want 2/12", r.Gap, r.Drift)
	}
	if !r.Deviated {
		t.Errorf("netlink-loss drift should deviate: %s", r)
	}
}

func TestCheckerStaleFIBDriftsNegative(t *testing.T) {
	// The opposite fault: the FIB keeps routes the kernel withdrew → gap moves
	// further negative → still flagged.
	c := Checker{
		BIRD:        fakeCounter{name: "bird", n: 200},
		Linux:       fakeCounter{name: "linux", n: 200},
		VPP:         fakeCounter{name: "vpp", n: 230}, // 30 surplus vs baseline 10
		BaselineGap: -10,
		Tolerance:   5,
	}
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Drift != -20 {
		t.Fatalf("drift=%d, want -20", r.Drift)
	}
	if !r.Deviated {
		t.Errorf("stale-FIB drift should deviate: %s", r)
	}
}

func TestCheckerExportGapDoesNotTrigger(t *testing.T) {
	// A large BIRD↔Linux gap (anchors) is reported but never drives the trigger;
	// only the mirror drift does.
	c := Checker{
		BIRD:        fakeCounter{name: "bird", n: 5000},
		Linux:       fakeCounter{name: "linux", n: 208},
		VPP:         fakeCounter{name: "vpp", n: 218},
		BaselineGap: -10,
		Tolerance:   3,
	}
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.ExportGap != 4792 {
		t.Errorf("export gap = %d, want 4792", r.ExportGap)
	}
	if r.Deviated {
		t.Errorf("export gap alone must not deviate: %s", r)
	}
}

func TestCheckerDriftBoundary(t *testing.T) {
	base := func(linux uint64) Checker {
		return Checker{
			BIRD:        fakeCounter{name: "bird", n: linux},
			Linux:       fakeCounter{name: "linux", n: linux},
			VPP:         fakeCounter{name: "vpp", n: 100},
			BaselineGap: 0,
			Tolerance:   5,
		}
	}
	// Drift exactly == tolerance is healthy; one more deviates (both directions).
	if r, _ := base(105).Check(context.Background()); r.Deviated {
		t.Errorf("drift == tolerance should be healthy: %s", r)
	}
	if r, _ := base(106).Check(context.Background()); !r.Deviated {
		t.Errorf("drift > tolerance should deviate: %s", r)
	}
	if r, _ := base(95).Check(context.Background()); r.Deviated {
		t.Errorf("negative drift == tolerance should be healthy: %s", r)
	}
	if r, _ := base(94).Check(context.Background()); !r.Deviated {
		t.Errorf("negative drift > tolerance should deviate: %s", r)
	}
}

func TestCalibrateBaseline(t *testing.T) {
	c := Checker{
		Linux: fakeCounter{name: "linux", n: 208},
		VPP:   fakeCounter{name: "vpp", n: 218},
	}
	gap, err := c.CalibrateBaseline(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gap != -10 {
		t.Fatalf("baseline = %d, want -10", gap)
	}
}

func TestCheckerLegErrorSurfaces(t *testing.T) {
	sentinel := errors.New("socket closed")
	c := Checker{
		BIRD:  fakeCounter{name: "bird", n: 1},
		Linux: fakeCounter{name: "linux", err: sentinel},
		VPP:   fakeCounter{name: "vpp", n: 1},
	}
	if _, err := c.Check(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapped sentinel", err)
	}
	if _, err := c.CalibrateBaseline(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("calibrate err = %v, want wrapped sentinel", err)
	}
}
