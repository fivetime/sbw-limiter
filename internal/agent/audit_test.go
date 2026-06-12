package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fivetime/sbw-limiter/internal/accounting"
	"github.com/fivetime/sbw-limiter/internal/bird"
)

type fakeCounter struct {
	name string
	n    uint64
}

func (f fakeCounter) Name() string                          { return f.name }
func (f fakeCounter) Count(context.Context) (uint64, error) { return f.n, nil }

type fakeReExporter struct {
	calls  int
	result bird.ConfigureResult
	err    error
}

func (f *fakeReExporter) Configure() (bird.ConfigureResult, error) {
	f.calls++
	return f.result, f.err
}

func checker(linux, vpp uint64, tol uint64) accounting.Checker {
	return accounting.Checker{
		BIRD:      fakeCounter{name: "bird", n: linux},
		Linux:     fakeCounter{name: "linux", n: linux},
		VPP:       fakeCounter{name: "vpp", n: vpp},
		Tolerance: tol,
	}
}

func TestAuditCleanDoesNotReExport(t *testing.T) {
	re := &fakeReExporter{result: bird.ConfigureResult{Code: bird.CodeReconfigured}}
	a := NewRouteAudit(checker(200, 198, 8), re, time.Minute, nil)
	res, err := a.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Triggered || re.calls != 0 {
		t.Fatalf("clean audit should not re-export (triggered=%v calls=%d)", res.Triggered, re.calls)
	}
}

func TestAuditDeviationTriggersReExport(t *testing.T) {
	re := &fakeReExporter{result: bird.ConfigureResult{Code: bird.CodeReconfigured, Message: "reconfigured"}}
	a := NewRouteAudit(checker(200, 100, 8), re, time.Minute, nil)
	res, err := a.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Triggered || re.calls != 1 {
		t.Fatalf("deviation should re-export once (triggered=%v calls=%d)", res.Triggered, re.calls)
	}
	if res.ReExportMsg != "reconfigured" {
		t.Errorf("re-export msg = %q", res.ReExportMsg)
	}
}

func TestAuditCooldownSuppressesRepeatReExport(t *testing.T) {
	re := &fakeReExporter{result: bird.ConfigureResult{Code: bird.CodeReconfigured}}
	a := NewRouteAudit(checker(200, 100, 8), re, time.Minute, nil)

	clock := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time { return clock }

	// First deviation triggers.
	if res, _ := a.Once(context.Background()); !res.Triggered {
		t.Fatal("first deviation should trigger")
	}
	// 30s later, still deviating, within the 60s cooldown → suppressed.
	clock = clock.Add(30 * time.Second)
	res, _ := a.Once(context.Background())
	if res.Triggered || !res.Suppressed {
		t.Fatalf("within cooldown should suppress (triggered=%v suppressed=%v)", res.Triggered, res.Suppressed)
	}
	if re.calls != 1 {
		t.Fatalf("re-export calls = %d, want 1 (cooldown held)", re.calls)
	}
	// Past the cooldown, a persistent deviation re-exports again.
	clock = clock.Add(31 * time.Second)
	if res, _ := a.Once(context.Background()); !res.Triggered {
		t.Fatal("past cooldown should re-export again")
	}
	if re.calls != 2 {
		t.Fatalf("re-export calls = %d, want 2", re.calls)
	}
}

func TestAuditReExportErrorSurfaces(t *testing.T) {
	sentinel := errors.New("control socket gone")
	re := &fakeReExporter{err: sentinel}
	a := NewRouteAudit(checker(200, 100, 8), re, time.Minute, nil)
	_, err := a.Once(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
}

func TestAuditDefaultCooldown(t *testing.T) {
	a := NewRouteAudit(checker(1, 1, 0), &fakeReExporter{}, 0, nil)
	if a.cooldown != 5*time.Minute {
		t.Fatalf("default cooldown = %v, want 5m", a.cooldown)
	}
}
