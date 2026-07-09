package agent

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

type fakeSink struct {
	mu   sync.Mutex
	got  []model.EdgeReport
	err  error
	gotC chan struct{}
}

func newFakeSink() *fakeSink { return &fakeSink{gotC: make(chan struct{}, 64)} }

func (s *fakeSink) SendReport(_ context.Context, r model.EdgeReport) error {
	s.mu.Lock()
	if s.err == nil {
		s.got = append(s.got, r)
	}
	err := s.err
	s.mu.Unlock()
	select {
	case s.gotC <- struct{}{}:
	default:
	}
	return err
}

func (s *fakeSink) reports() []model.EdgeReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.EdgeReport(nil), s.got...)
}

func TestReporterBuildBeforeAnyHealthIsNotReady(t *testing.T) {
	hc := NewHealthChecker("edge-2", fakeLive{healthy: true})
	r := NewReporter("edge-2", hc)
	if _, ok := r.Build(); ok {
		t.Error("Build must be not-ready before any health observation")
	}
}

func TestReporterBuildAssemblesValidReport(t *testing.T) {
	hc := NewHealthChecker("edge-2", fakeLive{healthy: true}, WithClock(func() int64 { return 100 }))
	// Observe a clean pass at generation 7.
	hc.Observe(model.EdgeDesiredState{Generation: 7, Policers: make([]model.PolicerSpec, 2)}, Result{}, nil)

	cap := model.CapacityReport{NICCapacityBps: 100e9, SoldBandwidthBps: 40e9, ObservedBps: 12e9}
	r := NewReporter("edge-2", hc,
		WithCapacity(func() model.CapacityReport { return cap }),
		WithMetering(func() []model.PoolMetering {
			return []model.PoolMetering{{PoolID: 200, Direction: model.DirectionEgress, ConformBytes: 99}}
		}),
		WithReporterClock(func() int64 { return 555 }))

	rep, ok := r.Build()
	if !ok {
		t.Fatal("Build should be ready after a health observation")
	}
	if rep.SchemaVersion != model.SchemaVersion || rep.EdgeID != "edge-2" {
		t.Errorf("envelope wrong: %+v", rep)
	}
	if rep.Generation != 7 {
		t.Errorf("Generation should echo health GenerationApplied (7), got %d", rep.Generation)
	}
	if rep.ReportedAtUnixMs != 555 {
		t.Errorf("ReportedAtUnixMs = %d, want 555", rep.ReportedAtUnixMs)
	}
	if rep.Health.State != model.HealthHealthy || !rep.Health.VPPConnected {
		t.Errorf("health section wrong: %+v", rep.Health)
	}
	if rep.Capacity != cap {
		t.Errorf("capacity = %+v, want %+v", rep.Capacity, cap)
	}
	if len(rep.Metering) != 1 || rep.Metering[0].ConformBytes != 99 {
		t.Errorf("metering wrong: %+v", rep.Metering)
	}
	// The assembled report must satisfy the frozen contract (S-04).
	if err := rep.Validate(); err != nil {
		t.Errorf("assembled report fails contract validation: %v", err)
	}
}

func TestReporterBuildWithoutOptionalSources(t *testing.T) {
	hc := NewHealthChecker("e", fakeLive{healthy: false})
	hc.Observe(model.EdgeDesiredState{Generation: 1}, Result{}, nil) // vpp down
	r := NewReporter("e", hc)                                        // no capacity/metering
	rep, ok := r.Build()
	if !ok {
		t.Fatal("Build ready")
	}
	if rep.Capacity != (model.CapacityReport{}) || rep.Metering != nil {
		t.Errorf("optional sources should be zero/nil: %+v", rep)
	}
	if !rep.Health.SoftDead() {
		t.Errorf("vpp-down health should be soft-dead: %+v", rep.Health)
	}
	if err := rep.Validate(); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestReporterRunSendsPeriodicallyAndStops(t *testing.T) {
	hc := NewHealthChecker("edge-2", fakeLive{healthy: true})
	hc.Observe(model.EdgeDesiredState{Generation: 3}, Result{}, nil)
	r := NewReporter("edge-2", hc)
	sink := newFakeSink()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Millisecond, sink); close(done) }()

	// Wait for at least two reports.
	for i := 0; i < 2; i++ {
		select {
		case <-sink.gotC:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for reports")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on ctx cancel")
	}
	if len(sink.reports()) == 0 {
		t.Error("expected reports sent")
	}
}

func TestReporterRunSinkErrorIsNotFatal(t *testing.T) {
	hc := NewHealthChecker("e", fakeLive{healthy: true})
	hc.Observe(model.EdgeDesiredState{Generation: 1}, Result{}, nil)
	r := NewReporter("e", hc)
	sink := newFakeSink()
	sink.err = errors.New("transport down")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, time.Millisecond, sink)

	// The loop must keep ticking despite send errors.
	for i := 0; i < 3; i++ {
		select {
		case <-sink.gotC:
		case <-time.After(2 * time.Second):
			t.Fatal("loop stalled after sink error")
		}
	}
}

// TestReporterWakeSendsImmediately pins the event-driven report path (§4.2.4
// ★实测更新): a Wake produces a report at once, without waiting out the periodic
// interval — this is what removes the 15s report-sampling term from
// permanent-VPP-death failover.
func TestReporterWakeSendsImmediately(t *testing.T) {
	hc := NewHealthChecker("edge-w", fakeLive{healthy: true})
	hc.Observe(model.EdgeDesiredState{Generation: 1}, Result{}, nil)
	r := NewReporter("edge-w", hc)
	sink := newFakeSink()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, time.Hour, sink) // interval effectively never fires

	r.Wake()
	select {
	case <-sink.gotC:
	case <-time.After(2 * time.Second):
		t.Fatal("Wake did not produce an immediate report (still waiting on the 1h ticker)")
	}
}

// TestReporterWakeStormGuard pins the wakeMinInterval rate guard: a burst of
// wakes right after a send is dropped (the ticker backstops), so a flapping
// health signal cannot turn into a report storm. Wake itself never blocks.
func TestReporterWakeStormGuard(t *testing.T) {
	hc := NewHealthChecker("edge-s", fakeLive{healthy: true})
	hc.Observe(model.EdgeDesiredState{Generation: 1}, Result{}, nil)
	r := NewReporter("edge-s", hc)
	sink := newFakeSink()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, time.Hour, sink)

	r.Wake() // first: sends
	select {
	case <-sink.gotC:
	case <-time.After(2 * time.Second):
		t.Fatal("first wake did not send")
	}
	// Burst inside wakeMinInterval: coalesced + DEFERRED (not sent now, not lost).
	// Wake must not block.
	for i := 0; i < 50; i++ {
		r.Wake()
	}
	select {
	case <-sink.gotC:
		t.Fatal("wake inside wakeMinInterval produced an immediate report; storm guard broken")
	case <-time.After(200 * time.Millisecond):
	}
	if n := len(sink.reports()); n != 1 {
		t.Fatalf("got %d reports during the guard window, want exactly 1", n)
	}
	// The guarded burst is deferred, not dropped: exactly one more send lands once
	// wakeMinInterval elapses (a permanent-death wake must never be silently lost
	// to the 15s ticker latency).
	select {
	case <-sink.gotC:
	case <-time.After(3 * wakeMinInterval):
		t.Fatal("deferred wake never fired; guarded wake was dropped, not deferred")
	}
	time.Sleep(50 * time.Millisecond) // absorb any (incorrect) extra sends
	if n := len(sink.reports()); n != 2 {
		t.Fatalf("got %d reports total, want exactly 2 (initial + one deferred)", n)
	}
}

// TestBuildSkipsObservedOnVPPGone pins the §6.44 fix: when the fault sensor types
// vpp-gone, Build must NOT call the observed-members source — that source is a VPP
// binary-API dump that would block on the dead API until the reply timeout,
// delaying the vpp-gone report itself. Other faults (VPP alive) still dump.
func TestBuildSkipsObservedOnVPPGone(t *testing.T) {
	hc := NewHealthChecker("edge-o", fakeLive{healthy: true})
	hc.Observe(model.EdgeDesiredState{Generation: 1}, Result{}, nil)

	observeCalls := 0
	fault := model.FaultVPPGone
	r := NewReporter("edge-o", hc,
		WithFault(faultFunc(func() (model.FaultKind, string) { return fault, "vpp gone" })),
		WithObservedMembers(func() []netip.Prefix { observeCalls++; return nil }),
	)

	if _, ok := r.Build(); !ok {
		t.Fatal("build should succeed")
	}
	if observeCalls != 0 {
		t.Fatalf("observed dump must be skipped on vpp-gone, called %d times", observeCalls)
	}
	// A non-vpp-gone fault (VPP alive) still dumps.
	fault = model.FaultLinkDown
	if _, ok := r.Build(); !ok {
		t.Fatal("build should succeed")
	}
	if observeCalls != 1 {
		t.Fatalf("observed dump must run for a VPP-alive fault, called %d times", observeCalls)
	}
}

type faultFunc func() (model.FaultKind, string)

func (f faultFunc) Fault() (model.FaultKind, string) { return f() }
