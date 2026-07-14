package agent

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

var errDisc = errors.New("stats disconnected")

// livenessHarness drives VppLiveness.check() directly with an injectable
// heartbeat source and a fake clock (for the wedge grace).
func newLivenessHarness(wedgeGrace time.Duration) (*VppLiveness, *func() (uint64, error), *[]bool, *time.Time) {
	var read func() (uint64, error)
	var transitions []bool
	now := time.Unix(1_700_000_000, 0)
	p := &VppLiveness{
		readBeat:     func() (uint64, error) { return read() },
		disconnected: func(e error) bool { return errors.Is(e, errDisc) },
		wedgeGrace:   wedgeGrace,
		now:          func() time.Time { return now },
		log:          slog.New(slog.DiscardHandler),
	}
	p.onTransition = func(dead bool) { transitions = append(transitions, dead) }
	return p, &read, &transitions, &now
}

// TestVppLivenessAdvanceIsAlive: an advancing heartbeat is alive, with no
// spurious dead-transition at start.
func TestVppLivenessAdvanceIsAlive(t *testing.T) {
	p, read, trans, _ := newLivenessHarness(3 * time.Second)
	beat := uint64(10)
	*read = func() (uint64, error) { return beat, nil }
	for i := 0; i < 5; i++ {
		beat++
		p.check()
	}
	if p.Dead() {
		t.Fatal("advancing heartbeat must be alive")
	}
	if len(*trans) != 0 {
		t.Fatalf("no transitions expected for a steadily-alive VPP, got %v", *trans)
	}
}

// TestVppLivenessDisconnectIsDead: a disconnected stats socket = process death,
// one dead-transition; reconnect (advancing again) recovers with one more.
func TestVppLivenessDisconnectIsDead(t *testing.T) {
	p, read, trans, _ := newLivenessHarness(3 * time.Second)
	beat := uint64(5)
	*read = func() (uint64, error) { return beat, nil }
	beat++
	p.check() // alive baseline

	*read = func() (uint64, error) { return 0, errDisc }
	p.check()
	if !p.Dead() {
		t.Fatal("stats-disconnected must be judged dead (process gone)")
	}
	p.check() // still disconnected: no duplicate transition
	if got := *trans; len(got) != 1 || got[0] != true {
		t.Fatalf("want one dead-transition, got %v", got)
	}

	// Reconnect: a fresh process counts from a low value → alive again.
	beat = 1
	*read = func() (uint64, error) { return beat, nil }
	p.check()
	if p.Dead() {
		t.Fatal("reconnected advancing heartbeat must be alive")
	}
	if got := *trans; len(got) != 2 || got[1] != false {
		t.Fatalf("want dead,alive transitions, got %v", got)
	}
}

// TestVppLivenessWedge pins the §4.1-blind-spot catch: the process is alive
// (segment readable, no error) but the heartbeat STOPS advancing — past
// wedgeGrace that is a main-thread wedge. A single stalled read (< grace) must
// NOT flip dead.
func TestVppLivenessWedge(t *testing.T) {
	p, read, _, now := newLivenessHarness(3 * time.Second)
	beat := uint64(100)
	*read = func() (uint64, error) { return beat, nil }
	p.check() // alive, lastAdvance = now

	// Heartbeat frozen. Within grace: not yet wedged.
	*now = now.Add(2 * time.Second)
	p.check()
	if p.Dead() {
		t.Fatal("2s stall < 3s grace must not flip wedge")
	}
	// Past grace: wedge.
	*now = now.Add(2 * time.Second) // total 4s stalled
	p.check()
	if !p.Dead() {
		t.Fatal("heartbeat stalled past grace must be judged dead (wedge)")
	}
	// Heartbeat resumes → recover.
	beat++
	p.check()
	if p.Dead() {
		t.Fatal("resumed heartbeat must clear the wedge")
	}
}

// TestVppLivenessGaugeNotFoundStaysAlive: a non-disconnect read error (gauge not
// registered yet on a fresh VPP) leaves the verdict unchanged — VPP is alive.
func TestVppLivenessGaugeNotFoundStaysAlive(t *testing.T) {
	p, read, trans, _ := newLivenessHarness(3 * time.Second)
	*read = func() (uint64, error) { return 0, errors.New("vpp: gauge /probe/heartbeat not found") }
	for i := 0; i < 5; i++ {
		p.check()
	}
	if p.Dead() {
		t.Fatal("gauge-not-found (segment connected, VPP alive) must not be judged dead")
	}
	if len(*trans) != 0 {
		t.Fatalf("no transitions expected, got %v", *trans)
	}
}

// TestFaultSensorTypesVPPGoneFromStats pins the §6.44 integration: stats liveness
// judging VPP dead types ① vpp-gone even while conn.Healthy() still reads true
// (govpp stalled on its reply timeout, or a wedge a socket dial can't see).
func TestFaultSensorTypesVPPGoneFromStats(t *testing.T) {
	s := discardSensor(func() bool { return true }, upList("host-data0"), "host-data0")
	s.vppDead = func() bool { return true }
	if fk, reason := s.Fault(); fk != model.FaultVPPGone {
		t.Fatalf("vppDead with healthy conn must type vpp-gone, got %v (%s)", fk, reason)
	}
	s.vppDead = func() bool { return false }
	if fk, _ := s.Fault(); fk != model.FaultNone {
		t.Fatalf("alive VPP + healthy dump must be FaultNone, got %v", fk)
	}
}

// TestVppLivenessReadFailureCountsAsStall pins the §6.44-live fix: after a beat
// has been seen, a non-disconnect READ FAILURE (a SIGSTOP-frozen VPP whose
// inProgress makes DumpStats fail) counts toward the wedge grace exactly like a
// frozen same-value read — otherwise a read-failing wedge drags on (16s vs 3s).
func TestVppLivenessReadFailureCountsAsStall(t *testing.T) {
	p, read, _, now := newLivenessHarness(3 * time.Second)
	beat := uint64(50)
	*read = func() (uint64, error) { return beat, nil }
	p.check() // alive, lastAdvance = now

	// Read now FAILS (non-disconnect: frozen-VPP DumpStats error), not just frozen.
	readErr := errors.New("vpp: dump gauge /probe/heartbeat: access failed")
	*read = func() (uint64, error) { return 0, readErr }
	*now = now.Add(2 * time.Second)
	p.check()
	if p.Dead() {
		t.Fatal("2s of read failure < 3s grace must not flip wedge")
	}
	*now = now.Add(2 * time.Second) // 4s of continuous read failure
	p.check()
	if !p.Dead() {
		t.Fatal("read failure sustained past grace must be judged wedge (§6.44 16s fix)")
	}
}

// TestVppLivenessStartupReadFailureSafe: a read failure BEFORE any beat has been
// seen (fresh VPP without the gauge yet) must NOT be judged dead, however long —
// only an ever-alive VPP's stall counts.
func TestVppLivenessStartupReadFailureSafe(t *testing.T) {
	p, read, trans, now := newLivenessHarness(3 * time.Second)
	*read = func() (uint64, error) { return 0, errors.New("vpp: gauge not found") }
	for i := 0; i < 10; i++ {
		*now = now.Add(2 * time.Second)
		p.check()
	}
	if p.Dead() {
		t.Fatal("read failure with no beat ever seen must not be judged dead (startup safety)")
	}
	if len(*trans) != 0 {
		t.Fatalf("no transitions expected at startup, got %v", *trans)
	}
}

// TestVppLivenessStaleReconnectRecovers pins the §6.44 crashloop-recovery gap: a
// stats reader stuck on a stale segment after a rapid VPP restart reads a FROZEN
// heartbeat (falsely wedged) even though VPP is live and advancing. The
// stale-reconnect hook rebuilds the reader while dead; after the rebuild the
// fresh reader sees the advancing heartbeat and the edge recovers on its own —
// no pod restart needed.
func TestVppLivenessStaleReconnectRecovers(t *testing.T) {
	p, read, trans, now := newLivenessHarness(3 * time.Second)
	p.reconnectEvery = 8 * time.Second

	// A "stale reader" reads a frozen value; a rebuild swaps in a "fresh reader"
	// that reads the live advancing heartbeat.
	stale := true
	live := uint64(500)
	*read = func() (uint64, error) {
		if stale {
			return 100, nil // frozen (stale segment)
		}
		return live, nil // fresh segment, advancing
	}
	p.reconnect = func() { stale = false } // rebuild → swap to the fresh reader

	// Prime alive on the (still-live) stale value, then freeze.
	p.check() // beat=100, alive, lastAdvance=now

	// Stall past grace → wedge, and the reconnect fires (lastReconnect zero → due).
	*now = now.Add(4 * time.Second)
	p.check()
	if !p.Dead() {
		t.Fatal("frozen stale read past grace must be judged dead")
	}

	// Next poll uses the rebuilt (fresh) reader → advancing heartbeat → recover.
	live++
	*now = now.Add(1 * time.Second)
	p.check()
	if p.Dead() {
		t.Fatal("after stale-reconnect the fresh reader's advancing heartbeat must revive the edge")
	}
	// dead→...→alive transitions both fired.
	if got := *trans; len(got) < 2 || got[len(got)-1] != false {
		t.Fatalf("want a final alive transition, got %v", got)
	}
}

// §6.67 wall-①: a stalled heartbeat while materializing (busy) is a BUSY main
// thread, not a wedge — the verdict is held; lastAdvance keeps aging, so a stall
// that outlives the busy window is declared on the first ungated check.
func TestVppLivenessBusyHoldsWedge(t *testing.T) {
	p, read, transitions, now := newLivenessHarness(3 * time.Second)
	busy := false
	p.BindBusy(func() bool { return busy })

	beat := uint64(7)
	*read = func() (uint64, error) { return beat, nil }
	p.check() // first read → alive baseline

	// Frozen heartbeat under busy for far past the grace → still alive.
	busy = true
	for i := 0; i < 10; i++ {
		*now = now.Add(2 * time.Second)
		p.check()
	}
	if p.Dead() {
		t.Fatal("stalled heartbeat while busy must not declare a wedge")
	}
	// Busy ends with the heartbeat STILL frozen (grace long elapsed) → immediate wedge.
	busy = false
	p.check()
	if !p.Dead() {
		t.Fatal("stall persisting past the busy window must declare the wedge at once")
	}
	if len(*transitions) == 0 || !(*transitions)[len(*transitions)-1] {
		t.Fatal("expected a dead transition")
	}
	// Heartbeat resumes → recovers.
	beat++
	p.check()
	if p.Dead() {
		t.Fatal("advancing heartbeat must recover")
	}
}
