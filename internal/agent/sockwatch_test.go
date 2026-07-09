package agent

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// harness: drive check() directly with an injectable dialer.
func newTestWatcher(k int) (*SocketWatcher, *bool, *[]bool) {
	fail := false
	var transitions []bool
	w := &SocketWatcher{
		dial: func() error {
			if fail {
				return errors.New("connect: no such file or directory")
			}
			return nil
		},
		k:   k,
		log: slog.New(slog.DiscardHandler),
	}
	w.onTransition = func(dead bool) { transitions = append(transitions, dead) }
	return w, &fail, &transitions
}

// TestSocketWatcherKConsecutive pins the §6.44 debounce: a single dial failure
// (a ~1s container self-heal) never flips Dead; K consecutive do, exactly one
// transition fires, and recovery flips back with one more.
func TestSocketWatcherKConsecutive(t *testing.T) {
	w, fail, trans := newTestWatcher(2)

	w.check() // healthy baseline
	if w.Dead() {
		t.Fatal("healthy dial must not be dead")
	}

	// One failure: a fast self-heal window — NOT dead (flap-safety).
	*fail = true
	w.check()
	if w.Dead() {
		t.Fatal("1 failure < K=2 must not flip dead (would re-introduce the restart flap)")
	}
	*fail = false
	w.check() // recovered; counter resets
	if w.Dead() || len(*trans) != 0 {
		t.Fatalf("clean recovery must stay alive with no transitions, got %v", *trans)
	}

	// K consecutive failures: dead, ONE transition.
	*fail = true
	w.check()
	w.check()
	if !w.Dead() {
		t.Fatal("K=2 consecutive failures must flip dead")
	}
	w.check() // still failing: no duplicate transition
	if got := *trans; len(got) != 1 || got[0] != true {
		t.Fatalf("want exactly one dead-transition, got %v", got)
	}

	// Recovery: alive again, one more transition.
	*fail = false
	w.check()
	if w.Dead() {
		t.Fatal("successful dial must clear dead")
	}
	if got := *trans; len(got) != 2 || got[1] != false {
		t.Fatalf("want dead,alive transitions, got %v", got)
	}
}

// TestFaultSensorTypesVPPGoneFromSocketWatcher pins the §6.44 integration: the
// api socket being un-dialable types ① vpp-gone EVEN WHILE conn.Healthy() still
// reads true (govpp stalled on its 30s reply timeout) — the exact blind spot
// that put permanent-death failover at ~44s in the drill.
func TestFaultSensorTypesVPPGoneFromSocketWatcher(t *testing.T) {
	s := discardSensor(func() bool { return true }, upList("host-data0"), "host-data0")
	s.apiDead = func() bool { return true }
	fk, reason := s.Fault()
	if fk != model.FaultVPPGone {
		t.Fatalf("apiDead with healthy conn must type vpp-gone, got %v (%s)", fk, reason)
	}
	// And with the socket dialable, the healthy dump path stands (FaultNone).
	s.apiDead = func() bool { return false }
	if fk, _ := s.Fault(); fk != model.FaultNone {
		t.Fatalf("dialable socket + healthy dump must be FaultNone, got %v", fk)
	}
}
