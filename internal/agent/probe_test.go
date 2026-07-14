package agent

import (
	"errors"
	"testing"
)

func TestForwardingProbeConsecutiveFails(t *testing.T) {
	var recv int
	var perr error
	p := NewForwardingProbe(func() (int, error) { return recv, perr }, 0, 3, nil)

	// Healthy rounds: never broken.
	recv = 3
	for i := 0; i < 5; i++ {
		p.round()
	}
	if p.Broken() {
		t.Fatal("healthy rounds must not break")
	}
	// Two fails — still under K=3.
	recv = 0
	p.round()
	p.round()
	if p.Broken() {
		t.Fatal("2 fails < K=3 must not break yet")
	}
	// Third consecutive fail → broken.
	p.round()
	if !p.Broken() {
		t.Fatal("3 consecutive fails must break")
	}
	// A single good round clears it.
	recv = 1
	p.round()
	if p.Broken() {
		t.Fatal("a reply must clear broken")
	}
}

// A transport error is neither a failure nor a recovery — the counter is untouched, so a
// wedged main thread never false-positives forwarding-broken.
func TestForwardingProbeErrorDoesNotCount(t *testing.T) {
	var recv int
	var perr error
	p := NewForwardingProbe(func() (int, error) { return recv, perr }, 0, 2, nil)
	// Arm the probe first: it only counts failures after being healthy once.
	recv = 1
	p.round()
	recv, perr = 0, nil
	p.round() // 1 real fail
	perr = errors.New("channel busy")
	for i := 0; i < 5; i++ {
		p.round() // errors — must not advance toward broken
	}
	if p.Broken() {
		t.Fatal("probe errors must not accumulate toward broken")
	}
	// One more real fail reaches K=2.
	perr = nil
	p.round()
	if !p.Broken() {
		t.Fatal("real fails on either side of errors must still reach K")
	}
}

// Until the target has been reachable once, zero-reply rounds are treated as
// initial convergence (not a black-hole), so a fresh probe never trips a
// failover during the startup window before routes/BGP come up.
func TestForwardingProbeArmsOnlyAfterFirstHealthy(t *testing.T) {
	var recv int
	p := NewForwardingProbe(func() (int, error) { return recv, nil }, 0, 2, nil)

	// Never healthy yet: any number of zero replies must not break.
	recv = 0
	for i := 0; i < 10; i++ {
		p.round()
	}
	if p.Broken() {
		t.Fatal("must not break before ever being healthy (startup convergence)")
	}
	// Becomes healthy → armed; a later regression breaks after K.
	recv = 3
	p.round()
	recv = 0
	p.round()
	p.round()
	if !p.Broken() {
		t.Fatal("after being healthy, K consecutive fails must break")
	}
}

// TestForwardingProbeDisarmsOnVPPRestart pins the §6.44 fix: a VPP restart
// (data-plane generation bump) under a still-ARMED probe must DISARM it — the
// post-restart FIB-rebuild window (bird/vppfib re-feed) legitimately reads
// unreachable, and an armed probe counting those rounds declares a spurious
// black-hole → trusted+immediate failover. Symmetric to the boot grace: re-arms
// on first reachability, and a real post-rebuild regression still breaks.
func TestForwardingProbeDisarmsOnVPPRestart(t *testing.T) {
	var recv int
	gen := uint64(1)
	p := NewForwardingProbe(func() (int, error) { return recv, nil }, 0, 3, nil)
	p.BindDataplaneGeneration(func() uint64 { return gen })

	// Arm: healthy once.
	recv = 3
	p.round()

	// VPP restarts; the FIB-rebuild window reads unreachable for many rounds.
	gen = 2
	recv = 0
	for i := 0; i < 10; i++ {
		p.round()
	}
	if p.Broken() {
		t.Fatal("rebuild window after VPP restart must not read as a black-hole (§6.44 regression)")
	}

	// Rebuild completes → first reachability re-arms.
	recv = 3
	p.round()
	// A REAL regression after re-arm still breaks in K rounds.
	recv = 0
	p.round()
	p.round()
	p.round()
	if !p.Broken() {
		t.Fatal("a real post-rebuild regression must still break")
	}
}

// §6.67 wall-①: while the edge is materializing (busy), a zero-reach round is
// INCONCLUSIVE — the counter holds, no black-hole is declared no matter how long the
// busy window lasts; a real regression is declared once busy clears.
func TestForwardingProbeBusyGatesZeroReach(t *testing.T) {
	var recv int
	busy := false
	p := NewForwardingProbe(func() (int, error) { return recv, nil }, 0, 3, nil)
	p.BindBusy(func() bool { return busy })

	recv = 3
	p.round() // arm (everHealthy)

	// Busy + zero-reach ×10 → counter held, never broken (was the 54-72s false window).
	busy = true
	recv = 0
	for i := 0; i < 10; i++ {
		p.round()
	}
	if p.Broken() {
		t.Fatal("zero-reach while busy must be inconclusive, not a black-hole")
	}
	// Busy ends, path genuinely still dead → K rounds then broken (delayed, not lost).
	busy = false
	p.round()
	p.round()
	if p.Broken() {
		t.Fatal("2 fails < K=3 after busy cleared must not break yet")
	}
	p.round()
	if !p.Broken() {
		t.Fatal("real black-hole after busy window must be declared")
	}
}
