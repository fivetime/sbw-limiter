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
