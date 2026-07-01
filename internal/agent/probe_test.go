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
