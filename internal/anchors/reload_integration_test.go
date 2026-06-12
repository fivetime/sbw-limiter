//go:build integration

package anchors

import (
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// T-303 acceptance against a real BIRD daemon: the full Applier loop —
// atomic write, configure check, reload, no-op skip, confirm window.
// Same environment as the renderer integration tests.

func TestApplierAgainstRealBIRD(t *testing.T) {
	c, path := setup(t)
	a := NewApplier(path, c)
	if err := a.EnsureFile(); err != nil {
		t.Fatalf("EnsureFile: %v", err)
	}

	set := []model.Anchor{
		{Prefix: netip.MustParsePrefix("203.0.113.10/32")},
		{Prefix: netip.MustParsePrefix("198.51.100.66/32"),
			Communities: []model.Community{{ASN: 65001, Value: 666}}},
	}
	res, err := a.Apply(set)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Skipped {
		t.Fatal("first apply must reload")
	}
	if n := routeCount(t, c); n != 2 {
		t.Fatalf("routes = %d, want 2", n)
	}

	// Identical set → skipped without touching BIRD.
	res, err = a.Apply(set)
	if err != nil || !res.Skipped {
		t.Fatalf("no-op apply: res=%+v err=%v", res, err)
	}

	// Shrink to empty and verify.
	res, err = a.Apply(nil)
	if err != nil || res.Skipped {
		t.Fatalf("empty apply: res=%+v err=%v", res, err)
	}
	if n := routeCount(t, c); n != 0 {
		t.Fatalf("routes after empty = %d, want 0", n)
	}
}

func TestApplierConfirmWindowAgainstRealBIRD(t *testing.T) {
	c, path := setup(t)
	a := NewApplier(path, c, WithConfirmTimeout(5))
	if err := a.EnsureFile(); err != nil {
		t.Fatalf("EnsureFile: %v", err)
	}

	set := []model.Anchor{{Prefix: netip.MustParsePrefix("203.0.113.77/32")}}
	res, err := a.Apply(set)
	if err != nil {
		t.Fatalf("Apply with confirm window: %v", err)
	}
	if !res.Configure.Accepted() {
		t.Fatalf("configure not accepted: %+v", res.Configure)
	}
	if n := routeCount(t, c); n != 1 {
		t.Fatalf("routes = %d, want 1", n)
	}
	// The route must survive past the 5s undo window because we confirmed.
	// (No sleep needed: a confirmed config has no pending undo; verify status.)
	reply, err := c.Do("configure status")
	if err != nil {
		t.Fatalf("configure status: %v", err)
	}
	for _, l := range reply.Lines {
		if l.Code == 22 { // "Configuration unconfirmed, undo in N s"
			t.Errorf("undo still pending after confirm: %s", reply.Text())
		}
	}
}
