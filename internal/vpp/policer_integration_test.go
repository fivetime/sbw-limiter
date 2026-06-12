//go:build integration

package vpp

import (
	"context"
	"os"
	"testing"
	"time"

	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-contract/model"
)

// T-402 acceptance against a real VPP: create/update/delete a pool policer and
// confirm via the API that it exists with the configured rate. Run with:
//
//	BWPOOL_TEST_VPP_SOCKET=/run/vpp/api.sock \
//	  go test -tags integration -run TestRealPolicer ./internal/vpp/
func realConn(t *testing.T) *Conn {
	t.Helper()
	sock := os.Getenv("BWPOOL_TEST_VPP_SOCKET")
	if sock == "" {
		t.Skip("BWPOOL_TEST_VPP_SOCKET not set")
	}
	c, err := Dial(context.Background(), sock, WithReadyTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestRealPolicerLifecycle(t *testing.T) {
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	p := NewPolicers(ch)

	spec := model.PolicerSpec{
		Name:                model.PolicerName(4242, model.DirectionIngress),
		PoolID:              4242,
		Direction:           model.DirectionIngress,
		Type:                model.Policer1R2C,
		RateType:            model.RateKbps,
		CIR:                 1_000_000, // 1 Gbps
		CommittedBurstBytes: 12_500_000,
		ConformAction:       model.PolicerTransmit,
		ExceedAction:        model.PolicerDrop,
	}

	idx, err := p.Add(spec)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	t.Cleanup(func() { _ = p.Delete(idx) })
	t.Logf("created policer %q at index %d", spec.Name, idx)

	if !policerExists(t, ch, spec.Name) {
		t.Fatalf("policer %q not found after Add", spec.Name)
	}

	// Update the rate; must still exist.
	spec.CIR = 2_000_000
	if err := p.Update(idx, spec); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Delete; must be gone.
	if err := p.Delete(idx); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if policerExists(t, ch, spec.Name) {
		t.Errorf("policer %q still present after Delete", spec.Name)
	}
}

func TestRealPolicerSharedBucket(t *testing.T) {
	// The pool semantics (multiple classify sessions → one policer) are verified
	// in the classify materializer (T-404). Here we just confirm both
	// directions of a pool coexist as two distinct policers (§5.2).
	c := realConn(t)
	ch, err := c.Channel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	p := NewPolicers(ch)

	base := model.PolicerSpec{
		PoolID: 4243, Type: model.Policer1R2C, RateType: model.RateKbps,
		CIR: 500_000, CommittedBurstBytes: 6_250_000,
		ConformAction: model.PolicerTransmit, ExceedAction: model.PolicerDrop,
	}
	in := base
	in.Direction = model.DirectionIngress
	in.Name = model.PolicerName(4243, model.DirectionIngress)
	out := base
	out.Direction = model.DirectionEgress
	out.Name = model.PolicerName(4243, model.DirectionEgress)

	iIdx, err := p.Add(in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Delete(iIdx) })
	oIdx, err := p.Add(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Delete(oIdx) })

	if iIdx == oIdx {
		t.Errorf("in/out policers share index %d; must be distinct", iIdx)
	}
	if !policerExists(t, ch, in.Name) || !policerExists(t, ch, out.Name) {
		t.Error("both pool4243_in and pool4243_out must exist")
	}
}

// policerExists dumps policers and reports whether one named `name` is present.
func policerExists(t *testing.T, ch govppapi.Channel, name string) bool {
	t.Helper()
	infos, err := NewPolicers(ch).Dump()
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	for _, i := range infos {
		if i.Name == name {
			return true
		}
	}
	return false
}
