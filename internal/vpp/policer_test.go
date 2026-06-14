package vpp

import (
	"testing"

	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/binapi/policer"
	"github.com/fivetime/sbw-limiter/internal/binapi/policer_types"
)

func ingressSpec() model.PolicerSpec {
	return model.PolicerSpec{
		Name:                model.PolicerName(200, model.DirectionIngress),
		PoolID:              200,
		Direction:           model.DirectionIngress,
		Type:                model.Policer1R2C,
		RateType:            model.RateKbps,
		CIR:                 1_000_000,
		CommittedBurstBytes: 12_500_000,
		ConformAction:       model.PolicerTransmit,
		ExceedAction:        model.PolicerDrop,
	}
}

func TestPolicerAddEncoding(t *testing.T) {
	ch := newFakeChannel(func(reply govppapi.Message) error {
		reply.(*policer.PolicerAddReply).PolicerIndex = 7
		return nil
	})
	p := NewPolicers(ch)

	idx, err := p.Add(ingressSpec())
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if idx != 7 {
		t.Errorf("index = %d, want 7", idx)
	}

	req, ok := ch.lastSent().(*policer.PolicerAdd)
	if !ok {
		t.Fatalf("last request type = %T, want *PolicerAdd", ch.lastSent())
	}
	if req.Name != "pool200_in" {
		t.Errorf("name = %q, want pool200_in", req.Name)
	}
	c := req.Infos
	if c.Cir != 1_000_000 || c.Cb != 12_500_000 {
		t.Errorf("cir/cb = %d/%d, want 1000000/12500000", c.Cir, c.Cb)
	}
	if c.RateType != policer_types.SSE2_QOS_RATE_API_KBPS {
		t.Errorf("rate_type = %v, want KBPS", c.RateType)
	}
	if c.Type != policer_types.SSE2_QOS_POLICER_TYPE_API_1R2C {
		t.Errorf("type = %v, want 1R2C", c.Type)
	}
	if c.ConformAction.Type != policer_types.SSE2_QOS_ACTION_API_TRANSMIT {
		t.Errorf("conform = %v, want TRANSMIT", c.ConformAction.Type)
	}
	if c.ExceedAction.Type != policer_types.SSE2_QOS_ACTION_API_DROP {
		t.Errorf("exceed = %v, want DROP", c.ExceedAction.Type)
	}
}

func TestPolicerAddPPS(t *testing.T) {
	spec := ingressSpec()
	spec.RateType = model.RatePps
	spec.CIR = 200_000
	spec.CommittedBurstBytes = 0       // pps burst is in packets, not bytes
	spec.CommittedBurstPackets = 1_000 // burst tolerance
	ch := newFakeChannel(nil)
	if _, err := NewPolicers(ch).Add(spec); err != nil {
		t.Fatalf("Add: %v", err)
	}
	req := ch.lastSent().(*policer.PolicerAdd)
	if req.Infos.RateType != policer_types.SSE2_QOS_RATE_API_PPS {
		t.Errorf("rate_type = %v, want PPS", req.Infos.RateType)
	}
	// Burst must be sent as MILLISECONDS for pps: ms = round(1000×1000/200000) = 5.
	// (VPP folds it back to cb_bytes = ms × cir_kbps/8 = 1000 nominal-256B packets.)
	if req.Infos.Cb != 5 {
		t.Errorf("pps cb = %d ms, want 5 (1000 packets / 200000 pps)", req.Infos.Cb)
	}
}

func TestCbMsForPps(t *testing.T) {
	// ms = round(burst_packets × 1000 / cir_pps).
	cases := []struct {
		packets, pps, wantMs uint64
	}{
		{1_000, 200_000, 5},   // 1000/200000 s = 5 ms
		{100, 5_000, 20},      // 100/5000 s = 20 ms
		{0, 5_000, 0},   // no burst
		{1_000, 0, 0},   // guard: cir 0 → 0 (malformed spec, no divide-by-zero)
		{5, 2_000, 3},   // 5000/2000 = 2.5 → rounds to 3 (round-half-up)
	}
	for _, c := range cases {
		if got := cbMsForPps(c.packets, c.pps); got != c.wantMs {
			t.Errorf("cbMsForPps(%d,%d) = %d, want %d", c.packets, c.pps, got, c.wantMs)
		}
	}
}

func TestPolicerAddWithWorkerBind(t *testing.T) {
	spec := ingressSpec()
	spec.BindWorker = true
	spec.WorkerIndex = 0
	ch := newFakeChannel(
		func(r govppapi.Message) error { r.(*policer.PolicerAddReply).PolicerIndex = 3; return nil },
		nil, // bind reply, retval 0
	)
	idx, err := NewPolicers(ch).Add(spec)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Second request must be the worker bind for the returned index.
	bind, ok := ch.sent[1].(*policer.PolicerBindV2)
	if !ok {
		t.Fatalf("second request = %T, want *PolicerBindV2", ch.sent[1])
	}
	if bind.PolicerIndex != idx || !bind.BindEnable {
		t.Errorf("bind = %+v, want index %d enable=true", bind, idx)
	}
}

func TestPolicerAddNonZeroRetvalFails(t *testing.T) {
	ch := newFakeChannel(func(r govppapi.Message) error {
		r.(*policer.PolicerAddReply).Retval = -7
		return nil
	})
	if _, err := NewPolicers(ch).Add(ingressSpec()); err == nil {
		t.Fatal("expected error for non-zero retval")
	}
}

func TestPolicerAddRejectsInvalidSpec(t *testing.T) {
	bad := ingressSpec()
	bad.CIR = 0 // invalid
	ch := newFakeChannel(nil)
	if _, err := NewPolicers(ch).Add(bad); err == nil {
		t.Fatal("expected validation error")
	}
	if len(ch.sent) != 0 {
		t.Error("must not send a request for an invalid spec")
	}
}

func TestPolicerUpdateAndDelete(t *testing.T) {
	ch := newFakeChannel(nil, nil)
	p := NewPolicers(ch)
	if err := p.Update(5, ingressSpec()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if u, ok := ch.sent[0].(*policer.PolicerUpdate); !ok || u.PolicerIndex != 5 {
		t.Errorf("update req = %+v", ch.sent[0])
	}
	if err := p.Delete(5); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if d, ok := ch.sent[1].(*policer.PolicerDel); !ok || d.PolicerIndex != 5 {
		t.Errorf("delete req = %+v", ch.sent[1])
	}
}

func TestPolicerBindEncoding(t *testing.T) {
	ch := newFakeChannel(nil)
	if err := NewPolicers(ch).Bind(9, 1, true); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	b, ok := ch.lastSent().(*policer.PolicerBindV2)
	if !ok || b.PolicerIndex != 9 || b.WorkerIndex != 1 || !b.BindEnable {
		t.Errorf("bind req = %+v", ch.lastSent())
	}
}
