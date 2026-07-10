package vpp

import (
	"fmt"

	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/binapi/policer"
	"github.com/fivetime/sbw-limiter/internal/binapi/policer_types"
)

// Policers materializes pool policers (T-402, DESIGN.md §5.2): one VPP policer
// per pool per direction, named by PolicerName so the agent can attribute and
// reconcile them (§7). Large pools bind to a single worker for exact accounting
// (§5.2 / §1.1-7). Methods take a govppapi.Channel from Conn.Channel().
type Policers struct {
	ch govppapi.Channel
}

// NewPolicers wraps a channel for policer operations.
func NewPolicers(ch govppapi.Channel) *Policers { return &Policers{ch: ch} }

// toConfig translates a PolicerSpec into the VPP policer_config. V1 uses a
// single-rate two-color (1R2C) policer: cir + committed burst, transmit on
// conform, the spec's action on exceed; violate mirrors exceed (unused in 1R2C).
func toConfig(s model.PolicerSpec) (policer_types.PolicerConfig, error) {
	rate, err := rateType(s.RateType)
	if err != nil {
		return policer_types.PolicerConfig{}, err
	}
	conform, err := action(s.ConformAction)
	if err != nil {
		return policer_types.PolicerConfig{}, err
	}
	exceed, err := action(s.ExceedAction)
	if err != nil {
		return policer_types.PolicerConfig{}, err
	}
	// Burst: VPP's token bucket is byte-denominated, but in PPS mode it reads the
	// cb field as MILLISECONDS (xlate.c: cb_bytes = cb_ms × cir_kbps/8, with
	// cir_kbps = pps×256×8/1000). So for pps we convert the packet burst to ms;
	// the bucket then holds CommittedBurstPackets nominal-256B packets. For kbps
	// the burst is bytes, passed straight through (T-803).
	cb := s.CommittedBurstBytes
	if s.RateType == model.RatePps {
		cb = cbMsForPps(s.CommittedBurstPackets, s.CIR)
	}
	return policer_types.PolicerConfig{
		Cir:           uint32(s.CIR),
		Cb:            cb,
		Eir:           0,
		Eb:            0,
		RateType:      rate,
		RoundType:     policer_types.SSE2_QOS_ROUND_API_TO_CLOSEST,
		Type:          policer_types.SSE2_QOS_POLICER_TYPE_API_1R2C,
		ColorAware:    s.ColorAware,
		ConformAction: policer_types.Sse2QosAction{Type: conform},
		ExceedAction:  policer_types.Sse2QosAction{Type: exceed},
		ViolateAction: policer_types.Sse2QosAction{Type: exceed},
	}, nil
}

// cbMsForPps converts a burst expressed in packets into the milliseconds VPP
// expects for a pps policer: ms = round(burst_packets × 1000 / cir_pps). VPP then
// computes cb_bytes = ms × cir_kbps/8 = burst_packets × 256, i.e. the bucket holds
// that many nominal-256B packets. cirPps is the validated CIR (> 0); a zero guard
// avoids a divide-by-zero on a malformed spec.
func cbMsForPps(burstPackets, cirPps uint64) uint64 {
	if cirPps == 0 {
		return 0
	}
	return (burstPackets*1000 + cirPps/2) / cirPps
}

func rateType(r model.RateType) (policer_types.Sse2QosRateType, error) {
	switch r {
	case model.RateKbps:
		return policer_types.SSE2_QOS_RATE_API_KBPS, nil
	case model.RatePps:
		return policer_types.SSE2_QOS_RATE_API_PPS, nil
	default:
		return 0, fmt.Errorf("vpp: unknown rate type %v", r)
	}
}

func action(a model.PolicerAction) (policer_types.Sse2QosActionType, error) {
	switch a {
	case model.PolicerTransmit:
		return policer_types.SSE2_QOS_ACTION_API_TRANSMIT, nil
	case model.PolicerDrop:
		return policer_types.SSE2_QOS_ACTION_API_DROP, nil
	case model.PolicerMarkAndTransmit:
		return policer_types.SSE2_QOS_ACTION_API_MARK_AND_TRANSMIT, nil
	default:
		return 0, fmt.Errorf("vpp: unknown policer action %v", a)
	}
}

// Add creates the policer and returns its VPP index. The CIR upper bound is
// asserted because PolicerConfig.Cir is u32; classify hit_next_index (the
// pool-policer link) is u16, but that limit lives in the classify layer.
func (p *Policers) Add(spec model.PolicerSpec) (uint32, error) {
	if err := spec.Validate(); err != nil {
		return 0, err
	}
	cfg, err := toConfig(spec)
	if err != nil {
		return 0, err
	}
	req := &policer.PolicerAdd{Name: spec.Name, Infos: cfg}
	reply := &policer.PolicerAddReply{}
	if err := exec(p.ch, fmt.Sprintf("policer_add %q", spec.Name), req, reply); err != nil {
		return 0, err
	}

	if spec.BindWorker {
		if err := p.bind(reply.PolicerIndex, spec.WorkerIndex, true); err != nil {
			// The policer exists but is unbound; report so the caller can retry
			// or alert. Leave it in place (reconcile will re-attempt the bind).
			return reply.PolicerIndex, fmt.Errorf("vpp: policer %q added but worker bind failed: %w", spec.Name, err)
		}
	}
	return reply.PolicerIndex, nil
}

// Update reconfigures an existing policer's rate/burst/actions in place (by
// index). The worker bind is not part of policer_update; callers manage it via
// Bind when the spec's bind flag changes.
func (p *Policers) Update(index uint32, spec model.PolicerSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	cfg, err := toConfig(spec)
	if err != nil {
		return err
	}
	return exec(p.ch, fmt.Sprintf("policer_update %d", index),
		&policer.PolicerUpdate{PolicerIndex: index, Infos: cfg}, &policer.PolicerUpdateReply{})
}

// Delete removes a policer by index.
func (p *Policers) Delete(index uint32) error {
	return exec(p.ch, fmt.Sprintf("policer_del %d", index),
		&policer.PolicerDel{PolicerIndex: index}, &policer.PolicerDelReply{})
}

// Bind enables or disables pinning a policer to a single worker thread, which
// restores exact token-bucket accounting under multiple workers (§5.2).
func (p *Policers) Bind(index, worker uint32, enable bool) error {
	return p.bind(index, worker, enable)
}

func (p *Policers) bind(index, worker uint32, enable bool) error {
	return exec(p.ch, fmt.Sprintf("policer_bind_v2 %d", index),
		&policer.PolicerBindV2{PolicerIndex: index, WorkerIndex: worker, BindEnable: enable},
		&policer.PolicerBindV2Reply{})
}

// PolicerInfo is one enumerated policer (for reconciliation, T-501). policer
// dump does not return the index, so deletion is by name (DeleteByName).
type PolicerInfo struct {
	Name string
	CIR  uint32
	CB   uint64
}

// DeleteByName removes a policer by name via policer_add_del — policer dump
// does not expose the index, so reconciliation deletes orphans by name.
func (p *Policers) DeleteByName(name string) error {
	return exec(p.ch, fmt.Sprintf("policer_add_del(del) %q", name),
		&policer.PolicerAddDel{IsAdd: false, Name: name}, &policer.PolicerAddDelReply{})
}

// Dump enumerates the policers currently in VPP. The agent uses this to find
// orphans and missing pool policers during reconciliation; names encode the
// pool id (model.ParsePolicerName).
func (p *Policers) Dump() ([]PolicerInfo, error) {
	var out []PolicerInfo
	err := dumpAll(p.ch, "policer_dump", &policer.PolicerDump{}, func(d *policer.PolicerDetails) {
		out = append(out, PolicerInfo{Name: d.Name, CIR: d.Cir, CB: d.Cb})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
