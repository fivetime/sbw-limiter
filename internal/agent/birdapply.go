// BIRD materialization (B-03 apply 接线, limiter §3/§4.4): turn the desired
// state's CONTROL-PLANE half — member anchors (ingress homing /32 carriers) and
// egress-homing FlowSpec — into the two agent-managed BIRD include files, each
// applied with the atomic-write + configure-check + configure + rollback
// discipline (anchors.Applier). The VPP half (policers/classify) is the
// Reconciler's job; together they materialize the whole EdgeDesiredState.
package agent

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/anchors"
	"github.com/fivetime/sbw-limiter/internal/flowspec"
)

// BirdApplier drives the two BIRD includes from the desired state. Same loop
// shape as the Reconciler: timer + coalescing wake (a fresh push applies in
// milliseconds, T-705), pulling the latest state from a DesiredProvider.
type BirdApplier struct {
	anchors *anchors.Applier // the anchors include (anchors4/anchors6 blocks)
	flow    *anchors.Applier // the egress FlowSpec include (flowspec4/flowspec6 blocks)
	log     *slog.Logger
	wake    chan struct{}
}

// NewBirdApplier wires the two appliers (built by the caller over one
// bird.Client and the two include paths from config).
func NewBirdApplier(anchorsApplier, flowApplier *anchors.Applier, log *slog.Logger) *BirdApplier {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &BirdApplier{
		anchors: anchorsApplier, flow: flowApplier, log: log,
		wake: make(chan struct{}, 1),
	}
}

// Wake requests an immediate apply pass (coalescing, non-blocking).
func (b *BirdApplier) Wake() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// EnsureFiles initializes both include files if absent (empty renders), so the
// main bird.conf's `include` lines are satisfiable before the first push.
func (b *BirdApplier) EnsureFiles() error {
	if err := b.anchors.EnsureFile(); err != nil {
		return err
	}
	empty, err := flowspec.Render(nil, netip.Addr{}, netip.Addr{})
	if err != nil {
		return err
	}
	return b.flow.EnsureFileBytes(empty)
}

// ApplyOnce materializes one desired state into BIRD: anchors include first
// (ingress carriers), then the FlowSpec include (egress homing). Both appliers
// skip no-op content, so steady-state passes don't touch BIRD.
func (b *BirdApplier) ApplyOnce(st model.EdgeDesiredState) error {
	return b.applyOnce(st)
}

func (b *BirdApplier) applyOnce(st model.EdgeDesiredState) error {
	if _, err := b.anchors.Apply(st.Anchors); err != nil {
		return err
	}
	flowContent, err := flowspec.Render(st.FlowRedirects, st.RedirectNextHop, st.RedirectNextHopV6)
	if err != nil {
		return err
	}
	if _, err := b.flow.ApplyBytes(flowContent); err != nil {
		return err
	}
	return nil
}

// Run applies on a timer and on Wake until ctx is cancelled, pulling the
// current state from provider (ok=false skips — fail-static, §6.4). Blocks;
// run in a goroutine.
func (b *BirdApplier) Run(ctx context.Context, interval time.Duration, provider DesiredProvider) {
	t := time.NewTicker(interval)
	defer t.Stop()
	pass := func() {
		st, ok := provider()
		if !ok {
			return // cold start: nothing authoritative to apply (fail-static)
		}
		if err := b.ApplyOnce(st); err != nil {
			b.log.Error("bird apply pass failed", "err", err)
		}
	}
	pass()
	for {
		select {
		case <-ctx.Done():
			b.log.Info("bird apply loop stopped")
			return
		case <-t.C:
			pass()
		case <-b.wake:
			pass()
		}
	}
}
