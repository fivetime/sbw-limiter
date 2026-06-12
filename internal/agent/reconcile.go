// Package agent's reconciler materializes the controller's EdgeDesiredState into
// VPP and prunes orphans (T-501, DESIGN.md §7). Each pass enumerates actual VPP
// state, installs what's missing, deletes what's no longer desired, and updates
// what drifted. It runs on a timer (§7: 60s) and is the convergence engine: the
// desired state is the only input, and VPP is driven to match it.
//
// The diff logic per resource is pure (takes small interfaces over the vpp
// materializers) so it is unit-testable without VPP; Reconcile wires the real
// materializers over a govpp channel.
package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// policerReconciler is the subset of *vpp.Policers the reconciler uses.
type policerReconciler interface {
	Dump() ([]vpp.PolicerInfo, error)
	Add(model.PolicerSpec) (uint32, error)
	Update(index uint32, spec model.PolicerSpec) error
	DeleteByName(name string) error
}

// classifyReconciler is the subset of *vpp.Classify the reconciler uses.
type classifyReconciler interface {
	FindTablesByMask() (map[model.MaskKind]uint32, error)
	AddTable(vpp.TableSpec) (uint32, error)
	DumpSessions(table uint32) ([]vpp.SessionInfo, error)
	AddSession(table uint32, mask model.MaskKind, prefix netip.Prefix, hitNext uint32) error
	DelSessionByKey(table uint32, mask model.MaskKind, key []byte) error
}

// Result counts what a reconcile pass changed, for logging and metrics.
type Result struct {
	PolicersAdded   int
	PolicersUpdated int
	PolicersDeleted int

	SessionsAdded   int
	SessionsDeleted int
	SessionsMoved   int // re-pointed to a different pool policer
}

// Empty reports whether the pass made no changes (steady state).
func (r Result) Empty() bool {
	return r.PolicersAdded == 0 && r.PolicersUpdated == 0 && r.PolicersDeleted == 0 &&
		r.SessionsAdded == 0 && r.SessionsDeleted == 0 && r.SessionsMoved == 0
}

// Total is the number of data-plane operations this pass applied; 0 means the
// data plane already matched desired. A non-zero total on a steady desired state
// is a drift signal — a soft-death symptom (rules lost/destroyed) that was
// self-healed locally this cycle (B-05, limiter §5.6).
func (r Result) Total() int {
	return r.PolicersAdded + r.PolicersUpdated + r.PolicersDeleted +
		r.SessionsAdded + r.SessionsDeleted + r.SessionsMoved
}

// Reconciler converges VPP to the desired state. It tracks policer name→index
// in memory (VPP's policer dump omits the index), rebuilt as it adds them.
type Reconciler struct {
	conn *vpp.Conn
	log  *slog.Logger

	polIdx map[string]uint32 // policer name → VPP index, learned on Add

	// observers are notified after each reconcile pass (B-05): the reconcile is
	// itself the dataplane-penetrating probe, so the soft-death health report is
	// driven off its result rather than a second VPP scan.
	observers []func(model.EdgeDesiredState, Result, error)
}

// AddObserver registers a callback invoked after each reconcile pass (success or
// failure) with the desired state, the result, and any error. Used to drive the
// soft-death health report (B-05, limiter §5.6) off the reconcile loop.
func (r *Reconciler) AddObserver(fn func(model.EdgeDesiredState, Result, error)) {
	r.observers = append(r.observers, fn)
}

func (r *Reconciler) notify(desired model.EdgeDesiredState, res Result, err error) {
	for _, fn := range r.observers {
		fn(desired, res, err)
	}
}

// New creates a reconciler over a VPP connection.
func New(conn *vpp.Conn, log *slog.Logger) *Reconciler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Reconciler{conn: conn, log: log, polIdx: map[string]uint32{}}
}

// Reset drops in-memory caches that a VPP restart invalidates. The policer
// name→index map is the only such state: after a restart VPP reassigns indexes
// from scratch, so a cached index would point at the wrong (or no) policer. The
// next reconcile then re-adds every policer by name (the post-restart dump is
// empty) and relearns the indexes. Call this before reinstalling after a
// reconnect (T-503). Run from the single reconcile goroutine, like Reconcile.
func (r *Reconciler) Reset() {
	r.polIdx = map[string]uint32{}
}

// Reconcile drives VPP to match desired in one pass. It opens a fresh channel,
// reconciles each resource, and reports what changed.
func (r *Reconciler) Reconcile(desired model.EdgeDesiredState) (Result, error) {
	ch, err := r.conn.Channel()
	if err != nil {
		return Result{}, fmt.Errorf("agent: reconcile: %w", err)
	}
	defer ch.Close()

	var res Result
	// Order matters: policers first (sessions reference their indexes), then
	// classify sessions (which read r.polIdx for the hit target).
	pr, err := r.reconcilePolicers(vpp.NewPolicers(ch), desired.Policers)
	if err != nil {
		return res, err
	}
	res.PolicersAdded, res.PolicersUpdated, res.PolicersDeleted = pr.added, pr.updated, pr.deleted

	cr, err := r.reconcileClassify(vpp.NewClassify(ch), desired.ClassifySessions)
	if err != nil {
		return res, err
	}
	res.SessionsAdded, res.SessionsDeleted, res.SessionsMoved = cr.added, cr.deleted, cr.moved
	return res, nil
}

type policerCounts struct{ added, updated, deleted int }
type classifyCounts struct{ added, deleted, moved int }

// reconcileClassify makes VPP's classify sessions match desired. Tables are
// recovered (or created) per mask kind; on each table, sessions are added,
// orphans deleted, and members re-pointed when their pool's policer index
// changed. The hit target is the pool policer index from r.polIdx (populated by
// the policer pass).
func (r *Reconciler) reconcileClassify(cl classifyReconciler, desired []model.ClassifySession) (classifyCounts, error) {
	var c classifyCounts

	tables, err := cl.FindTablesByMask()
	if err != nil {
		return c, fmt.Errorf("agent: find classify tables: %w", err)
	}

	// Group desired sessions by mask, keyed by their match bytes → hit target.
	type want struct {
		mask    model.MaskKind
		prefix  netip.Prefix
		hitNext uint32
	}
	byMask := map[model.MaskKind]map[string]want{} // mask → matchKey → want
	for _, s := range desired {
		idx, ok := r.polIdx[s.PolicerName]
		if !ok {
			return c, fmt.Errorf("agent: classify session %s references unknown policer %q (not reconciled?)", s.Prefix, s.PolicerName)
		}
		key, err := vpp.SessionKey(s.Mask, s.Prefix)
		if err != nil {
			return c, err
		}
		if byMask[s.Mask] == nil {
			byMask[s.Mask] = map[string]want{}
		}
		byMask[s.Mask][hex.EncodeToString(key)] = want{s.Mask, s.Prefix, idx}
	}

	for mask, wants := range byMask {
		table, ok := tables[mask]
		if !ok {
			table, err = cl.AddTable(vpp.TableSpec{Mask: mask})
			if err != nil {
				return c, err
			}
			tables[mask] = table
			r.log.Info("reconcile: created classify table", "mask", mask, "index", table)
		}

		actual, err := cl.DumpSessions(table)
		if err != nil {
			return c, err
		}
		actualByKey := make(map[string]vpp.SessionInfo, len(actual))
		for _, s := range actual {
			actualByKey[hex.EncodeToString(s.Match)] = s
		}

		// Delete orphans: sessions on the table not in desired.
		for key, s := range actualByKey {
			if _, keep := wants[key]; keep {
				continue
			}
			if err := cl.DelSessionByKey(table, mask, s.Match); err != nil {
				return c, err
			}
			c.deleted++
		}

		// Add missing / re-point moved.
		for key, w := range wants {
			cur, present := actualByKey[key]
			switch {
			case !present:
				if err := cl.AddSession(table, w.mask, w.prefix, w.hitNext); err != nil {
					return c, err
				}
				c.added++
			case cur.HitNextIndex != w.hitNext:
				// Same key, different policer → atomic overwrite (§5.3).
				if err := cl.AddSession(table, w.mask, w.prefix, w.hitNext); err != nil {
					return c, err
				}
				c.moved++
			}
		}
	}
	return c, nil
}

// reconcilePolicers makes VPP's managed policers match desired: add missing,
// delete orphans (managed names not in desired, by name), update drifted
// (CIR/CB change, in place via the tracked index to keep the index — and thus
// the shared classify-session bindings — stable).
func (r *Reconciler) reconcilePolicers(p policerReconciler, desired []model.PolicerSpec) (policerCounts, error) {
	var c policerCounts

	desiredByName := make(map[string]model.PolicerSpec, len(desired))
	for _, s := range desired {
		desiredByName[s.Name] = s
	}

	actual, err := p.Dump()
	if err != nil {
		return c, fmt.Errorf("agent: dump policers: %w", err)
	}
	actualByName := make(map[string]vpp.PolicerInfo)
	for _, a := range actual {
		// Only touch policers this system manages (name encodes a pool id).
		if _, _, err := model.ParsePolicerName(a.Name); err != nil {
			continue
		}
		actualByName[a.Name] = a
	}

	// Delete orphans: managed policers VPP has but desired no longer wants.
	for name := range actualByName {
		if _, want := desiredByName[name]; want {
			continue
		}
		if err := p.DeleteByName(name); err != nil {
			return c, err
		}
		delete(r.polIdx, name)
		c.deleted++
		r.log.Info("reconcile: deleted orphan policer", "name", name)
	}

	// Add missing, update drifted.
	for name, spec := range desiredByName {
		cur, present := actualByName[name]
		if !present {
			idx, err := p.Add(spec)
			if err != nil {
				return c, err
			}
			r.polIdx[name] = idx
			c.added++
			r.log.Info("reconcile: added policer", "name", name, "index", idx)
			continue
		}
		if policerDrifted(spec, cur) {
			idx, known := r.polIdx[name]
			if !known {
				// Index unknown (e.g. after an agent restart): re-create by name
				// to converge. The index changes, so classify-session
				// reconciliation (later in this pass) re-points members.
				if err := p.DeleteByName(name); err != nil {
					return c, err
				}
				newIdx, err := p.Add(spec)
				if err != nil {
					return c, err
				}
				r.polIdx[name] = newIdx
				c.updated++
				r.log.Warn("reconcile: re-created drifted policer (index unknown)", "name", name, "index", newIdx)
				continue
			}
			if err := p.Update(idx, spec); err != nil {
				return c, err
			}
			c.updated++
			r.log.Info("reconcile: updated drifted policer", "name", name, "index", idx)
		}
	}
	return c, nil
}

// policerDrifted reports whether the live policer differs from the desired spec
// in a field reconcile must fix (rate / burst).
func policerDrifted(spec model.PolicerSpec, cur vpp.PolicerInfo) bool {
	return uint32(spec.CIR) != cur.CIR || spec.CommittedBurstBytes != cur.CB
}

// DesiredProvider supplies the desired state for a reconcile pass. ok=false
// means there is no authoritative desired state to apply — the loop then SKIPS
// the pass instead of pruning, the fail-static cold-start freeze (DESIGN.md
// §6.4). A *DesiredStore satisfies this via its Desired method.
type DesiredProvider func() (model.EdgeDesiredState, bool)

// Run reconciles on a timer until ctx is cancelled. provider returns the current
// desired state each tick (wired to the distribution layer, T-704); when it
// reports ok=false the pass is skipped so the agent never reconciles to a state
// the controller did not send (fail-static, §6.4).
func (r *Reconciler) Run(ctx context.Context, interval time.Duration, provider DesiredProvider) {
	t := time.NewTicker(interval)
	defer t.Stop()
	r.runOnce(provider) // converge immediately, don't wait a full interval
	for {
		select {
		case <-ctx.Done():
			r.log.Info("reconcile loop stopped")
			return
		case <-t.C:
			r.runOnce(provider)
		case <-r.conn.Reconnects():
			// VPP restarted (or the link flapped): the data plane lost our
			// rules. Drop stale index caches and reinstall immediately rather
			// than waiting up to a full interval (T-503, §5/§7). Reconcile is
			// idempotent, so a mere flap with intact state is a harmless no-op.
			r.log.Warn("VPP reconnect detected; resetting caches and reinstalling data plane",
				"generation", r.conn.Generation())
			r.Reset()
			r.runOnce(provider)
		}
	}
}

func (r *Reconciler) runOnce(provider DesiredProvider) {
	desired, ok := provider()
	if !ok {
		// Fail-static cold start (§6.4): no controller state ever received, so
		// we don't know the desired data plane. Touch nothing — freeze whatever
		// is already programmed rather than prune it to empty.
		r.log.Debug("no authoritative desired state; skipping reconcile (fail-static)")
		return
	}
	res, err := r.Reconcile(desired)
	if err != nil {
		r.log.Error("reconcile pass failed", "err", err)
		r.notify(desired, res, err)
		return
	}
	if !res.Empty() {
		r.log.Info("reconcile pass applied changes",
			"policers_added", res.PolicersAdded,
			"policers_updated", res.PolicersUpdated,
			"policers_deleted", res.PolicersDeleted,
			"sessions_added", res.SessionsAdded,
			"sessions_deleted", res.SessionsDeleted,
			"sessions_moved", res.SessionsMoved)
	}
	r.notify(desired, res, nil)
}
