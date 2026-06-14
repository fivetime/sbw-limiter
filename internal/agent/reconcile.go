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
	"sort"
	"sync/atomic"
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

	BindingsChanged int // policer-classify interface attach/detach (data plane)

	// PolicersActual / SessionsActual are the AUTHORITATIVE VPP-programmed counts
	// re-read at the END of a successful pass (managed policers; classify sessions
	// summed across all mask tables) — not derived from the diff, so they catch
	// state the desired-scoped diff never looked at (e.g. an orphan mask). They
	// feed the agent's health report for the controller's three-number
	// reconciliation (B-02). Left zero on a failed pass (the count is untrustworthy
	// then; the report's DataPlaneDown state already says so).
	PolicersActual int
	SessionsActual int
}

// Empty reports whether the pass made no changes (steady state).
func (r Result) Empty() bool {
	return r.PolicersAdded == 0 && r.PolicersUpdated == 0 && r.PolicersDeleted == 0 &&
		r.SessionsAdded == 0 && r.SessionsDeleted == 0 && r.SessionsMoved == 0 &&
		r.BindingsChanged == 0
}

// Total is the number of data-plane operations this pass applied; 0 means the
// data plane already matched desired. A non-zero total on a steady desired state
// is a drift signal — a soft-death symptom (rules lost/destroyed) that was
// self-healed locally this cycle (B-05, limiter §5.6).
func (r Result) Total() int {
	return r.PolicersAdded + r.PolicersUpdated + r.PolicersDeleted +
		r.SessionsAdded + r.SessionsDeleted + r.SessionsMoved +
		r.BindingsChanged
}

// Reconciler converges VPP to the desired state. It tracks policer name→index
// in memory (VPP's policer dump omits the index), rebuilt as it adds them.
type Reconciler struct {
	conn *vpp.Conn
	log  *slog.Logger

	polIdx map[string]uint32 // policer name → VPP index, learned on Add

	// polSnap publishes a read-only copy of polIdx after each pass so the metering
	// loop (T-1001) can map a policer's stats-segment index back to its pool with
	// no lock on the reconcile hot path. atomic.Value holds map[string]uint32.
	polSnap atomic.Value

	// observers are notified after each reconcile pass (B-05): the reconcile is
	// itself the dataplane-penetrating probe, so the soft-death health report is
	// driven off its result rather than a second VPP scan.
	observers []func(model.EdgeDesiredState, Result, error)

	// wake forces an immediate reconcile out of band (a fresh desired-state push)
	// so a failover/urgent change applies in milliseconds, not up to a full
	// interval later. Buffered+coalescing: extra wakes are dropped because the
	// next pass reads the latest desired state anyway.
	wake chan struct{}

	// policerIfaces names the data interfaces whose ingress feeds the policer-
	// classify chain (§5.3 data plane). Set once at startup from config.
	policerIfaces []string
}

// SetPolicerInterfaces sets the data interfaces the reconciler binds the
// policer-classify mask chain to (the L lower leg facing R). Call once before
// Run; empty leaves classify tables unattached (control plane only).
func (r *Reconciler) SetPolicerInterfaces(names []string) {
	r.policerIfaces = names
}

// Wake requests an immediate reconcile pass (a fresh desired-state push arrived,
// T-705). Non-blocking and coalescing: if a wake is already pending it is a
// no-op, since the next pass reads the latest desired state. Safe before Run
// starts (the buffered slot just carries the request to the first select).
func (r *Reconciler) Wake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
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
	return &Reconciler{conn: conn, log: log, polIdx: map[string]uint32{}, wake: make(chan struct{}, 1)}
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
	cl := vpp.NewClassify(ch)

	// Lossless index re-learn (agent restart): recover each policer's index from
	// the hit_next of an existing classify session that points at it, so
	// reconcilePolicers needn't Delete+Add a correct policer just to relearn its
	// index. A no-op once every desired policer's index is known (steady state).
	if err := r.relearnPolicerIndexes(cl, desired.Policers, desired.ClassifySessions); err != nil {
		return res, err
	}

	// Order matters: policers first (sessions reference their indexes), then
	// classify sessions (which read r.polIdx for the hit target).
	pr, err := r.reconcilePolicers(vpp.NewPolicers(ch), desired.Policers)
	if err != nil {
		return res, err
	}
	res.PolicersAdded, res.PolicersUpdated, res.PolicersDeleted = pr.added, pr.updated, pr.deleted

	cr, err := r.reconcileClassify(cl, desired.ClassifySessions)
	if err != nil {
		return res, err
	}
	res.SessionsAdded, res.SessionsDeleted, res.SessionsMoved = cr.added, cr.deleted, cr.moved

	// Data plane: attach the classify chain to the configured ingress
	// interfaces so policed traffic actually flows through it (T-501).
	bc, err := r.reconcileBindings(cl, vpp.NewInterfaces(ch))
	if err != nil {
		return res, err
	}
	res.BindingsChanged = bc

	// Authoritative re-count of what VPP is now actually running, for the
	// controller's three-number reconciliation (B-02). Read fresh rather than
	// derived from the diff so it reflects true VPP state — including anything the
	// desired-scoped diff above never enumerated. A count error is non-fatal: the
	// data plane was reconciled fine, we just couldn't attest the totals this pass.
	if pa, sa, err := countProgrammed(vpp.NewPolicers(ch), cl); err != nil {
		r.log.Warn("reconcile: programmed-count attestation failed (B-02)", "err", err)
	} else {
		res.PolicersActual, res.SessionsActual = pa, sa
	}

	// Publish the policer name→index map for the metering loop (T-1001). A fresh
	// copy each pass; readers get a consistent, never-mutated snapshot.
	snap := make(map[string]uint32, len(r.polIdx))
	for name, idx := range r.polIdx {
		snap[name] = idx
	}
	r.polSnap.Store(snap)
	return res, nil
}

// PolicerIndexes returns a read-only snapshot of the policer name→VPP-index map
// as of the last completed reconcile pass (T-1001). Lock-free; empty until the
// first pass. The returned map must not be mutated.
func (r *Reconciler) PolicerIndexes() map[string]uint32 {
	v := r.polSnap.Load()
	if v == nil {
		return nil
	}
	return v.(map[string]uint32)
}

// countProgrammed re-reads VPP for the authoritative count of MANAGED policers
// (name encodes a pool id) and of classify sessions summed across every mask
// table. This is the "actual" side of the B-02 three-number audit; counting all
// tables (not just desired masks) means an orphan session on an otherwise-empty
// mask still shows up as a discrepancy rather than hiding.
func countProgrammed(p policerReconciler, cl classifyReconciler) (policers, sessions int, err error) {
	pols, err := p.Dump()
	if err != nil {
		return 0, 0, fmt.Errorf("agent: count policers: %w", err)
	}
	for _, a := range pols {
		if _, _, err := model.ParsePolicerName(a.Name); err == nil {
			policers++
		}
	}
	tables, err := cl.FindTablesByMask()
	if err != nil {
		return 0, 0, fmt.Errorf("agent: count sessions: find tables: %w", err)
	}
	for _, table := range tables {
		ss, err := cl.DumpSessions(table)
		if err != nil {
			return 0, 0, fmt.Errorf("agent: count sessions: dump: %w", err)
		}
		sessions += len(ss)
	}
	return policers, sessions, nil
}

// relearnPolicerIndexes recovers policer name→index mappings from the hit_next of
// existing classify sessions, WITHOUT touching the policers (lossless). VPP's
// policer_dump omits the index (PolicerDetails has no index field), so after an
// agent restart (polIdx empty, VPP state intact) the only non-disruptive source
// of a policer's index is a session already pointing at it — that session's
// hit_next IS the index. This spares reconcilePolicers from re-creating a correct
// policer (a brief policing gap + index churn) just to relearn it. Only fills
// MISSING entries; skips the VPP dump entirely once every desired policer's index
// is known (steady state). The re-create path remains the fallback for a policer
// with no session to identify it.
func (r *Reconciler) relearnPolicerIndexes(cl *vpp.Classify, policers []model.PolicerSpec, sessions []model.ClassifySession) error {
	allKnown := true
	for _, p := range policers {
		if _, ok := r.polIdx[p.Name]; !ok {
			allKnown = false
			break
		}
	}
	if allKnown {
		return nil
	}

	tables, err := cl.FindTablesByMask()
	if err != nil {
		return fmt.Errorf("agent: relearn: find tables: %w", err)
	}
	actual := make(map[model.MaskKind]map[string]uint32, len(tables)) // mask → matchKey → hit_next
	for mask, table := range tables {
		ss, err := cl.DumpSessions(table)
		if err != nil {
			return fmt.Errorf("agent: relearn: dump sessions: %w", err)
		}
		m := make(map[string]uint32, len(ss))
		for _, s := range ss {
			m[hex.EncodeToString(s.Match)] = s.HitNextIndex
		}
		actual[mask] = m
	}
	for _, s := range sessions {
		if _, known := r.polIdx[s.PolicerName]; known {
			continue
		}
		key, err := vpp.SessionKey(s.Mask, s.Prefix)
		if err != nil {
			continue
		}
		if hit, ok := actual[s.Mask][hex.EncodeToString(key)]; ok {
			r.polIdx[s.PolicerName] = hit
			r.log.Info("reconcile: relearned policer index from classify session (lossless)",
				"name", s.PolicerName, "index", hit)
		}
	}
	return nil
}

// reconcileBindings attaches the policer-classify mask chain to each configured
// data interface so pool traffic ingressing there is classified→policed (§5.3
// data plane). Without it, classify tables exist but no interface feeds them, so
// the shared-bucket policer never sees a packet. The head of each family's mask
// chain is the attach point; if a family spans several mask tables they are
// linked into one chain first. Idempotent: re-binds only on drift.
func (r *Reconciler) reconcileBindings(cl *vpp.Classify, ifaces *vpp.Interfaces) (int, error) {
	if len(r.policerIfaces) == 0 {
		return 0, nil
	}
	tables, err := cl.FindTablesByMask()
	if err != nil {
		return 0, fmt.Errorf("agent: bindings: find tables: %w", err)
	}
	ip4Head, err := familyHead(cl, tables, model.FamilyIPv4)
	if err != nil {
		return 0, fmt.Errorf("agent: bindings: ip4 chain: %w", err)
	}
	ip6Head, err := familyHead(cl, tables, model.FamilyIPv6)
	if err != nil {
		return 0, fmt.Errorf("agent: bindings: ip6 chain: %w", err)
	}

	bound4, err := bindingMap(cl, model.FamilyIPv4)
	if err != nil {
		return 0, err
	}
	bound6, err := bindingMap(cl, model.FamilyIPv6)
	if err != nil {
		return 0, err
	}

	idxByName, err := ifaces.IndexMap(r.policerIfaces...)
	if err != nil {
		return 0, fmt.Errorf("agent: bindings: %w", err)
	}

	var changed int
	for _, name := range r.policerIfaces {
		sw := idxByName[name]
		c4 := tableOr(bound4, sw)
		c6 := tableOr(bound6, sw)
		if c4 == ip4Head && c6 == ip6Head {
			continue // already attached to the right chain heads
		}
		if ip4Head == vpp.NoTable && ip6Head == vpp.NoTable {
			// Nothing desired: detach the chain currently bound (pool destroyed).
			if err := cl.SetPolicerInterface(sw, c4, c6, false); err != nil {
				return changed, fmt.Errorf("agent: bindings: detach %s: %w", name, err)
			}
			r.log.Info("reconcile: detached policer-classify", "iface", name, "swifindex", sw)
		} else {
			if err := cl.SetPolicerInterface(sw, ip4Head, ip6Head, true); err != nil {
				return changed, fmt.Errorf("agent: bindings: attach %s: %w", name, err)
			}
			r.log.Info("reconcile: attached policer-classify", "iface", name,
				"swifindex", sw, "ip4table", ip4Head, "ip6table", ip6Head)
		}
		changed++
	}
	return changed, nil
}

// familyHead returns the head mask table for a family, linking that family's
// tables into a single串查 chain (head→…→none) when more than one exists.
// Returns vpp.NoTable when the family has no tables.
func familyHead(cl *vpp.Classify, tables map[model.MaskKind]uint32, fam model.Family) (uint32, error) {
	var ts []uint32
	for mask, t := range tables {
		if maskFamily(mask) == fam {
			ts = append(ts, t)
		}
	}
	if len(ts) == 0 {
		return vpp.NoTable, nil
	}
	if len(ts) == 1 {
		return ts[0], nil // AddTable already sets next_table_index = none
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	for i := 0; i < len(ts)-1; i++ {
		if err := cl.LinkTable(ts[i], ts[i+1]); err != nil {
			return vpp.NoTable, err
		}
	}
	if err := cl.LinkTable(ts[len(ts)-1], vpp.NoTable); err != nil {
		return vpp.NoTable, err
	}
	return ts[0], nil
}

// maskFamily reports the address family a classify mask kind operates on.
func maskFamily(m model.MaskKind) model.Family {
	switch m {
	case model.MaskIP6Dst128, model.MaskIP6Src128:
		return model.FamilyIPv6
	default:
		return model.FamilyIPv4
	}
}

// bindingMap reads the current policer-classify interface→table bindings for a
// family into a lookup keyed by sw_if_index.
func bindingMap(cl *vpp.Classify, fam model.Family) (map[uint32]uint32, error) {
	att, err := cl.DumpPolicerClassify(fam)
	if err != nil {
		return nil, fmt.Errorf("agent: bindings: dump %s: %w", fam, err)
	}
	m := make(map[uint32]uint32, len(att))
	for _, a := range att {
		m[a.SwIfIndex] = a.TableIndex
	}
	return m, nil
}

// tableOr returns the table bound to sw, or vpp.NoTable if unbound.
func tableOr(m map[uint32]uint32, sw uint32) uint32 {
	if t, ok := m[sw]; ok {
		return t
	}
	return vpp.NoTable
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

	// Prune EMPTIED-MASK tables: the byMask loop only visits masks the desired set
	// still uses, so a mask table whose pools were all removed (e.g. the last IPv6
	// pool deleted, or stale sessions a restarted agent inherited from VPP) is
	// never enumerated and its sessions linger as orphans forever — a program drift
	// no re-push can heal (B-02 surfaced exactly this). Every session on a table
	// with no desired sessions of its mask is an orphan, so delete them all.
	for mask, table := range tables {
		if _, desiredMask := byMask[mask]; desiredMask {
			continue // visited above
		}
		actual, err := cl.DumpSessions(table)
		if err != nil {
			return c, err
		}
		if len(actual) == 0 {
			continue
		}
		for _, s := range actual {
			if err := cl.DelSessionByKey(table, mask, s.Match); err != nil {
				return c, err
			}
			c.deleted++
		}
		r.log.Info("reconcile: pruned orphan classify sessions on emptied mask",
			"mask", mask, "table", table, "pruned", len(actual))
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
		// Present in VPP. We need its index — VPP's policer dump omits it
		// (PolicerDetails has no index field) and classify sessions hit it by
		// index. If the index is unknown — the agent restarted while VPP kept
		// its policers, so polIdx is empty but the policer already exists, drift
		// or not — re-create by name to relearn it. The index changes, so
		// classify-session reconciliation (later this pass) re-points members.
		// Without this, a CORRECT (non-drifted) policer leaves polIdx empty and
		// every reconcileClassify fails "unknown policer" → false DataPlaneDown.
		idx, known := r.polIdx[name]
		if !known {
			if err := p.DeleteByName(name); err != nil {
				return c, err
			}
			newIdx, err := p.Add(spec)
			if err != nil {
				return c, err
			}
			r.polIdx[name] = newIdx
			c.updated++
			r.log.Warn("reconcile: re-created policer to relearn index (agent restart)", "name", name, "index", newIdx)
			continue
		}
		if policerDrifted(spec, cur) {
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
	// A nil conn (tests) has no reconnect channel; a nil channel blocks forever in
	// select, which is the right behaviour (that case simply never fires).
	var reconnects <-chan struct{}
	if r.conn != nil {
		reconnects = r.conn.Reconnects()
	}
	r.runOnce(provider) // converge immediately, don't wait a full interval
	for {
		select {
		case <-ctx.Done():
			r.log.Info("reconcile loop stopped")
			return
		case <-t.C:
			r.runOnce(provider)
		case <-r.wake:
			// A fresh desired-state push: apply now (failover/urgent) rather than
			// waiting up to a full interval (T-705 / §5).
			r.runOnce(provider)
		case <-reconnects:
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
