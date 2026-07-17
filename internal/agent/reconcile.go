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
	LookupHits(table uint32, mask model.MaskKind, prefixes []netip.Prefix) ([]uint32, error)
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

	// classifyNbuckets/classifyMem size each VPP classify mask table, auto-tuned from
	// the node memory budget (cgroup/RAM, see classifysizing.go) so different-sized
	// k8s nodes self-size. 0 → AddTable's legacy 4096/16 MiB default.
	classifyNbuckets, classifyMem uint32

	// polSnap publishes a read-only copy of polIdx after each pass so the metering
	// loop (T-1001) can map a policer's stats-segment index back to its pool with
	// no lock on the reconcile hot path. atomic.Value holds map[string]uint32.
	polSnap atomic.Value

	// Incremental ACTUAL counters (§6.52 #5 续集): the authoritative programmed
	// counts come from countProgrammed at each FULL reconcile (up to a reconcile
	// interval stale), while pools churn on the seconds-level DELTA path — the
	// stale numbers made the B-02 audit see phantom desired≠actual "program-drift"
	// on routine churn. The full pass ANCHORS these to VPP truth (Store); the
	// delta path adjusts them at each successful mutate (Add) so the reported
	// ACTUAL stays fresh across deltas. actAnchored gates the report overlay
	// until the first anchor (before that, the Result counts stand).
	actPol      atomic.Int64
	actSess     atomic.Int64
	actAnchored atomic.Bool

	// observers are notified after each reconcile pass (B-05): the reconcile is
	// itself the dataplane-penetrating probe, so the soft-death health report is
	// driven off its result rather than a second VPP scan.
	observers []func(model.EdgeDesiredState, Result, error)

	// wake forces an immediate reconcile out of band (a fresh desired-state push)
	// so a failover/urgent change applies in milliseconds, not up to a full
	// interval later. Buffered+coalescing: extra wakes are dropped because the
	// next pass reads the latest desired state anyway.
	wake chan struct{}

	// deltaQ carries incremental DESIRED_DELTA pushes to the single reconcile
	// goroutine, where they are applied in O(delta) (the hot path) mutually exclusive
	// with the full Reconcile — both touch polIdx and a VPP channel, so they must not
	// run concurrently. The transport's dispatch goroutine only enqueues; the Run
	// loop drains and applies via onDelta. Buffered so a burst of pushes is not lost.
	deltaQ chan model.EdgeDesiredDelta

	// deltasDropped is the CUMULATIVE count of deltas SubmitDelta discarded because
	// deltaQ was full (local back-pressure — the resync backstop re-delivers, but a
	// rising count means this agent is saturated). Surfaced in the health report so
	// the server emits a `delivery-degraded` BSS event on a rise (DESIGN §9.1). Bumped
	// from the transport dispatch goroutine, read from the health goroutine → atomic.
	deltasDropped atomic.Uint64

	// applying is true while the reconcile goroutine is mid-apply — a full pass OR a
	// queued delta (§6.67 wall-①). The phase tracker's Observe feed only fires at
	// pass END with pending=0, so without this a minutes-long 100K-route grind (or a
	// sustained delta stream) reads as PhaseReady the whole way through: the busy
	// gates on the VPP-layer death sensors stay OPEN in exactly the window they were
	// built for. Busy() folds it (plus queue depth) into the phase as ApplyBusy.
	applying atomic.Bool

	// onDelta applies one queued delta from the reconcile goroutine: gap-detect
	// against lastGen, merge into the held desired state, and apply just the touched
	// pools (wired by main to DesiredStore.Merge + ApplyDelta). On a gap it requests
	// a full resync instead of applying. nil → deltas are ignored (delta path off).
	onDelta func(model.EdgeDesiredDelta)

	// policerIfaces names the data interfaces whose ingress feeds the policer-
	// classify chain (§5.3 data plane). Set once at startup from config.
	policerIfaces []string

	// lastGen is the generation of the most recently applied desired state (full
	// reconcile OR delta merge). The DESIRED_DELTA hot path's gap detection compares
	// a delta's BaseGeneration against this: a mismatch means the agent missed an
	// update and must NOT apply the delta onto a divergent base (it drops it and
	// relies on the controller's full DESIRED_STATE resync). Read/written only from
	// the single reconcile goroutine (Reconcile / ApplyDelta), so no lock is needed.
	lastGen uint64

	// appliedNonEmpty / pendingEmpty implement the reconcile-to-empty guard: a desired
	// state that suddenly collapses to EMPTY right after a non-empty one was applied is
	// treated as SUSPECT (a transient desired-state drop — a VPP reconnect/resync race
	// or an in-flight delta that momentarily emptied the store) and its teardown is
	// deferred ONE pass; the live policers/sessions are deleted as "orphans" only if the
	// empty state PERSISTS (a real "all pools deleted"). Without this one bad pass
	// blackholes every pool. Reconcile-goroutine-only, like lastGen, so no lock.
	appliedNonEmpty bool
	pendingEmpty    bool

	// poolHash caches the installed pool-set hash (model.PoolSetHash over the
	// distinct pool ids materialized in polIdx) recomputed after each apply, so the
	// report builder can read it lock-free. The controller compares it against its
	// own view to detect drift and trigger a resync (the report-driven backstop).
	poolHash atomic.Uint64
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
		// Isolate each observer: a panic in one (e.g. the metrics observer) must NOT skip
		// the others — the canary/health observers drive soft-death failover signalling and
		// must always run regardless of an earlier observer faulting.
		func() {
			defer func() {
				if p := recover(); p != nil {
					r.log.Error("reconcile observer panicked; continuing with the rest", "panic", p)
				}
			}()
			fn(desired, res, err)
		}()
	}
}

// New creates a reconciler over a VPP connection.
func New(conn *vpp.Conn, log *slog.Logger) *Reconciler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	nb, mem := classifyAutoSizing()
	log.Info("classify table auto-sizing",
		"nbuckets", nb, "memory_size_mb", mem>>20,
		"memory_budget_mb", memoryBudget()>>20,
		"note", "per VPP classify mask table; BWPOOL_CLASSIFY_MEMBERS / BWPOOL_CLASSIFY_MEM_PCT override")
	return &Reconciler{conn: conn, log: log, polIdx: map[string]uint32{},
		classifyNbuckets: nb, classifyMem: mem,
		wake: make(chan struct{}, 1), deltaQ: make(chan model.EdgeDesiredDelta, 64)}
}

// SetDeltaApplier wires the hot-path delta handler invoked from the reconcile
// goroutine for each queued DESIRED_DELTA (DesiredStore.Merge + ApplyDelta, with
// gap detection). Call once before Run. Without it, SubmitDelta is a no-op.
func (r *Reconciler) SetDeltaApplier(fn func(model.EdgeDesiredDelta)) { r.onDelta = fn }

// SubmitDelta enqueues an incremental delta for the reconcile goroutine to apply
// in O(delta) (the hot path). Called from the transport's dispatch goroutine.
// Non-blocking: if the queue is full the delta is dropped and the next full
// reconcile + the controller's hash-mismatch resync heal any divergence (the
// backstop), so a buffer overrun degrades to the safe slow path rather than blocks.
func (r *Reconciler) SubmitDelta(d model.EdgeDesiredDelta) {
	select {
	case r.deltaQ <- d:
	default:
		r.deltasDropped.Add(1)
		r.log.Warn("delta queue full; dropping (resync backstop will heal)",
			"generation", d.Generation, "base", d.BaseGeneration,
			"deltas_dropped", r.deltasDropped.Load())
	}
}

// DeltasDropped returns the cumulative count of deltas dropped under deltaQ overflow
// (see deltasDropped). The health builder reads it into HealthReport.DeltasDropped so
// the server can emit a delivery-degraded BSS event on a rise (DESIGN §9.1).
func (r *Reconciler) DeltasDropped() uint64 { return r.deltasDropped.Load() }

// Busy reports whether materialization work is in flight or queued: a full pass or
// delta mid-apply on the reconcile goroutine, or deltas waiting in deltaQ. Wire to
// PhaseTracker.SetApplyBusy (§6.67 wall-①) so a long grind reads as Reconciling —
// not Ready — for the sensor busy-gates and the server's phase-aware grace alike.
func (r *Reconciler) Busy() bool { return r.applying.Load() || len(r.deltaQ) > 0 }

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
	// Reconcile-to-empty guard: defer the teardown on the FIRST pass whose desired
	// state collapses to empty right after a non-empty one was applied — a transient
	// drop would otherwise delete live policers/sessions as orphans and blackhole real
	// pools. Act only once the empty state persists (see appliedNonEmpty/pendingEmpty).
	desiredEmpty := len(desired.Policers) == 0 && len(desired.ClassifySessions) == 0
	if desiredEmpty && r.appliedNonEmpty && !r.pendingEmpty {
		r.pendingEmpty = true
		r.log.Warn("reconcile: desired collapsed to empty after non-empty — deferring teardown one pass (suspected transient drop)",
			"generation", desired.Generation)
		return Result{}, nil
	}
	r.pendingEmpty = false

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
		// Anchor the incremental counters to VPP truth: overwrites any drift the
		// delta-path adjustments accumulated (silent VPP rejects, missed paths).
		r.actPol.Store(int64(pa))
		r.actSess.Store(int64(sa))
		r.actAnchored.Store(true)
	}

	// Publish the policer name→index map for the metering loop (T-1001). A fresh
	// copy each pass; readers get a consistent, never-mutated snapshot.
	snap := make(map[string]uint32, len(r.polIdx))
	for name, idx := range r.polIdx {
		snap[name] = idx
	}
	r.polSnap.Store(snap)

	// The full reconcile is the drift backstop: it has just made VPP match desired,
	// so adopt this generation as the apply baseline (delta gap detection) and
	// recompute the installed pool-set hash the report attests (B-02 / hash drift).
	r.lastGen = desired.Generation
	r.appliedNonEmpty = !desiredEmpty
	r.recomputePoolHash()
	return res, nil
}

// recomputePoolHash recomputes and caches the installed pool-set hash from the
// distinct pool ids currently materialized (polIdx keys → model.ParsePolicerName),
// with model.PoolSetHash — the SAME function the controller computes over its
// expected set, so equality means converged and a mismatch is the authoritative
// drift signal that triggers a full resync. Called from the reconcile goroutine
// after every apply (full reconcile or delta merge).
func (r *Reconciler) recomputePoolHash() {
	seen := make(map[model.PoolID]struct{}, len(r.polIdx))
	ids := make([]model.PoolID, 0, len(r.polIdx))
	for name := range r.polIdx {
		pool, _, err := model.ParsePolicerName(name)
		if err != nil {
			continue // unmanaged name (shouldn't be in polIdx, but be defensive)
		}
		if _, dup := seen[pool]; dup {
			continue
		}
		seen[pool] = struct{}{}
		ids = append(ids, pool)
	}
	r.poolHash.Store(model.PoolSetHash(ids))
}

// InstalledPoolHash returns the hash of the pool-set currently materialized in
// the data plane, as of the last completed apply (full reconcile or delta merge).
// It is model.PoolSetHash over the distinct pool ids in polIdx — the controller
// computes the same hash over its expected set and triggers a full DESIRED_STATE
// resync on a mismatch (the report-driven drift backstop; the hot path stays the
// controller's PushDelta). Lock-free; 0 before the first apply.
func (r *Reconciler) InstalledPoolHash() uint64 {
	return r.poolHash.Load()
}

// LastAppliedGeneration returns the generation of the most recently applied
// desired state (full reconcile or delta merge). The delta hot path's gap
// detection compares a delta's BaseGeneration against it. Read from the reconcile
// goroutine.
func (r *Reconciler) LastAppliedGeneration() uint64 { return r.lastGen }

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
		// Set each family in its OWN policer_classify_set_interface call. A single
		// COMBINED call that sets BOTH the ip4 and ip6 table indices at once enables
		// only ip4 on VPP — the ip6 feature is silently dropped (ip6-policer-classify
		// never lands on the interface's ip6-unicast arc), so v6 ingress traffic
		// bypasses the policer entirely (classify hits=0; rate stays 0). The v6 ingress
		// dataplane e2e exposed this; the single-family CLI (`set policer classify
		// interface X ip6-table N`) proves a per-family call works. is_add=true with
		// NoTable for the other family is additive and never clobbers it, so we drive
		// attach/detach independently per family.
		if c4 != ip4Head {
			ip4, add := ip4Head, true
			if ip4Head == vpp.NoTable {
				ip4, add = c4, false // pool gone for v4: detach the currently-bound chain
			}
			if err := cl.SetPolicerInterface(sw, ip4, vpp.NoTable, add); err != nil {
				return changed, fmt.Errorf("agent: bindings: %s ip4: %w", name, err)
			}
		}
		if c6 != ip6Head {
			ip6, add := ip6Head, true
			if ip6Head == vpp.NoTable {
				ip6, add = c6, false // pool gone for v6: detach the currently-bound chain
			}
			if err := cl.SetPolicerInterface(sw, vpp.NoTable, ip6, add); err != nil {
				return changed, fmt.Errorf("agent: bindings: %s ip6: %w", name, err)
			}
		}
		r.log.Info("reconcile: set policer-classify", "iface", name,
			"swifindex", sw, "ip4table", ip4Head, "ip6table", ip6Head)
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

	byMask, err := r.buildSessionWants(desired)
	if err != nil {
		return c, err
	}

	for mask, wants := range byMask {
		table, err := r.ensureTable(cl, tables, mask)
		if err != nil {
			return c, err
		}

		// FULL path: dump the WHOLE table so orphans (installed sessions no longer
		// desired) can be swept — the divergence from the delta hot path, which
		// point-looks-up only its own members and drives deletes from prev instead.
		actual, err := cl.DumpSessions(table)
		if err != nil {
			return c, err
		}
		actualHit := make(map[string]uint32, len(actual))
		for _, s := range actual {
			actualHit[sessionMapKey(mask, hex.EncodeToString(s.Match))] = s.HitNextIndex
		}
		wantKeys := make(map[string]struct{}, len(wants))
		for _, w := range wants {
			wantKeys[w.key] = struct{}{}
		}

		// Delete orphans: installed sessions on the table not in desired.
		for _, s := range actual {
			if _, keep := wantKeys[sessionMapKey(mask, hex.EncodeToString(s.Match))]; keep {
				continue
			}
			if err := cl.DelSessionByKey(table, mask, s.Match); err != nil {
				return c, err
			}
			c.deleted++
		}

		// Add missing / re-point moved (shared with the delta path).
		a, m, err := applySessionUpserts(cl, table, wants, actualHit)
		if err != nil {
			return c, err
		}
		c.added += a
		c.moved += m
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
		case d := <-r.deltaQ:
			// Hot path: apply an incremental delta in O(delta) on this (the only)
			// reconcile goroutine, mutually exclusive with the full pass. The handler
			// gap-detects and either applies the touched pools or requests a resync.
			if r.onDelta != nil {
				r.applying.Store(true)
				r.onDelta(d)
				r.applying.Store(false)
			}
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
	r.applying.Store(true)
	defer r.applying.Store(false)
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

// ActualCounts returns the incrementally-maintained programmed counts (anchored
// to countProgrammed truth each full reconcile, adjusted on each successful
// delta mutate). ok=false until the first anchor — the reporter then leaves the
// last full-reconcile Result counts untouched.
func (r *Reconciler) ActualCounts() (policers, sessions int, ok bool) {
	return int(r.actPol.Load()), int(r.actSess.Load()), r.actAnchored.Load()
}
