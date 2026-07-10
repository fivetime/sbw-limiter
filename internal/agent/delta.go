// Delta hot path (the agent is hands, not brain): apply the incremental per-pool
// changes the controller pushes (Directive_DESIRED_DELTA) in O(delta), WITHOUT
// re-diffing the whole edge. This is the steady-state apply path; the full
// Reconcile (reconcile.go) stays ONLY as the resync/drift backstop (it runs on a
// hash-mismatch resync, VPP reconnect, and the periodic interval).
//
// The controller renders exactly one changed pool's contribution (a model.PoolDelta)
// and ships a set of them; the agent touches only those pools' VPP resources,
// reusing the same vpp materializers as the full reconcile. Gap detection lives in
// the transport (grpcclient): a delta whose BaseGeneration ≠ the agent's last
// applied generation is dropped, and the controller's resync (full DESIRED_STATE)
// heals the divergence.
package agent

import (
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// ApplyDelta materializes one EdgeDesiredDelta into VPP, scoped to ONLY the pools
// the delta touches — O(delta), not a full edge Dump/diff. prevSessions is the
// classify-session set the agent held BEFORE this delta (the pre-merge desired
// state's ClassifySessions): a pool that is being replaced (re-upserted) or removed
// may have moved/dropped some members, and the only record of the sessions that
// must be DELETED for that pool is the previous desired set — VPP's session dump is
// scoped per table, not per pool, so we drive deletions from prevSessions rather
// than dumping the whole table (which would be the full-reconcile cost we are
// avoiding).
//
// Order per the full reconcile: policers first (sessions hit them by index), then
// classify sessions. Removed pools are torn down (sessions then policers); upserted
// pools have their policers added/updated and their sessions installed (reading back
// only the pool's own mask tables to decide add-vs-move, never the whole edge). On
// success it adopts the delta's generation as the apply baseline and recomputes the
// installed pool-set hash. The caller runs this on the SINGLE reconcile goroutine
// (via Reconciler.deltaQ → onDelta), mutually exclusive with the full Reconcile —
// both touch polIdx and a VPP channel.
func (r *Reconciler) ApplyDelta(delta model.EdgeDesiredDelta, prevSessions []model.ClassifySession) (Result, error) {
	ch, err := r.conn.Channel()
	if err != nil {
		return Result{}, fmt.Errorf("agent: apply delta: %w", err)
	}
	defer ch.Close()

	pols := vpp.NewPolicers(ch)
	cl := vpp.NewClassify(ch)

	// Index prev sessions by pool so a removed/replaced pool's members can be
	// deleted without dumping the whole table.
	prevByPool := map[model.PoolID][]model.ClassifySession{}
	for _, s := range prevSessions {
		prevByPool[s.PoolID] = append(prevByPool[s.PoolID], s)
	}

	var res Result

	// --- REMOVED pools: delete their sessions, then their policers. ---------------
	for _, pool := range delta.Removed {
		d, err := r.deletePoolSessions(cl, prevByPool[pool])
		if err != nil {
			return res, err
		}
		res.SessionsDeleted += d
		pd, err := r.deletePoolPolicers(pols, pool)
		if err != nil {
			return res, err
		}
		res.PolicersDeleted += pd
	}

	// --- UPSERTED pools: policers (add/update) then classify sessions. ------------
	// A re-upsert may MOVE or DROP a member, so first remove the prev sessions of
	// any pool whose desired session set differs, then install the new set. We do
	// this per pool by diffing the pool's prev vs new sessions (scoped, O(pool)),
	// not by scanning the table.
	for _, up := range delta.Upserts {
		pa, pu, err := r.upsertPoolPolicers(pols, up.Policers)
		if err != nil {
			return res, err
		}
		res.PolicersAdded += pa
		res.PolicersUpdated += pu

		da, dd, dm, err := r.upsertPoolSessions(cl, up.PoolID, prevByPool[up.PoolID], up.ClassifySessions)
		if err != nil {
			return res, err
		}
		res.SessionsAdded += da
		res.SessionsDeleted += dd
		res.SessionsMoved += dm
	}

	// Republish the metering snapshot (polIdx changed) and adopt this delta as the
	// new apply baseline + recompute the installed pool-set hash (drift backstop).
	r.AdoptDeltaBaseline(delta.Generation)
	return res, nil
}

// AdoptDeltaBaseline advances the applied-generation chain to gen and republishes
// the metering snapshot + installed pool-set hash from the CURRENT polIdx.
// ApplyDelta calls it on success; the delta handler ALSO calls it when the VPP
// apply FAILED after the desired-state Merge succeeded (§6.40 layer 4): lastGen is
// the position on the DESIRED chain (what the agent has been told), not a VPP
// completion marker — refusing to advance it on an apply error stranded every
// subsequent delta in the reorder buffer behind a predecessor that could never
// "complete" (a pool with VPP-rejected parameters retries forever), so even the
// pool's own REMOVAL delta could not land and the ghost pool kept the edge
// Degraded until restart. The VPP-side gap a failed apply leaves is healed by the
// periodic full reconcile (which retries everything in the held desired state);
// the snapshot/hash here reflect whatever polIdx really holds (partial applies
// included), which is exactly the "installed" truth the drift backstop wants.
// Reconcile-goroutine-only, like ApplyDelta.
func (r *Reconciler) AdoptDeltaBaseline(gen uint64) {
	snap := make(map[string]uint32, len(r.polIdx))
	for name, idx := range r.polIdx {
		snap[name] = idx
	}
	r.polSnap.Store(snap)
	r.lastGen = gen
	r.recomputePoolHash()
}

// upsertPoolPolicers adds missing / updates drifted policers for one pool's specs,
// scoped — it never Dumps VPP. Presence is decided by polIdx (the in-memory
// name→index map), the same authority the full reconcile uses for the hit target.
// An unknown index means we have not added this policer (or the agent restarted and
// lost the map — but the delta path only runs once a full reconcile has established
// a baseline, so polIdx reflects what we installed). Update is in place via the
// tracked index, keeping classify-session bindings stable.
func (r *Reconciler) upsertPoolPolicers(p policerReconciler, specs []model.PolicerSpec) (added, updated int, err error) {
	for _, spec := range specs {
		idx, known := r.polIdx[spec.Name]
		if !known {
			newIdx, err := p.Add(spec)
			if err != nil {
				return added, updated, err
			}
			r.polIdx[spec.Name] = newIdx
			r.actPol.Add(1)
			added++
			r.log.Info("delta: added policer", "name", spec.Name, "index", newIdx)
			continue
		}
		if err := p.Update(idx, spec); err != nil {
			return added, updated, err
		}
		updated++
		r.log.Info("delta: updated policer", "name", spec.Name, "index", idx)
	}
	return added, updated, nil
}

// deletePoolPolicers deletes every managed policer belonging to pool, by name, and
// drops it from polIdx. It enumerates polIdx (in-memory) for that pool's names —
// no VPP Dump — so the cost is the number of installed policers, not the whole edge.
func (r *Reconciler) deletePoolPolicers(p policerReconciler, pool model.PoolID) (int, error) {
	var names []string
	for name := range r.polIdx {
		id, _, err := model.ParsePolicerName(name)
		if err != nil || id != pool {
			continue
		}
		names = append(names, name)
	}
	var deleted int
	for _, name := range names {
		if err := p.DeleteByName(name); err != nil {
			return deleted, err
		}
		delete(r.polIdx, name)
		r.actPol.Add(-1)
		deleted++
		r.log.Info("delta: deleted policer", "name", name, "pool", pool)
	}
	return deleted, nil
}

// deletePoolSessions deletes the given pool's classify sessions (its prev desired
// members), scoped to the tables those masks use. It looks up table indexes once
// via FindTablesByMask but only touches the keys it is deleting — no per-table
// session dump/diff.
func (r *Reconciler) deletePoolSessions(cl classifyReconciler, sessions []model.ClassifySession) (int, error) {
	if len(sessions) == 0 {
		return 0, nil
	}
	tables, err := cl.FindTablesByMask()
	if err != nil {
		return 0, fmt.Errorf("agent: delta: find tables: %w", err)
	}
	var deleted int
	for _, s := range sessions {
		table, ok := tables[s.Mask]
		if !ok {
			continue // mask table gone already; nothing to delete
		}
		key, err := vpp.SessionKey(s.Mask, s.Prefix)
		if err != nil {
			return deleted, err
		}
		if err := cl.DelSessionByKey(table, s.Mask, key); err != nil {
			return deleted, err
		}
		r.actSess.Add(-1)
		deleted++
	}
	return deleted, nil
}

// upsertPoolSessions makes the pool's classify sessions match its new desired set,
// scoped to this pool: it deletes prev members no longer wanted, adds new ones, and
// re-points (moves) members whose installed hit target differs from desired. The hit
// target is the pool policer index from polIdx (filled by upsertPoolPolicers). To
// decide add-vs-move correctly it reads back ONLY the tables of the masks this pool
// touches (typically one or two), not the whole edge — so the cost is bounded by the
// pool's masks/members, not N. prev is the pool's pre-delta members (the teardown
// record for members no longer desired).
func (r *Reconciler) upsertPoolSessions(cl classifyReconciler, pool model.PoolID, prev, next []model.ClassifySession) (added, deleted, moved int, err error) {
	tables, err := cl.FindTablesByMask()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("agent: delta: find tables: %w", err)
	}

	byMask, err := r.buildSessionWants(next)
	if err != nil {
		return 0, 0, 0, err
	}
	wantKeys := map[string]struct{}{}
	for _, wants := range byMask {
		for _, w := range wants {
			wantKeys[w.key] = struct{}{}
		}
	}

	// Delete prev members of this pool no longer desired. DELTA divergence: the delta
	// path cannot see the whole table, so it drives deletes from the pool's pre-delta
	// member record (prev), not the full reconcile's orphan sweep.
	for _, s := range prev {
		key, err := vpp.SessionKey(s.Mask, s.Prefix)
		if err != nil {
			return added, deleted, moved, err
		}
		if _, keep := wantKeys[sessionMapKey(s.Mask, hex.EncodeToString(key))]; keep {
			continue // still desired; handled below (add-or-move)
		}
		table, ok := tables[s.Mask]
		if !ok {
			continue
		}
		if err := cl.DelSessionByKey(table, s.Mask, key); err != nil {
			return added, deleted, moved, err
		}
		r.actSess.Add(-1)
		deleted++
	}

	// Add missing / re-point moved, per mask. DELTA divergence: actualHit comes from an
	// O(pool) POINT-LOOKUP (probe_classify_lookup) of just this pool's desired members,
	// NOT a whole-table dump — a member add/remove no longer serializes the edge-wide
	// shared mask table across VPP's main thread. The add/move decision itself is shared
	// with the full reconcile (applySessionUpserts).
	for mask, wants := range byMask {
		table, err := r.ensureTable(cl, tables, mask)
		if err != nil {
			return added, deleted, moved, err
		}
		prefixes := make([]netip.Prefix, len(wants))
		for i, w := range wants {
			prefixes[i] = w.prefix
		}
		hits, err := cl.LookupHits(table, mask, prefixes)
		if err != nil {
			return added, deleted, moved, fmt.Errorf("agent: delta: lookup sessions: %w", err)
		}
		actualHit := make(map[string]uint32, len(wants))
		for i, w := range wants {
			if hits[i] != vpp.NoTable {
				actualHit[w.key] = hits[i]
			}
		}
		a, m, err := applySessionUpserts(cl, table, wants, actualHit)
		r.actSess.Add(int64(a))
		if err != nil {
			return added, deleted, moved, err
		}
		added += a
		moved += m
	}
	_ = pool // pool is the scoping identity; sessions already filtered to it by caller
	return added, deleted, moved, nil
}
