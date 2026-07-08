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
// sessionMapKey namespaces a session's VPP match key by its mask. The SAME /128
// address under different masks — notably ip6-dst-128 (ingress) vs ip6-src-128
// (egress) of one member — produces a BYTE-IDENTICAL VPP match key (vpp.SessionKey
// encodes only the masked address, dropping the mask/direction). An un-namespaced
// desired map therefore collides a member's ingress and egress sessions: the second
// overwrites the first, so only ONE mask's table is ever created — v6 ingress ended
// up with no dst table at all and its traffic went unpoliced/uncounted. The VPP
// match bytes are unchanged; this is purely the in-memory map key. (The full
// reconcile path was already immune: it nests its desired map by mask.)
func sessionMapKey(mask model.MaskKind, keyHex string) string {
	return mask.String() + "\x00" + keyHex
}

func (r *Reconciler) upsertPoolSessions(cl classifyReconciler, pool model.PoolID, prev, next []model.ClassifySession) (added, deleted, moved int, err error) {
	tables, err := cl.FindTablesByMask()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("agent: delta: find tables: %w", err)
	}

	type want struct {
		mask    model.MaskKind
		prefix  netip.Prefix
		hitNext uint32
	}
	// Desired key → want (within this pool), and the set of masks this pool uses.
	wantByKey := map[string]want{}
	masks := map[model.MaskKind]struct{}{}
	for _, s := range next {
		idx, ok := r.polIdx[s.PolicerName]
		if !ok {
			return added, deleted, moved, fmt.Errorf("agent: delta: classify session %s references unknown policer %q", s.Prefix, s.PolicerName)
		}
		key, err := vpp.SessionKey(s.Mask, s.Prefix)
		if err != nil {
			return added, deleted, moved, err
		}
		wantByKey[sessionMapKey(s.Mask, hex.EncodeToString(key))] = want{s.Mask, s.Prefix, idx}
		masks[s.Mask] = struct{}{}
	}

	// Delete prev members of this pool no longer desired.
	for _, s := range prev {
		key, err := vpp.SessionKey(s.Mask, s.Prefix)
		if err != nil {
			return added, deleted, moved, err
		}
		if _, keep := wantByKey[sessionMapKey(s.Mask, hex.EncodeToString(key))]; keep {
			continue // still desired; handled below (add-or-move)
		}
		table, ok := tables[s.Mask]
		if !ok {
			continue
		}
		if err := cl.DelSessionByKey(table, s.Mask, key); err != nil {
			return added, deleted, moved, err
		}
		deleted++
	}

	// Read back the ACTUAL installed sessions for just this pool's masks, so a member
	// already present at a different hit index is re-pointed (moved), and an unchanged
	// one is a no-op. Scoped to the pool's mask tables — not a whole-edge dump.
	actualHit := map[string]uint32{} // matchKey → installed hit index
	for mask := range masks {
		table, ok := tables[mask]
		if !ok {
			continue
		}
		ss, err := cl.DumpSessions(table)
		if err != nil {
			return added, deleted, moved, fmt.Errorf("agent: delta: dump sessions: %w", err)
		}
		for _, s := range ss {
			actualHit[sessionMapKey(mask, hex.EncodeToString(s.Match))] = s.HitNextIndex
		}
	}

	// Add new / re-point moved. AddSession on an existing key is an atomic overwrite
	// (§5.3), so a moved member is a single AddSession with the new hit index.
	for keyHex, w := range wantByKey {
		table, ok := tables[w.mask]
		if !ok {
			table, err = cl.AddTable(vpp.TableSpec{Mask: w.mask, Nbuckets: r.classifyNbuckets, MemorySize: r.classifyMem})
			if err != nil {
				return added, deleted, moved, err
			}
			tables[w.mask] = table
			r.log.Info("delta: created classify table", "mask", w.mask, "index", table)
		}
		curHit, present := actualHit[keyHex]
		switch {
		case !present:
			if err := cl.AddSession(table, w.mask, w.prefix, w.hitNext); err != nil {
				return added, deleted, moved, err
			}
			added++
		case curHit != w.hitNext:
			if err := cl.AddSession(table, w.mask, w.prefix, w.hitNext); err != nil {
				return added, deleted, moved, err
			}
			moved++
		}
	}
	_ = pool // pool is the scoping identity; sessions already filtered to it by caller
	return added, deleted, moved, nil
}
