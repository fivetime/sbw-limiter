package agent

import (
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// Shared classify-session diff primitives, used by BOTH the full reconcile
// (reconcile.go: whole-table dump + orphan sweep, the drift backstop) and the
// delta hot path (delta.go: per-pool point-lookup). Keeping the key derivation
// and the add/move decision in ONE place is deliberate: the two paths used to
// each re-implement them and DRIFTED — the delta path flattened its desired map
// without namespacing by mask, so a member's ingress ip6-dst-128 and egress
// ip6-src-128 sessions (BYTE-IDENTICAL VPP match keys, since vpp.SessionKey
// encodes only the masked address, not the mask/direction) collided and one
// silently overwrote the other (v6 ingress lost its table entirely). The full
// path was immune only because it happened to nest its map by mask. These
// helpers make that class of drift impossible; the ONLY thing the two callers
// still differ on is how they obtain `actualHit` (dump vs point-lookup) and how
// they drive deletes (orphan-sweep vs prev-driven).

// sessionMapKey namespaces a session's VPP match key by its mask so the ingress
// and egress sessions of one member (same masked address, different mask) never
// collide in an in-memory map.
func sessionMapKey(mask model.MaskKind, keyHex string) string {
	return mask.String() + "\x00" + keyHex
}

// sessionWant is one desired classify session: its identity, hit target (the pool
// policer index), and precomputed mask-namespaced map key.
type sessionWant struct {
	mask    model.MaskKind
	prefix  netip.Prefix
	hitNext uint32
	key     string
}

// buildSessionWants resolves desired sessions to sessionWants grouped by mask,
// taking each hit target from polIdx. Both diff paths call it, so the (collision-
// proof) key derivation can never drift between them.
func (r *Reconciler) buildSessionWants(desired []model.ClassifySession) (map[model.MaskKind][]sessionWant, error) {
	byMask := map[model.MaskKind][]sessionWant{}
	for _, s := range desired {
		idx, ok := r.polIdx[s.PolicerName]
		if !ok {
			return nil, fmt.Errorf("agent: classify session %s references unknown policer %q", s.Prefix, s.PolicerName)
		}
		key, err := vpp.SessionKey(s.Mask, s.Prefix)
		if err != nil {
			return nil, err
		}
		byMask[s.Mask] = append(byMask[s.Mask], sessionWant{
			mask: s.Mask, prefix: s.Prefix, hitNext: idx,
			key: sessionMapKey(s.Mask, hex.EncodeToString(key)),
		})
	}
	return byMask, nil
}

// ensureTable returns the classify table for mask, creating it (and recording it
// in tables) if absent.
func (r *Reconciler) ensureTable(cl classifyReconciler, tables map[model.MaskKind]uint32, mask model.MaskKind) (uint32, error) {
	if t, ok := tables[mask]; ok {
		return t, nil
	}
	t, err := cl.AddTable(vpp.TableSpec{Mask: mask, Nbuckets: r.classifyNbuckets, MemorySize: r.classifyMem})
	if err != nil {
		return 0, err
	}
	tables[mask] = t
	r.log.Info("reconcile: created classify table", "mask", mask, "index", t)
	return t, nil
}

// applySessionUpserts installs each want on table given actualHit (map key →
// currently-installed hit index; a key absent means no session). It Adds a missing
// member and re-points (moves) one whose installed hit index differs — an
// AddSession overwrite either way (§5.3). The two diff paths differ ONLY in how
// they build actualHit (whole-table dump vs point-lookup) and how they delete
// (orphan-sweep vs prev-driven); both of those stay in the caller.
func applySessionUpserts(cl classifyReconciler, table uint32, wants []sessionWant, actualHit map[string]uint32) (added, moved int, err error) {
	for _, w := range wants {
		cur, present := actualHit[w.key]
		switch {
		case !present:
			if err := cl.AddSession(table, w.mask, w.prefix, w.hitNext); err != nil {
				return added, moved, err
			}
			added++
		case cur != w.hitNext:
			if err := cl.AddSession(table, w.mask, w.prefix, w.hitNext); err != nil {
				return added, moved, err
			}
			moved++
		}
	}
	return added, moved, nil
}
