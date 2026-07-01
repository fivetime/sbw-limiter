package agent

import (
	"log/slog"
	"strings"

	"github.com/fivetime/sbw-contract/model"

	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// FaultSensor types the edge's data-plane fault kind (DESIGN-liveness §4.2.3) from
// LIVE signals, independent of the slow reconcile pass, so a DETERMINATE fault reaches
// the controller within one report interval rather than one reconcile interval:
//
//   - ① vpp-gone   — the binary-API connection is down (api.sock EOF): the whole data
//     plane is unreachable. Read straight off vpp.Conn.Healthy(), which flips
//     asynchronously on the connection event, so there is no polling lag.
//   - ② link-down  — a policer (member/data) interface has its physical carrier down
//     while still administratively up: a pulled cable / dead peer. Read from a fresh
//     sw_interface_dump of the named interfaces (LINK_UP bit).
//
// It deliberately does NOT type the ambiguous faults (③ forwarding-broken needs an
// active probe, ④ loss needs per-member metering): Fault returns FaultNone for those,
// leaving the reconcile-derived soft-death classification (and the server's canary∧
// health conjunction) to stand. The server routes each kind to its own failover speed
// (§4.2.4): vpp-gone → short restart grace, link-down → immediate.
type FaultSensor struct {
	// healthy is the live binary-API connection liveness (vpp.Conn.Healthy).
	healthy func() bool
	// dumpIfaces returns VPP's current interface list (a fresh sw_interface_dump).
	dumpIfaces func() ([]vpp.Interface, error)
	// policerIfaces are the interface names carrying member traffic (the same set the
	// reconcile attaches policer-classify to); a link-down on any of them breaks
	// forwarding for this edge's members.
	policerIfaces []string
	// broken is the §4.2.7 device-level forwarding-probe verdict (③): true once the
	// active probe has seen K consecutive black-holed rounds. nil → ③ disabled.
	broken func() bool
	log    *slog.Logger
}

// NewFaultSensor builds a sensor over a live VPP connection. policerIfaces is the
// member/data interface set (cfg.PolicerInterfaces). Each Fault() call opens a
// short-lived channel for the dump (only when the connection is healthy).
// NewFaultSensor builds a sensor over a live VPP connection. broken is the §4.2.7
// forwarding-probe verdict (ForwardingProbe.Broken); nil disables the ③ path.
func NewFaultSensor(conn *vpp.Conn, policerIfaces []string, broken func() bool, log *slog.Logger) *FaultSensor {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &FaultSensor{
		healthy: conn.Healthy,
		dumpIfaces: func() ([]vpp.Interface, error) {
			ch, err := conn.Channel()
			if err != nil {
				return nil, err
			}
			defer ch.Close()
			return vpp.NewInterfaces(ch).List()
		},
		policerIfaces: policerIfaces,
		broken:        broken,
		log:           log,
	}
}

// Fault returns the current determinate fault kind + a human reason, or FaultNone with
// an empty reason when no determinate fault is observed.
func (s *FaultSensor) Fault() (model.FaultKind, string) {
	if !s.healthy() {
		return model.FaultVPPGone, "vpp control link down (api.sock EOF)"
	}
	list, err := s.dumpIfaces()
	if err != nil {
		// Raced down between the health check and the dump, or a transient channel
		// error. If the connection is now down it IS vpp-gone; otherwise leave the fault
		// untyped (the reconcile pass will classify it) rather than guess.
		if !s.healthy() {
			return model.FaultVPPGone, "vpp control link down (dump failed)"
		}
		s.log.Warn("fault sensor: interface dump failed; not typing the fault", "err", err)
		return model.FaultNone, ""
	}
	if down := linkDownAmong(list, s.policerIfaces); len(down) > 0 {
		return model.FaultLinkDown, "link down on " + strings.Join(down, ",")
	}
	// ③ forwarding-broken (§4.2.7): VPP up + links up, but the active probe sees a
	// silent black-hole. Ranked LAST — an unambiguous vpp-gone/link-down explains the
	// probe failure and is preferred; only an otherwise-healthy edge that still can't
	// forward is a genuine ③.
	if s.broken != nil && s.broken() {
		return model.FaultForwardingBroken, "forwarding probe: path black-holed (device up, not forwarding)"
	}
	return model.FaultNone, ""
}

// linkDownAmong returns the named interfaces whose physical carrier is down while they
// are administratively up — a pulled cable / dead peer (§4.2 fault ②). An admin-down
// interface is an OPERATOR action (decommission), not a fault, so it is excluded; a
// name missing from the dump is left to the reconcile pass (undetermined here).
func linkDownAmong(list []vpp.Interface, names []string) []string {
	byName := make(map[string]vpp.Interface, len(list))
	for _, i := range list {
		byName[i.Name] = i
	}
	var down []string
	for _, n := range names {
		if i, ok := byName[n]; ok && i.Up && !i.LinkUp {
			down = append(down, n)
		}
	}
	return down
}
