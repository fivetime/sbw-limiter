package agent

import (
	"log/slog"
	"strings"
	"time"

	"github.com/fivetime/sbw-contract/model"

	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// dumpTimeout bounds the report-time sw_interface_dump so a wedged/slow VPP main thread
// cannot block the report goroutine (Fault runs on Reporter.Build). A dump that exceeds
// it is treated as "undetermined link state", NOT a stall of the whole report path.
// 5s (not govpp's 2s default) matches vpp.WithReplyTimeout: VPP's single busy-poll main
// thread legitimately takes >2s to answer a multipart dump under packet+API contention,
// which is slow-not-wedged (< the 15s report interval). See vpp-single-mainthread-bottleneck.
const dumpTimeout = 5 * time.Second

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
	// apiDead is the transport-level VPP-process liveness (SocketWatcher.Dead,
	// §6.44): the api socket has been un-dialable for K consecutive checks. It
	// covers govpp's stalled-health-probe blind spot, where conn.Healthy() reads
	// true for up to the 30s reply timeout after the process died. nil → disabled.
	apiDead func() bool
	log     *slog.Logger
}

// NewFaultSensor builds a sensor over a live VPP connection. policerIfaces is the
// member/data interface set (cfg.PolicerInterfaces). Each Fault() call opens a
// short-lived channel for the dump (only when the connection is healthy).
// broken is the §4.2.7 forwarding-probe verdict (ForwardingProbe.Broken); nil
// disables the ③ path. apiDead is the transport-level process liveness
// (SocketWatcher.Dead, §6.44); nil disables that supplement.
func NewFaultSensor(conn *vpp.Conn, policerIfaces []string, broken, apiDead func() bool, log *slog.Logger) *FaultSensor {
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
			ch.SetReplyTimeout(dumpTimeout) // never block the report path on a wedged main thread
			return vpp.NewInterfaces(ch).List()
		},
		policerIfaces: policerIfaces,
		broken:        broken,
		apiDead:       apiDead,
		log:           log,
	}
}

// Fault returns the current determinate fault kind + a human reason, or FaultNone with
// an empty reason when no determinate fault is observed.
func (s *FaultSensor) Fault() (model.FaultKind, string) {
	if !s.healthy() {
		return model.FaultVPPGone, "vpp control link down (api.sock EOF)"
	}
	// govpp can claim healthy for up to its 30s reply timeout after the process
	// died (a health probe whose write buffered just before death stalls with no
	// EPIPE chance — §6.44). The socket watcher's K-consecutive un-dialable is
	// hard transport-level evidence the process is GONE, immune to a busy main
	// thread; type ① from it even while conn.Healthy() lies.
	if s.apiDead != nil && s.apiDead() {
		return model.FaultVPPGone, "vpp api socket un-dialable (process gone; health-check stalled)"
	}
	list, err := s.dumpIfaces()
	if err != nil {
		// Raced down between the health check and the dump, or a slow/wedged main thread
		// timed the dump out. If the connection is now down it IS vpp-gone.
		if !s.healthy() {
			return model.FaultVPPGone, "vpp control link down (dump failed)"
		}
		// VPP is up but we couldn't read link state. A dump failure must NOT MASK a
		// probe-confirmed ③ — the forwarding probe is authoritative for forwarding-broken
		// and does not depend on the dump; report it (a wedged main thread that also
		// black-holes forwarding is exactly a case we want to catch, not swallow).
		if s.broken != nil && s.broken() {
			return model.FaultForwardingBroken, "forwarding probe: path black-holed (interface dump unavailable)"
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
