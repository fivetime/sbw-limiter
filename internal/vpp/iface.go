package vpp

import (
	"fmt"

	govppapi "go.fd.io/govpp/api"

	vppif "github.com/fivetime/sbw-limiter/internal/binapi/interface"
	"github.com/fivetime/sbw-limiter/internal/binapi/interface_types"
)

// Interfaces resolves VPP interface names to sw_if_index (T-410): the agent's
// config names interfaces (uplink/core/inter-edge); the policer-classify
// attach materializer needs the numeric sw_if_index. VPP assigns indexes at
// runtime, so the agent must look them up.
type Interfaces struct {
	ch govppapi.Channel
}

// NewInterfaces wraps a channel for interface lookups.
func NewInterfaces(ch govppapi.Channel) *Interfaces { return &Interfaces{ch: ch} }

// Interface is a name→index pair read from VPP.
type Interface struct {
	Name      string
	SwIfIndex uint32
	Up        bool // ADMIN_UP (operator intent): the interface is administratively enabled
	LinkUp    bool // LINK_UP (physical carrier): the link is actually up (cable in, peer up)
}

// List dumps all interfaces.
func (i *Interfaces) List() ([]Interface, error) {
	var out []Interface
	err := dumpAll(i.ch, "sw_interface_dump",
		&vppif.SwInterfaceDump{SwIfIndex: interface_types.InterfaceIndex(NoTable)},
		func(d *vppif.SwInterfaceDetails) {
			out = append(out, Interface{
				Name:      d.InterfaceName,
				SwIfIndex: uint32(d.SwIfIndex),
				Up:        d.Flags&interfaceFlagAdminUp != 0,
				LinkUp:    d.Flags&interfaceFlagLinkUp != 0,
			})
		})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// interfaceFlagAdminUp / interfaceFlagLinkUp are IF_STATUS_API_FLAG_ADMIN_UP (bit 0) /
// IF_STATUS_API_FLAG_LINK_UP (bit 1) — operator intent vs physical carrier. A pulled
// cable / down peer clears LINK_UP while ADMIN_UP stays set (§4.2 fault ②).
const (
	interfaceFlagAdminUp = 1
	interfaceFlagLinkUp  = 2
)

// IndexMap resolves several names at once, returning a name→index map. Missing
// names are reported together.
func (i *Interfaces) IndexMap(names ...string) (map[string]uint32, error) {
	list, err := i.List()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]uint32, len(list))
	for _, iface := range list {
		byName[iface.Name] = iface.SwIfIndex
	}
	out := make(map[string]uint32, len(names))
	var missing []string
	for _, n := range names {
		if idx, ok := byName[n]; ok {
			out[n] = idx
		} else {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return out, fmt.Errorf("vpp: interfaces not found: %v", missing)
	}
	return out, nil
}
