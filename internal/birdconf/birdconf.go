// Package birdconf renders the baseline edge bird.conf (T-304, DESIGN.md
// §4.3/§4.5): kernel protocols with the dual anchor-leak guard and graceful
// restart (§1.1-2), the upstream eBGP template with the to_upstream export
// filter (no-export + INT_LC stripping), the controller tap iBGP session with
// the scope-narrowed to_tap filter (§6.3-5), the canary static (§6.3-2), and
// the anchors include managed by the Applier (T-303).
//
// The rendered file is the agent-owned baseline; only the anchors include
// changes at runtime. Rendering is deterministic for a given Config.
package birdconf

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"text/template"

	"github.com/fivetime/sbw-contract/model"
)

// Upstream is one upstream eBGP session instantiated from the template.
type Upstream struct {
	Name         string // BIRD protocol name, e.g. "upstream1"
	NeighborAddr netip.Addr
	NeighborASN  uint32
	NeighborPort uint16 // 0 = default 179
	Password     string // optional TCP-MD5
}

// IntLC is the internal-signaling large-community range (ASN, From..To, *)
// stripped from everything exported upstream (§4.5).
type IntLC struct {
	ASN  uint32
	From uint32
	To   uint32
}

// Config parameterizes the baseline. Zero-value optional sections are omitted
// from the output.
type Config struct {
	RouterID netip.Addr // required, IPv4
	LocalASN uint32     // required
	LogFile  string     // optional "log <file> all;"

	// LocalAddr + StrictBind pin the BGP listener to one address — required
	// when multiple BIRD instances share a host (tests), optional in prod.
	LocalAddr  netip.Addr
	StrictBind bool

	// Kernel protocols (§4.3). Disable only on hosts where BIRD must not
	// touch the kernel RIB.
	Kernel               bool
	KernelScanTime       int // default 10
	MergePathsLimit      int // default 16
	NetlinkRxBufferBytes int // default 128 MiB (§1.1-3 alignment)

	BFD bool // emit protocol bfd + bfd on in the upstream template

	// BFD desensitization on the upstream session (§2.6/§4.3): not as aggressive
	// as possible — trade fast detection for jitter immunity, paired with LLGR.
	// Zero values fall back to BIRD defaults. Tune from the T-106 RTT profile.
	BFDIntervalMs int // tx/rx interval in ms (e.g. 300)
	BFDMultiplier int // detection multiplier (e.g. 3)

	// LLGR on the upstream session (§2.6/§4.3): on a BFD flap, keep the learned
	// routes as stale rather than withdrawing immediately, closing the
	// "jitter → /32 momentary withdraw → traffic falls back to the normal path
	// unmetered" window. NOTE: the retention that closes the leak window happens
	// on the MX204 side (it must be a GR/LLGR helper for this session, T-102);
	// this only configures the edge side.
	LLGR          bool
	LLGRStaleTime int // "long lived stale time <sec>"; default 3600 when LLGR on

	Upstreams []Upstream

	// Tap session to the controller (§6.2): import none, export to_tap.
	TapEnabled      bool
	TapNeighborAddr netip.Addr
	TapNeighborPort uint16 // 1790 per DESIGN

	// TapAddPathTx emits "add paths tx" on the tap channels (§4.3/§6.3-6): send
	// ALL paths for a prefix to the guard, not just best-path, so the unique-
	// announcement check can see a second source claiming the same /32. The
	// GoBGP tap peer must enable add-path receive for this to take effect (T-601).
	TapAddPathTx bool

	// Canary statics (§6.3-2): per-edge loopback host routes carrying the
	// canary large community, exported only to the tap.
	CanaryPrefix4 netip.Prefix // optional /32
	CanaryPrefix6 netip.Prefix // optional /128
	CanaryLC      model.LargeCommunity

	IntLC IntLC // zero ASN = omit

	Aggregates4, Aggregates6         []netip.Prefix // MY_AGGREGATES (§4.5)
	FabricInternal4, FabricInternal6 []netip.Prefix // to_tap scope (§6.3-5)

	AnchorsPath string // required: include managed by anchors.Applier
}

func (c Config) withDefaults() Config {
	if c.LLGR && c.LLGRStaleTime == 0 {
		c.LLGRStaleTime = 3600
	}
	if c.KernelScanTime == 0 {
		c.KernelScanTime = 10
	}
	if c.MergePathsLimit == 0 {
		c.MergePathsLimit = 16
	}
	if c.NetlinkRxBufferBytes == 0 {
		c.NetlinkRxBufferBytes = 128 << 20
	}
	return c
}

// Protocol names owned by the template or the anchors include; upstream names
// must not collide with them.
var reservedNames = map[string]bool{
	"anchors4": true, "anchors6": true, // anchors include (T-302)
	"canary4": true, "canary6": true,
	"kernel4": true, "kernel6": true,
	"tap": true, "upstream_tpl": true, "upstream_in": true,
}

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate checks the config for render-blocking errors.
func (c Config) Validate() error {
	if !c.RouterID.Is4() {
		return fmt.Errorf("birdconf: router id must be an IPv4 address")
	}
	if c.LocalASN == 0 {
		return fmt.Errorf("birdconf: local asn must be set")
	}
	if c.AnchorsPath == "" {
		return fmt.Errorf("birdconf: anchors path must be set")
	}
	seen := map[string]bool{}
	for i, u := range c.Upstreams {
		if !nameRe.MatchString(u.Name) {
			return fmt.Errorf("birdconf: upstream[%d] name %q invalid", i, u.Name)
		}
		if reservedNames[u.Name] {
			return fmt.Errorf("birdconf: upstream name %q is reserved", u.Name)
		}
		if seen[u.Name] {
			return fmt.Errorf("birdconf: duplicate upstream name %q", u.Name)
		}
		seen[u.Name] = true
		if !u.NeighborAddr.IsValid() || u.NeighborASN == 0 {
			return fmt.Errorf("birdconf: upstream %q needs neighbor addr and asn", u.Name)
		}
	}
	if c.TapEnabled && (!c.TapNeighborAddr.IsValid() || c.TapNeighborPort == 0) {
		return fmt.Errorf("birdconf: tap requires neighbor addr and port")
	}
	if c.CanaryPrefix4.IsValid() && (!c.CanaryPrefix4.Addr().Is4() || c.CanaryPrefix4.Bits() != 32) {
		return fmt.Errorf("birdconf: canary4 must be an IPv4 /32")
	}
	if c.CanaryPrefix6.IsValid() && (!c.CanaryPrefix6.Addr().Is6() || c.CanaryPrefix6.Bits() != 128) {
		return fmt.Errorf("birdconf: canary6 must be an IPv6 /128")
	}
	if (c.CanaryPrefix4.IsValid() || c.CanaryPrefix6.IsValid()) && c.CanaryLC == (model.LargeCommunity{}) {
		return fmt.Errorf("birdconf: canary requires a large community")
	}
	return nil
}

// Render produces the bird.conf for cfg.
func Render(cfg Config) ([]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	var b strings.Builder
	if err := tpl.Execute(&b, cfg); err != nil {
		return nil, fmt.Errorf("birdconf: render: %w", err)
	}
	return []byte(b.String()), nil
}

func prefixSet(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return "[ " + strings.Join(parts, ", ") + " ]"
}

var tpl = template.Must(template.New("bird.conf").
	Funcs(template.FuncMap{"prefixSet": prefixSet}).
	Parse(`# Managed by bwpool edge-agent — DO NOT EDIT (baseline, T-304).
# DESIGN.md §4.3/§4.5. Anchors live in the include below (T-302/T-303).

router id {{.RouterID}};
{{- if .LogFile}}
log "{{.LogFile}}" all;
{{- end}}

protocol device { scan time 10; }
{{- if .BFD}}

protocol bfd { }
{{- end}}
{{- if .IntLC.ASN}}

# Internal signaling large communities — must never leak upstream (§4.5).
define INT_LC = [({{.IntLC.ASN}}, {{.IntLC.From}}..{{.IntLC.To}}, *)];
{{- end}}
{{- if .Aggregates4}}
define MY_AGGREGATES4 = {{prefixSet .Aggregates4}};
{{- end}}
{{- if .Aggregates6}}
define MY_AGGREGATES6 = {{prefixSet .Aggregates6}};
{{- end}}
{{- if .FabricInternal4}}
define FABRIC_INTERNAL4 = {{prefixSet .FabricInternal4}};
{{- end}}
{{- if .FabricInternal6}}
define FABRIC_INTERNAL6 = {{prefixSet .FabricInternal6}};
{{- end}}

# Anchor-leak guard, two layers (§4.2 / §1.1-2): reject by source protocol
# AND by blackhole dest. An anchor reaching the kernel becomes a DROP in the
# VPP FIB — traffic pulled to this edge would be discarded.
filter krt_export {
  if proto = "anchors4" || proto = "anchors6" then reject;
  if proto = "canary4" || proto = "canary6" then reject;
  if dest = RTD_BLACKHOLE then reject;
  accept;
}
{{- if .Kernel}}

protocol kernel kernel4 {
  ipv4 { import none; export filter krt_export; };
  learn off;
  scan time {{.KernelScanTime}};
  graceful restart on;             # §1.1-2: restart must not flush the in-use table
  merge paths on limit {{.MergePathsLimit}};
  netlink rx buffer {{.NetlinkRxBufferBytes}};
}

protocol kernel kernel6 {
  ipv6 { import none; export filter krt_export; };
  learn off;
  scan time {{.KernelScanTime}};
  graceful restart on;
  merge paths on limit {{.MergePathsLimit}};
  netlink rx buffer {{.NetlinkRxBufferBytes}};
}
{{- end}}

# Upstream import: V1 accepts the full table; outbound TE policy lands here
# later (§4.1).
filter upstream_in { accept; }

# Upstream export (§4.5): anchors get no-export and lose internal LCs; own
# aggregates pass cleaned; everything else (full table, fabric, canary) is
# rejected by default.
filter to_upstream4 {
  if proto = "anchors4" then {
    bgp_community.add((65535, 65281));   # no-export: dies at the first hop
{{- if .IntLC.ASN}}
    bgp_large_community.delete(INT_LC);
{{- end}}
    accept;
  }
{{- if .Aggregates4}}
  if net ~ MY_AGGREGATES4 then {
{{- if .IntLC.ASN}}
    bgp_large_community.delete(INT_LC);
{{- end}}
    accept;
  }
{{- end}}
  reject;
}

filter to_upstream6 {
  if proto = "anchors6" then {
    bgp_community.add((65535, 65281));
{{- if .IntLC.ASN}}
    bgp_large_community.delete(INT_LC);
{{- end}}
    accept;
  }
{{- if .Aggregates6}}
  if net ~ MY_AGGREGATES6 then {
{{- if .IntLC.ASN}}
    bgp_large_community.delete(INT_LC);
{{- end}}
    accept;
  }
{{- end}}
  reject;
}

template bgp upstream_tpl {
  local{{if .LocalAddr.IsValid}} {{.LocalAddr}}{{end}} as {{.LocalASN}};
{{- if .StrictBind}}
  strict bind on;
{{- end}}
  graceful restart on;
{{- if .LLGR}}
  # LLGR (§2.6/§4.3): keep stale routes on a flap instead of withdrawing —
  # closes the "/32 momentary withdraw → fall back to normal path unmetered"
  # window. The peer (MX204) must be a GR/LLGR helper for this to take effect.
  long lived graceful restart on;
  long lived stale time {{.LLGRStaleTime}};
{{- end}}
{{- if .BFD}}
  bfd on;
{{- if or .BFDIntervalMs .BFDMultiplier}}
  # BFD desensitized (§2.6): trade fast detection for jitter immunity.
  bfd {
{{- if .BFDIntervalMs}}
    interval {{.BFDIntervalMs}} ms;
{{- end}}
{{- if .BFDMultiplier}}
    multiplier {{.BFDMultiplier}};
{{- end}}
  };
{{- end}}
{{- end}}
  ipv4 { import filter upstream_in; export filter to_upstream4; next hop self; };
  ipv6 { import filter upstream_in; export filter to_upstream6; next hop self; };
}
{{- range .Upstreams}}

protocol bgp {{.Name}} from upstream_tpl {
  neighbor {{.NeighborAddr}}{{if .NeighborPort}} port {{.NeighborPort}}{{end}} as {{.NeighborASN}};
{{- if .Password}}
  password "{{.Password}}";
{{- end}}
}
{{- end}}
{{- if .CanaryPrefix4.IsValid}}

# Canary (§6.3-2): always-exported host route proving this edge's tap view is
# live end-to-end. Blackhole dest keeps it out of the kernel via krt_export.
protocol static canary4 {
  ipv4 { table master4; };
  route {{.CanaryPrefix4}} blackhole {
    bgp_large_community.add(({{.CanaryLC.GlobalAdmin}}, {{.CanaryLC.LocalData1}}, {{.CanaryLC.LocalData2}}));
  };
}
{{- end}}
{{- if .CanaryPrefix6.IsValid}}

protocol static canary6 {
  ipv6 { table master6; };
  route {{.CanaryPrefix6}} blackhole {
    bgp_large_community.add(({{.CanaryLC.GlobalAdmin}}, {{.CanaryLC.LocalData1}}, {{.CanaryLC.LocalData2}}));
  };
}
{{- end}}
{{- if .TapEnabled}}

# Controller tap (§6.2/§6.3-5): export only canary + fabric-internal scope —
# never the upstream full table. The controller side never advertises
# (ExportPolicy=REJECT there); import none here is defense in depth.
filter to_tap4 {
{{- if .CanaryPrefix4.IsValid}}
  if proto = "canary4" then accept;
{{- end}}
{{- if .FabricInternal4}}
  if net ~ FABRIC_INTERNAL4 then accept;
{{- end}}
  reject;
}

filter to_tap6 {
{{- if .CanaryPrefix6.IsValid}}
  if proto = "canary6" then accept;
{{- end}}
{{- if .FabricInternal6}}
  if net ~ FABRIC_INTERNAL6 then accept;
{{- end}}
  reject;
}

protocol bgp tap {
  local{{if .LocalAddr.IsValid}} {{.LocalAddr}}{{end}} as {{.LocalASN}};
{{- if .StrictBind}}
  strict bind on;
{{- end}}
  neighbor {{.TapNeighborAddr}} port {{.TapNeighborPort}} as {{.LocalASN}};
  multihop;
{{- if .TapAddPathTx}}
  # Add-Path tx (§4.3/§6.3-6): send ALL paths for a prefix to the guard, not
  # just best-path, so the unique-announcement check sees a second source
  # claiming the same /32. The GoBGP tap peer must enable add-path receive.
  ipv4 { import none; export filter to_tap4; add paths tx; };
  ipv6 { import none; export filter to_tap6; add paths tx; };
{{- else}}
  ipv4 { import none; export filter to_tap4; };
  ipv6 { import none; export filter to_tap6; };
{{- end}}
}
{{- end}}

include "{{.AnchorsPath}}";
`))
