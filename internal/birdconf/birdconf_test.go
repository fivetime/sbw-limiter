package birdconf

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

func fullConfig() Config {
	return Config{
		RouterID:      netip.MustParseAddr("10.0.0.1"),
		LocalASN:      65010,
		Kernel:        true,
		BFD:           true,
		BFDIntervalMs: 300,
		BFDMultiplier: 3,
		LLGR:          true,
		LLGRStaleTime: 3600,
		TapAddPathTx:  true,
		Upstreams: []Upstream{
			{Name: "upstream1", NeighborAddr: netip.MustParseAddr("198.51.100.1"), NeighborASN: 65001},
			{Name: "upstream2", NeighborAddr: netip.MustParseAddr("198.51.100.5"), NeighborASN: 65002, NeighborPort: 1179, Password: "s3cret"},
		},
		TapEnabled:      true,
		TapNeighborAddr: netip.MustParseAddr("10.0.0.100"),
		TapNeighborPort: 1790,
		CanaryPrefix4:   netip.MustParsePrefix("10.255.255.1/32"),
		CanaryPrefix6:   netip.MustParsePrefix("2001:db8:ffff::1/128"),
		CanaryLC:        model.LargeCommunity{GlobalAdmin: 65010, LocalData1: 0, LocalData2: 1},
		IntLC:           IntLC{ASN: 65010, From: 100, To: 199},
		Aggregates4:     []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		FabricInternal4: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		AnchorsPath:     "/etc/bird/anchors.conf",
	}
}

func renderString(t *testing.T, c Config) string {
	t.Helper()
	out, err := Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return string(out)
}

func TestRenderContainsCriticalSections(t *testing.T) {
	s := renderString(t, fullConfig())

	mustContain := []string{
		// dual leak guard (§4.2 / §1.1-2)
		`if proto = "anchors4" || proto = "anchors6" then reject;`,
		`if dest = RTD_BLACKHOLE then reject;`,
		// kernel hardening
		"graceful restart on;",
		"merge paths on limit 16;",
		"netlink rx buffer 134217728;",
		"learn off;",
		// upstream export: no-export + INT_LC strip
		"bgp_community.add((65535, 65281));",
		"define INT_LC = [(65010, 100..199, *)];",
		"bgp_large_community.delete(INT_LC);",
		"if net ~ MY_AGGREGATES4 then {",
		// upstream instances
		"protocol bgp upstream1 from upstream_tpl {",
		"neighbor 198.51.100.1 as 65001;",
		"neighbor 198.51.100.5 port 1179 as 65002;",
		`password "s3cret";`,
		// canary with LC
		"protocol static canary4 {",
		"route 10.255.255.1/32 blackhole {",
		"bgp_large_community.add((65010, 0, 1));",
		// tap scope narrowing
		`if proto = "canary4" then accept;`,
		"if net ~ FABRIC_INTERNAL4 then accept;",
		"neighbor 10.0.0.100 port 1790 as 65010;",
		"import none; export filter to_tap4;",
		// anchors include
		`include "/etc/bird/anchors.conf";`,
		// bfd
		"protocol bfd { }",
		"bfd on;",
		// bfd desensitization (§2.6/§4.3)
		"interval 300 ms;",
		"multiplier 3;",
		// LLGR (§2.6/§4.3)
		"long lived graceful restart on;",
		"long lived stale time 3600;",
		// tap add-path (§4.3/§6.3-6)
		"export filter to_tap4; add paths tx;",
	}
	for _, want := range mustContain {
		if !strings.Contains(s, want) {
			t.Errorf("rendered config missing %q", want)
		}
	}
}

func TestRenderOmitsDisabledSections(t *testing.T) {
	c := fullConfig()
	c.Kernel = false
	c.BFD = false
	c.LLGR = false
	c.TapEnabled = false
	c.CanaryPrefix4 = netip.Prefix{}
	c.CanaryPrefix6 = netip.Prefix{}
	c.CanaryLC = model.LargeCommunity{}
	c.IntLC = IntLC{}
	c.Aggregates4 = nil
	c.FabricInternal4 = nil
	s := renderString(t, c)

	mustNotContain := []string{
		"protocol kernel", "protocol bfd", "bfd on;",
		"protocol bgp tap", "protocol static canary4", "INT_LC", "MY_AGGREGATES4", "FABRIC_INTERNAL4",
		"long lived graceful restart", "add paths tx",
	}
	for _, bad := range mustNotContain {
		if strings.Contains(s, bad) {
			t.Errorf("rendered config should omit %q", bad)
		}
	}
	// The leak-guard filter must remain even without kernel protocols (harmless,
	// and present if kernel is enabled later by hand).
	if !strings.Contains(s, "filter krt_export") {
		t.Error("krt_export filter must always be rendered")
	}
}

func TestRenderDeterministic(t *testing.T) {
	a := renderString(t, fullConfig())
	b := renderString(t, fullConfig())
	if a != b {
		t.Error("render is not deterministic")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"no router id", func(c *Config) { c.RouterID = netip.Addr{} }},
		{"v6 router id", func(c *Config) { c.RouterID = netip.MustParseAddr("2001:db8::1") }},
		{"no asn", func(c *Config) { c.LocalASN = 0 }},
		{"no anchors path", func(c *Config) { c.AnchorsPath = "" }},
		{"reserved upstream name", func(c *Config) { c.Upstreams[0].Name = "anchors4" }},
		{"duplicate upstream name", func(c *Config) { c.Upstreams[1].Name = "upstream1" }},
		{"bad upstream name", func(c *Config) { c.Upstreams[0].Name = "up stream" }},
		{"upstream no asn", func(c *Config) { c.Upstreams[0].NeighborASN = 0 }},
		{"tap without port", func(c *Config) { c.TapNeighborPort = 0 }},
		{"canary4 not /32", func(c *Config) { c.CanaryPrefix4 = netip.MustParsePrefix("10.0.0.0/24") }},
		{"canary without LC", func(c *Config) { c.CanaryLC = model.LargeCommunity{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fullConfig()
			tc.mut(&c)
			if _, err := Render(c); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}
