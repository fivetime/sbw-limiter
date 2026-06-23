package flowspec

import (
	"bytes"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

func fr(p string) model.FlowRedirect {
	return model.FlowRedirect{SrcPrefix: netip.MustParsePrefix(p)}
}

const goldenTwo = `# Managed by sbw-limiter edge-agent — DO NOT EDIT (rendered, B-01).
# Egress-homing FlowSpec (limiter §3.2): "source ∈ home member → redirect to
# this edge". Exported to all R (export filter), never to fabric (export none).
# Reloaded via: atomic rename + configure check + configure (§4.4).
protocol static flowspec4 {
  flow4 { table flowtab4; };
  route flow4 { src 10.0.0.0/24; } {
    bgp_ext_community.add((generic, 0x010c0a00, 0x00050000));
  };
  route flow4 { src 10.20.0.0/24; } {
    bgp_ext_community.add((generic, 0x010c0a00, 0x00050000));
  };
}
protocol static flowspec6 {
  flow6 { table flowtab6; };
}
`

func TestRenderGolden(t *testing.T) {
	out, err := Render([]model.FlowRedirect{fr("10.20.0.0/24"), fr("10.0.0.0/24")}, netip.MustParseAddr("10.0.0.5"), netip.Addr{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(out) != goldenTwo {
		t.Errorf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", out, goldenTwo)
	}
}

func TestRenderDeterministicUnderShuffle(t *testing.T) {
	base := []model.FlowRedirect{fr("10.0.0.0/24"), fr("10.20.0.0/24"), fr("10.1.2.0/24"), fr("203.0.113.5/32")}
	nh := netip.MustParseAddr("10.0.0.5")
	want, err := Render(base, nh, netip.Addr{})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		shuf := append([]model.FlowRedirect(nil), base...)
		r.Shuffle(len(shuf), func(a, b int) { shuf[a], shuf[b] = shuf[b], shuf[a] })
		got, err := Render(shuf, nh, netip.Addr{})
		if err != nil {
			t.Fatalf("Render shuffle: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("non-deterministic output for shuffle %d", i)
		}
	}
}

func TestRenderEmptyEmitsProtocol(t *testing.T) {
	// Empty set must still emit the protocol block so the export filter's name
	// resolves. No next-hop needed when there are no redirects.
	out, err := Render(nil, netip.Addr{}, netip.Addr{})
	if err != nil {
		t.Fatalf("Render(nil): %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "protocol static flowspec4 {") || !strings.Contains(s, "protocol static flowspec6 {") {
		t.Errorf("empty render must emit both protocol blocks:\n%s", s)
	}
	if strings.Contains(s, "route flow4") || strings.Contains(s, "route flow6") {
		t.Errorf("empty render should have no routes:\n%s", s)
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	nh := netip.MustParseAddr("10.0.0.5")
	cases := []struct {
		name      string
		redirects []model.FlowRedirect
		nextHop   netip.Addr
	}{
		{"host bits set", []model.FlowRedirect{fr("10.20.0.1/24")}, nh},
		{"v6 source no v6 next-hop", []model.FlowRedirect{{SrcPrefix: netip.MustParsePrefix("2001:db8::5/128")}}, nh},
		{"duplicate", []model.FlowRedirect{fr("10.20.0.0/24"), fr("10.20.0.0/24")}, nh},
		{"missing next-hop", []model.FlowRedirect{fr("10.20.0.0/24")}, netip.Addr{}},
		{"v6 next-hop for v4 source", []model.FlowRedirect{fr("10.20.0.0/24")}, netip.MustParseAddr("2001:db8::1")},
		{"invalid prefix", []model.FlowRedirect{{SrcPrefix: netip.Prefix{}}}, nh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Render(c.redirects, c.nextHop, netip.Addr{}); err == nil {
				t.Errorf("expected error for %s, got nil", c.name)
			}
		})
	}
}

// A v6 redirect renders the flowspec6 block with the RFC 5701 IPv6
// address-specific redirect EC (i6ec(0x000c, <v6 next-hop>, 0)).
func TestRenderV6FlowSpec(t *testing.T) {
	nh6 := netip.MustParseAddr("2001:db8:2::1")
	out, err := Render([]model.FlowRedirect{{SrcPrefix: netip.MustParsePrefix("2001:db8::5/128")}}, netip.Addr{}, nh6)
	if err != nil {
		t.Fatalf("Render v6: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "protocol static flowspec6 {") || !strings.Contains(s, "flow6 { table flowtab6; };") {
		t.Errorf("missing flowspec6 block:\n%s", s)
	}
	if !strings.Contains(s, "route flow6 { src 2001:db8::5/128; }") {
		t.Errorf("missing flow6 route:\n%s", s)
	}
	if !strings.Contains(s, "bgp_ipv6_ext_community.add(i6ec(0x000c, 2001:db8:2::1, 0));") {
		t.Errorf("missing/incorrect v6 redirect EC:\n%s", s)
	}
	// No v4 routes when there are no v4 members.
	if strings.Contains(s, "route flow4") {
		t.Errorf("v6-only render should have no flow4 routes:\n%s", s)
	}
}

// A mixed v4+v6 redirect set renders both blocks with their respective ECs.
func TestRenderMixedV4V6(t *testing.T) {
	out, err := Render(
		[]model.FlowRedirect{fr("10.20.0.0/24"), {SrcPrefix: netip.MustParsePrefix("2001:db8::5/128")}},
		netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("2001:db8:2::1"))
	if err != nil {
		t.Fatalf("Render mixed: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "route flow4 { src 10.20.0.0/24; }") {
		t.Errorf("missing flow4 route:\n%s", s)
	}
	if !strings.Contains(s, "route flow6 { src 2001:db8::5/128; }") {
		t.Errorf("missing flow6 route:\n%s", s)
	}
	if !strings.Contains(s, "bgp_ipv6_ext_community.add(i6ec(0x000c, 2001:db8:2::1, 0));") {
		t.Errorf("missing v6 redirect EC:\n%s", s)
	}
}

func TestRedirectExtCommunityEncoding(t *testing.T) {
	// Cross-check against project A's proven A-05b values and the draft-ietf-idr-flowspec-redirect-ip
	// type-0x01 sub-0x0c layout [0x01,0x0c,a,b,c,d,0,0].
	cases := []struct {
		ip     string
		hi, lo uint32
	}{
		{"10.0.0.5", 0x010c0a00, 0x00050000},
		{"10.0.0.6", 0x010c0a00, 0x00060000},
		{"0.0.0.0", 0x010c0000, 0x00000000},
		{"255.255.255.255", 0x010cffff, 0xffff0000},
		{"192.0.2.1", 0x010cc000, 0x02010000},
	}
	for _, c := range cases {
		hi, lo := redirectIP4ExtCommunity(netip.MustParseAddr(c.ip))
		if hi != c.hi || lo != c.lo {
			t.Errorf("%s: got (0x%08x,0x%08x) want (0x%08x,0x%08x)", c.ip, hi, lo, c.hi, c.lo)
		}
	}
}
