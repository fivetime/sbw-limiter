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
    bgp_ext_community.add((generic, 0x81080a00, 0x00050000));
  };
  route flow4 { src 10.20.0.0/24; } {
    bgp_ext_community.add((generic, 0x81080a00, 0x00050000));
  };
}
`

func TestRenderGolden(t *testing.T) {
	out, err := Render([]model.FlowRedirect{fr("10.20.0.0/24"), fr("10.0.0.0/24")}, netip.MustParseAddr("10.0.0.5"))
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
	want, err := Render(base, nh)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		shuf := append([]model.FlowRedirect(nil), base...)
		r.Shuffle(len(shuf), func(a, b int) { shuf[a], shuf[b] = shuf[b], shuf[a] })
		got, err := Render(shuf, nh)
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
	out, err := Render(nil, netip.Addr{})
	if err != nil {
		t.Fatalf("Render(nil): %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "protocol static flowspec4 {") {
		t.Errorf("empty render missing protocol block:\n%s", s)
	}
	if strings.Contains(s, "route flow4") {
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
		{"ipv6 source", []model.FlowRedirect{{SrcPrefix: netip.MustParsePrefix("2001:db8::/64")}}, nh},
		{"duplicate", []model.FlowRedirect{fr("10.20.0.0/24"), fr("10.20.0.0/24")}, nh},
		{"missing next-hop", []model.FlowRedirect{fr("10.20.0.0/24")}, netip.Addr{}},
		{"ipv6 next-hop", []model.FlowRedirect{fr("10.20.0.0/24")}, netip.MustParseAddr("2001:db8::1")},
		{"invalid prefix", []model.FlowRedirect{{SrcPrefix: netip.Prefix{}}}, nh},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Render(c.redirects, c.nextHop); err == nil {
				t.Errorf("expected error for %s, got nil", c.name)
			}
		})
	}
}

func TestRedirectExtCommunityEncoding(t *testing.T) {
	// Cross-check against project A's proven A-05b values and the RFC 8955
	// type-0x81 sub-0x08 layout [0x81,0x08,a,b,c,d,0,0].
	cases := []struct {
		ip     string
		hi, lo uint32
	}{
		{"10.0.0.5", 0x81080a00, 0x00050000},
		{"10.0.0.6", 0x81080a00, 0x00060000},
		{"0.0.0.0", 0x81080000, 0x00000000},
		{"255.255.255.255", 0x8108ffff, 0xffff0000},
		{"192.0.2.1", 0x8108c000, 0x02010000},
	}
	for _, c := range cases {
		hi, lo := redirectIP4ExtCommunity(netip.MustParseAddr(c.ip))
		if hi != c.hi || lo != c.lo {
			t.Errorf("%s: got (0x%08x,0x%08x) want (0x%08x,0x%08x)", c.ip, hi, lo, c.hi, c.lo)
		}
	}
}
