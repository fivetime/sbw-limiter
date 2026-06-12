package anchors

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

func mixedSet() []model.Anchor {
	return []model.Anchor{
		{Prefix: netip.MustParsePrefix("203.0.113.10/32")},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24")},
		{
			Prefix:      netip.MustParsePrefix("198.51.100.66/32"),
			Communities: []model.Community{{ASN: 65001, Value: 666}},
		},
		{
			Prefix: netip.MustParsePrefix("2001:db8::a/128"),
			Communities: []model.Community{
				{ASN: 65001, Value: 666},
				{ASN: 64999, Value: 100},
			},
			LargeCommunities: []model.LargeCommunity{
				{GlobalAdmin: 65010, LocalData1: 0, LocalData2: 1},
			},
		},
	}
}

const golden = `# Managed by bwpool edge-agent — DO NOT EDIT (rendered, T-302).
# Anchors are BGP advertisement carriers only (DESIGN.md §4.4): blackhole
# statics that MUST NOT reach the kernel/VPP FIB (excluded by krt_export,
# §4.2). Reloaded via: atomic rename + configure check + configure (§4.4).
protocol static anchors4 {
  ipv4 { table master4; };
  route 198.51.100.66/32 blackhole {
    bgp_community.add((65001, 666));
  };
  route 203.0.113.0/24 blackhole;
  route 203.0.113.10/32 blackhole;
}

protocol static anchors6 {
  ipv6 { table master6; };
  route 2001:db8::a/128 blackhole {
    bgp_community.add((64999, 100));
    bgp_community.add((65001, 666));
    bgp_large_community.add((65010, 0, 1));
  };
}
`

func TestRenderGolden(t *testing.T) {
	got, err := Render(mixedSet())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(got) != golden {
		t.Errorf("output mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, golden)
	}
}

func TestRenderDeterministicUnderShuffle(t *testing.T) {
	want, err := Render(mixedSet())
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 20; i++ {
		set := mixedSet()
		rng.Shuffle(len(set), func(a, b int) { set[a], set[b] = set[b], set[a] })
		// Shuffle communities inside the v6 anchor too.
		for j := range set {
			cs := set[j].Communities
			rng.Shuffle(len(cs), func(a, b int) { cs[a], cs[b] = cs[b], cs[a] })
		}
		got, err := Render(set)
		if err != nil {
			t.Fatalf("Render(shuffle %d): %v", i, err)
		}
		if string(got) != string(want) {
			t.Fatalf("non-deterministic output on shuffle %d:\n%s", i, got)
		}
	}
}

func TestRenderEmptyEmitsBothProtocols(t *testing.T) {
	got, err := Render(nil)
	if err != nil {
		t.Fatalf("Render(nil): %v", err)
	}
	s := string(got)
	if !strings.Contains(s, "protocol static anchors4 {") ||
		!strings.Contains(s, "protocol static anchors6 {") {
		t.Errorf("empty render must keep both protocol blocks:\n%s", s)
	}
	if strings.Contains(s, "route ") {
		t.Errorf("empty render must contain no routes:\n%s", s)
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		in   []model.Anchor
	}{
		{"invalid prefix", []model.Anchor{{}}},
		{"host bits set", []model.Anchor{{Prefix: netip.MustParsePrefix("203.0.113.10/24")}}},
		{"v4-mapped v6", []model.Anchor{{Prefix: netip.MustParsePrefix("::ffff:203.0.113.10/128")}}},
		{"duplicate", []model.Anchor{
			{Prefix: netip.MustParsePrefix("203.0.113.10/32")},
			{Prefix: netip.MustParsePrefix("203.0.113.10/32"), Communities: []model.Community{{ASN: 1, Value: 2}}},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Render(c.in); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}
