package leakcheck

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// --- parsing -----------------------------------------------------------------

func TestParseRouteLinePrefix(t *testing.T) {
	cases := []struct {
		line string
		want string // "" = skipped
	}{
		{"203.0.113.0/24 dev vedge proto bird scope link", "203.0.113.0/24"},
		{"blackhole 203.0.113.10", "203.0.113.10/32"},   // the leak form
		{"unreachable 203.0.113.20", "203.0.113.20/32"}, // also a leak form
		{"10.0.0.0/24 dev vedge proto kernel scope link", "10.0.0.0/24"},
		{"default via 10.0.0.2 dev vedge", ""},
		{"local 10.0.0.1 dev vedge table local", "10.0.0.1/32"},
		{"2001:db8::a via fe80::1 dev vedge", "2001:db8::a/128"},
		{"2001:db8::/64 dev vedge", "2001:db8::/64"},
		{"", ""},
		{"   ", ""},
		{"blackhole", ""}, // malformed, no prefix
	}
	for _, c := range cases {
		got, ok := parseRouteLinePrefix(c.line)
		if c.want == "" {
			if ok {
				t.Errorf("%q: expected skip, got %v", c.line, got)
			}
			continue
		}
		if !ok || got != netip.MustParsePrefix(c.want) {
			t.Errorf("%q: got (%v,%v), want %s", c.line, got, ok, c.want)
		}
	}
}

// --- fakes -------------------------------------------------------------------

type fakeRunner struct {
	v4, v6 string
	err    error
}

func (f fakeRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	for _, a := range args {
		if a == "-6" {
			return []byte(f.v6), nil
		}
	}
	return []byte(f.v4), nil
}

func kernelLister(v4, v6 string) *KernelLister {
	return &KernelLister{runner: fakeRunner{v4: v4, v6: v6}, v4Args: []string{"-4", "route", "show"}, v6Args: []string{"-6", "route", "show"}}
}

type fakeExported struct {
	byProto map[string][]netip.Prefix
	err     error
}

func (f fakeExported) ShowRouteExported(proto string) ([]netip.Prefix, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byProto[proto], nil
}

type fakeLister struct {
	name string
	set  map[netip.Prefix]struct{}
	err  error
}

func (f fakeLister) Name() string { return f.name }
func (f fakeLister) ListPrefixes(context.Context) (map[netip.Prefix]struct{}, error) {
	return f.set, f.err
}

func prefixSet(ps ...string) map[netip.Prefix]struct{} {
	m := make(map[netip.Prefix]struct{})
	for _, p := range ps {
		m[netip.MustParsePrefix(p)] = struct{}{}
	}
	return m
}

// --- checker -----------------------------------------------------------------

var anchorPrefixes = []netip.Prefix{
	netip.MustParsePrefix("203.0.113.10/32"),
	netip.MustParsePrefix("2001:db8::a/128"),
}

func TestCheckClean(t *testing.T) {
	c := Checker{
		Kernel: kernelLister(
			"10.0.0.0/24 dev vedge\ndefault via 10.0.0.2\n",
			"2001:db8:1::/64 dev vedge\n",
		),
		BirdExported: NewBirdExportedLister(fakeExported{byProto: map[string][]netip.Prefix{
			"upstream1": anchorPrefixes,
		}}, "upstream1"),
	}
	rep, err := c.Check(context.Background(), anchorPrefixes)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("expected clean, got %v", rep.Err())
	}
	if rep.FIBChecked {
		t.Error("FIBChecked should be false without a FIB source")
	}
}

func TestCheckDetectsKernelLeak(t *testing.T) {
	c := Checker{
		Kernel: kernelLister(
			"blackhole 203.0.113.10\n10.0.0.0/24 dev vedge\n", // leaked!
			"",
		),
		BirdExported: NewBirdExportedLister(fakeExported{byProto: map[string][]netip.Prefix{
			"upstream1": anchorPrefixes,
		}}, "upstream1"),
	}
	rep, err := c.Check(context.Background(), anchorPrefixes)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.OK() {
		t.Fatal("expected leak detection")
	}
	if len(rep.LeakedToKernel) != 1 || rep.LeakedToKernel[0] != netip.MustParsePrefix("203.0.113.10/32") {
		t.Errorf("LeakedToKernel = %v", rep.LeakedToKernel)
	}
	if !strings.Contains(rep.Err().Error(), "LEAKED to kernel") {
		t.Errorf("Err = %v", rep.Err())
	}
}

func TestCheckDetectsMissingExport(t *testing.T) {
	c := Checker{
		Kernel: kernelLister("10.0.0.0/24 dev vedge\n", ""),
		BirdExported: NewBirdExportedLister(fakeExported{byProto: map[string][]netip.Prefix{
			"upstream1": {netip.MustParsePrefix("203.0.113.10/32")}, // v6 anchor missing
		}}, "upstream1"),
	}
	rep, err := c.Check(context.Background(), anchorPrefixes)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(rep.MissingExport) != 1 || rep.MissingExport[0] != netip.MustParsePrefix("2001:db8::a/128") {
		t.Errorf("MissingExport = %v", rep.MissingExport)
	}
}

func TestCheckDetectsFIBLeak(t *testing.T) {
	c := Checker{
		Kernel:       kernelLister("10.0.0.0/24 dev vedge\n", ""),
		BirdExported: NewBirdExportedLister(fakeExported{byProto: map[string][]netip.Prefix{"upstream1": anchorPrefixes}}, "upstream1"),
		FIB:          fakeLister{name: "vpp-fib", set: prefixSet("203.0.113.10/32")},
	}
	rep, err := c.Check(context.Background(), anchorPrefixes)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !rep.FIBChecked {
		t.Error("FIBChecked should be true")
	}
	if len(rep.LeakedToFIB) != 1 {
		t.Errorf("LeakedToFIB = %v", rep.LeakedToFIB)
	}
	if !strings.Contains(rep.Err().Error(), "VPP FIB") {
		t.Errorf("Err = %v", rep.Err())
	}
}

func TestCheckUnionAcrossUpstreams(t *testing.T) {
	c := Checker{
		Kernel: kernelLister("", ""),
		BirdExported: NewBirdExportedLister(fakeExported{byProto: map[string][]netip.Prefix{
			"upstream1": {netip.MustParsePrefix("203.0.113.10/32")},
			"upstream2": {netip.MustParsePrefix("2001:db8::a/128")},
		}}, "upstream1", "upstream2"),
	}
	rep, err := c.Check(context.Background(), anchorPrefixes)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("union of both upstreams should satisfy export: %v", rep.Err())
	}
}

func TestCheckListerErrorIsInfra(t *testing.T) {
	c := Checker{
		Kernel:       fakeLister{name: "kernel-rib", err: errors.New("ip failed")},
		BirdExported: NewBirdExportedLister(fakeExported{}, "upstream1"),
	}
	_, err := c.Check(context.Background(), anchorPrefixes)
	if err == nil || !strings.Contains(err.Error(), "kernel-rib") {
		t.Fatalf("expected infra error naming the source, got %v", err)
	}
}

func TestCheckEmptyAnchors(t *testing.T) {
	c := Checker{
		Kernel:       fakeLister{name: "kernel-rib", err: errors.New("should not be called")},
		BirdExported: NewBirdExportedLister(fakeExported{err: errors.New("nope")}, "upstream1"),
		FIB:          fakeLister{name: "vpp-fib"},
	}
	rep, err := c.Check(context.Background(), nil)
	if err != nil {
		t.Fatalf("empty anchors should short-circuit without listing: %v", err)
	}
	if !rep.OK() || rep.Checked != 0 || !rep.FIBChecked {
		t.Errorf("rep = %+v", rep)
	}
}
