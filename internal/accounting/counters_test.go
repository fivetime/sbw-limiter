package accounting

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// fakeRunner returns canned output keyed by the joined argv, and records calls.
type fakeRunner struct {
	out  map[string][]byte
	err  error
	seen [][]string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	argv := append([]string{name}, args...)
	f.seen = append(f.seen, argv)
	if f.err != nil {
		return nil, f.err
	}
	key := ""
	for _, a := range argv {
		key += a + " "
	}
	return f.out[key], nil
}

func TestCountRouteEntries(t *testing.T) {
	// Two single-hop routes + one ECMP route (two indented nexthop lines) = 3
	// prefixes, not 5 lines. "default" still counts as one entry.
	out := `default via 10.0.0.1 dev eth0
203.0.113.0/24 via 10.77.0.2 dev bwtap0
198.51.100.0/24 proto bird
	nexthop via 10.77.0.2 dev bwtap0 weight 1
	nexthop via 10.77.0.3 dev bwtap0 weight 1
`
	if n := countRouteEntries(out); n != 3 {
		t.Fatalf("entries = %d, want 3", n)
	}
	if n := countRouteEntries(""); n != 0 {
		t.Fatalf("empty = %d, want 0", n)
	}
}

func TestSumFIBSummary(t *testing.T) {
	// Real `show ip fib summary` shape: a VRF header, a column header, then
	// prefix-length/count rows.
	out := `ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto flowlabel ] epoch:0 flags:none locks:[default-route:1, lcp-rt:1, ]
    Prefix length         Count
                   0               1
                   4               2
                  24             100
                  32               2
`
	if n := sumFIBSummary(out); n != 105 {
		t.Fatalf("sum = %d, want 105", n)
	}
}

func TestKernelCounterSumsFamilies(t *testing.T) {
	r := &fakeRunner{out: map[string][]byte{
		"ip -4 route show table main ": []byte("10.0.0.0/24 dev a\n203.0.113.0/24 via x\n"),
		"ip -6 route show table main ": []byte("2001:db8::/64 dev a\n"),
	}}
	k := &KernelCounter{runner: r, cmds: [][]string{
		{"ip", "-4", "route", "show", "table", "main"},
		{"ip", "-6", "route", "show", "table", "main"},
	}}
	n, err := k.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("count = %d, want 3 (2 v4 + 1 v6)", n)
	}
}

func TestKernelCounterInPrefixesNetns(t *testing.T) {
	k := NewKernelCounterIn("dataplane")
	want := []string{"ip", "netns", "exec", "dataplane", "ip", "-4", "route", "show", "table", "main"}
	if !reflect.DeepEqual(k.cmds[0], want) {
		t.Fatalf("netns cmd = %v, want %v", k.cmds[0], want)
	}
}

func TestVPPFIBCounterAppendsShow(t *testing.T) {
	r := &fakeRunner{out: map[string][]byte{
		"vppctl -s /run/vpp/cli.sock show ip fib summary ":  []byte("    Prefix length Count\n   0   1\n  24   5\n"),
		"vppctl -s /run/vpp/cli.sock show ip6 fib summary ": []byte("   0   2\n"),
	}}
	v := &VPPFIBCounter{
		runner:  r,
		vppctl:  []string{"vppctl", "-s", "/run/vpp/cli.sock"},
		showCmd: [][]string{{"show", "ip", "fib", "summary"}, {"show", "ip6", "fib", "summary"}},
	}
	n, err := v.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("count = %d, want 8 (1+5 v4 + 2 v6)", n)
	}
	// The vppctl flags must be preserved ahead of the show subcommand.
	if got := r.seen[0]; got[0] != "vppctl" || got[1] != "-s" || got[3] != "show" {
		t.Fatalf("argv = %v, flags not preserved before show", got)
	}
}

func TestVPPFIBCounterEmptyCommand(t *testing.T) {
	v := &VPPFIBCounter{runner: &fakeRunner{}, vppctl: nil}
	if _, err := v.Count(context.Background()); err == nil {
		t.Fatal("expected error for empty vppctl command")
	}
}

func TestBirdCounterClosure(t *testing.T) {
	b := NewBirdCounter(func() (uint64, error) { return 215, nil })
	n, err := b.Count(context.Background())
	if err != nil || n != 215 {
		t.Fatalf("count = %d, %v", n, err)
	}
	if b.Name() != "bird-rib" {
		t.Fatalf("name = %q", b.Name())
	}
	sentinel := errors.New("boom")
	be := NewBirdCounter(func() (uint64, error) { return 0, sentinel })
	if _, err := be.Count(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
}

func TestKernelCounterRunError(t *testing.T) {
	r := &fakeRunner{err: errors.New("no netns")}
	if _, err := NewKernelCounter().withRunner(r).Count(context.Background()); err == nil {
		t.Fatal("expected error from runner")
	}
}

// withRunner swaps the runner for tests.
func (k *KernelCounter) withRunner(r CommandRunner) *KernelCounter { k.runner = r; return k }
