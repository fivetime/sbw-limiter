package accounting

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// CommandRunner runs an external command; abstracted so the Linux and VPP legs
// are testable with canned output.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// --- BIRD leg ---------------------------------------------------------------

// BirdCounter is the BIRD RIB leg. It is built from a closure so this package
// stays free of a bird import (the agent wires *bird.Client.ShowRouteCount).
type BirdCounter struct {
	count func() (uint64, error)
}

// NewBirdCounter builds the BIRD leg from a function returning the total route
// count (typically wrapping bird.Client.ShowRouteCount → RouteCount.TotalRoutes).
func NewBirdCounter(count func() (uint64, error)) *BirdCounter {
	return &BirdCounter{count: count}
}

func (b *BirdCounter) Name() string { return "bird-rib" }

func (b *BirdCounter) Count(_ context.Context) (uint64, error) { return b.count() }

// --- Linux leg --------------------------------------------------------------

// KernelCounter counts route entries in the Linux RIB via `ip route` (DESIGN.md
// §5.1: `ip route list table main | wc -l`). It sums the configured command
// sets — by default the IPv4 and IPv6 main tables — counting one entry per
// prefix (ECMP "nexthop" continuation lines and blank lines are not entries).
type KernelCounter struct {
	runner CommandRunner
	cmds   [][]string // each is a full argv; outputs are counted and summed
}

// NewKernelCounter counts the IPv4+IPv6 main tables on the host. Use
// NewKernelCounterIn to count inside a network namespace (the agent runs beside
// VPP, whose dataplane lives in the "dataplane" netns).
func NewKernelCounter() *KernelCounter {
	return &KernelCounter{
		runner: execRunner{},
		cmds: [][]string{
			{"ip", "-4", "route", "show", "table", "main"},
			{"ip", "-6", "route", "show", "table", "main"},
		},
	}
}

// NewKernelCounterIn counts the same tables inside the given netns by prefixing
// each command with `ip netns exec <ns>`.
func NewKernelCounterIn(netns string) *KernelCounter {
	k := NewKernelCounter()
	for i, c := range k.cmds {
		k.cmds[i] = append([]string{"ip", "netns", "exec", netns}, c...)
	}
	return k
}

func (k *KernelCounter) Name() string { return "linux-rib" }

func (k *KernelCounter) Count(ctx context.Context) (uint64, error) {
	var total uint64
	for _, cmd := range k.cmds {
		out, err := k.runner.Run(ctx, cmd[0], cmd[1:]...)
		if err != nil {
			return 0, fmt.Errorf("%s: %w (%s)", strings.Join(cmd, " "), err, strings.TrimSpace(string(out)))
		}
		total += countRouteEntries(string(out))
	}
	return total, nil
}

// countRouteEntries counts route prefixes in `ip route` output. Each route
// starts a line at column 0; ECMP multipath routes add indented "nexthop"
// continuation lines, which are not separate prefixes.
func countRouteEntries(out string) uint64 {
	var n uint64
	for _, line := range strings.Split(out, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue // blank or an ECMP continuation line
		}
		n++
	}
	return n
}

// --- VPP leg ----------------------------------------------------------------

// VPPFIBCounter counts FIB entries via `vppctl show ip fib summary` (and ip6),
// summing the per-prefix-length Count column (DESIGN.md §5.1). vppctl is the
// monitoring interface here, matching §5.1; the hot-path materializers use the
// binary API.
type VPPFIBCounter struct {
	runner  CommandRunner
	vppctl  []string   // base argv, e.g. {"vppctl","-s","/run/vpp/cli.sock"}
	showCmd [][]string // show subcommands appended to vppctl; counts summed
}

// NewVPPFIBCounter builds the VPP leg over the given vppctl invocation
// (program + flags), counting the IPv4 and IPv6 FIB summaries.
func NewVPPFIBCounter(vppctl []string) *VPPFIBCounter {
	return &VPPFIBCounter{
		runner: execRunner{},
		vppctl: vppctl,
		showCmd: [][]string{
			{"show", "ip", "fib", "summary"},
			{"show", "ip6", "fib", "summary"},
		},
	}
}

func (v *VPPFIBCounter) Name() string { return "vpp-fib" }

func (v *VPPFIBCounter) Count(ctx context.Context) (uint64, error) {
	if len(v.vppctl) == 0 {
		return 0, fmt.Errorf("vpp-fib: empty vppctl command")
	}
	var total uint64
	for _, show := range v.showCmd {
		args := append(append([]string{}, v.vppctl[1:]...), show...)
		out, err := v.runner.Run(ctx, v.vppctl[0], args...)
		if err != nil {
			return 0, fmt.Errorf("vppctl %s: %w (%s)", strings.Join(show, " "), err, strings.TrimSpace(string(out)))
		}
		total += sumFIBSummary(string(out))
	}
	return total, nil
}

// sumFIBSummary sums the Count column of `show ip fib summary`. The output is a
// VRF header line, a "Prefix length / Count" header, then rows of two integers
// (prefix length, entry count). Only the two-integer rows are summed, so headers
// and the VRF line are ignored; multiple VRF blocks sum across.
func sumFIBSummary(out string) uint64 {
	var total uint64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if _, err := strconv.ParseUint(fields[0], 10, 32); err != nil {
			continue // header row ("Prefix length")
		}
		cnt, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		total += cnt
	}
	return total
}
