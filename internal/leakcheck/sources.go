package leakcheck

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// CommandRunner runs an external command; abstracted for testability.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// routeTypeKeywords are the leading words `ip route` may print before the
// prefix. Crucially this includes "blackhole"/"unreachable"/"prohibit" — the
// exact forms a leaked anchor takes in the kernel RIB.
var routeTypeKeywords = map[string]bool{
	"unicast": true, "local": true, "broadcast": true, "multicast": true,
	"throw": true, "unreachable": true, "prohibit": true, "blackhole": true,
	"nat": true, "anycast": true,
}

// KernelLister lists the Linux main-table routes via `ip route`. The anchor
// invariant is that anchors must NOT appear here (krt_export excludes them,
// §4.2). If a non-default kernel table is used, adjust the args via WithIPArgs.
//
// Note: `ip route show` reads the main table, which is where the BIRD kernel
// protocol writes by default — exactly where a leak would surface.
type KernelLister struct {
	runner CommandRunner
	v4Args []string
	v6Args []string
}

// NewKernelLister builds a kernel RIB lister using the system `ip` command.
func NewKernelLister() *KernelLister {
	return &KernelLister{
		runner: execRunner{},
		v4Args: []string{"-4", "route", "show"},
		v6Args: []string{"-6", "route", "show"},
	}
}

func (k *KernelLister) Name() string { return "kernel-rib" }

// ListPrefixes runs `ip -4 route show` and `ip -6 route show`, parsing the
// prefix from each line (handling the route-type-keyword prefix form).
func (k *KernelLister) ListPrefixes(ctx context.Context) (map[netip.Prefix]struct{}, error) {
	out := make(map[netip.Prefix]struct{})
	for _, args := range [][]string{k.v4Args, k.v6Args} {
		raw, err := k.runner.Run(ctx, "ip", args...)
		if err != nil {
			return nil, fmt.Errorf("ip %s: %w", strings.Join(args, " "), err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if p, ok := parseRouteLinePrefix(line); ok {
				out[p] = struct{}{}
			}
		}
	}
	return out, nil
}

// parseRouteLinePrefix extracts the destination prefix from one `ip route`
// line. A bare address becomes a host prefix (/32 or /128). "default" and
// unparseable lines are skipped.
func parseRouteLinePrefix(line string) (netip.Prefix, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return netip.Prefix{}, false
	}
	tok := fields[0]
	if routeTypeKeywords[tok] {
		if len(fields) < 2 {
			return netip.Prefix{}, false
		}
		tok = fields[1]
	}
	if tok == "default" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(tok); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// ExportedReader is the subset of *bird.Client the BIRD exported lister needs.
type ExportedReader interface {
	ShowRouteExported(proto string) ([]netip.Prefix, error)
}

// BirdExportedLister lists the union of prefixes BIRD has exported to the given
// upstream protocols (the "must be present" invariant, §4.2-3). It uses
// `show route exported` — the real already-exported set, not a filter
// simulation (§1.1-1).
type BirdExportedLister struct {
	reader    ExportedReader
	protocols []string
}

// NewBirdExportedLister builds a lister over the named upstream protocols.
func NewBirdExportedLister(reader ExportedReader, protocols ...string) *BirdExportedLister {
	return &BirdExportedLister{reader: reader, protocols: protocols}
}

func (b *BirdExportedLister) Name() string { return "bird-exported" }

// ListPrefixes returns the union of exported prefixes across all upstreams.
// The ctx is accepted for interface symmetry; the BIRD client carries its own
// per-command deadline.
func (b *BirdExportedLister) ListPrefixes(_ context.Context) (map[netip.Prefix]struct{}, error) {
	out := make(map[netip.Prefix]struct{})
	for _, proto := range b.protocols {
		prefixes, err := b.reader.ShowRouteExported(proto)
		if err != nil {
			return nil, fmt.Errorf("show route exported %s: %w", proto, err)
		}
		for _, p := range prefixes {
			out[p] = struct{}{}
		}
	}
	return out, nil
}
