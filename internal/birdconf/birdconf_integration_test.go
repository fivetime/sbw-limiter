//go:build integration

package birdconf

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/anchors"
	"github.com/fivetime/sbw-limiter/internal/bird"
)

// End-to-end acceptance for T-304 (DoD: config loads; anchor stays out of the
// kernel; anchor is exported to the upstream with no-export). Two BIRD
// instances run in two network namespaces joined by a veth:
//
//	edge (10.0.0.1, AS 65010)  <--eBGP-->  upstream (10.0.0.2, AS 65001)
//
// The edge runs our rendered baseline with kernel protocols enabled; the
// upstream is a minimal collector that imports all. Requires root, `ip`, and
// a BIRD binary in BWPOOL_TEST_BIRD_BIN (default: bird in PATH).
//
//	sudo BWPOOL_TEST_BIRD_BIN=/tmp/bird-src/bird \
//	  go test -tags integration -run TestEdgeUpstream ./internal/birdconf/

const (
	nsEdge = "bwt-edge"
	nsUp   = "bwt-up"
)

func birdBin(t *testing.T) string {
	if b := os.Getenv("BWPOOL_TEST_BIRD_BIN"); b != "" {
		return b
	}
	p, err := exec.LookPath("bird")
	if err != nil {
		t.Skip("no BIRD binary (set BWPOOL_TEST_BIRD_BIN)")
	}
	return p
}

func run(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func tryRun(args ...string) { _ = exec.Command(args[0], args[1:]...).Run() }

// nsExec runs a command inside a netns.
func nsExec(t *testing.T, ns string, args ...string) string {
	t.Helper()
	full := append([]string{"ip", "netns", "exec", ns}, args...)
	out, err := exec.Command(full[0], full[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(full, " "), err, out)
	}
	return string(out)
}

func setupTopology(t *testing.T) {
	t.Helper()
	// Clean any stale state, then build fresh.
	teardownTopology()
	t.Cleanup(teardownTopology)

	run(t, "ip", "netns", "add", nsEdge)
	run(t, "ip", "netns", "add", nsUp)
	run(t, "ip", "link", "add", "vedge", "type", "veth", "peer", "name", "vup")
	run(t, "ip", "link", "set", "vedge", "netns", nsEdge)
	run(t, "ip", "link", "set", "vup", "netns", nsUp)
	run(t, "ip", "netns", "exec", nsEdge, "ip", "addr", "add", "10.0.0.1/24", "dev", "vedge")
	run(t, "ip", "netns", "exec", nsUp, "ip", "addr", "add", "10.0.0.2/24", "dev", "vup")
	run(t, "ip", "netns", "exec", nsEdge, "ip", "link", "set", "vedge", "up")
	run(t, "ip", "netns", "exec", nsUp, "ip", "link", "set", "vup", "up")
	run(t, "ip", "netns", "exec", nsEdge, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", nsUp, "ip", "link", "set", "lo", "up")
}

func teardownTopology() {
	tryRun("ip", "netns", "del", nsEdge)
	tryRun("ip", "netns", "del", nsUp)
	tryRun("ip", "link", "del", "vedge")
}

// startBird launches a BIRD daemon inside ns and returns its control socket
// path. It waits until the socket is connectable.
func startBird(t *testing.T, bin, ns, dir, conf string) string {
	t.Helper()
	sock := filepath.Join(dir, "bird.ctl")
	cmd := exec.Command("ip", "netns", "exec", ns, bin,
		"-c", conf, "-s", sock, "-P", filepath.Join(dir, "bird.pid"), "-f")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bird in %s: %v", ns, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	// The control socket lives in the host fs namespace; just wait for it.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := bird.Dial(sock); err == nil {
			_ = c.Close()
			return sock
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("bird in %s did not come up", ns)
	return ""
}

func TestEdgeUpstreamEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for network namespaces")
	}
	bin := birdBin(t)
	setupTopology(t)

	edgeDir := t.TempDir()
	upDir := t.TempDir()
	anchorsPath := filepath.Join(edgeDir, "anchors.conf")

	// Render the edge baseline: kernel on (writes the netns RIB), one upstream.
	// LLGR + BFD-desensitization + tap add-path exercise the §2.6/§4.3 syntax
	// against a real BIRD (the upstream/tap sessions stay down — we only need
	// the daemon to accept and load the config).
	cfg := Config{
		RouterID: netip.MustParseAddr("10.0.0.1"), LocalASN: 65010,
		Kernel: true,
		BFD:    true, BFDIntervalMs: 300, BFDMultiplier: 3,
		LLGR: true, LLGRStaleTime: 3600,
		Upstreams: []Upstream{
			{Name: "upstream1", NeighborAddr: netip.MustParseAddr("10.0.0.2"), NeighborASN: 65001},
		},
		TapEnabled: true, TapNeighborAddr: netip.MustParseAddr("10.0.0.250"), TapNeighborPort: 1790,
		TapAddPathTx:    true,
		FabricInternal4: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Aggregates4:     []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		IntLC:           IntLC{ASN: 65010, From: 100, To: 199},
		AnchorsPath:     anchorsPath,
	}
	edgeConf := filepath.Join(edgeDir, "bird.conf")
	out, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := os.WriteFile(edgeConf, out, 0o644); err != nil {
		t.Fatal(err)
	}

	// Seed the anchors include with one /32 anchor and one non-anchor static
	// (to prove krt_export only blocks the anchor, not normal routes — but the
	// anchor IS blackhole so we just check it's absent from the kernel).
	anchorBytes, _ := anchors.Render([]model.Anchor{
		{Prefix: netip.MustParsePrefix("203.0.113.10/32")},
	})
	if err := os.WriteFile(anchorsPath, anchorBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	// Minimal upstream collector: passive, imports everything.
	upConf := filepath.Join(upDir, "bird.conf")
	upText := `router id 10.0.0.2;
protocol device { scan time 10; }
protocol bgp edge {
  local 10.0.0.2 as 65001;
  neighbor 10.0.0.1 as 65010;
  ipv4 { import all; export none; };
}
`
	if err := os.WriteFile(upConf, []byte(upText), 0o644); err != nil {
		t.Fatal(err)
	}

	edgeSock := startBird(t, bin, nsEdge, edgeDir, edgeConf)
	upSock := startBird(t, bin, nsUp, upDir, upConf)

	edge, err := bird.Dial(edgeSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = edge.Close() })
	up, err := bird.Dial(upSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })

	// DoD #1: rendered config loaded — protocols are present and the session
	// establishes.
	waitProtoUp(t, edge, "upstream1")
	waitProtoUp(t, up, "edge")

	// DoD #2: the anchor must NOT be in the netns kernel RIB (krt_export
	// rejects it; otherwise it would be a DROP route).
	rib := nsExec(t, nsEdge, "ip", "route", "show")
	if strings.Contains(rib, "203.0.113.10") {
		t.Errorf("anchor leaked into kernel RIB:\n%s", rib)
	}

	// DoD #2b: it IS in BIRD's exported set to the upstream.
	exported, err := edge.ShowRouteExported("upstream1")
	if err != nil {
		t.Fatalf("ShowRouteExported: %v", err)
	}
	if !containsPrefix(exported, "203.0.113.10/32") {
		t.Errorf("anchor not exported to upstream: %v", exported)
	}

	// DoD #3: the upstream actually received the anchor, carrying no-export.
	waitRoute(t, up, "203.0.113.10/32")
	detail, err := up.Do("show route 203.0.113.10/32 all")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail.Text(), "(65535,65281)") {
		t.Errorf("anchor at upstream missing no-export community:\n%s", detail.Text())
	}
}

func waitProtoUp(t *testing.T, c *bird.Client, name string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if p, ok, err := c.Protocol(name); err == nil && ok && p.Up() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("protocol %s did not reach up", name)
}

func waitRoute(t *testing.T, c *bird.Client, prefix string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		reply, err := c.Do("show route " + prefix)
		if err == nil {
			for _, l := range reply.Lines {
				if strings.HasPrefix(l.Text, strings.Split(prefix, "/")[0]) {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("route %s not seen at peer", prefix)
}

func containsPrefix(ps []netip.Prefix, want string) bool {
	w := netip.MustParsePrefix(want)
	for _, p := range ps {
		if p == w {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf
