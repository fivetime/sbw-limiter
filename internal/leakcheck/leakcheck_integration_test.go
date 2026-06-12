//go:build integration

package leakcheck

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fivetime/sbw-limiter/internal/bird"
)

// T-306 acceptance: with a real BIRD writing the kernel RIB inside a netns,
// the checker must (a) stay clean when krt_export excludes anchors and (b)
// fire when an injected misconfiguration lets an anchor leak into the kernel.
//
//	sudo BWPOOL_TEST_BIRD_BIN=/tmp/bird-src/bird \
//	  go test -tags integration -run TestLeak ./internal/leakcheck/

const ns = "bwt-leak"

func birdBin(t *testing.T) string {
	if b := os.Getenv("BWPOOL_TEST_BIRD_BIN"); b != "" {
		return b
	}
	if p, err := exec.LookPath("bird"); err == nil {
		return p
	}
	t.Skip("no BIRD binary (set BWPOOL_TEST_BIRD_BIN)")
	return ""
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func nsRunner(t *testing.T) CommandRunner { return nsCmdRunner{t: t} }

type nsCmdRunner struct{ t *testing.T }

func (r nsCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	full := append([]string{"netns", "exec", ns, name}, args...)
	return exec.CommandContext(ctx, "ip", full...).Output()
}

// kernelListerIn builds a KernelLister that runs `ip` inside the test netns.
func kernelListerIn(t *testing.T) *KernelLister {
	return &KernelLister{
		runner: nsRunner(t),
		v4Args: []string{"-4", "route", "show"},
		v6Args: []string{"-6", "route", "show"},
	}
}

func startBirdNS(t *testing.T, bin, conf, sock, pid string) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, bin, "-c", conf, "-s", sock, "-P", pid, "-f")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bird: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := bird.Dial(sock); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("bird did not come up")
}

const anchorPrefix = "203.0.113.10/32"

// birdConfWithFilter renders a self-contained BIRD config: an anchor static
// plus a kernel protocol whose export filter is the given snippet.
func birdConfWithFilter(dir, krtFilter string) string {
	return `router id 10.9.9.9;
protocol device { scan time 1; }
protocol static anchors4 {
  ipv4 { table master4; };
  route ` + anchorPrefix + ` blackhole;
}
filter krt_export {
` + krtFilter + `
  accept;
}
protocol kernel kernel4 {
  ipv4 { import none; export filter krt_export; };
  learn off;
  scan time 1;
}
`
}

func TestLeakCheckAgainstRealBIRD(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for network namespaces")
	}
	bin := birdBin(t)

	_ = exec.Command("ip", "netns", "del", ns).Run()
	mustRun(t, "ip", "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	mustRun(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")

	dir := t.TempDir()
	conf := filepath.Join(dir, "bird.conf")
	sock := filepath.Join(dir, "bird.ctl")
	pid := filepath.Join(dir, "bird.pid")

	anchors := []netip.Prefix{netip.MustParsePrefix(anchorPrefix)}

	t.Run("guard active: clean", func(t *testing.T) {
		guard := `  if proto = "anchors4" then reject;
  if dest = RTD_BLACKHOLE then reject;`
		if err := os.WriteFile(conf, []byte(birdConfWithFilter(dir, guard)), 0o644); err != nil {
			t.Fatal(err)
		}
		startBirdNS(t, bin, conf, sock, pid)
		waitForKernelScan(t)

		// Sanity: anchor really is NOT in the kernel RIB.
		assertKernelAbsent(t, anchorPrefix, true)

		chk := Checker{Kernel: kernelListerIn(t), BirdExported: clean()}
		rep, err := chk.Check(context.Background(), anchors)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !rep.OK() {
			t.Fatalf("expected clean with guard active, got %v", rep.Err())
		}
	})

	// Restart with a broken filter (accept everything) — the anchor leaks.
	t.Run("guard removed: leak detected", func(t *testing.T) {
		_ = exec.Command("kill", readPID(t, pid)).Run()
		time.Sleep(300 * time.Millisecond)

		if err := os.WriteFile(conf, []byte(birdConfWithFilter(dir, "  # no guard")), 0o644); err != nil {
			t.Fatal(err)
		}
		startBirdNS(t, bin, conf, sock, pid)
		waitForKernelScan(t)

		// Sanity: the anchor IS now in the kernel RIB (as a blackhole route).
		assertKernelAbsent(t, anchorPrefix, false)

		chk := Checker{Kernel: kernelListerIn(t), BirdExported: clean()}
		rep, err := chk.Check(context.Background(), anchors)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if rep.OK() {
			t.Fatal("expected leak detection after guard removed")
		}
		if len(rep.LeakedToKernel) != 1 || rep.LeakedToKernel[0] != netip.MustParsePrefix(anchorPrefix) {
			t.Fatalf("LeakedToKernel = %v", rep.LeakedToKernel)
		}
		t.Logf("alert would fire: %v", rep.Err())
	})
}

// clean returns a BIRD exported lister that reports the anchor as exported, so
// the MissingExport leg never trips during the kernel-leak test (no upstream
// session here).
func clean() Lister {
	return fakeLister{name: "bird-exported", set: prefixSet(anchorPrefix)}
}

func waitForKernelScan(t *testing.T) {
	t.Helper()
	time.Sleep(1500 * time.Millisecond) // scan time 1s + margin
}

func assertKernelAbsent(t *testing.T, prefix string, wantAbsent bool) {
	t.Helper()
	out, err := nsRunner(t).Run(context.Background(), "ip", "-4", "route", "show")
	if err != nil {
		t.Fatalf("ip route: %v", err)
	}
	present := strings.Contains(string(out), strings.Split(prefix, "/")[0])
	if wantAbsent && present {
		t.Fatalf("anchor unexpectedly present in kernel:\n%s", out)
	}
	if !wantAbsent && !present {
		t.Fatalf("anchor expected in kernel but absent:\n%s", out)
	}
}

func readPID(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pid: %v", err)
	}
	return strings.TrimSpace(string(b))
}
