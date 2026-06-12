//go:build integration

package agent

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/vpp"
)

// T-503 acceptance against real VPP: a VPP process restart drops the entire data
// plane (policers/classify/ABF); linux-cp re-dumps the FIB on its own, but our
// rules do not come back by themselves. The agent must notice the reconnect and
// reinstall everything. This test installs rules, KILLS and restarts VPP, and
// confirms the rules reappear in the fresh instance — driven only by the
// reconnect path (the reconcile interval is set huge so the periodic tick can't
// be what recovers them).
//
// Requires root and:
//
//	BWPOOL_TEST_VPP_SOCKET=/run/vpp/api.sock
//	BWPOOL_TEST_VPP_BIN=.../bin/vpp
//	BWPOOL_TEST_VPP_STARTUP=.../deploy/vpp/startup.conf
//
// plus LD_LIBRARY_PATH / VPP_PLUGIN_PATH in the environment so VPP can launch.
func TestRealVPPRestartReinstallsDataPlane(t *testing.T) {
	bin := os.Getenv("BWPOOL_TEST_VPP_BIN")
	conf := os.Getenv("BWPOOL_TEST_VPP_STARTUP")
	sock := os.Getenv("BWPOOL_TEST_VPP_SOCKET")
	if bin == "" || conf == "" || sock == "" || os.Geteuid() != 0 {
		t.Skip("needs root + BWPOOL_TEST_VPP_BIN + BWPOOL_TEST_VPP_STARTUP + BWPOOL_TEST_VPP_SOCKET")
	}

	// Leave the final VPP running for any sibling integration tests; restartVPP
	// reaps the intermediate (killed) child to avoid a zombie mid-test.
	vppCmd := startVPP(t, bin, conf, sock)

	// Reconnect generously: a VPP boot takes several seconds, well within reach.
	conn, err := vpp.Dial(context.Background(), sock,
		vpp.WithReconnect(120, time.Second),
		vpp.WithReadyTimeout(20*time.Second))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(conn.Close)
	r := New(conn, nil)

	desired := desiredWith(
		spec(5200, model.DirectionIngress, 1_000_000),
		spec(5200, model.DirectionEgress, 1_000_000),
		spec(5201, model.DirectionIngress, 500_000),
	)
	managed := []string{"pool5200_in", "pool5200_out", "pool5201_in"}

	// Run the reconcile loop with a huge interval, so the ONLY thing that can
	// reinstall after the restart is the reconnect trigger, not a periodic tick.
	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		r.Run(ctx, time.Hour, func() (model.EdgeDesiredState, bool) { return desired, true })
		close(loopDone)
	}()
	t.Cleanup(func() {
		cancel()
		<-loopDone
		_, _ = r.Reconcile(desiredWith()) // clean managed policers
	})

	// Initial install lands.
	waitForPolicers(t, conn, managed, true, 10*time.Second)
	gen0 := conn.Generation()
	t.Logf("installed at generation %d", gen0)

	// Kill VPP → the data plane (and our policers) vanish with it.
	restartVPP(t, vppCmd, bin, conf, sock)

	// govpp reconnects to the fresh instance; the loop's reconnect case resets
	// the index cache and reinstalls. Wait for both the generation bump (proof
	// it was a real reconnect) and the policers' reappearance.
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		if conn.Generation() > gen0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if conn.Generation() <= gen0 {
		t.Fatalf("connection generation did not advance past %d after restart", gen0)
	}
	t.Logf("reconnected at generation %d", conn.Generation())

	waitForPolicers(t, conn, managed, true, 30*time.Second)
}

// startVPP launches a fresh VPP, killing any existing instance first, and waits
// for its API socket. It returns the child handle so the caller can reap it
// (Wait) after killing, avoiding a <defunct> zombie that lingers under the test
// process.
func startVPP(t *testing.T, bin, conf, sock string) *exec.Cmd {
	t.Helper()
	killVPP()
	waitGone(t, 10*time.Second)
	for _, s := range []string{sock, "/run/vpp/cli.sock", "/run/vpp/stats.sock"} {
		_ = os.Remove(s)
	}
	logf, err := os.Create("/tmp/vpp-restart-test.log")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-c", conf)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start vpp: %v", err)
	}
	waitForSocket(t, sock, 20*time.Second)
	return cmd
}

// restartVPP simulates a crash/restart: kill the running VPP, reap it, and bring
// up a new one on the same socket. The new instance is left running (orphaned on
// test exit) so sibling integration tests still find a VPP.
func restartVPP(t *testing.T, old *exec.Cmd, bin, conf, sock string) {
	t.Helper()
	killVPP()
	_ = old.Wait() // reap the killed child so pgrep stops seeing it
	waitGone(t, 10*time.Second)
	startVPP(t, bin, conf, sock)
}

// killVPP terminates the running VPP. Its main process reports its comm as
// "vpp_main" (not "vpp"), and matching the comm exactly avoids also hitting
// shell commands that merely mention the vpp path on their command line.
func killVPP() {
	_ = exec.Command("pkill", "-9", "-x", "vpp_main").Run()
}

func waitForSocket(t *testing.T, sock string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			time.Sleep(500 * time.Millisecond) // let VPP finish binding
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("VPP socket %s did not appear within %s", sock, d)
}

func waitGone(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if out, _ := exec.Command("pgrep", "-x", "vpp_main").Output(); len(out) == 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("VPP process still present after %s; proceeding", d)
}

func waitForPolicers(t *testing.T, conn *vpp.Conn, names []string, want bool, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	var last map[string]vpp.PolicerInfo
	for time.Now().Before(deadline) {
		live, err := tryPolicerNames(conn)
		if err == nil {
			last = live
			ok := true
			for _, n := range names {
				if _, present := live[n]; present != want {
					ok = false
					break
				}
			}
			if ok {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("policers %v present==%v not reached within %s (live=%v)", names, want, d, last)
}

// tryPolicerNames dumps managed policers without failing the test, for polling
// across the window where the connection may be transiently down.
func tryPolicerNames(conn *vpp.Conn) (map[string]vpp.PolicerInfo, error) {
	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	defer ch.Close()
	infos, err := vpp.NewPolicers(ch).Dump()
	if err != nil {
		return nil, err
	}
	out := map[string]vpp.PolicerInfo{}
	for _, i := range infos {
		out[i.Name] = i
	}
	return out, nil
}
