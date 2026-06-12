//go:build integration

package flowspec

import (
	"net/netip"
	"os"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/bird"
)

// Integration acceptance (B-01 DoD): rendered output must pass a real BIRD's
// `configure check` and load, and the source-only flow4 routes must appear in
// the flow table. Expects a daemon whose config is
//
//	router id 10.0.0.1;
//	flow4 table flowtab4;
//	protocol device { }
//	include "<BWPOOL_TEST_BIRD_FLOWSPEC>";
//
// where the include file is wholly owned by this renderer. Run with:
//
//	BWPOOL_TEST_BIRD_SOCKET=/tmp/birdtest/bird.ctl \
//	BWPOOL_TEST_BIRD_FLOWSPEC=/tmp/birdtest/flowspec.conf \
//	go test -tags integration ./internal/flowspec/
func TestRenderedFlowSpecLoadsInRealBIRD(t *testing.T) {
	sock := os.Getenv("BWPOOL_TEST_BIRD_SOCKET")
	path := os.Getenv("BWPOOL_TEST_BIRD_FLOWSPEC")
	if sock == "" || path == "" {
		t.Skip("BWPOOL_TEST_BIRD_SOCKET / BWPOOL_TEST_BIRD_FLOWSPEC not set")
	}
	c, err := bird.Dial(sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	orig, _ := os.ReadFile(path)
	t.Cleanup(func() {
		_ = os.WriteFile(path, orig, 0o644)
		_, _ = c.Configure()
		_ = c.Close()
	})

	out, err := Render([]model.FlowRedirect{
		fr("10.20.0.0/24"),
		fr("203.0.113.0/24"),
	}, netip.MustParseAddr("10.0.0.5"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write include: %v", err)
	}

	chk, err := c.ConfigureCheck("")
	if err != nil || chk.Code != bird.CodeConfigOK {
		t.Fatalf("configure check rejected rendered flowspec: err=%v code=%d msg=%s", err, chk.Code, chk.Message)
	}
	if _, err := c.Configure(); err != nil {
		t.Fatalf("configure: %v", err)
	}

	// The static protocol must be loaded.
	protos, err := c.ShowProtocols()
	if err != nil {
		t.Fatalf("show protocols: %v", err)
	}
	found := false
	for _, p := range protos {
		if p.Name == Protocol4 {
			found = true
		}
	}
	if !found {
		t.Errorf("protocol %q not found after configure", Protocol4)
	}

	// The two source-only flow4 routes must be present.
	rc, err := c.ShowRouteCount()
	if err != nil {
		t.Fatalf("show route count: %v", err)
	}
	if rc.TotalRoutes < 2 {
		t.Errorf("expected >=2 flow routes loaded, got TotalRoutes=%d", rc.TotalRoutes)
	}
}
