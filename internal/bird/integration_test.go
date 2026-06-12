//go:build integration

package bird

import (
	"net/netip"
	"os"
	"strings"
	"testing"
)

// Integration acceptance against a real BIRD daemon (T-301 DoD). Run with:
//
//	BWPOOL_TEST_BIRD_SOCKET=/tmp/birdtest/bird.ctl \
//	BWPOOL_TEST_BIRD_ANCHORS=/tmp/birdtest/anchors.conf \
//	go test -tags integration ./internal/bird/
//
// The daemon is expected to serve the config in scripts/ (device protocol +
// static anchors4 with 2 routes + an include with anchors6 / 1 route).
func dialReal(t *testing.T) *Client {
	t.Helper()
	sock := os.Getenv("BWPOOL_TEST_BIRD_SOCKET")
	if sock == "" {
		t.Skip("BWPOOL_TEST_BIRD_SOCKET not set")
	}
	c, err := Dial(sock)
	if err != nil {
		t.Fatalf("Dial(%s): %v", sock, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRealBanner(t *testing.T) {
	c := dialReal(t)
	if v := c.Version(); !strings.HasPrefix(v, "3.") {
		t.Errorf("version = %q, want 3.x (banner %q)", v, c.Banner())
	}
}

func TestRealShowProtocols(t *testing.T) {
	c := dialReal(t)
	p, ok, err := c.Protocol("anchors4")
	if err != nil || !ok {
		t.Fatalf("Protocol(anchors4): ok=%v err=%v", ok, err)
	}
	if p.Proto != "Static" || p.Table != "master4" || !p.Up() {
		t.Errorf("anchors4 = %+v", p)
	}
}

func TestRealShowRouteCount(t *testing.T) {
	c := dialReal(t)
	rc, err := c.ShowRouteCount()
	if err != nil {
		t.Fatalf("ShowRouteCount: %v", err)
	}
	// bird.conf: anchors4 has 2 routes (v4), include has 1 (v6).
	if rc.TotalRoutes != 3 {
		t.Errorf("total routes = %d, want 3 (tables %+v)", rc.TotalRoutes, rc.Tables)
	}
}

func TestRealConfigureCheckAndReload(t *testing.T) {
	c := dialReal(t)

	r, err := c.ConfigureCheck("")
	if err != nil || r.Code != CodeConfigOK {
		t.Fatalf("ConfigureCheck: %+v, %v", r, err)
	}

	anchors := os.Getenv("BWPOOL_TEST_BIRD_ANCHORS")
	if anchors == "" {
		t.Skip("BWPOOL_TEST_BIRD_ANCHORS not set")
	}
	orig, err := os.ReadFile(anchors)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.WriteFile(anchors, orig, 0o644)
		c.Configure()
	})

	// Add one route to the rendered include, reload, verify count moved 3→4.
	grown := string(orig) + "\nprotocol static anchors4b {\n  ipv4 { table master4; };\n  route 203.0.113.99/32 blackhole;\n}\n"
	if err := os.WriteFile(anchors, []byte(grown), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err = c.Configure()
	if err != nil || !r.Accepted() {
		t.Fatalf("Configure after grow: %+v, %v", r, err)
	}
	rc, err := c.ShowRouteCount()
	if err != nil || rc.TotalRoutes != 4 {
		t.Fatalf("after reload: routes = %d, want 4 (%v)", rc.TotalRoutes, err)
	}

	// Syntax error path: garbage include must fail with 8002-class error and
	// keep the previous config active.
	if err := os.WriteFile(anchors, []byte("this is not bird config;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = c.Configure()
	cmdErr, ok := err.(*CommandError)
	if !ok {
		t.Fatalf("Configure with bad include: err = %v (%T), want *CommandError", err, err)
	}
	if cmdErr.Code < 8000 {
		t.Errorf("error code = %d, want >= 8000", cmdErr.Code)
	}
	rc, err = c.ShowRouteCount()
	if err != nil || rc.TotalRoutes != 4 {
		t.Errorf("old config should stay active after failed reload: routes = %d, want 4 (%v)", rc.TotalRoutes, err)
	}
}

func TestRealShowRouteExportedNoSuchProtocol(t *testing.T) {
	c := dialReal(t)
	_, err := c.ShowRouteExported("nonexistent_proto")
	if _, ok := err.(*CommandError); !ok {
		t.Errorf("expected *CommandError for unknown protocol, got %v (%T)", err, err)
	}
	// Client must survive the error.
	if _, err := c.ShowRouteCount(); err != nil {
		t.Errorf("client unusable after command error: %v", err)
	}
}

func TestRealStaticRoutesVisible(t *testing.T) {
	c := dialReal(t)
	reply, err := c.Do("show route table master4")
	if err != nil {
		t.Fatalf("show route: %v", err)
	}
	found := false
	for _, l := range reply.Lines {
		if strings.HasPrefix(l.Text, "203.0.113.10/32") {
			found = true
		}
	}
	if !found {
		t.Errorf("anchor 203.0.113.10/32 not in master4:\n%s", reply.Text())
	}
	_ = netip.Prefix{} // keep import for future assertions
}
