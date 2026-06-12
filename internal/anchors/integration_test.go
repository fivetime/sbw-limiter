//go:build integration

package anchors

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/bird"
)

// Integration acceptance (T-302 DoD): rendered output must pass a real BIRD's
// `configure check` and load. Expects a daemon whose config is
//
//	protocol device { ... }
//	include "<BWPOOL_TEST_BIRD_ANCHORS>";
//
// where the include file is wholly owned by this renderer. Run with:
//
//	BWPOOL_TEST_BIRD_SOCKET=/tmp/birdtest/bird.ctl \
//	BWPOOL_TEST_BIRD_ANCHORS=/tmp/birdtest/anchors.conf \
//	go test -tags integration ./internal/anchors/
func setup(t *testing.T) (*bird.Client, string) {
	t.Helper()
	sock := os.Getenv("BWPOOL_TEST_BIRD_SOCKET")
	anchorsPath := os.Getenv("BWPOOL_TEST_BIRD_ANCHORS")
	if sock == "" || anchorsPath == "" {
		t.Skip("BWPOOL_TEST_BIRD_SOCKET / BWPOOL_TEST_BIRD_ANCHORS not set")
	}
	c, err := bird.Dial(sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	orig, err := os.ReadFile(anchorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", anchorsPath, err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(anchorsPath, orig, 0o644)
		_, _ = c.Configure()
		_ = c.Close()
	})
	return c, anchorsPath
}

func applyRendered(t *testing.T, c *bird.Client, path string, set []model.Anchor) {
	t.Helper()
	out, err := Render(set)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	chk, err := c.ConfigureCheck("")
	if err != nil || chk.Code != bird.CodeConfigOK {
		t.Fatalf("configure check rejected rendered output: %+v, %v\n--- rendered ---\n%s", chk, err, out)
	}
	r, err := c.Configure()
	if err != nil || !r.Accepted() {
		t.Fatalf("configure failed: %+v, %v", r, err)
	}
}

func routeCount(t *testing.T, c *bird.Client) uint64 {
	t.Helper()
	rc, err := c.ShowRouteCount()
	if err != nil {
		t.Fatalf("ShowRouteCount: %v", err)
	}
	return rc.TotalRoutes
}

func TestRenderedConfigLoadsInRealBIRD(t *testing.T) {
	c, path := setup(t)

	// Full mixed set: v4 hosts, a /24 block, v6 host, RTBH + large communities.
	applyRendered(t, c, path, []model.Anchor{
		{Prefix: netip.MustParsePrefix("203.0.113.10/32")},
		{Prefix: netip.MustParsePrefix("203.0.113.0/24")},
		{Prefix: netip.MustParsePrefix("198.51.100.66/32"),
			Communities: []model.Community{{ASN: 65001, Value: 666}}},
		{Prefix: netip.MustParsePrefix("2001:db8::a/128"),
			LargeCommunities: []model.LargeCommunity{{GlobalAdmin: 65010, LocalData1: 0, LocalData2: 1}}},
	})
	if n := routeCount(t, c); n != 4 {
		t.Fatalf("after apply: routes = %d, want 4", n)
	}

	// Both protocols must exist and be up.
	for _, name := range []string{Protocol4, Protocol6} {
		p, ok, err := c.Protocol(name)
		if err != nil || !ok || !p.Up() {
			t.Errorf("protocol %s: ok=%v up=%v err=%v", name, ok, p.Up(), err)
		}
	}

	// Shrink to a single anchor — incremental reconfigure, count follows.
	applyRendered(t, c, path, []model.Anchor{
		{Prefix: netip.MustParsePrefix("203.0.113.10/32")},
	})
	if n := routeCount(t, c); n != 1 {
		t.Fatalf("after shrink: routes = %d, want 1", n)
	}

	// Empty set keeps both protocol blocks, zero routes.
	applyRendered(t, c, path, nil)
	if n := routeCount(t, c); n != 0 {
		t.Fatalf("after empty: routes = %d, want 0", n)
	}
	for _, name := range []string{Protocol4, Protocol6} {
		if _, ok, _ := c.Protocol(name); !ok {
			t.Errorf("protocol %s must survive empty render", name)
		}
	}
}

func TestRenderedCommunitiesVisibleInRIB(t *testing.T) {
	c, path := setup(t)
	applyRendered(t, c, path, []model.Anchor{
		{Prefix: netip.MustParsePrefix("198.51.100.66/32"),
			Communities:      []model.Community{{ASN: 65001, Value: 666}},
			LargeCommunities: []model.LargeCommunity{{GlobalAdmin: 65010, LocalData1: 7, LocalData2: 9}}},
	})

	reply, err := c.Do("show route 198.51.100.66/32 all")
	if err != nil {
		t.Fatalf("show route all: %v", err)
	}
	text := reply.Text()
	if !strings.Contains(text, "(65001,666)") {
		t.Errorf("standard community missing from RIB attrs:\n%s", text)
	}
	if !strings.Contains(text, "(65010, 7, 9)") && !strings.Contains(text, "(65010,7,9)") {
		t.Errorf("large community missing from RIB attrs:\n%s", text)
	}
}
