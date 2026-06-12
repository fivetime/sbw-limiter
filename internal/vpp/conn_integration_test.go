//go:build integration

package vpp

import (
	"context"
	"os"
	"testing"
	"time"
)

// Acceptance against a real VPP (T-401 DoD): connect, compatibility check, and
// channel open against the VPP binary-API socket. Run with:
//
//	BWPOOL_TEST_VPP_SOCKET=/run/vpp/api.sock \
//	  go test -tags integration -run TestReal ./internal/vpp/
//
// Skipped when the socket is not configured. A compatibility failure here means
// the generated bindings (T-204) do not match the running VPP — regenerate.
func TestRealVPPConnect(t *testing.T) {
	sock := os.Getenv("BWPOOL_TEST_VPP_SOCKET")
	if sock == "" {
		t.Skip("BWPOOL_TEST_VPP_SOCKET not set")
	}
	ctx := context.Background()
	c, err := Dial(ctx, sock, WithReadyTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("Dial(%s): %v", sock, err)
	}
	defer c.Close()

	if !c.Healthy() {
		t.Fatal("not healthy after connect")
	}
	ch, err := c.Channel()
	if err != nil {
		t.Fatalf("Channel: %v", err)
	}
	ch.Close()
}
