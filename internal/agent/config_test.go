package agent

import (
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/config"
)

func TestDefaultsRequireEdgeID(t *testing.T) {
	// No edge id set → validation fails.
	if _, err := LoadConfig(""); err == nil {
		t.Fatal("expected error when edge_id is unset")
	}
}

func TestLoadWithEdgeID(t *testing.T) {
	t.Setenv(config.EnvPrefix+"EDGE_ID", "edge-a")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.EdgeID != "edge-a" {
		t.Errorf("edge_id = %q, want edge-a", cfg.EdgeID)
	}
	if cfg.BIRDSocketPath != "/run/bird.ctl" {
		t.Errorf("bird socket default = %q", cfg.BIRDSocketPath)
	}
	if cfg.ReconcileInterval.Std() != 60*time.Second {
		t.Errorf("reconcile interval default = %s, want 1m0s", cfg.ReconcileInterval)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv(config.EnvPrefix+"EDGE_ID", "edge-b")
	t.Setenv(config.EnvPrefix+"BIRD_SOCKET", "/var/run/bird/bird.ctl")
	t.Setenv(config.EnvPrefix+"RECONCILE_INTERVAL", "30s")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.EdgeID != "edge-b" {
		t.Errorf("edge_id = %q", cfg.EdgeID)
	}
	if cfg.BIRDSocketPath != "/var/run/bird/bird.ctl" {
		t.Errorf("bird socket = %q", cfg.BIRDSocketPath)
	}
	if cfg.ReconcileInterval.Std() != 30*time.Second {
		t.Errorf("reconcile interval = %s, want 30s", cfg.ReconcileInterval)
	}
}

func TestValidate(t *testing.T) {
	t.Run("missing edge id", func(t *testing.T) {
		c := DefaultConfig()
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for missing edge id")
		}
	})
	t.Run("non-positive reconcile interval", func(t *testing.T) {
		c := DefaultConfig()
		c.EdgeID = "edge-a"
		c.ReconcileInterval = config.Duration(0)
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for zero reconcile interval")
		}
	})
	t.Run("malformed env duration", func(t *testing.T) {
		t.Setenv(config.EnvPrefix+"EDGE_ID", "edge-a")
		t.Setenv(config.EnvPrefix+"RECONCILE_INTERVAL", "soon")
		if _, err := LoadConfig(""); err == nil {
			t.Fatal("expected error for malformed duration env")
		}
	})
}
