package agent

import (
	"fmt"
	"time"

	"github.com/fivetime/sbw-contract/config"
	"github.com/fivetime/sbw-contract/logx"
)

// Config is the edge-agent's runtime configuration. EdgeID identifies which
// edge this agent runs on and is required; the remaining fields have sensible
// defaults from DESIGN.md §4/§5/§7.
type Config struct {
	Log logx.Config `json:"log"`

	EdgeID             string          `json:"edge_id"`
	BIRDSocketPath     string          `json:"bird_socket_path"`    // §4: /run/bird.ctl
	VPPAPISocket       string          `json:"vpp_api_socket"`      // §5: govpp binary API
	ControllerEndpoint string          `json:"controller_endpoint"` // desired-state source
	ReconcileInterval  config.Duration `json:"reconcile_interval"`  // §7: 60s
}

// DefaultConfig returns the edge-agent defaults from DESIGN.md §4/§5/§7.
func DefaultConfig() Config {
	return Config{
		Log:               logx.Config{Level: "info", Format: logx.FormatJSON},
		BIRDSocketPath:    "/run/bird.ctl",
		VPPAPISocket:      "/run/vpp/api.sock",
		ReconcileInterval: config.Duration(60 * time.Second),
	}
}

// LoadConfig builds the edge-agent config: defaults → optional JSON file → env
// overrides → validation. It always returns a defaults-populated Config (so the
// caller can still build a logger) alongside any error.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if err := config.LoadFile(path, &cfg); err != nil {
		return cfg, err
	}
	if err := cfg.applyEnv(); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) applyEnv() error {
	c.Log.Level = config.String("LOG_LEVEL", c.Log.Level)
	c.Log.Format = logx.Format(config.String("LOG_FORMAT", string(c.Log.Format)))

	c.EdgeID = config.String("EDGE_ID", c.EdgeID)
	c.BIRDSocketPath = config.String("BIRD_SOCKET", c.BIRDSocketPath)
	c.VPPAPISocket = config.String("VPP_API_SOCKET", c.VPPAPISocket)
	c.ControllerEndpoint = config.String("CONTROLLER_ENDPOINT", c.ControllerEndpoint)

	ri, err := config.DurationEnv("RECONCILE_INTERVAL", c.ReconcileInterval)
	if err != nil {
		return err
	}
	c.ReconcileInterval = ri
	return nil
}

// Validate checks the edge-agent config for startup-blocking errors.
func (c Config) Validate() error {
	if c.EdgeID == "" {
		return fmt.Errorf("agent config: edge_id must be set (BWPOOL_EDGE_ID or config file)")
	}
	if c.ReconcileInterval.Std() <= 0 {
		return fmt.Errorf("agent config: reconcile_interval must be positive, got %s", c.ReconcileInterval)
	}
	return nil
}
