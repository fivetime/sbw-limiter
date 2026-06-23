package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/fivetime/sbw-contract/config"
	"github.com/fivetime/sbw-contract/logx"
)

// Config is the edge-agent's runtime configuration. EdgeID identifies which
// edge this agent runs on and is required; the remaining fields have sensible
// defaults from DESIGN.md §4/§5/§7.
type Config struct {
	Log logx.Config `json:"log"`

	EdgeID             string `json:"edge_id"`
	CapacityBps        uint64 `json:"capacity_bps"`        // NIC line rate; controller sells capacity×90% (§4.1)
	BIRDSocketPath     string `json:"bird_socket_path"`    // §4: /run/bird.ctl
	VPPAPISocket       string `json:"vpp_api_socket"`      // §5: govpp binary API
	ControllerEndpoint string `json:"controller_endpoint"` // desired-state source (single / bootstrap)
	// ControllerEndpoints is the bootstrap set for controller sharding (L-06): the
	// agent connects to any one, Registers, and is told its primary/fallback
	// coverers to home onto. Empty → [ControllerEndpoint] (single-controller mode).
	ControllerEndpoints []string        `json:"controller_endpoints"`
	ReconcileInterval   config.Duration `json:"reconcile_interval"`  // §7: 60s
	ReportInterval      config.Duration `json:"report_interval"`     // B-03 uplink cadence
	MetricsListenAddr   string          `json:"metrics_listen_addr"` // Prometheus /metrics; empty disables (T-1003)

	// BIRD materialization (B-03 apply): the two agent-managed include files the
	// main bird.conf includes. BOTH set (with BIRDSocketPath) enables the BIRD
	// apply loop — anchors (/32 carriers) + egress FlowSpec; empty disables it
	// (VPP-only deployments / tests).
	BirdAnchorsInclude  string `json:"bird_anchors_include"`
	BirdFlowspecInclude string `json:"bird_flowspec_include"`

	// PolicerInterfaces names the VPP interfaces whose ingress carries pool
	// traffic to be policed (the L node's lower leg facing R, §5.3 data plane).
	// The reconciler attaches the policer-classify mask chain to each so that
	// classified packets actually reach the shared-bucket policer; empty means
	// no interface binding (classify tables exist but feed no traffic — control
	// plane only / tests). Env POLICER_INTERFACES is comma-separated.
	PolicerInterfaces []string `json:"policer_interfaces"`

	// Canary (soft-death §4.7/6.13): when all three are set, the agent advertises
	// CanaryPrefix tagged with CanaryLC via BIRD WHILE the data plane is healthy
	// and WITHDRAWS it on HealthDataPlaneDown (re-advertises on recovery). The
	// controller's RIB tap recognises the route by CanaryLC; its withdrawal
	// (CanaryDown), conjoined with the agent's own healthDead report, trips
	// soft-death failover — catching a dead data plane that BGP/heartbeat alone
	// cannot see. Empty disables the canary (liveness falls back to PeerDown).
	CanaryInclude string `json:"canary_include"` // agent-managed BIRD include path
	CanaryPrefix  string `json:"canary_prefix"`  // /32 or /128
	CanaryLC      string `json:"canary_lc"`      // "global:local1:local2"

	// Metering export (T-1001): when MeteringEnable and the Kafka brokers/topic/
	// creds are set, the agent reads VPP policer counters every MeteringInterval
	// and pushes RAW CUMULATIVE samples to Kafka (→ ClickHouse → BSS). The system
	// only collects + ships; BSS computes billing. Disabled = no metering export.
	MeteringEnable   bool            `json:"metering_enable"`
	MeteringInterval config.Duration `json:"metering_interval"` // §8.1 default 30s
	VPPStatsSocket   string          `json:"vpp_stats_socket"`  // /run/vpp/stats.sock
	KafkaBrokers     []string        `json:"kafka_brokers"`     // bootstrap host:port
	KafkaTopic       string          `json:"kafka_topic"`       // default sbw.metering
	KafkaSASLUser    string          `json:"kafka_sasl_user"`
	KafkaSASLPass    string          `json:"kafka_sasl_pass"`
	KafkaSASLMech    string          `json:"kafka_sasl_mechanism"` // default SCRAM-SHA-256
	KafkaTLSCAFile   string          `json:"kafka_tls_ca_file"`
	KafkaTLSInsecure bool            `json:"kafka_tls_insecure"` // test only
}

// DefaultConfig returns the edge-agent defaults from DESIGN.md §4/§5/§7.
func DefaultConfig() Config {
	return Config{
		Log:               logx.Config{Level: "info", Format: logx.FormatJSON},
		BIRDSocketPath:    "/run/bird.ctl",
		VPPAPISocket:      "/run/vpp/api.sock",
		ReconcileInterval: config.Duration(60 * time.Second),
		ReportInterval:    config.Duration(15 * time.Second),
		MetricsListenAddr: ":9102",
		MeteringInterval:  config.Duration(30 * time.Second),
		VPPStatsSocket:    "/run/vpp/stats.sock",
		KafkaTopic:        "sbw.metering",
		KafkaSASLMech:     "SCRAM-SHA-256",
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
	c.ControllerEndpoints = config.Strings("CONTROLLER_ENDPOINTS", c.ControllerEndpoints)

	capBps, err := config.Uint64("CAPACITY_BPS", c.CapacityBps)
	if err != nil {
		return err
	}
	c.CapacityBps = capBps

	ri, err := config.DurationEnv("RECONCILE_INTERVAL", c.ReconcileInterval)
	if err != nil {
		return err
	}
	c.ReconcileInterval = ri

	rp, err := config.DurationEnv("REPORT_INTERVAL", c.ReportInterval)
	if err != nil {
		return err
	}
	c.ReportInterval = rp

	c.MetricsListenAddr = config.String("METRICS_LISTEN_ADDR", c.MetricsListenAddr)
	c.BirdAnchorsInclude = config.String("BIRD_ANCHORS_INCLUDE", c.BirdAnchorsInclude)
	c.BirdFlowspecInclude = config.String("BIRD_FLOWSPEC_INCLUDE", c.BirdFlowspecInclude)
	if v := config.String("POLICER_INTERFACES", ""); v != "" {
		c.PolicerInterfaces = splitCSV(v)
	}
	c.CanaryInclude = config.String("CANARY_INCLUDE", c.CanaryInclude)
	c.CanaryPrefix = config.String("CANARY_PREFIX", c.CanaryPrefix)
	c.CanaryLC = config.String("CANARY_LC", c.CanaryLC)

	me, err := config.Bool("METERING_ENABLE", c.MeteringEnable)
	if err != nil {
		return err
	}
	c.MeteringEnable = me
	mi, err := config.DurationEnv("METERING_INTERVAL", c.MeteringInterval)
	if err != nil {
		return err
	}
	c.MeteringInterval = mi
	c.VPPStatsSocket = config.String("VPP_STATS_SOCKET", c.VPPStatsSocket)
	c.KafkaBrokers = config.Strings("METERING_KAFKA_BROKERS", c.KafkaBrokers)
	c.KafkaTopic = config.String("METERING_KAFKA_TOPIC", c.KafkaTopic)
	c.KafkaSASLUser = config.String("METERING_SASL_USER", c.KafkaSASLUser)
	c.KafkaSASLPass = config.String("METERING_SASL_PASS", c.KafkaSASLPass)
	c.KafkaSASLMech = config.String("METERING_SASL_MECHANISM", c.KafkaSASLMech)
	c.KafkaTLSCAFile = config.String("METERING_TLS_CA", c.KafkaTLSCAFile)
	ti, err := config.Bool("METERING_TLS_INSECURE", c.KafkaTLSInsecure)
	if err != nil {
		return err
	}
	c.KafkaTLSInsecure = ti
	return nil
}

// splitCSV parses a comma-separated list, trimming spaces and dropping empties.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Bootstrap returns the controller endpoints the homing director boots from:
// ControllerEndpoints if set, else the single ControllerEndpoint. Empty only when
// neither is configured.
func (c Config) Bootstrap() []string {
	if len(c.ControllerEndpoints) > 0 {
		return c.ControllerEndpoints
	}
	if c.ControllerEndpoint != "" {
		return []string{c.ControllerEndpoint}
	}
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
