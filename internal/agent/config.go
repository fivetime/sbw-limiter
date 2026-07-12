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

	EdgeID         string `json:"edge_id"`
	CapacityBps    uint64 `json:"capacity_bps"`     // NIC line rate; controller sells capacity×90% (§4.1)
	BIRDSocketPath string `json:"bird_socket_path"` // §4: /run/bird.ctl
	VPPAPISocket   string `json:"vpp_api_socket"`   // §5: govpp binary API
	// VPPHealthTimeout bounds how long govpp waits for a VPP health-probe reply
	// before counting a failure. With the phase model (DESIGN-liveness §4.1) the
	// ControlPing NO LONGER owns data-plane liveness — the socket (real death) and
	// the L4 worker loops (engine) do — so this is set high to NEUTER the probe: it
	// must not false-disconnect a busy VPP (which triggered the reinstall storm). A
	// real crash still breaks the socket and is caught immediately, independent of it.
	VPPHealthTimeout config.Duration `json:"vpp_health_timeout"`
	// VPPReplyTimeout overrides govpp's default per-channel reply timeout for every
	// reconcile dump/apply channel. govpp's 2s default is too tight for VPP's single
	// busy-poll main thread: under normal packet+API contention a multipart dump takes
	// >2s to COMPLETE (not a wedge, just slow), which times out the reconcile pass →
	// Degraded → canary withdrawn though forwarding is healthy. 0 → govpp default.
	// See vpp.WithReplyTimeout / vpp-single-mainthread-bottleneck.
	VPPReplyTimeout config.Duration `json:"vpp_reply_timeout"`
	// ControllerEndpoint is the SERVER endpoint the agent connects to DIRECTLY (REFACTOR
	// step 4): register + subscribe (desired-state) + report all over one AgentService
	// connection to sbw-server. Formerly a coverer address; the coverer no longer relays
	// agent control (it taps passively). Env CONTROLLER_ENDPOINT.
	ControllerEndpoint string `json:"controller_endpoint"`
	// ControllerEndpoints is retained for a multi-replica server behind DISTINCT addresses
	// (bootstrap list; the agent uses the first). With a single server Service DNS the
	// gRPC client's own reconnect suffices, so this is usually empty → [ControllerEndpoint].
	// (Formerly the coverer-sharding primary/fallback set; coverer homing is gone.)
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

	// BirdFeedMode selects how anchors + egress flowspec reach BIRD: "api" streams
	// them incrementally to the bird-vpp `api` proto over BirdAPISocket (no
	// configure — DESIGN-bird-api.md); anything else uses the legacy include-file +
	// `birdc configure` path (BirdAnchorsInclude/BirdFlowspecInclude).
	BirdFeedMode  string `json:"bird_feed_mode"`
	BirdAPISocket string `json:"bird_api_socket"` // api proto socket; default /run/bird/api.sock

	// BirdFeedMaxOpsPerPass bounds how many anchor/flow frames the api feed writes
	// before it flushes + yields (BirdFeedPace), so bird-vpp's vppfib drains between
	// chunks instead of receiving a whole (re)dump as one in-flight burst. A full
	// resync of a large homed set in ONE burst overran bird-vpp's vapi accumulation
	// and os_panic'd under 60K churn — and a bird restart (socket EOF → resync) re-
	// dumped the whole set into the just-restarted bird, re-crashing it (the self-
	// sustaining loop). Pacing bounds the in-flight the re-dump imposes. A steady-
	// state incremental pass smaller than this is unaffected (one flush at the end,
	// as before). 0 disables pacing (whole pass in one burst — legacy behaviour).
	BirdFeedMaxOpsPerPass int             `json:"bird_feed_max_ops_per_pass"`
	BirdFeedPace          config.Duration `json:"bird_feed_pace"` // yield between chunks; 0 → flush only, no sleep

	// PolicerInterfaces names the VPP interfaces whose ingress carries pool
	// traffic to be policed (the L node's lower leg facing R, §5.3 data plane).
	// The reconciler attaches the policer-classify mask chain to each so that
	// classified packets actually reach the shared-bucket policer; empty means
	// no interface binding (classify tables exist but feed no traffic — control
	// plane only / tests). Env POLICER_INTERFACES is comma-separated.
	PolicerInterfaces []string `json:"policer_interfaces"`

	// Canary (soft-death §4.7/6.13): when all three are set, the agent advertises
	// CanaryPrefix tagged with CanaryLC via BIRD WHILE the data plane is healthy
	// and WITHDRAWS it when SoftDead — the link down OR a Degraded/Dead phase
	// (§4.1) — re-advertising on recovery. The
	// controller's RIB tap recognises the route by CanaryLC; its withdrawal
	// (CanaryDown), conjoined with the agent's own healthDead report, trips
	// soft-death failover — catching a dead data plane that BGP/heartbeat alone
	// cannot see. Empty disables the canary (liveness falls back to PeerDown).
	CanaryInclude string `json:"canary_include"` // agent-managed BIRD include path
	CanaryPrefix  string `json:"canary_prefix"`  // /32 or /128
	CanaryLC      string `json:"canary_lc"`      // "global:local1:local2"

	// Forwarding probe (③ forwarding-broken, DESIGN-liveness §4.2.7): when
	// ForwardingProbeTarget is set, the agent periodically pings it through VPP's data
	// plane; ForwardingProbeFails consecutive no-reply rounds flip fault_kind to
	// forwarding-broken (device up + links up, but a silent black-hole). Immune to the
	// policer — a low-rate echo is far below any pool rate. Empty target disables ③.
	ForwardingProbeTarget   string          `json:"forwarding_probe_target"`   // stable reachable next-hop (fabric gateway); empty = off
	ForwardingProbeInterval config.Duration `json:"forwarding_probe_interval"` // 0 → 3s
	ForwardingProbeFails    int             `json:"forwarding_probe_fails"`    // consecutive no-reply rounds → broken; 0 → 3
	ForwardingProbeTimeout  config.Duration `json:"forwarding_probe_timeout"`  // per-round reply timeout (bounds a wedged main thread); 0 → 2s

	// Plugin-based forwarding probe (preferred): instead of a cli_inband ping —
	// which self-times-out and stalls VPP's single main thread under load — the
	// `probe` VPP plugin resolves ForwardingProbeTarget in the FIB on its own
	// process node and publishes reachability to the stats segment. The agent
	// registers the target once (`probe fib add`) and reads the gauge over shared
	// memory each round (never touching the main thread). Empty target still = off.
	ForwardingProbePlugin   bool   `json:"forwarding_probe_plugin"`    // true → read the probe-plugin gauge instead of cli_inband ping
	ForwardingProbeStatName string `json:"forwarding_probe_stat_name"` // probe target name; gauge = /probe/fib/<name>/reachable; default "fwd"
	ForwardingProbeTable    int    `json:"forwarding_probe_table"`     // FIB table id the target is resolved in; default 0

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
	KafkaPlaintext   bool            `json:"kafka_plaintext"`    // dev/lab: no SASL, no TLS (plain Kafka)
}

// DefaultConfig returns the edge-agent defaults from DESIGN.md §4/§5/§7.
func DefaultConfig() Config {
	return Config{
		Log:                   logx.Config{Level: "info", Format: logx.FormatJSON},
		BIRDSocketPath:        "/run/bird.ctl",
		VPPAPISocket:          "/run/vpp/api.sock",
		VPPHealthTimeout:      config.Duration(30 * time.Second),
		VPPReplyTimeout:       config.Duration(5 * time.Second),
		BirdAPISocket:         "/run/bird/api.sock",
		BirdFeedMaxOpsPerPass: 1000,
		BirdFeedPace:          config.Duration(10 * time.Millisecond),
		ReconcileInterval:     config.Duration(60 * time.Second),
		ReportInterval:        config.Duration(15 * time.Second),
		MetricsListenAddr:     ":9102",
		MeteringInterval:      config.Duration(30 * time.Second),
		VPPStatsSocket:        "/run/vpp/stats.sock",
		KafkaTopic:            "sbw.metering",
		KafkaSASLMech:         "SCRAM-SHA-256",

		ForwardingProbeInterval: config.Duration(3 * time.Second),
		ForwardingProbeFails:    3,
		ForwardingProbeTimeout:  config.Duration(2 * time.Second),
		ForwardingProbeStatName: "fwd",
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
	vht, err := config.DurationEnv("VPP_HEALTH_TIMEOUT", c.VPPHealthTimeout)
	if err != nil {
		return err
	}
	c.VPPHealthTimeout = vht
	vrt, err := config.DurationEnv("VPP_REPLY_TIMEOUT", c.VPPReplyTimeout)
	if err != nil {
		return err
	}
	c.VPPReplyTimeout = vrt
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
	c.BirdFeedMode = config.String("BIRD_FEED", c.BirdFeedMode)
	c.BirdAPISocket = config.String("BIRD_API_SOCKET", c.BirdAPISocket)
	if c.BirdFeedMaxOpsPerPass, err = config.Int("BIRD_FEED_MAX_OPS_PER_PASS", c.BirdFeedMaxOpsPerPass); err != nil {
		return err
	}
	if c.BirdFeedPace, err = config.DurationEnv("BIRD_FEED_PACE", c.BirdFeedPace); err != nil {
		return err
	}
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
	pt, err := config.Bool("METERING_PLAINTEXT", c.KafkaPlaintext)
	if err != nil {
		return err
	}
	c.KafkaPlaintext = pt

	c.ForwardingProbeTarget = config.String("FORWARDING_PROBE_TARGET", c.ForwardingProbeTarget)
	if c.ForwardingProbeInterval, err = config.DurationEnv("FORWARDING_PROBE_INTERVAL", c.ForwardingProbeInterval); err != nil {
		return err
	}
	if c.ForwardingProbeFails, err = config.Int("FORWARDING_PROBE_FAILS", c.ForwardingProbeFails); err != nil {
		return err
	}
	if c.ForwardingProbeTimeout, err = config.DurationEnv("FORWARDING_PROBE_TIMEOUT", c.ForwardingProbeTimeout); err != nil {
		return err
	}
	if c.ForwardingProbePlugin, err = config.Bool("FORWARDING_PROBE_PLUGIN", c.ForwardingProbePlugin); err != nil {
		return err
	}
	c.ForwardingProbeStatName = config.String("FORWARDING_PROBE_STAT_NAME", c.ForwardingProbeStatName)
	if c.ForwardingProbeTable, err = config.Int("FORWARDING_PROBE_TABLE", c.ForwardingProbeTable); err != nil {
		return err
	}
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
