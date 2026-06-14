// Package kafkasink ships metering samples to a Kafka/Redpanda topic over
// SASL_SSL (T-1001 external push). It is the agent's "dial-out" telemetry leg:
// raw cumulative samples → Kafka (durable, replayable) → ClickHouse → BSS. The
// franz-go dependency is isolated here so the agent core stays transport-agnostic.
package kafkasink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/fivetime/sbw-limiter/internal/agent"
)

// Config parameterizes the Kafka producer.
type Config struct {
	Brokers   []string // bootstrap brokers (host:port)
	Topic     string   // e.g. "sbw.metering"
	Username  string   // SASL username
	Password  string   // SASL password
	Mechanism string   // "SCRAM-SHA-256" (default) or "SCRAM-SHA-512"
	// TLSCAFile is the PEM CA that signs the broker certs ("" → system roots).
	TLSCAFile string
	// TLSInsecureSkipVerify disables broker cert verification (test only).
	TLSInsecureSkipVerify bool
}

// Sink is an agent.MeteringSink backed by a Kafka producer.
type Sink struct {
	client *kgo.Client
	topic  string
}

var _ agent.MeteringSink = (*Sink)(nil)

// New builds a Kafka producer over SASL_SSL. The producer buffers + retries
// internally (franz-go), so a transient broker/collector outage backfills rather
// than dropping — billing-grade for a cumulative-counter stream.
func New(cfg Config) (*Sink, error) {
	if len(cfg.Brokers) == 0 || cfg.Topic == "" {
		return nil, fmt.Errorf("kafkasink: brokers and topic required")
	}
	auth := scram.Auth{User: cfg.Username, Pass: cfg.Password}
	var mech = auth.AsSha256Mechanism()
	if cfg.Mechanism == "SCRAM-SHA-512" {
		mech = auth.AsSha512Mechanism()
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.TLSInsecureSkipVerify} //nolint:gosec // gated by config
	if cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("kafkasink: read CA %s: %w", cfg.TLSCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kafkasink: CA %s has no usable certificate", cfg.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}

	cl, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.DefaultProduceTopic(cfg.Topic),
		kgo.SASL(mech),
		kgo.DialTLSConfig(tlsCfg),
	)
	if err != nil {
		return nil, fmt.Errorf("kafkasink: new client: %w", err)
	}
	return &Sink{client: cl, topic: cfg.Topic}, nil
}

// Emit produces one JSON record per sample, keyed by pool id so a pool's samples
// land in one partition (ordered — the rate/increase computation relies on it).
// Synchronous: it waits for acks so a failure surfaces to the caller (which
// retries next tick).
func (s *Sink) Emit(ctx context.Context, samples []agent.MeteringSample) error {
	recs := make([]*kgo.Record, 0, len(samples))
	for _, smp := range samples {
		b, err := json.Marshal(smp)
		if err != nil {
			continue
		}
		recs = append(recs, &kgo.Record{
			Topic: s.topic,
			Key:   []byte(strconv.FormatUint(smp.PoolID, 10)),
			Value: b,
		})
	}
	if len(recs) == 0 {
		return nil
	}
	return s.client.ProduceSync(ctx, recs...).FirstErr()
}

// Close flushes and shuts down the producer.
func (s *Sink) Close() { s.client.Close() }

// Ping verifies broker connectivity + auth at startup (fail fast on bad creds/CA).
func (s *Sink) Ping(ctx context.Context) error { return s.client.Ping(ctx) }
