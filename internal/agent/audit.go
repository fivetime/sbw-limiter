package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/fivetime/sbw-limiter/internal/accounting"
	"github.com/fivetime/sbw-limiter/internal/bird"
)

// RouteAudit runs the three-way route-count reconciliation (T-502, DESIGN.md
// §5.1) on a timer. Each cycle it samples the BIRD RIB, the Linux RIB, and the
// VPP FIB; when the kernel↔FIB mirror gap exceeds the tolerance — the signature
// of silent netlink loss — it alerts and triggers a full BIRD re-export, which
// re-pushes the export filter's routes to the kernel so linux-cp re-mirrors them
// and the FIB converges.
//
// A re-export is rate-limited by Cooldown: a single drift would otherwise fire a
// reconfigure on every tick until the (asynchronous) re-mirror catches up.
type RouteAudit struct {
	checker  accounting.Checker
	reexport ReExporter
	log      *slog.Logger

	cooldown    time.Duration
	now         func() time.Time // injectable clock for tests
	lastTrigger time.Time
}

// ReExporter triggers BIRD's full re-export (a "configure" reload re-runs the
// export filters, re-announcing routes to the kernel). *bird.Client satisfies it.
type ReExporter interface {
	Configure() (bird.ConfigureResult, error)
}

// NewRouteAudit builds the audit loop. A zero cooldown defaults to 5 minutes so
// a re-export's asynchronous re-mirror has time to land before another fires.
func NewRouteAudit(checker accounting.Checker, reexport ReExporter, cooldown time.Duration, log *slog.Logger) *RouteAudit {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	return &RouteAudit{
		checker:  checker,
		reexport: reexport,
		log:      log,
		cooldown: cooldown,
		now:      time.Now,
	}
}

// AuditResult reports one audit cycle.
type AuditResult struct {
	Report      accounting.Report
	Triggered   bool   // a re-export was issued this cycle
	Suppressed  bool   // deviation present but re-export held off by the cooldown
	ReExportMsg string // BIRD's reply when triggered
}

// Once runs a single audit cycle: sample, compare, and re-export if the mirror
// gap deviates and the cooldown has elapsed.
func (a *RouteAudit) Once(ctx context.Context) (AuditResult, error) {
	rep, err := a.checker.Check(ctx)
	if err != nil {
		return AuditResult{}, err
	}
	res := AuditResult{Report: rep}
	if !rep.Deviated {
		a.log.Debug("route audit clean", "report", rep.String())
		return res, nil
	}

	// Deviation: this is the silent-netlink-loss alarm.
	a.log.Warn("route count deviation (kernel↔FIB mirror drift)",
		"bird", rep.BIRD, "linux", rep.Linux, "vpp", rep.VPP,
		"gap", rep.Gap, "drift", rep.Drift, "tolerance", a.checker.Tolerance)

	if since := a.now().Sub(a.lastTrigger); !a.lastTrigger.IsZero() && since < a.cooldown {
		res.Suppressed = true
		a.log.Info("re-export suppressed by cooldown", "since_last", since.Round(time.Second), "cooldown", a.cooldown)
		return res, nil
	}

	cr, err := a.reexport.Configure()
	if err != nil {
		return res, fmt.Errorf("agent: route audit re-export: %w", err)
	}
	a.lastTrigger = a.now()
	res.Triggered = true
	res.ReExportMsg = cr.Message
	if !cr.Accepted() {
		a.log.Warn("re-export not accepted by BIRD", "code", cr.Code, "message", cr.Message)
	} else {
		a.log.Warn("triggered BIRD re-export to converge FIB", "code", cr.Code)
	}
	return res, nil
}

// Run audits every interval until ctx is cancelled. It runs once immediately so
// drift is caught at startup, then on each tick.
func (a *RouteAudit) Run(ctx context.Context, interval time.Duration) {
	if _, err := a.Once(ctx); err != nil {
		a.log.Error("route audit cycle failed", "err", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := a.Once(ctx); err != nil {
				a.log.Error("route audit cycle failed", "err", err)
			}
		}
	}
}
