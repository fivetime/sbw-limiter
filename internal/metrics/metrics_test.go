package metrics

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordReconcile(t *testing.T) {
	m := New("edge-a")
	m.RecordReconcile(nil)
	m.RecordReconcile(errors.New("boom"))
	m.RecordReconcile(nil)
	if v := testutil.ToFloat64(m.reconcilePasses); v != 3 {
		t.Errorf("passes = %v, want 3", v)
	}
	if v := testutil.ToFloat64(m.reconcileErrors); v != 1 {
		t.Errorf("errors = %v, want 1", v)
	}
}

func TestRecordHealth(t *testing.T) {
	m := New("edge-a")
	m.RecordHealth(model.HealthReport{
		State:             model.HealthDegraded,
		VPPConnected:      true,
		RepairActions:     4,
		PolicersDesired:   6,
		SessionsDesired:   12,
		FIBDrift:          2,
		GenerationApplied: 9,
	})
	if v := testutil.ToFloat64(m.healthState); v != float64(model.HealthDegraded) {
		t.Errorf("health_state = %v, want %v", v, model.HealthDegraded)
	}
	if v := testutil.ToFloat64(m.vppConnected); v != 1 {
		t.Errorf("vpp_connected = %v, want 1", v)
	}
	if v := testutil.ToFloat64(m.repairs); v != 4 {
		t.Errorf("repairs = %v, want 4", v)
	}
	if v := testutil.ToFloat64(m.fibDrift); v != 2 {
		t.Errorf("fib_drift = %v, want 2", v)
	}
	if v := testutil.ToFloat64(m.generation); v != 9 {
		t.Errorf("generation = %v, want 9", v)
	}
	// A data-plane-down report flips the gauges.
	m.RecordHealth(model.HealthReport{State: model.HealthDataPlaneDown, VPPConnected: false})
	if v := testutil.ToFloat64(m.vppConnected); v != 0 {
		t.Errorf("vpp_connected after down = %v, want 0", v)
	}
	if v := testutil.ToFloat64(m.healthState); v != float64(model.HealthDataPlaneDown) {
		t.Errorf("health_state after down = %v", v)
	}
}

func TestRecordDesiredStatus(t *testing.T) {
	m := New("edge-a")
	m.RecordDesiredStatus(true, 5)
	if v := testutil.ToFloat64(m.frozen); v != 1 {
		t.Errorf("frozen = %v, want 1", v)
	}
	if v := testutil.ToFloat64(m.generation); v != 5 {
		t.Errorf("generation = %v, want 5", v)
	}
	m.RecordDesiredStatus(false, 0) // generation 0 must not clobber
	if v := testutil.ToFloat64(m.frozen); v != 0 {
		t.Errorf("frozen after up = %v, want 0", v)
	}
	if v := testutil.ToFloat64(m.generation); v != 5 {
		t.Errorf("generation must be unchanged by gen=0, got %v", v)
	}
}

func TestNilSafe(t *testing.T) {
	var m *Metrics
	m.RecordReconcile(nil)
	m.RecordHealth(model.HealthReport{})
	m.RecordDesiredStatus(true, 1)
}

func TestExpositionHasEdgeLabel(t *testing.T) {
	m := New("edge-7")
	m.RecordReconcile(nil)
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `sbw_agent_reconcile_passes_total{edge_id="edge-7"} 1`) {
		t.Errorf("exposition missing labeled counter:\n%s", body)
	}
}
