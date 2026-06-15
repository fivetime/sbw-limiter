package homing

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/grpcclient"
)

// fakeConn is a stand-in controller connection. It fires the coverer callback on
// Register (initial homing) and blocks SubscribePass until ctx is cancelled, so
// the director's loop is exercised without real gRPC.
type fakeConn struct {
	endpoint  string
	onCov     grpcclient.CovererFunc
	assignOn  func(endpoint string) (model.CovererAssignment, bool) // what Register reports
	dialErr   error
	mu        sync.Mutex
	reports   int
	registers int
	closed    bool
	// rehomeMid, if set, pushes a new assignment shortly after SubscribePass starts.
	rehomeMid func(endpoint string) (model.CovererAssignment, bool)
}

func (f *fakeConn) Register(context.Context, uint64) error {
	f.mu.Lock()
	f.registers++
	f.mu.Unlock()
	if f.assignOn != nil {
		if a, ok := f.assignOn(f.endpoint); ok {
			f.onCov(a)
		}
	}
	return nil
}

func (f *fakeConn) SendReport(context.Context, model.EdgeReport) error {
	f.mu.Lock()
	f.reports++
	f.mu.Unlock()
	return nil
}

func (f *fakeConn) SubscribePass(ctx context.Context) error {
	if f.rehomeMid != nil {
		go func() {
			time.Sleep(20 * time.Millisecond)
			if a, ok := f.rehomeMid(f.endpoint); ok {
				f.onCov(a)
			}
		}()
	}
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func assign(primary string, fallbacks ...string) model.CovererAssignment {
	cs := []model.Coverer{{ControllerID: primary, GRPCEndpoint: primary, Primary: true}}
	for _, f := range fallbacks {
		cs = append(cs, model.Coverer{ControllerID: f, GRPCEndpoint: f})
	}
	return model.CovererAssignment{EdgeID: "l1", Coverers: cs}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestOrderedCandidates(t *testing.T) {
	a := assign("p:1", "f1:1", "f2:1")
	got := orderedCandidates(a, []string{"boot:1", "p:1"})
	want := []string{"p:1", "f1:1", "f2:1", "boot:1"} // primary, fallbacks, new bootstrap; p:1 deduped
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestNextAfterWraps(t *testing.T) {
	list := []string{"a", "b", "c"}
	if nextAfter(list, "a") != "b" || nextAfter(list, "c") != "a" {
		t.Error("nextAfter should round-robin")
	}
	if nextAfter(list, "zzz") != "a" {
		t.Error("off-list current should restart at first")
	}
	if nextAfter(nil, "a") != "a" {
		t.Error("empty list returns cur")
	}
}

// The agent boots on a bootstrap endpoint, learns its primary from Register, and
// re-homes onto the primary.
func TestHomesOntoPrimary(t *testing.T) {
	dial := func(endpoint string, onCov grpcclient.CovererFunc) (Conn, error) {
		return &fakeConn{
			endpoint: endpoint, onCov: onCov,
			assignOn: func(string) (model.CovererAssignment, bool) { return assign("primary:1", "boot:1"), true },
		}, nil
	}
	d := New([]string{"boot:1"}, 1_000, dial, WithBackoff(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	waitFor(t, func() bool { return d.CurrentEndpoint() == "primary:1" }, "home onto primary")
}

// SendReport goes to the current primary; before connecting it errors.
func TestSendReportRoutesToCurrent(t *testing.T) {
	var last *fakeConn
	dial := func(endpoint string, onCov grpcclient.CovererFunc) (Conn, error) {
		c := &fakeConn{endpoint: endpoint, onCov: onCov,
			assignOn: func(string) (model.CovererAssignment, bool) { return assign("primary:1"), true }}
		if endpoint == "primary:1" {
			last = c
		}
		return c, nil
	}
	d := New([]string{"boot:1"}, 1, dial, WithBackoff(5*time.Millisecond))

	if err := d.SendReport(context.Background(), model.EdgeReport{}); err != ErrNotConnected {
		t.Errorf("want ErrNotConnected before connect, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	waitFor(t, func() bool { return d.CurrentEndpoint() == "primary:1" }, "home onto primary")

	if err := d.SendReport(context.Background(), model.EdgeReport{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { last.mu.Lock(); defer last.mu.Unlock(); return last.reports == 1 }, "report routed to primary")
}

// A REHOME mid-subscribe switches the director to the new primary.
func TestRehomeMidStream(t *testing.T) {
	dial := func(endpoint string, onCov grpcclient.CovererFunc) (Conn, error) {
		c := &fakeConn{endpoint: endpoint, onCov: onCov}
		switch endpoint {
		case "p1:1":
			c.assignOn = func(string) (model.CovererAssignment, bool) { return assign("p1:1"), true }
			c.rehomeMid = func(string) (model.CovererAssignment, bool) { return assign("p2:1"), true }
		case "p2:1":
			c.assignOn = func(string) (model.CovererAssignment, bool) { return assign("p2:1"), true }
		}
		return c, nil
	}
	d := New([]string{"p1:1"}, 1, dial, WithBackoff(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	waitFor(t, func() bool { return d.CurrentEndpoint() == "p1:1" }, "home onto p1")
	waitFor(t, func() bool { return d.CurrentEndpoint() == "p2:1" }, "re-home onto p2 after REHOME")
}

// A primary that fails to dial rolls over to a fallback candidate.
func TestFallbackOnDialFailure(t *testing.T) {
	dial := func(endpoint string, onCov grpcclient.CovererFunc) (Conn, error) {
		if endpoint == "deadprimary:1" {
			return nil, context.DeadlineExceeded
		}
		return &fakeConn{endpoint: endpoint, onCov: onCov,
			assignOn: func(string) (model.CovererAssignment, bool) {
				// learned assignment names a dead primary + a live fallback
				return assign("deadprimary:1", "boot:1"), true
			}}, nil
	}
	d := New([]string{"boot:1"}, 1, dial, WithBackoff(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	// It connects to boot:1, learns deadprimary:1 (which won't dial), and must end
	// up back on a working endpoint (boot:1) rather than stuck.
	waitFor(t, func() bool { return d.CurrentEndpoint() == "boot:1" }, "stay/return to a reachable endpoint")
}
