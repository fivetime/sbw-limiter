package grpcclient

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-contract/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// fakeServer is a minimal controller for client tests (the real one lives in
// sbw-controller, a different module).
type fakeServer struct {
	rpc.UnimplementedAgentServiceServer
	mu       sync.Mutex
	regEdge  string
	regCap   uint64
	reports  []model.EdgeReport
	coverers []byte // JSON model.CovererAssignment returned by Register
	pushCh   chan *rpc.Directive
	subbed   chan struct{}
}

func newFakeServer() *fakeServer {
	return &fakeServer{pushCh: make(chan *rpc.Directive, 8), subbed: make(chan struct{}, 1)}
}

func (f *fakeServer) Register(_ context.Context, req *rpc.RegisterRequest) (*rpc.RegisterResponse, error) {
	f.mu.Lock()
	f.regEdge, f.regCap = req.EdgeId, req.CapacityBps
	cov := f.coverers
	f.mu.Unlock()
	return &rpc.RegisterResponse{SchemaVersion: model.SchemaVersion, Accepted: true, Coverers: cov}, nil
}

func (f *fakeServer) Subscribe(_ *rpc.SubscribeRequest, stream rpc.AgentService_SubscribeServer) error {
	select {
	case f.subbed <- struct{}{}:
	default:
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case d := <-f.pushCh:
			if err := stream.Send(d); err != nil {
				return err
			}
		}
	}
}

func (f *fakeServer) Report(_ context.Context, req *rpc.ReportRequest) (*rpc.ReportAck, error) {
	var r model.EdgeReport
	_ = json.Unmarshal(req.Payload, &r)
	f.mu.Lock()
	f.reports = append(f.reports, r)
	f.mu.Unlock()
	return &rpc.ReportAck{}, nil
}

func dialFake(t *testing.T, f *fakeServer, edge model.EdgeID, opts ...Option) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	rpc.RegisterAgentServiceServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); gs.Stop() })
	return NewWithConn(conn, edge, opts...)
}

func TestRegister(t *testing.T) {
	f := newFakeServer()
	c := dialFake(t, f, "edge-2")
	if err := c.Register(context.Background(), 100_000_000_000); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.regEdge != "edge-2" || f.regCap != 100_000_000_000 {
		t.Errorf("server got edge=%s cap=%d", f.regEdge, f.regCap)
	}
}

func TestRunDispatchesDesiredState(t *testing.T) {
	f := newFakeServer()
	got := make(chan model.EdgeDesiredState, 1)
	c := dialFake(t, f, "edge-2", WithDesired(func(s model.EdgeDesiredState) { got <- s }), WithBackoff(10*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	// Wait until subscribed, then push a desired state.
	select {
	case <-f.subbed:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not subscribe")
	}
	payload, _ := json.Marshal(model.EdgeDesiredState{SchemaVersion: model.SchemaVersion, EdgeID: "edge-2", Generation: 11})
	f.pushCh <- &rpc.Directive{Kind: rpc.Directive_DESIRED_STATE, Generation: 11, Payload: payload}

	select {
	case s := <-got:
		if s.EdgeID != "edge-2" || s.Generation != 11 {
			t.Errorf("dispatched state = %+v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("desired-state not dispatched")
	}
}

func TestRunDispatchesDesiredDelta(t *testing.T) {
	f := newFakeServer()
	got := make(chan model.EdgeDesiredDelta, 1)
	c := dialFake(t, f, "edge-2",
		WithDelta(func(d model.EdgeDesiredDelta) { got <- d }),
		WithBackoff(10*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	<-f.subbed

	delta := model.EdgeDesiredDelta{
		SchemaVersion: model.SchemaVersion, EdgeID: "edge-2",
		Generation: 12, BaseGeneration: 11,
		Removed: []model.PoolID{200},
	}
	payload, _ := json.Marshal(delta)
	f.pushCh <- &rpc.Directive{Kind: rpc.Directive_DESIRED_DELTA, Generation: 12, Payload: payload}

	select {
	case d := <-got:
		if d.Generation != 12 || d.BaseGeneration != 11 || len(d.Removed) != 1 || d.Removed[0] != 200 {
			t.Errorf("dispatched delta = %+v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("desired-delta not dispatched")
	}
}

func TestRunRejectsDeltaSchemaMismatch(t *testing.T) {
	f := newFakeServer()
	called := make(chan struct{}, 1)
	c := dialFake(t, f, "edge-2",
		WithDelta(func(model.EdgeDesiredDelta) { called <- struct{}{} }),
		WithBackoff(10*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	<-f.subbed
	bad, _ := json.Marshal(model.EdgeDesiredDelta{SchemaVersion: 999, EdgeID: "edge-2"})
	f.pushCh <- &rpc.Directive{Kind: rpc.Directive_DESIRED_DELTA, Payload: bad}
	select {
	case <-called:
		t.Error("schema-mismatch delta must not be dispatched")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestRunRejectsSchemaMismatch(t *testing.T) {
	f := newFakeServer()
	called := make(chan struct{}, 1)
	c := dialFake(t, f, "edge-2", WithDesired(func(model.EdgeDesiredState) { called <- struct{}{} }), WithBackoff(10*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	<-f.subbed
	bad, _ := json.Marshal(model.EdgeDesiredState{SchemaVersion: 999, EdgeID: "edge-2"})
	f.pushCh <- &rpc.Directive{Kind: rpc.Directive_DESIRED_STATE, Payload: bad}
	select {
	case <-called:
		t.Error("schema-mismatch desired state must not be dispatched")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestSendReport(t *testing.T) {
	f := newFakeServer()
	c := dialFake(t, f, "edge-2")
	rep := model.EdgeReport{SchemaVersion: model.SchemaVersion, EdgeID: "edge-2", Generation: 5,
		Health: model.HealthReport{EdgeID: "edge-2", State: model.HealthDegraded}}
	if err := c.SendReport(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) != 1 || f.reports[0].EdgeID != "edge-2" || f.reports[0].Health.State != model.HealthDegraded {
		t.Errorf("server reports = %+v", f.reports)
	}
}

func TestRegisterSurfacesCoverers(t *testing.T) {
	f := newFakeServer()
	a := model.CovererAssignment{EdgeID: "edge-2", Coverers: []model.Coverer{
		{ControllerID: "ctrl-a", GRPCEndpoint: "a:1791", Primary: true},
		{ControllerID: "ctrl-b", GRPCEndpoint: "b:1791"},
	}}
	f.coverers, _ = json.Marshal(a)

	got := make(chan model.CovererAssignment, 1)
	c := dialFake(t, f, "edge-2", WithCoverers(func(x model.CovererAssignment) { got <- x }))
	if err := c.Register(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	select {
	case x := <-got:
		if p, ok := x.Primary(); !ok || p.GRPCEndpoint != "a:1791" {
			t.Errorf("primary = %+v, want a:1791", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("coverers not surfaced from Register")
	}
}

func TestRehomeDirectiveSurfacesCoverers(t *testing.T) {
	f := newFakeServer()
	got := make(chan model.CovererAssignment, 1)
	c := dialFake(t, f, "edge-2",
		WithCoverers(func(x model.CovererAssignment) { got <- x }),
		WithBackoff(10*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	select {
	case <-f.subbed:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not subscribe")
	}
	a := model.CovererAssignment{EdgeID: "edge-2", Coverers: []model.Coverer{{ControllerID: "ctrl-z", GRPCEndpoint: "z:1791", Primary: true}}}
	payload, _ := json.Marshal(a)
	f.pushCh <- &rpc.Directive{Kind: rpc.Directive_REHOME, Payload: payload}

	select {
	case x := <-got:
		if p, ok := x.Primary(); !ok || p.GRPCEndpoint != "z:1791" {
			t.Errorf("rehome primary = %+v, want z:1791", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("REHOME directive did not surface coverers")
	}
}

// chunkState builds an EdgeDesiredState with n policers (member-bearing entries) at
// the given generation.
func chunkState(gen uint64, n int) model.EdgeDesiredState {
	st := model.EdgeDesiredState{SchemaVersion: model.SchemaVersion, EdgeID: "edge-2", Generation: gen, DesiredVersion: 3}
	for i := 0; i < n; i++ {
		st.Policers = append(st.Policers, model.PolicerSpec{
			Name: "p", PoolID: model.PoolID(i), Direction: model.DirectionIngress,
			Type: model.Policer1R2C, RateType: model.RateKbps, CIR: uint64(i),
			ConformAction: model.PolicerTransmit, ExceedAction: model.PolicerDrop,
		})
	}
	return st
}

// TestAcceptChunkReassembles feeds the chunked fragments of a full snapshot to the
// client's reassembler and asserts onDesired receives the byte-identical full state
// with the snapshot Generation preserved (echo semantics).
func TestAcceptChunkReassembles(t *testing.T) {
	var got *model.EdgeDesiredState
	c := &Client{onDesired: func(s model.EdgeDesiredState) { got = &s }, log: discardLogger()}

	want := chunkState(100, 50)
	chunks := model.SplitDesiredState(want, 8) // 50/8 → 7 chunks
	if len(chunks) <= 1 {
		t.Fatal("expected multiple chunks")
	}
	for _, ch := range chunks {
		c.acceptChunk(ch)
	}
	if got == nil {
		t.Fatal("onDesired not called after Last chunk")
	}
	if got.Generation != want.Generation {
		t.Fatalf("echoed generation %d != %d", got.Generation, want.Generation)
	}
	gj, _ := json.Marshal(*got)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		t.Fatalf("reassembled state != original")
	}
}

// TestAcceptChunkNoPartialOnMissingLast asserts that without a Last chunk NO state is
// applied — the agent keeps its last good state.
func TestAcceptChunkNoPartialOnMissingLast(t *testing.T) {
	calls := 0
	c := &Client{onDesired: func(model.EdgeDesiredState) { calls++ }, log: discardLogger()}
	chunks := model.SplitDesiredState(chunkState(100, 50), 8)
	for _, ch := range chunks[:len(chunks)-1] { // feed all but the Last chunk
		c.acceptChunk(ch)
	}
	if calls != 0 {
		t.Fatalf("applied a partial snapshot (%d calls) without Last", calls)
	}
}

// TestAcceptChunkSupersedesByEpoch asserts a newer Epoch arriving mid-sequence
// discards the older partial and only the NEW snapshot is applied, with the new
// generation.
func TestAcceptChunkSupersedesByEpoch(t *testing.T) {
	var got *model.EdgeDesiredState
	c := &Client{onDesired: func(s model.EdgeDesiredState) { got = &s }, log: discardLogger()}

	oldChunks := model.SplitDesiredState(chunkState(100, 50), 8)
	// Feed the old snapshot's first two fragments (partial, no Last).
	c.acceptChunk(oldChunks[0])
	c.acceptChunk(oldChunks[1])

	// A newer Epoch arrives in full — it must supersede the partial.
	newWant := chunkState(200, 30)
	for _, ch := range model.SplitDesiredState(newWant, 8) {
		c.acceptChunk(ch)
	}
	if got == nil {
		t.Fatal("newer snapshot not applied")
	}
	if got.Generation != 200 {
		t.Fatalf("applied generation %d, want 200 (newer epoch)", got.Generation)
	}
	if len(got.Policers) != 30 {
		t.Fatalf("applied %d policers, want 30 (old partial must not leak in)", len(got.Policers))
	}
	wj, _ := json.Marshal(newWant)
	gj, _ := json.Marshal(*got)
	if string(gj) != string(wj) {
		t.Fatal("superseding reassembly != new snapshot")
	}
}

// TestAcceptChunkDropsStaleEpoch asserts a straggler chunk for an OLDER epoch is
// dropped and does not corrupt the in-progress newer snapshot.
func TestAcceptChunkDropsStaleEpoch(t *testing.T) {
	var got *model.EdgeDesiredState
	c := &Client{onDesired: func(s model.EdgeDesiredState) { got = &s }, log: discardLogger()}

	newWant := chunkState(200, 20)
	newChunks := model.SplitDesiredState(newWant, 8)
	oldChunks := model.SplitDesiredState(chunkState(100, 20), 8)

	c.acceptChunk(newChunks[0]) // start epoch 200
	c.acceptChunk(oldChunks[0]) // stale epoch 100 straggler — must be dropped
	for _, ch := range newChunks[1:] {
		c.acceptChunk(ch)
	}
	if got == nil || got.Generation != 200 {
		t.Fatalf("stale straggler corrupted the snapshot: %+v", got)
	}
	gj, _ := json.Marshal(*got)
	wj, _ := json.Marshal(newWant)
	if string(gj) != string(wj) {
		t.Fatal("stale straggler leaked into reassembly")
	}
}
