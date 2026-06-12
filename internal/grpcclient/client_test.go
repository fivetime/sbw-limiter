package grpcclient

import (
	"context"
	"encoding/json"
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

// fakeServer is a minimal controller for client tests (the real one lives in
// sbw-controller, a different module).
type fakeServer struct {
	rpc.UnimplementedAgentServiceServer
	mu      sync.Mutex
	regEdge string
	regCap  uint64
	reports []model.EdgeReport
	pushCh  chan *rpc.Directive
	subbed  chan struct{}
}

func newFakeServer() *fakeServer {
	return &fakeServer{pushCh: make(chan *rpc.Directive, 8), subbed: make(chan struct{}, 1)}
}

func (f *fakeServer) Register(_ context.Context, req *rpc.RegisterRequest) (*rpc.RegisterResponse, error) {
	f.mu.Lock()
	f.regEdge, f.regCap = req.EdgeId, req.CapacityBps
	f.mu.Unlock()
	return &rpc.RegisterResponse{SchemaVersion: model.SchemaVersion, Accepted: true}, nil
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
