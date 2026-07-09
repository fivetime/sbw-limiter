package birdfeed

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/fivetime/sbw-contract/model"
)

// fakeSink captures frames instead of writing to a socket.
type fakeSink struct {
	conn   bool
	frames [][]byte
}

func (s *fakeSink) connected() bool { return s.conn }
func (s *fakeSink) connect() error  { s.conn = true; return nil }
func (s *fakeSink) write(f []byte)  { s.frames = append(s.frames, append([]byte(nil), f...)) }
func (s *fakeSink) flush() error    { return nil }
func (s *fakeSink) close()          { s.conn = false }

func newTestFeed() (*Feed, *fakeSink) {
	s := &fakeSink{}
	return &Feed{
		client:  s,
		log:     slog.New(slog.DiscardHandler),
		anchors: map[netip.Prefix]struct{}{},
		flows:   map[netip.Prefix]struct{}{},
		resync:  true,
	}, s
}

func countOps(frames [][]byte) (add, del, hello, eor int) {
	for _, fr := range frames {
		switch fr[1] {
		case opAdd:
			add++
		case opDel:
			del++
		case opHello:
			hello++
		case opEOR:
			eor++
		}
	}
	return
}

func anchor(s string) model.Anchor { return model.Anchor{Prefix: netip.MustParsePrefix(s)} }
func flow(s string) model.FlowRedirect {
	return model.FlowRedirect{SrcPrefix: netip.MustParsePrefix(s)}
}

func TestFeedResyncThenDiff(t *testing.T) {
	f, s := newTestFeed()
	nh := netip.MustParseAddr("10.0.0.1")
	st := model.EdgeDesiredState{
		Anchors:         []model.Anchor{anchor("11.0.0.0/32"), anchor("11.0.0.1/32")},
		FlowRedirects:   []model.FlowRedirect{flow("11.0.0.0/32")},
		RedirectNextHop: nh,
	}

	// Pass 1: cold connect → full resync: HELLO + 2 anchor ADD + 1 flow ADD + EOR.
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	add, del, hello, eor := countOps(s.frames)
	if hello != 1 || eor != 1 || add != 3 || del != 0 {
		t.Fatalf("resync: hello=%d eor=%d add=%d del=%d (want 1/1/3/0)", hello, eor, add, del)
	}

	// Pass 2: +1 anchor, -1 anchor; flows unchanged → incremental: 1 ADD + 1 DEL.
	s.frames = nil
	st.Anchors = []model.Anchor{anchor("11.0.0.1/32"), anchor("11.0.0.2/32")}
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	add, del, hello, eor = countOps(s.frames)
	if hello != 0 || eor != 0 || add != 1 || del != 1 {
		t.Fatalf("diff: hello=%d eor=%d add=%d del=%d (want 0/0/1/1)", hello, eor, add, del)
	}
}

// A redirect next-hop change re-syncs all flows (the EC changes for every flow).
func TestFeedNextHopChangeResyncs(t *testing.T) {
	f, s := newTestFeed()
	st := model.EdgeDesiredState{
		Anchors:         []model.Anchor{anchor("11.0.0.0/32")},
		FlowRedirects:   []model.FlowRedirect{flow("11.0.0.0/32")},
		RedirectNextHop: netip.MustParseAddr("10.0.0.1"),
	}
	if err := f.apply(st); err != nil { // pass 1: resync
		t.Fatal(err)
	}
	s.frames = nil
	st.RedirectNextHop = netip.MustParseAddr("10.0.0.2") // next-hop changed
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	_, _, hello, eor := countOps(s.frames)
	if hello != 1 || eor != 1 {
		t.Fatalf("next-hop change should resync: hello=%d eor=%d (want 1/1)", hello, eor)
	}
}

// v4 flowspec with a non-v4 redirect next-hop is a hard error (fail-static): the
// pass is skipped, nothing fed (mirrors flowspec.Render rejecting the include).
func TestFeedBadNextHopFails(t *testing.T) {
	f, s := newTestFeed()
	st := model.EdgeDesiredState{
		FlowRedirects:   []model.FlowRedirect{flow("11.0.0.0/32")},
		RedirectNextHop: netip.Addr{}, // not v4
	}
	if err := f.apply(st); err == nil {
		t.Fatal("expected error for v4 flowspec with non-v4 next-hop")
	}
	if len(s.frames) != 0 {
		t.Fatalf("nothing should be fed on a failed pass, got %d frames", len(s.frames))
	}
}

// v6 flowspec is now fed (no longer skipped): a v6 source + RedirectNextHopV6
// produces a flow6 ADD carrying the 20-byte i6ec redirect EC, alongside v4.
func TestFeedV6Flowspec(t *testing.T) {
	f, s := newTestFeed()
	st := model.EdgeDesiredState{
		FlowRedirects: []model.FlowRedirect{
			flow("11.0.0.0/32"),    // v4
			flow("fc00:16::3/128"), // v6
		},
		RedirectNextHop:   netip.MustParseAddr("10.0.0.1"),
		RedirectNextHopV6: netip.MustParseAddr("2001:db8::7"),
	}
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	var v6flow []byte
	for _, fr := range s.frames {
		if fr[1] == opAdd && fr[hdrLen] == netFlow6 {
			v6flow = fr
		}
	}
	if v6flow == nil {
		t.Fatal("v6 flowspec was not fed (still skipped?)")
	}
	// body: net(1) px(1) key(16) then the attr TLV — must be EXTCOMM, len 20.
	if at, alen := v6flow[hdrLen+18], v6flow[hdrLen+19]; at != attrExtComm || alen != 20 {
		t.Fatalf("v6 flow attr = type %d len %d, want EXTCOMM/20", at, alen)
	}
}

// v6 flowspec with a non-v6 redirect next-hop is fail-static (nothing fed),
// mirroring the v4 rule.
func TestFeedV6BadNextHopFails(t *testing.T) {
	f, s := newTestFeed()
	st := model.EdgeDesiredState{
		FlowRedirects:     []model.FlowRedirect{flow("fc00:16::3/128")},
		RedirectNextHopV6: netip.Addr{}, // not v6
	}
	if err := f.apply(st); err == nil {
		t.Fatal("expected error for v6 flowspec with non-v6 next-hop")
	}
	if len(s.frames) != 0 {
		t.Fatalf("nothing should be fed on a failed pass, got %d frames", len(s.frames))
	}
}

// --- peer-death resync (bird restart → re-feed unchanged desired state) -----

func TestFeedPeerDeathResyncsUnchangedState(t *testing.T) {
	f, s := newTestFeed()
	st := model.EdgeDesiredState{
		Anchors:         []model.Anchor{anchor("11.0.0.0/32"), anchor("11.0.0.1/32")},
		FlowRedirects:   []model.FlowRedirect{flow("11.0.0.0/32")},
		RedirectNextHop: netip.MustParseAddr("10.0.0.1"),
	}
	if err := f.apply(st); err != nil { // pass 1: cold resync
		t.Fatal(err)
	}
	s.frames = nil
	if err := f.apply(st); err != nil { // pass 2: steady state → zero diff
		t.Fatal(err)
	}
	if len(s.frames) != 0 {
		t.Fatalf("steady state must be a zero-diff pass, wrote %d frames", len(s.frames))
	}

	s.conn = false // bird restarted: the watcher tore the connection down
	s.frames = nil
	if err := f.apply(st); err != nil { // pass 3: SAME state → reconnect + full resync
		t.Fatal(err)
	}
	add, del, hello, eor := countOps(s.frames)
	if hello != 1 || eor != 1 || add != 3 || del != 0 {
		t.Fatalf("post-death resync: hello=%d eor=%d add=%d del=%d (want 1/1/3/0)", hello, eor, add, del)
	}
}
