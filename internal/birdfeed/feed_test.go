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

// --- REFACTOR step 5: local physical anti-blackhole gate --------------------

// hostAnchorsFed applies st through a feed gated by observed and returns how many
// anchor ADD frames were emitted on a cold resync (= how many anchors were advertised).
func gatedResyncAdds(t *testing.T, observed func() []netip.Prefix, anchors ...string) int {
	t.Helper()
	f, s := newTestFeed()
	f.observed = observed
	as := make([]model.Anchor, len(anchors))
	for i, a := range anchors {
		as[i] = anchor(a)
	}
	if err := f.apply(model.EdgeDesiredState{Anchors: as}); err != nil {
		t.Fatal(err)
	}
	add, _, _, _ := countOps(s.frames)
	return add
}

func TestGateNilObservationFailsStatic(t *testing.T) {
	// No gate wired → advertise all.
	if got := gatedResyncAdds(t, nil, "11.0.0.0/32", "11.0.0.1/32"); got != 2 {
		t.Fatalf("nil gate: adds=%d want 2 (advertise all)", got)
	}
	// Gate wired but returns nil (untrustworthy read) → fail-static, advertise all.
	if got := gatedResyncAdds(t, func() []netip.Prefix { return nil }, "11.0.0.0/32", "11.0.0.1/32"); got != 2 {
		t.Fatalf("nil-return gate: adds=%d want 2 (fail-static)", got)
	}
}

func TestGateIntersectsPhysical(t *testing.T) {
	// Observe only .0 present → only its anchor is advertised; .1 withheld.
	obs := func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("11.0.0.0/32")} }
	if got := gatedResyncAdds(t, obs, "11.0.0.0/32", "11.0.0.1/32"); got != 1 {
		t.Fatalf("intersect gate: adds=%d want 1 (only physically-present)", got)
	}
	// Empty (but non-nil = trustworthy "none present") → withhold all host anchors.
	empty := func() []netip.Prefix { return []netip.Prefix{} }
	if got := gatedResyncAdds(t, empty, "11.0.0.0/32", "11.0.0.1/32"); got != 0 {
		t.Fatalf("empty-observation gate: adds=%d want 0 (none present)", got)
	}
}

func TestGateNeverGatesNonHost(t *testing.T) {
	// A /24 bare-metal block is not a physical-presence signal → advertised even when
	// the observation is empty (mirrors the server's shouldWithdraw non-host exemption).
	empty := func() []netip.Prefix { return []netip.Prefix{} }
	if got := gatedResyncAdds(t, empty, "11.0.0.0/24", "11.0.0.1/32"); got != 1 {
		t.Fatalf("non-host gate: adds=%d want 1 (/24 always fed, /32 withheld)", got)
	}
}

// A member reappearing in the physical set re-advertises its withheld anchor (the diff
// turns the gate change into an ADD), and disappearing withdraws it (DEL).
func TestGateReappearAndWithdraw(t *testing.T) {
	f, s := newTestFeed()
	present := map[netip.Prefix]bool{netip.MustParsePrefix("11.0.0.0/32"): true}
	f.observed = func() []netip.Prefix {
		out := []netip.Prefix{} // NON-nil: a clean observation (empty = "none present"), not "unread"
		for p, ok := range present {
			if ok {
				out = append(out, p)
			}
		}
		return out
	}
	st := model.EdgeDesiredState{Anchors: []model.Anchor{anchor("11.0.0.0/32")}}
	if err := f.apply(st); err != nil { // resync: .0 present → 1 ADD
		t.Fatal(err)
	}
	// .0 physically leaves → next pass DELs it.
	s.frames = nil
	present[netip.MustParsePrefix("11.0.0.0/32")] = false
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	if _, del, _, _ := countOps(s.frames); del != 1 {
		t.Fatalf("physical-leave: del=%d want 1 (withdraw)", del)
	}
	// .0 comes back → ADD again.
	s.frames = nil
	present[netip.MustParsePrefix("11.0.0.0/32")] = true
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	if add, _, _, _ := countOps(s.frames); add != 1 {
		t.Fatalf("physical-return: add=%d want 1 (re-advertise)", add)
	}
}
