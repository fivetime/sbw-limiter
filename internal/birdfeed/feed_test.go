package birdfeed

import (
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/fivetime/sbw-contract/model"
)

// fakeSink captures frames instead of writing to a socket.
type fakeSink struct {
	conn     bool
	frames   [][]byte
	flushErr error // injected flush failure (nil = success)
	flushes  int   // count of flush() calls (pacing test)
}

func (s *fakeSink) connected() bool { return s.conn }
func (s *fakeSink) connect() error  { s.conn = true; return nil }
func (s *fakeSink) write(f []byte)  { s.frames = append(s.frames, append([]byte(nil), f...)) }
func (s *fakeSink) flush() error    { s.flushes++; return s.flushErr }
func (s *fakeSink) close()          { s.conn = false }

func newTestFeed() (*Feed, *fakeSink) {
	s := &fakeSink{}
	return &Feed{
		client:  s,
		log:     slog.New(slog.DiscardHandler),
		anchors: map[netip.Prefix][]byte{},
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

// A pass that fails on FLUSH — bird's death detected by the agent's OWN write,
// where f.client.close() also tears down the reader-EOF watcher that would have
// woken the feed — must self-arm the short-fuse retry wake, not wait out the next
// full interval tick (2026-07-17 audit #5).
func TestFeedFlushFailureArmsRetryWake(t *testing.T) {
	f, s := newTestFeed()
	f.wake = make(chan struct{}, 1)
	s.flushErr = errors.New("EPIPE (bird went away)")
	st := model.EdgeDesiredState{Anchors: []model.Anchor{anchor("203.0.113.10/32")}}
	f.pass(func() (model.EdgeDesiredState, bool) { return st, true })
	if fails, _ := f.Status(); fails != 1 {
		t.Fatalf("fails = %d after flush-failure pass, want 1", fails)
	}
	select {
	case <-f.wake: // the ~2s fuse fired
	case <-time.After(4 * time.Second):
		t.Fatal("no retry wake after a flush-failure pass — steering re-feed degrades to the next interval tick")
	}
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

// TestFeedStatusCountsConsecutiveFailures locks the feed-health contract
// (HealthReport.BirdFeedFails / metrics): a failed apply pass increments the
// CONSECUTIVE counter, a successful (flushed+committed) pass resets it to 0 and
// stamps lastOK — so a persistently broken feed is visible to the server
// (bird-feed-degraded) instead of log-only.
func TestFeedStatusCountsConsecutiveFailures(t *testing.T) {
	f, s := newTestFeed()
	st := model.EdgeDesiredState{
		Anchors: []model.Anchor{anchor("11.0.0.1/32")},
	}
	provider := func() (model.EdgeDesiredState, bool) { return st, true }

	// Two failing passes (flush error) → fails=2, lastOK still 0.
	s.flushErr = errors.New("bird gone")
	f.pass(provider)
	f.pass(provider)
	if fails, lastOK := f.Status(); fails != 2 || lastOK != 0 {
		t.Fatalf("after 2 failed passes: fails=%d lastOK=%d, want 2/0", fails, lastOK)
	}

	// Recovery: flush succeeds → fails resets, lastOK stamped.
	s.flushErr = nil
	f.pass(provider)
	if fails, lastOK := f.Status(); fails != 0 || lastOK == 0 {
		t.Fatalf("after recovery: fails=%d lastOK=%d, want 0/nonzero", fails, lastOK)
	}

	// Cold-start skip (provider not ok) is NOT a failure.
	f.pass(func() (model.EdgeDesiredState, bool) { return model.EdgeDesiredState{}, false })
	if fails, _ := f.Status(); fails != 0 {
		t.Fatalf("cold-start skip must not count as failure, fails=%d", fails)
	}
}

// TestFeedAnchorCarriesCommunities pins the §6.56 fix: an anchor's RTBH
// communities must ride the api feed as TLVs (they were dropped — upstream got
// plain unicast and never dropped the victim traffic), and a community CHANGE
// must re-announce the anchor (diff by prefix+attr signature, upsert in bird).
func TestFeedAnchorCarriesCommunities(t *testing.T) {
	f, s := newTestFeed()
	rtbh := model.Community{ASN: 65000, Value: 666}
	lc := model.LargeCommunity{GlobalAdmin: 4231457290, LocalData1: 666, LocalData2: 0}
	st := model.EdgeDesiredState{
		Anchors: []model.Anchor{{
			Prefix:           netip.MustParsePrefix("172.16.8.7/32"),
			Communities:      []model.Community{rtbh},
			LargeCommunities: []model.LargeCommunity{lc},
		}},
	}
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	// One anchor ADD; its body must contain both community TLVs with BE payloads.
	var add []byte
	for _, fr := range s.frames {
		if fr[1] == opAdd {
			add = fr
		}
	}
	if add == nil {
		t.Fatal("no anchor ADD frame")
	}
	body := add[hdrLen:]
	// body: net(1) px(1) key(4) blackholeTLV(2) then community TLVs.
	at := body[2+4+2:]
	if at[0] != attrCommunity || at[1] != 4 {
		t.Fatalf("community TLV header = %d/%d, want %d/4", at[0], at[1], attrCommunity)
	}
	if got := []byte{at[2], at[3], at[4], at[5]}; got[0] != 0xFD || got[1] != 0xE8 || got[2] != 0x02 || got[3] != 0x9A {
		t.Fatalf("community payload = % x, want fd e8 02 9a (65000:666 BE)", got)
	}
	lt := at[2+4:]
	if lt[0] != attrLargeCommunity || lt[1] != 12 {
		t.Fatalf("large-community TLV header = %d/%d, want %d/12", lt[0], lt[1], attrLargeCommunity)
	}

	// Community change (same prefix) → re-announce (one more ADD), not silence.
	s.frames = nil
	st.Anchors[0].Communities = []model.Community{{ASN: 65000, Value: 667}}
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	adds := 0
	for _, fr := range s.frames {
		if fr[1] == opAdd {
			adds++
		}
	}
	if adds != 1 {
		t.Fatalf("community change must re-announce exactly once, got %d ADDs", adds)
	}
	// Unchanged pass → zero writes.
	s.frames = nil
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	if len(s.frames) != 0 {
		t.Fatalf("steady state must be zero-diff, wrote %d frames", len(s.frames))
	}
}

// Pacing (#1, the 60K-churn os_panic amplifier fix): a resync larger than maxOps
// flushes mid-pass (bounding bird-vpp's in-flight between chunks) while still
// writing every frame. maxOps=2 over HELLO+5 ADD+EOR (7 frames) = 3 mid-pass
// flushes + 1 final flush.
func TestFeedPacingChunksResync(t *testing.T) {
	f, s := newTestFeed()
	f.maxOps = 2 // pace=0: no sleep, fast test
	st := model.EdgeDesiredState{Anchors: []model.Anchor{
		anchor("11.0.0.0/32"), anchor("11.0.0.1/32"), anchor("11.0.0.2/32"),
		anchor("11.0.0.3/32"), anchor("11.0.0.4/32"),
	}}
	if err := f.apply(st); err != nil {
		t.Fatal(err)
	}
	add, del, hello, eor := countOps(s.frames)
	if hello != 1 || eor != 1 || add != 5 || del != 0 {
		t.Fatalf("paced resync frames: hello=%d eor=%d add=%d del=%d (want 1/1/5/0)", hello, eor, add, del)
	}
	if s.flushes != 4 {
		t.Fatalf("flushes=%d, want 4 (3 mid-pass chunks of 2 + 1 final)", s.flushes)
	}
}

// A mid-pass paced flush failure (bird went away during a big resync) must return
// the error, tear the connection down, and keep resync armed for the next pass.
func TestFeedPacingMidPassFlushErrorResyncs(t *testing.T) {
	f, s := newTestFeed()
	f.maxOps = 2
	s.flushErr = errors.New("bird gone")
	st := model.EdgeDesiredState{Anchors: []model.Anchor{
		anchor("11.0.0.0/32"), anchor("11.0.0.1/32"), anchor("11.0.0.2/32"),
	}}
	if err := f.apply(st); err == nil {
		t.Fatal("want error from the mid-pass flush")
	}
	if !f.resync {
		t.Fatal("resync must stay armed after a mid-pass flush error")
	}
	if s.connected() {
		t.Fatal("client must be closed after a mid-pass flush error")
	}
}
