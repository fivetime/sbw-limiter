package vpp

import (
	"net/netip"
	"testing"

	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/binapi/probe"
)

// TestLookupHitsRequestAndReply asserts LookupHits builds one probe_classify_lookup
// carrying the FULL match buffers (as AddSession sends), and maps the positional
// reply hits back — including NoTable (~0) for an absent member.
func TestLookupHitsRequestAndReply(t *testing.T) {
	// Reply: first member hits policer 7, second is absent.
	ch := newFakeChannel(func(reply govppapi.Message) error {
		r := reply.(*probe.ProbeClassifyLookupReply)
		r.Count = 2
		r.Hits = []uint32{7, NoTable}
		return nil
	})
	cl := NewClassify(ch)

	mask := model.MaskIP4Dst32
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.10/32"),
		netip.MustParsePrefix("203.0.113.11/32"),
	}
	hits, err := cl.LookupHits(42, mask, prefixes)
	if err != nil {
		t.Fatalf("LookupHits: %v", err)
	}
	if len(hits) != 2 || hits[0] != 7 || hits[1] != NoTable {
		t.Fatalf("hits = %v, want [7, %d]", hits, NoTable)
	}

	// The request must be a single probe_classify_lookup with the concatenated
	// full match buffers and a per-key length matching AddSession's byte layout.
	req, ok := ch.lastSent().(*probe.ProbeClassifyLookup)
	if !ok {
		t.Fatalf("sent %T, want *probe.ProbeClassifyLookup", ch.lastSent())
	}
	ms, _ := specOf(mask)
	want0, _ := ms.sessionMatch(prefixes[0])
	want1, _ := ms.sessionMatch(prefixes[1])
	if req.TableID != 42 {
		t.Errorf("TableID = %d, want 42", req.TableID)
	}
	if int(req.KeyLen) != len(want0) {
		t.Errorf("KeyLen = %d, want %d (full skip+match buffer)", req.KeyLen, len(want0))
	}
	if int(req.MatchLen) != len(want0)+len(want1) {
		t.Errorf("MatchLen = %d, want %d", req.MatchLen, len(want0)+len(want1))
	}
	wantBuf := append(append([]byte{}, want0...), want1...)
	if string(req.Match) != string(wantBuf) {
		t.Errorf("Match buffer mismatch:\n got %x\nwant %x", req.Match, wantBuf)
	}
	if len(ch.sent) != 1 {
		t.Errorf("sent %d requests, want 1", len(ch.sent))
	}
}

// TestLookupHitsChunks verifies a batch larger than the per-request chunk (1024)
// is split into multiple requests and the positional results are concatenated.
func TestLookupHitsChunks(t *testing.T) {
	const n = 2500 // 1024 + 1024 + 452
	sizes := []uint32{1024, 1024, 452}
	// One reply per chunk, each echoing its chunk-sized hits (all = policer 3).
	var replies []replyFn
	for _, sz := range sizes {
		count := sz
		replies = append(replies, func(reply govppapi.Message) error {
			r := reply.(*probe.ProbeClassifyLookupReply)
			r.Count = count
			r.Hits = make([]uint32, count)
			for i := range r.Hits {
				r.Hits[i] = 3
			}
			return nil
		})
	}
	ch := newFakeChannel(replies...)
	cl := NewClassify(ch)

	prefixes := make([]netip.Prefix, n)
	base := netip.MustParseAddr("10.0.0.0")
	for i := range prefixes {
		prefixes[i] = netip.PrefixFrom(addrAdd(base, uint32(i)), 32)
	}
	hits, err := cl.LookupHits(9, model.MaskIP4Dst32, prefixes)
	if err != nil {
		t.Fatalf("LookupHits: %v", err)
	}
	if len(hits) != n {
		t.Fatalf("hits len = %d, want %d", len(hits), n)
	}
	for i, h := range hits {
		if h != 3 {
			t.Fatalf("hits[%d] = %d, want 3", i, h)
		}
	}
	if len(ch.sent) != len(sizes) {
		t.Fatalf("sent %d requests, want %d (1024+1024+452)", len(ch.sent), len(sizes))
	}
	for i, req := range ch.sent {
		r := req.(*probe.ProbeClassifyLookup)
		if got := r.MatchLen / r.KeyLen; got != sizes[i] {
			t.Errorf("chunk %d count = %d, want %d", i, got, sizes[i])
		}
	}
}

func addrAdd(a netip.Addr, n uint32) netip.Addr {
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += n
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
