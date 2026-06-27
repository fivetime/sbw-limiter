package vpp

import (
	"fmt"
	"net/netip"

	govppapi "go.fd.io/govpp/api"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/binapi/classify"
	"github.com/fivetime/sbw-limiter/internal/binapi/interface_types"
)

// Classify materializes the six fixed classify mask tables and their member
// sessions (T-403/T-404, DESIGN.md §5.2/§5.3). The mask/match byte layout is
// derived from first principles and verified byte-identical against real VPP:
//
//	absStart = ethHdr(14) + ipFieldOffset      // where the address sits in the packet
//	skip_n_vectors  = absStart / 16            // VPP skips leading all-zero 16B vectors
//	match_n_vectors = absEnd/16 - skip + 1     // 16B vectors spanning the address
//
// The TABLE mask is the match portion only (mask_len == match_n_vectors*16);
// the SESSION match is the full buffer ((skip+match)*16) with the address at
// its absolute packet offset (VPP masks the key on insert).
type Classify struct {
	ch govppapi.Channel
}

// NewClassify wraps a channel for classify operations.
func NewClassify(ch govppapi.Channel) *Classify { return &Classify{ch: ch} }

const (
	ethHdrLen = 14 // Ethernet header consumed before the IP header
	vec       = 16 // one u32x4 classify vector
)

// maskSpec describes a fixed mask kind in packet terms.
type maskSpec struct {
	family   model.Family
	isDst    bool
	maskBits int // netmask width: 32/24 (v4), 128 (v6)
}

func specOf(m model.MaskKind) (maskSpec, error) {
	switch m {
	case model.MaskIP4Dst32:
		return maskSpec{model.FamilyIPv4, true, 32}, nil
	case model.MaskIP4Dst24:
		return maskSpec{model.FamilyIPv4, true, 24}, nil
	case model.MaskIP6Dst128:
		return maskSpec{model.FamilyIPv6, true, 128}, nil
	case model.MaskIP4Src32:
		return maskSpec{model.FamilyIPv4, false, 32}, nil
	case model.MaskIP4Src24:
		return maskSpec{model.FamilyIPv4, false, 24}, nil
	case model.MaskIP6Src128:
		return maskSpec{model.FamilyIPv6, false, 128}, nil
	default:
		return maskSpec{}, fmt.Errorf("vpp: unknown mask kind %v", m)
	}
}

// addrField returns the IP-header field offset and address length for a mask.
func (s maskSpec) addrField() (fieldOffset, addrLen int) {
	if s.family == model.FamilyIPv4 {
		if s.isDst {
			return 16, 4
		}
		return 12, 4
	}
	if s.isDst {
		return 24, 16
	}
	return 8, 16
}

// layout computes skip/match vector counts and the absolute packet byte range
// of the matched address.
func (s maskSpec) layout() (skip, match, absStart, absEnd int) {
	fieldOff, addrLen := s.addrField()
	absStart = ethHdrLen + fieldOff
	absEnd = absStart + addrLen - 1
	skip = absStart / vec
	match = absEnd/vec - skip + 1
	return
}

// netmask returns the CIDR netmask bytes for the spec's address length.
func (s maskSpec) netmask() []byte {
	_, addrLen := s.addrField()
	out := make([]byte, addrLen)
	bits := s.maskBits
	for i := range out {
		switch {
		case bits >= 8:
			out[i] = 0xff
			bits -= 8
		case bits > 0:
			out[i] = byte(0xff << (8 - bits))
			bits = 0
		}
	}
	return out
}

// tableMask builds the match-only mask buffer (match_n_vectors*16 bytes) with
// the netmask placed at the address offset within the match region.
func (s maskSpec) tableMask() (skip, match uint32, mask []byte) {
	skipI, matchI, absStart, _ := s.layout()
	mask = make([]byte, matchI*vec)
	off := absStart - skipI*vec // offset within the match region
	copy(mask[off:], s.netmask())
	return uint32(skipI), uint32(matchI), mask
}

// sessionMatch builds the full match buffer ((skip+match)*16 bytes) with the
// prefix's address at its absolute packet offset.
func (s maskSpec) sessionMatch(p netip.Prefix) ([]byte, error) {
	skipI, matchI, absStart, _ := s.layout()
	addr := p.Addr()
	var addrBytes []byte
	switch {
	case s.family == model.FamilyIPv4 && addr.Is4():
		b := addr.As4()
		addrBytes = b[:]
	case s.family == model.FamilyIPv6 && addr.Is6() && !addr.Is4In6():
		b := addr.As16()
		addrBytes = b[:]
	default:
		return nil, fmt.Errorf("vpp: prefix %s family mismatch for mask spec", p)
	}
	buf := make([]byte, (skipI+matchI)*vec)
	copy(buf[absStart:], addrBytes)
	return buf, nil
}

// TableSpec configures one mask table. The table is created standalone; chain
// it to the next mask table with LinkTable (table index 0 is valid, so a "next"
// field with a zero-value sentinel would be ambiguous — chaining is explicit).
type TableSpec struct {
	Mask       model.MaskKind
	Nbuckets   uint32
	MemorySize uint32
}

// NoTable is the sentinel for "no next/this table" (VPP ~0).
const NoTable = ^uint32(0)

// AddTable creates a standalone mask table and returns its index. Zero-value
// fallback defaults: nbuckets 4096, memory 16 MiB. These are the legacy default
// only — production callers pass Nbuckets/MemorySize sized by the per-node memory
// budget (internal/agent/classifysizing.go); the classify table is a fixed
// non-growable heap and the old "16M/4096 ample for 3000" assumption crashed VPP
// at full (§5.3). Use LinkTable to chain it. next/miss default to NoTable (chain
// end / fall through arc).
func (c *Classify) AddTable(spec TableSpec) (uint32, error) {
	ms, err := specOf(spec.Mask)
	if err != nil {
		return 0, err
	}
	skip, match, mask := ms.tableMask()

	nbuckets := spec.Nbuckets
	if nbuckets == 0 {
		nbuckets = 4096
	}
	mem := spec.MemorySize
	if mem == 0 {
		mem = 16 << 20
	}

	req := &classify.ClassifyAddDelTable{
		IsAdd:          true,
		TableIndex:     NoTable,
		Nbuckets:       nbuckets,
		MemorySize:     mem,
		SkipNVectors:   skip,
		MatchNVectors:  match,
		NextTableIndex: NoTable,
		MissNextIndex:  NoTable,
		MaskLen:        uint32(len(mask)),
		Mask:           mask,
	}
	reply := &classify.ClassifyAddDelTableReply{}
	if err := c.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return 0, fmt.Errorf("vpp: classify_add_del_table (%v): %w", spec.Mask, err)
	}
	if reply.Retval != 0 {
		return 0, fmt.Errorf("vpp: classify_add_del_table (%v) failed: retval %d", spec.Mask, reply.Retval)
	}
	return reply.NewTableIndex, nil
}

// LinkTable sets an existing table's next_table_index (chains a mask table to
// the next one in the串查 chain, §5.3).
func (c *Classify) LinkTable(tableIndex, nextTableIndex uint32) error {
	req := &classify.ClassifyAddDelTable{
		IsAdd:          true, // is_add with an existing index = update
		TableIndex:     tableIndex,
		NextTableIndex: nextTableIndex,
		MissNextIndex:  NoTable,
	}
	reply := &classify.ClassifyAddDelTableReply{}
	if err := c.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return fmt.Errorf("vpp: link table %d->%d: %w", tableIndex, nextTableIndex, err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("vpp: link table %d->%d failed: retval %d", tableIndex, nextTableIndex, reply.Retval)
	}
	return nil
}

// DeleteTable removes a mask table by index.
func (c *Classify) DeleteTable(tableIndex uint32) error {
	req := &classify.ClassifyAddDelTable{IsAdd: false, TableIndex: tableIndex, NextTableIndex: NoTable, MissNextIndex: NoTable}
	reply := &classify.ClassifyAddDelTableReply{}
	if err := c.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return fmt.Errorf("vpp: delete table %d: %w", tableIndex, err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("vpp: delete table %d failed: retval %d", tableIndex, reply.Retval)
	}
	return nil
}

// AddSession installs a member session: a prefix mapped to a hit target on the
// given mask table. For policer-classify, hitNext is the pool policer index
// (T-404) — multiple sessions naming the same index share its token bucket.
func (c *Classify) AddSession(tableIndex uint32, mask model.MaskKind, prefix netip.Prefix, hitNext uint32) error {
	return c.session(true, tableIndex, mask, prefix, hitNext)
}

// DelSession removes a member session.
func (c *Classify) DelSession(tableIndex uint32, mask model.MaskKind, prefix netip.Prefix) error {
	return c.session(false, tableIndex, mask, prefix, NoTable)
}

// SessionKey returns a session's stored KEY (the match-only region,
// match_n_vectors*16 bytes) for a (mask, prefix). This is what
// classify_session_dump returns in Match, so reconciliation compares desired
// SessionKey against the dumped Match directly. NOTE: the key is SHORTER than
// the add/del match buffer, which includes the skipped region — see
// DelSessionByKey for the reconstruction.
func SessionKey(mask model.MaskKind, prefix netip.Prefix) ([]byte, error) {
	ms, err := specOf(mask)
	if err != nil {
		return nil, err
	}
	full, err := ms.sessionMatch(prefix)
	if err != nil {
		return nil, err
	}
	skip, _, _ := ms.tableMask()
	return full[int(skip)*vec:], nil // strip the skipped (all-zero) prefix
}

// DelSessionByKey deletes a session given its match-only key (as returned by
// DumpSessions). VPP's classify_add_del_session needs the FULL buffer
// ((skip+match)*16), so we prepend the skipped region (zeros) back.
func (c *Classify) DelSessionByKey(tableIndex uint32, mask model.MaskKind, key []byte) error {
	ms, err := specOf(mask)
	if err != nil {
		return err
	}
	skip, _, _ := ms.tableMask()
	full := make([]byte, int(skip)*vec+len(key))
	copy(full[int(skip)*vec:], key)

	req := &classify.ClassifyAddDelSession{
		IsAdd:        false,
		TableIndex:   tableIndex,
		HitNextIndex: NoTable,
		OpaqueIndex:  NoTable,
		MatchLen:     uint32(len(full)),
		Match:        full,
	}
	reply := &classify.ClassifyAddDelSessionReply{}
	if err := c.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return fmt.Errorf("vpp: classify_add_del_session(del key): %w", err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("vpp: classify session delete failed: retval %d", reply.Retval)
	}
	return nil
}

// FindTablesByMask enumerates VPP's classify tables and maps each back to its
// mask kind by matching skip/match/mask against the six fixed layouts. Used to
// recover the mask→table-index map after an agent restart (VPP assigns table
// indices, and the agent's in-memory map is lost on restart).
func (c *Classify) FindTablesByMask() (map[model.MaskKind]uint32, error) {
	idsReply := &classify.ClassifyTableIdsReply{}
	if err := c.ch.SendRequest(&classify.ClassifyTableIds{}).ReceiveReply(idsReply); err != nil {
		return nil, fmt.Errorf("vpp: classify_table_ids: %w", err)
	}
	out := make(map[model.MaskKind]uint32)
	for _, id := range idsReply.Ids {
		info, err := c.TableInfo(id)
		if err != nil {
			return nil, err
		}
		for _, mk := range allMaskKinds {
			ms, _ := specOf(mk)
			skip, match, mask := ms.tableMask()
			if info.SkipNVectors == skip && info.MatchNVectors == match && bytesEqual(info.Mask, mask) {
				out[mk] = id
				break
			}
		}
	}
	return out, nil
}

var allMaskKinds = []model.MaskKind{
	model.MaskIP4Dst32, model.MaskIP4Dst24, model.MaskIP6Dst128,
	model.MaskIP4Src32, model.MaskIP4Src24, model.MaskIP6Src128,
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *Classify) session(isAdd bool, tableIndex uint32, mask model.MaskKind, prefix netip.Prefix, hitNext uint32) error {
	ms, err := specOf(mask)
	if err != nil {
		return err
	}
	match, err := ms.sessionMatch(prefix)
	if err != nil {
		return err
	}
	req := &classify.ClassifyAddDelSession{
		IsAdd:        isAdd,
		TableIndex:   tableIndex,
		HitNextIndex: hitNext,
		OpaqueIndex:  NoTable,
		MatchLen:     uint32(len(match)),
		Match:        match,
	}
	reply := &classify.ClassifyAddDelSessionReply{}
	if err := c.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return fmt.Errorf("vpp: classify_add_del_session %s: %w", prefix, err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("vpp: classify_add_del_session %s failed: retval %d", prefix, reply.Retval)
	}
	return nil
}

// SetPolicerInterface attaches (isAdd) or detaches the ip4/ip6 classify chain
// heads to an interface for policer-classify (§5.2). Pass NoTable for a family
// to leave untouched. NOTE: VPP skips any family whose table index is NoTable,
// so DETACH must pass the SAME table index that was attached (not NoTable) —
// passing NoTable on detach is a silent no-op.
func (c *Classify) SetPolicerInterface(swIfIndex uint32, ip4Table, ip6Table uint32, isAdd bool) error {
	req := &classify.PolicerClassifySetInterface{
		SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
		IP4TableIndex: ip4Table,
		IP6TableIndex: ip6Table,
		L2TableIndex:  NoTable,
		IsAdd:         isAdd,
	}
	reply := &classify.PolicerClassifySetInterfaceReply{}
	if err := c.ch.SendRequest(req).ReceiveReply(reply); err != nil {
		return fmt.Errorf("vpp: policer_classify_set_interface %d: %w", swIfIndex, err)
	}
	if reply.Retval != 0 {
		return fmt.Errorf("vpp: policer_classify_set_interface %d failed: retval %d", swIfIndex, reply.Retval)
	}
	return nil
}

// PolicerClassifyAttachment is one interface→table binding (for verification
// and reconciliation, T-501).
type PolicerClassifyAttachment struct {
	SwIfIndex  uint32
	TableIndex uint32
}

// DumpPolicerClassify lists the policer-classify table bindings for the given
// family (ip4 or ip6). VPP returns one entry per interface that has a table.
func (c *Classify) DumpPolicerClassify(family model.Family) ([]PolicerClassifyAttachment, error) {
	t := classify.POLICER_CLASSIFY_API_TABLE_IP4
	if family == model.FamilyIPv6 {
		t = classify.POLICER_CLASSIFY_API_TABLE_IP6
	}
	reqCtx := c.ch.SendMultiRequest(&classify.PolicerClassifyDump{Type: t})
	var out []PolicerClassifyAttachment
	for {
		d := &classify.PolicerClassifyDetails{}
		stop, err := reqCtx.ReceiveReply(d)
		if err != nil {
			return nil, fmt.Errorf("vpp: policer_classify_dump: %w", err)
		}
		if stop {
			break
		}
		out = append(out, PolicerClassifyAttachment{SwIfIndex: uint32(d.SwIfIndex), TableIndex: d.TableIndex})
	}
	return out, nil
}

// TableInfo is a table's layout, read back from VPP (for verification/recon).
type TableInfo struct {
	TableID        uint32
	SkipNVectors   uint32
	MatchNVectors  uint32
	NextTableIndex uint32
	Mask           []byte
}

// SessionInfo is one classify session read back from VPP. HitNextIndex is the
// policer index for policer-classify sessions — the shared-bucket link (§5.2).
type SessionInfo struct {
	HitNextIndex uint32
	Match        []byte
}

// DumpSessions enumerates the sessions on a table (for reconciliation T-501 and
// shared-bucket verification: multiple members sharing one policer all report
// the same HitNextIndex).
func (c *Classify) DumpSessions(tableIndex uint32) ([]SessionInfo, error) {
	reqCtx := c.ch.SendMultiRequest(&classify.ClassifySessionDump{TableID: tableIndex})
	var out []SessionInfo
	for {
		d := &classify.ClassifySessionDetails{}
		stop, err := reqCtx.ReceiveReply(d)
		if err != nil {
			return nil, fmt.Errorf("vpp: classify_session_dump %d: %w", tableIndex, err)
		}
		if stop {
			break
		}
		out = append(out, SessionInfo{HitNextIndex: d.HitNextIndex, Match: d.Match})
	}
	return out, nil
}

// TableInfo reads back one table's layout via classify_table_info.
func (c *Classify) TableInfo(tableIndex uint32) (TableInfo, error) {
	reply := &classify.ClassifyTableInfoReply{}
	if err := c.ch.SendRequest(&classify.ClassifyTableInfo{TableID: tableIndex}).ReceiveReply(reply); err != nil {
		return TableInfo{}, fmt.Errorf("vpp: classify_table_info %d: %w", tableIndex, err)
	}
	if reply.Retval != 0 {
		return TableInfo{}, fmt.Errorf("vpp: classify_table_info %d failed: retval %d", tableIndex, reply.Retval)
	}
	return TableInfo{
		TableID:        reply.TableID,
		SkipNVectors:   reply.SkipNVectors,
		MatchNVectors:  reply.MatchNVectors,
		NextTableIndex: reply.NextTableIndex,
		Mask:           reply.Mask,
	}, nil
}
