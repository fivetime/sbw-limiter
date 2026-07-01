package ipfix

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func be64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }

func msg(obsDomain uint32, sets ...[]byte) []byte {
	m := make([]byte, 0, 16)
	m = append(m, be16(version)...)
	total := 16
	for _, s := range sets {
		total += len(s)
	}
	m = append(m, be16(uint16(total))...)
	m = append(m, be32(0)...)         // export time
	m = append(m, be32(1)...)         // sequence
	m = append(m, be32(obsDomain)...) // observation domain
	for _, s := range sets {
		m = append(m, s...)
	}
	return m
}

// field is {ie, length}.
func templateSet(templateID uint16, fields ...[2]uint16) []byte {
	body := append(be16(templateID), be16(uint16(len(fields)))...)
	for _, f := range fields {
		body = append(body, be16(f[0])...)
		body = append(body, be16(f[1])...)
	}
	set := append(be16(setIDTemplate), be16(uint16(4+len(body)))...)
	return append(set, body...)
}

func dataSet(templateID uint16, records ...[]byte) []byte {
	body := []byte{}
	for _, r := range records {
		body = append(body, r...)
	}
	set := append(be16(templateID), be16(uint16(4+len(body)))...)
	return append(set, body...)
}

// a flowprobe-like IPv4 template: src, dst, packetDeltaCount, ingressInterface.
var v4fields = [][2]uint16{
	{IESrcIPv4, 4}, {IEDstIPv4, 4}, {IEPacketDeltaCount, 8}, {IEIngressInterface, 4},
}

func v4record(src, dst netip.Addr, pkts uint64, ingress uint32) []byte {
	sb, db := src.As4(), dst.As4()
	r := append([]byte{}, sb[:]...)
	r = append(r, db[:]...)
	r = append(r, be64(pkts)...)
	r = append(r, be32(ingress)...)
	return r
}

func TestDecodeTemplateThenData(t *testing.T) {
	d := NewDecoder()
	// Template first — no records, no error.
	recs, err := d.Decode(msg(7, templateSet(256, v4fields...)))
	if err != nil || len(recs) != 0 {
		t.Fatalf("template-only: recs=%d err=%v", len(recs), err)
	}
	// Data in a later datagram, decoded against the remembered template.
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("172.16.0.5")
	recs, err = d.Decode(msg(7, dataSet(256,
		v4record(src, dst, 1234, 3),
		v4record(dst, src, 56, 4),
	)))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if a, _ := recs[0].Addr(IESrcIPv4); a != src {
		t.Fatalf("src = %v, want %v", a, src)
	}
	if a, _ := recs[0].Addr(IEDstIPv4); a != dst {
		t.Fatalf("dst = %v, want %v", a, dst)
	}
	if p, _ := recs[0].Uint(IEPacketDeltaCount); p != 1234 {
		t.Fatalf("pkts = %d, want 1234", p)
	}
	if in, _ := recs[0].Uint(IEIngressInterface); in != 3 {
		t.Fatalf("ingress = %d, want 3", in)
	}
	if p, _ := recs[1].Uint(IEPacketDeltaCount); p != 56 {
		t.Fatalf("record 2 pkts = %d, want 56", p)
	}
}

func TestDecodeTemplateAndDataSameMessage(t *testing.T) {
	d := NewDecoder()
	src := netip.MustParseAddr("10.0.0.9")
	dst := netip.MustParseAddr("172.16.0.9")
	recs, err := d.Decode(msg(1,
		templateSet(300, v4fields...),
		dataSet(300, v4record(src, dst, 42, 2)),
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].TemplateID != 300 {
		t.Fatalf("want 1 record for template 300, got %+v", recs)
	}
	if p, _ := recs[0].Uint(IEPacketDeltaCount); p != 42 {
		t.Fatalf("pkts = %d, want 42", p)
	}
}

func TestDataBeforeTemplateIsSkipped(t *testing.T) {
	d := NewDecoder()
	// A data set with no known template → no records, no error (a later template+data
	// retransmit will decode it).
	recs, err := d.Decode(msg(1, dataSet(256, make([]byte, 20))))
	if err != nil || len(recs) != 0 {
		t.Fatalf("data-before-template: recs=%d err=%v", len(recs), err)
	}
}

func TestSetPaddingDoesNotYieldGhostRecord(t *testing.T) {
	d := NewDecoder()
	if _, err := d.Decode(msg(1, templateSet(256, v4fields...))); err != nil {
		t.Fatal(err)
	}
	// One 20-byte record + 8 bytes of trailing padding (< one record) must decode to
	// exactly one record, not two.
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("172.16.0.5")
	padded := append(v4record(src, dst, 1, 3), make([]byte, 8)...)
	recs, err := d.Decode(msg(1, dataSet(256, padded)))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("padding must not create a ghost record; got %d", len(recs))
	}
}

func TestTemplateWithdrawal(t *testing.T) {
	d := NewDecoder()
	if _, err := d.Decode(msg(1, templateSet(256, v4fields...))); err != nil {
		t.Fatal(err)
	}
	// Withdrawal = a template set with field count 0.
	withdraw := func(tid uint16) []byte {
		body := append(be16(tid), be16(0)...)
		return append(append(be16(setIDTemplate), be16(uint16(4+len(body)))...), body...)
	}
	if _, err := d.Decode(msg(1, withdraw(256))); err != nil {
		t.Fatal(err)
	}
	// Data against the withdrawn template is now undecodable → skipped.
	recs, err := d.Decode(msg(1, dataSet(256, make([]byte, 20))))
	if err != nil || len(recs) != 0 {
		t.Fatalf("withdrawn template: recs=%d err=%v", len(recs), err)
	}
}

func TestBadVersionRejected(t *testing.T) {
	m := msg(1, templateSet(256, v4fields...))
	m[1] = 9 // version 9
	if _, err := NewDecoder().Decode(m); err == nil {
		t.Fatal("bad version must error")
	}
}
