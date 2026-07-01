// Package ipfix is a minimal RFC 7011 IPFIX decoder for the agent's localhost
// flowprobe collector (§4.2.5 per-member forwarding loss). VPP's flowprobe plugin
// exports per-flow records over UDP to this collector; the decoder turns each datagram
// into decoded flow Records. It is deliberately small — enough to decode flowprobe's
// IPv4/IPv6 flow templates (fixed-length fields), stateful across datagrams so a data
// set can reference a template seen in an earlier message. Not safe for concurrent use.
package ipfix

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// IPFIX information-element ids flowprobe emits (IANA IPFIX registry). Only the ones
// the loss collector needs are named.
const (
	IEOctetDeltaCount  = 1
	IEPacketDeltaCount = 2
	IEProtocol         = 4
	IESrcIPv4          = 8
	IEIngressInterface = 10
	IEDstIPv4          = 12
	IEEgressInterface  = 14
	IESrcIPv6          = 27
	IEDstIPv6          = 28
)

const (
	version        = 10
	msgHeaderLen   = 16
	setHeaderLen   = 4
	setIDTemplate  = 2
	setIDOptions   = 3
	setIDDataFloor = 256
	varLen         = 0xffff
)

type fieldSpec struct {
	id         uint16
	enterprise uint32
	length     uint16
}

type template struct {
	fields   []fieldSpec
	fixedLen int  // sum of field lengths when none is variable-length
	hasVar   bool // any field is variable-length
}

// Record is one decoded IPFIX data record (a flow): its template id plus each present
// information element's raw bytes. Use the typed accessors to read values.
type Record struct {
	TemplateID uint16
	Fields     map[uint16][]byte
}

// Uint decodes a fixed-width unsigned IE (1..8 bytes, network byte order).
func (r Record) Uint(ie uint16) (uint64, bool) {
	b, ok := r.Fields[ie]
	if !ok || len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, true
}

// Addr decodes a 4-byte (IPv4) or 16-byte (IPv6) address IE.
func (r Record) Addr(ie uint16) (netip.Addr, bool) {
	b, ok := r.Fields[ie]
	if !ok {
		return netip.Addr{}, false
	}
	if a, ok := netip.AddrFromSlice(b); ok {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// Decoder holds template state across datagrams (templates arrive periodically; data
// sets reference them by id within an observation domain).
type Decoder struct {
	templates map[uint32]map[uint16]template // obsDomain → templateID → template
}

// NewDecoder returns an empty decoder.
func NewDecoder() *Decoder {
	return &Decoder{templates: map[uint32]map[uint16]template{}}
}

// Decode parses one UDP datagram: it folds any template sets into state and returns the
// data records it could decode. A templates-only message (or data referencing a
// not-yet-seen template) returns no records without error.
func (d *Decoder) Decode(msg []byte) ([]Record, error) {
	if len(msg) < msgHeaderLen {
		return nil, fmt.Errorf("ipfix: short message (%d < %d)", len(msg), msgHeaderLen)
	}
	if v := binary.BigEndian.Uint16(msg[0:2]); v != version {
		return nil, fmt.Errorf("ipfix: bad version %d", v)
	}
	obsDomain := binary.BigEndian.Uint32(msg[12:16])

	var out []Record
	off := msgHeaderLen
	for off+setHeaderLen <= len(msg) {
		setID := binary.BigEndian.Uint16(msg[off : off+2])
		setLen := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		if setLen < setHeaderLen || off+setLen > len(msg) {
			return nil, fmt.Errorf("ipfix: bad set length %d at offset %d", setLen, off)
		}
		body := msg[off+setHeaderLen : off+setLen]
		switch {
		case setID == setIDTemplate:
			if err := d.parseTemplates(obsDomain, body); err != nil {
				return out, err
			}
		case setID == setIDOptions:
			// options templates carry metadata, not flow data — ignore.
		case setID >= setIDDataFloor:
			out = append(out, d.parseDataSet(obsDomain, setID, body)...)
		default:
			// reserved set id — skip.
		}
		off += setLen
	}
	return out, nil
}

func (d *Decoder) parseTemplates(obsDomain uint32, body []byte) error {
	p := 0
	for p+4 <= len(body) {
		tid := binary.BigEndian.Uint16(body[p : p+2])
		fieldCount := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if fieldCount == 0 {
			// template withdrawal — forget it.
			if m := d.templates[obsDomain]; m != nil {
				delete(m, tid)
			}
			continue
		}
		t := template{fields: make([]fieldSpec, 0, fieldCount)}
		for i := 0; i < fieldCount; i++ {
			if p+4 > len(body) {
				return fmt.Errorf("ipfix: truncated template %d", tid)
			}
			ieRaw := binary.BigEndian.Uint16(body[p : p+2])
			flen := binary.BigEndian.Uint16(body[p+2 : p+4])
			p += 4
			fs := fieldSpec{id: ieRaw & 0x7fff, length: flen}
			if ieRaw&0x8000 != 0 { // enterprise bit → 4-byte enterprise number follows
				if p+4 > len(body) {
					return fmt.Errorf("ipfix: truncated enterprise field in template %d", tid)
				}
				fs.enterprise = binary.BigEndian.Uint32(body[p : p+4])
				p += 4
			}
			if flen == varLen {
				t.hasVar = true
			} else {
				t.fixedLen += int(flen)
			}
			t.fields = append(t.fields, fs)
		}
		if d.templates[obsDomain] == nil {
			d.templates[obsDomain] = map[uint16]template{}
		}
		d.templates[obsDomain][tid] = t
	}
	return nil
}

func (d *Decoder) parseDataSet(obsDomain uint32, setID uint16, body []byte) []Record {
	t, ok := d.templates[obsDomain][setID]
	if !ok {
		return nil // data before its template — cannot decode; a later retransmit will
	}
	var out []Record
	p := 0
	for {
		// Fixed-length templates: stop when the remainder is smaller than one record
		// (that remainder is set padding, RFC 7011 §3.3.1).
		if !t.hasVar && (t.fixedLen == 0 || len(body)-p < t.fixedLen) {
			break
		}
		if t.hasVar && p >= len(body) {
			break
		}
		rec := Record{TemplateID: setID, Fields: make(map[uint16][]byte, len(t.fields))}
		ok := true
		for _, fs := range t.fields {
			flen := int(fs.length)
			if fs.length == varLen {
				if p >= len(body) {
					ok = false
					break
				}
				flen = int(body[p])
				p++
				if flen == 255 { // 3-byte length encoding
					if p+2 > len(body) {
						ok = false
						break
					}
					flen = int(binary.BigEndian.Uint16(body[p : p+2]))
					p += 2
				}
			}
			if p+flen > len(body) {
				ok = false
				break
			}
			rec.Fields[fs.id] = body[p : p+flen]
			p += flen
		}
		if !ok {
			break
		}
		out = append(out, rec)
	}
	return out
}
