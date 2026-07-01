package vpp

import "testing"

func TestParsePingStats(t *testing.T) {
	ok := "76 bytes from fc00::66: icmp_seq=1 ttl=64 time=2.0 ms\n\nStatistics: 3 sent, 3 received, 0% packet loss"
	s, r, valid := parsePingStats(ok)
	if !valid || s != 3 || r != 3 {
		t.Fatalf("success parse = %d/%d ok=%v", s, r, valid)
	}
	fail := "\nStatistics: 2 sent, 0 received, 100% packet loss"
	if s, r, valid := parsePingStats(fail); !valid || s != 2 || r != 0 {
		t.Fatalf("fail parse = %d/%d ok=%v", s, r, valid)
	}
	if _, _, valid := parsePingStats("garbage without a stats line"); valid {
		t.Fatal("unparseable output must return ok=false")
	}
}
