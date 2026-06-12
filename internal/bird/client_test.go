package bird

import (
	"bufio"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBird serves the BIRD wire protocol on a unix socket: it sends the banner
// on accept, then answers each received command from the script map. A command
// mapped to "" gets no reply (for timeout tests).
func fakeBird(t *testing.T, script map[string]string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "bird.ctl")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if _, err := conn.Write([]byte("0001 BIRD 3.3.1 ready.\n")); err != nil {
					return
				}
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.TrimRight(line, "\n")
					resp, ok := script[cmd]
					if !ok {
						resp = "9001 syntax error in unit test script\n"
					}
					if resp == "" {
						continue // simulate a hang
					}
					if _, err := conn.Write([]byte(resp)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return sock
}

func dialFake(t *testing.T, script map[string]string, opts ...Option) *Client {
	t.Helper()
	c, err := Dial(fakeBird(t, script), opts...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestBannerAndVersion(t *testing.T) {
	c := dialFake(t, nil)
	if got := c.Banner(); got != "BIRD 3.3.1 ready." {
		t.Errorf("banner = %q", got)
	}
	if got := c.Version(); got != "3.3.1" {
		t.Errorf("version = %q, want 3.3.1", got)
	}
}

func TestReplyParsingContinuationsAndAsync(t *testing.T) {
	c := dialFake(t, map[string]string{
		"show test": "1007-first\n" +
			" second same code\n" + // single-space continuation inherits 1007
			"+async noise\n" + // async line mid-reply
			"2002-heading\n" +
			"0000 \n",
	})
	r, err := c.Do("show test")
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if r.Code != 0 {
		t.Errorf("final code = %d, want 0", r.Code)
	}
	want := []Line{
		{1007, "first"},
		{1007, "second same code"},
		{2002, "heading"},
		{0, ""},
	}
	if len(r.Lines) != len(want) {
		t.Fatalf("lines = %+v, want %+v", r.Lines, want)
	}
	for i := range want {
		if r.Lines[i] != want[i] {
			t.Errorf("line[%d] = %+v, want %+v", i, r.Lines[i], want[i])
		}
	}
	if len(r.Async) != 1 || r.Async[0] != "async noise" {
		t.Errorf("async = %v", r.Async)
	}
}

func TestRuntimeErrorBecomesCommandError(t *testing.T) {
	c := dialFake(t, map[string]string{
		"configure": "0002-Reading configuration from /etc/bird/bird.conf\n" +
			"8002 /etc/bird/anchors.conf:3:10 syntax error, unexpected CF_SYM_UNDEFINED\n",
	})
	_, err := c.Configure()
	cmdErr, ok := err.(*CommandError)
	if !ok {
		t.Fatalf("err = %v (%T), want *CommandError", err, err)
	}
	if cmdErr.Code != 8002 {
		t.Errorf("code = %d, want 8002", cmdErr.Code)
	}
	if !strings.Contains(cmdErr.Message, "anchors.conf:3:10") {
		t.Errorf("message should carry file:line:col, got %q", cmdErr.Message)
	}
	// Connection must remain usable after a command-level error.
	if _, err := c.Do("show test2"); err == nil {
		t.Log("ok: connection still alive (scripted 9001 follows)")
	}
}

func TestConfigureSuccessAndCheck(t *testing.T) {
	c := dialFake(t, map[string]string{
		"configure": "0002-Reading configuration from /etc/bird/bird.conf\n" +
			"0003 Reconfigured\n",
		`configure check "/etc/bird/anchors.conf"`: "0002-Reading configuration from /etc/bird/anchors.conf\n" +
			"0020 Configuration OK\n",
		"configure timeout 30": "0002-Reading configuration from /etc/bird/bird.conf\n" +
			"0003 Reconfigured\n",
		"configure confirm": "0018 Reconfiguration confirmed\n",
		"configure undo":    "0019 Nothing to do\n",
	})

	r, err := c.Configure()
	if err != nil || !r.Accepted() || r.Code != CodeReconfigured {
		t.Fatalf("Configure: %+v, %v", r, err)
	}
	r, err = c.ConfigureCheck("/etc/bird/anchors.conf")
	if err != nil || r.Code != CodeConfigOK {
		t.Fatalf("ConfigureCheck: %+v, %v", r, err)
	}
	r, err = c.ConfigureTimeout(30)
	if err != nil || !r.Accepted() {
		t.Fatalf("ConfigureTimeout: %+v, %v", r, err)
	}
	r, err = c.ConfigureConfirm()
	if err != nil || r.Code != CodeReconfigConfirmed {
		t.Fatalf("ConfigureConfirm: %+v, %v", r, err)
	}
	r, err = c.ConfigureUndo()
	if err != nil || r.Code != CodeNothingToDo || r.Accepted() {
		t.Fatalf("ConfigureUndo: %+v, %v", r, err)
	}
}

func TestShowRouteCount(t *testing.T) {
	c := dialFake(t, map[string]string{
		"show route count": "1007-203 of 203 routes for 198 networks in table master4\n" +
			" 12 of 12 routes for 10 networks in table master6\n" +
			"0014 Total: 215 of 215 routes for 208 networks in 2 tables\n",
	})
	rc, err := c.ShowRouteCount()
	if err != nil {
		t.Fatalf("ShowRouteCount: %v", err)
	}
	if rc.TotalRoutes != 215 || rc.TotalNetworks != 208 {
		t.Errorf("totals = %d/%d, want 215/208", rc.TotalRoutes, rc.TotalNetworks)
	}
	if len(rc.Tables) != 2 || rc.Tables[0].Table != "master4" || rc.Tables[0].Routes != 203 ||
		rc.Tables[1].Table != "master6" || rc.Tables[1].Networks != 10 {
		t.Errorf("tables = %+v", rc.Tables)
	}
}

func TestShowRouteCountSumsWithoutTotal(t *testing.T) {
	c := dialFake(t, map[string]string{
		"show route count": "0014 7 of 7 routes for 5 networks in table master4\n",
	})
	rc, err := c.ShowRouteCount()
	if err != nil {
		t.Fatalf("ShowRouteCount: %v", err)
	}
	if rc.TotalRoutes != 7 || rc.TotalNetworks != 5 {
		t.Errorf("totals = %d/%d, want 7/5 (summed)", rc.TotalRoutes, rc.TotalNetworks)
	}
}

func TestShowRouteExported(t *testing.T) {
	c := dialFake(t, map[string]string{
		"show route exported upstream1": "1007-203.0.113.10/32     blackhole [anchors4 09:24:20.123] * (200)\n" +
			" 203.0.113.0/24      blackhole [anchors4 09:24:20.123] * (200)\n" +
			"1007-2001:db8::a/128     blackhole [anchors6 09:24:20.123] * (200)\n" +
			"1007-203.0.113.10/32     blackhole [anchors4 09:24:20.123] (190)\n" + // duplicate path
			"0000 \n",
	})
	got, err := c.ShowRouteExported("upstream1")
	if err != nil {
		t.Fatalf("ShowRouteExported: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.10/32"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::a/128"),
	}
	if len(got) != len(want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestShowProtocols(t *testing.T) {
	c := dialFake(t, map[string]string{
		"show protocols": "2002-Name       Proto      Table      State  Since         Info\n" +
			"1002-device1    Device     ---        up     09:24:20.123  \n" +
			" anchors4   Static     master4    up     09:24:21.000  \n" +
			"1002-upstream1  BGP        ---        start  09:24:22.000  Active        Socket: Connection refused\n" +
			"0000 \n",
	})
	ps, err := c.ShowProtocols()
	if err != nil {
		t.Fatalf("ShowProtocols: %v", err)
	}
	if len(ps) != 3 {
		t.Fatalf("rows = %+v, want 3", ps)
	}
	if !ps[0].Up() || ps[0].Name != "device1" || ps[0].Proto != "Device" {
		t.Errorf("row0 = %+v", ps[0])
	}
	if ps[1].Name != "anchors4" || ps[1].Table != "master4" || !ps[1].Up() {
		t.Errorf("row1 = %+v", ps[1])
	}
	if ps[2].State != "start" || ps[2].Up() {
		t.Errorf("row2 = %+v", ps[2])
	}
	if !strings.Contains(ps[2].Info, "Connection refused") {
		t.Errorf("row2 info = %q", ps[2].Info)
	}

	p, ok, err := c.Protocol("anchors4")
	if err != nil || !ok || p.Table != "master4" {
		t.Errorf("Protocol(anchors4) = %+v, %v, %v", p, ok, err)
	}
	_, ok, err = c.Protocol("nope")
	if err != nil || ok {
		t.Errorf("Protocol(nope) should be absent, got ok=%v err=%v", ok, err)
	}
}

func TestTimeoutClosesConnection(t *testing.T) {
	c := dialFake(t, map[string]string{"hang": ""}, WithTimeout(150*time.Millisecond))
	start := time.Now()
	_, err := c.Do("hang")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took %s, want ~150ms", elapsed)
	}
	if _, err := c.Do("anything"); err != ErrClosed {
		t.Errorf("after timeout, Do should return ErrClosed, got %v", err)
	}
}

func TestMalformedReply(t *testing.T) {
	c := dialFake(t, map[string]string{"bad": "12x4 nope\n"})
	if _, err := c.Do("bad"); err == nil {
		t.Fatal("expected protocol error for malformed code")
	}
}
