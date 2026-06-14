package bird

import (
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
)

// restartableBird is a fake BIRD control socket that can drop its live
// connection on demand (simulating a BIRD process restart) while continuing to
// accept new ones. Each accepted connection sends the banner then answers from
// the script. acceptCount lets a test assert whether a redial happened.
type restartableBird struct {
	ln     net.Listener
	script map[string]string

	mu      sync.Mutex
	conns   []net.Conn
	accepts int
}

func newRestartableBird(t *testing.T, script map[string]string) (*restartableBird, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "bird.ctl")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	s := &restartableBird{ln: ln, script: script}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s, sock
}

func (s *restartableBird) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.accepts++
		s.mu.Unlock()
		go s.handle(conn)
	}
}

func (s *restartableBird) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("0001 BIRD 3.3.1 ready.\n")); err != nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		cmd := string(buf[:n])
		cmd = cmd[:len(cmd)-1] // strip trailing newline
		resp, ok := s.script[cmd]
		if !ok {
			resp = "9001 syntax error in unit test script\n"
		}
		if _, err := conn.Write([]byte(resp)); err != nil {
			return
		}
	}
}

// restart drops every live connection so the next command on an existing client
// fails — exactly as a BIRD restart drops the control socket — while the
// listener keeps accepting, so a redial succeeds.
func (s *restartableBird) restart() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
}

func (s *restartableBird) acceptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepts
}

// A BIRD restart that kills the control socket must be transparent: the next
// command redials and succeeds rather than wedging on ErrClosed forever.
func TestReconnectingRedialsAfterRestart(t *testing.T) {
	s, sock := newRestartableBird(t, map[string]string{
		"configure check": "0020 Configuration OK\n",
		"configure":       "0003 Reconfigured\n",
	})
	rc := NewReconnecting(sock, slog.New(slog.DiscardHandler))
	defer func() { _ = rc.Close() }()

	if res, err := rc.ConfigureCheck(""); err != nil || res.Code != CodeConfigOK {
		t.Fatalf("first ConfigureCheck: res=%+v err=%v", res, err)
	}
	if got := s.acceptCount(); got != 1 {
		t.Fatalf("accepts after first call = %d, want 1", got)
	}

	s.restart() // BIRD restarts: live control connection dropped

	if res, err := rc.Configure(); err != nil || !res.Accepted() {
		t.Fatalf("Configure after restart: res=%+v err=%v", res, err)
	}
	if got := s.acceptCount(); got != 2 {
		t.Fatalf("accepts after redial = %d, want 2 (must have redialed)", got)
	}
}

// A BIRD CommandError (config rejected, 9xxx) is a valid reply on a healthy
// connection — it must NOT trigger a redial, or every rejected config would
// needlessly churn the control connection.
func TestReconnectingDoesNotRedialOnCommandError(t *testing.T) {
	s, sock := newRestartableBird(t, map[string]string{
		"configure check": "9001 syntax error in config\n",
	})
	rc := NewReconnecting(sock, slog.New(slog.DiscardHandler))
	defer func() { _ = rc.Close() }()

	_, err := rc.ConfigureCheck("")
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CommandError, got %v", err)
	}
	if _, err := rc.ConfigureCheck(""); !errors.As(err, &ce) {
		t.Fatalf("second call: want *CommandError, got %v", err)
	}
	if got := s.acceptCount(); got != 1 {
		t.Fatalf("accepts = %d, want 1 (CommandError must not redial)", got)
	}
}

// Before the first command the wrapper holds no connection; the first call dials
// lazily. This lets the agent start before BIRD is up.
func TestReconnectingLazyDial(t *testing.T) {
	s, sock := newRestartableBird(t, map[string]string{"configure check": "0020 Configuration OK\n"})
	rc := NewReconnecting(sock, slog.New(slog.DiscardHandler))
	defer func() { _ = rc.Close() }()

	if got := s.acceptCount(); got != 0 {
		t.Fatalf("accepts before any call = %d, want 0 (lazy)", got)
	}
	if _, err := rc.ConfigureCheck(""); err != nil {
		t.Fatalf("ConfigureCheck: %v", err)
	}
	if got := s.acceptCount(); got != 1 {
		t.Fatalf("accepts after first call = %d, want 1", got)
	}
}
