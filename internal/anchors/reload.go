package anchors

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/bird"
)

// BirdConfigurer is the subset of *bird.Client the reload flow needs;
// narrowed for testability.
type BirdConfigurer interface {
	ConfigureCheck(path string) (bird.ConfigureResult, error)
	Configure() (bird.ConfigureResult, error)
	ConfigureTimeout(seconds int) (bird.ConfigureResult, error)
	ConfigureConfirm() (bird.ConfigureResult, error)
}

// ErrCheckRejected wraps a configure-check failure: the rendered file was
// rolled back and BIRD's previous configuration stays active (§4.4 discipline:
// a broken include must never be left on disk).
var ErrCheckRejected = errors.New("anchors: configure check rejected new config")

// ErrConfigureFailed wraps a configure failure after a passing check (e.g. a
// race with another config change). The file was rolled back.
var ErrConfigureFailed = errors.New("anchors: configure failed")

// ApplyResult reports what one Apply did.
type ApplyResult struct {
	// Skipped is true when the desired set was already applied (same rendered
	// bytes as the last successful apply and on disk) — no BIRD interaction.
	Skipped bool
	// Check / Configure are the BIRD replies for a non-skipped apply.
	Check     bird.ConfigureResult
	Configure bird.ConfigureResult
}

// Applier owns the anchors include file lifecycle (T-303, DESIGN.md §4.4):
// atomic render-to-disk, pre-flight configure check, reload (optionally inside
// a timed undo window), and file rollback on failure. Not safe for concurrent
// use from multiple processes; in-process calls are serialized.
type Applier struct {
	path string
	bird BirdConfigurer
	log  *slog.Logger

	// confirmTimeout > 0 reloads via "configure timeout N" + confirm, so a
	// reload that kills the control channel auto-rolls-back after N seconds.
	confirmTimeout int

	mu       sync.Mutex
	lastGood []byte // rendered bytes of the last apply BIRD accepted
}

// ApplierOption configures an Applier.
type ApplierOption func(*Applier)

// WithConfirmTimeout enables the configure-timeout/confirm reload pattern
// with the given undo window in seconds.
func WithConfirmTimeout(seconds int) ApplierOption {
	return func(a *Applier) { a.confirmTimeout = seconds }
}

// WithLogger sets the logger (default: discard).
func WithLogger(log *slog.Logger) ApplierOption {
	return func(a *Applier) { a.log = log }
}

// NewApplier creates an Applier for the anchors file at path (e.g.
// /etc/bird/anchors.conf) driving the given BIRD client.
func NewApplier(path string, b BirdConfigurer, opts ...ApplierOption) *Applier {
	a := &Applier{path: path, bird: b, log: slog.New(slog.DiscardHandler)}
	for _, o := range opts {
		o(a)
	}
	return a
}

// EnsureFile guarantees the anchors file exists, creating it as an empty
// render if missing. BIRD refuses to start (and configure fails) when an
// include is absent (§4.4), so the agent calls this before anything else.
// An existing file is left untouched: BIRD may be running with it.
func (a *Applier) EnsureFile() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := os.Stat(a.path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("anchors: stat %s: %w", a.path, err)
	}
	empty, err := Render(nil)
	if err != nil {
		return err
	}
	if err := atomicWrite(a.path, empty); err != nil {
		return err
	}
	a.log.Info("anchors file initialized empty", "path", a.path)
	return nil
}

// Apply renders the set, atomically replaces the include file, validates with
// configure check, and reloads. On check/configure failure the previous file
// content is restored so disk always matches BIRD's active configuration.
// Equal consecutive sets are skipped without touching BIRD; after a process
// restart the first Apply always reloads (BIRD state is unknown).
func (a *Applier) Apply(set []model.Anchor) (ApplyResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	content, err := Render(set)
	if err != nil {
		return ApplyResult{}, err
	}

	prev, err := os.ReadFile(a.path)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("anchors: read %s (EnsureFile not run?): %w", a.path, err)
	}

	if a.lastGood != nil && bytes.Equal(a.lastGood, content) && bytes.Equal(prev, content) {
		return ApplyResult{Skipped: true}, nil
	}

	if err := atomicWrite(a.path, content); err != nil {
		return ApplyResult{}, err
	}

	res := ApplyResult{}
	res.Check, err = a.bird.ConfigureCheck("")
	if err != nil || res.Check.Code != bird.CodeConfigOK {
		a.rollback(prev)
		if err == nil {
			err = fmt.Errorf("unexpected check code %04d: %s", res.Check.Code, res.Check.Message)
		}
		a.log.Error("anchors apply: check rejected, file rolled back", "err", err)
		return res, fmt.Errorf("%w: %w", ErrCheckRejected, err)
	}

	res.Configure, err = a.reconfigure()
	if err != nil || !res.Configure.Accepted() {
		a.rollback(prev)
		if err == nil {
			err = fmt.Errorf("unexpected configure code %04d: %s", res.Configure.Code, res.Configure.Message)
		}
		a.log.Error("anchors apply: configure failed, file rolled back", "err", err)
		return res, fmt.Errorf("%w: %w", ErrConfigureFailed, err)
	}

	a.lastGood = content
	a.log.Info("anchors applied",
		"anchors", len(set),
		"check_code", res.Check.Code,
		"configure_code", res.Configure.Code,
	)
	return res, nil
}

// reconfigure runs plain configure, or the timeout+confirm pattern when a
// confirm window is configured. If confirm cannot be delivered (control
// channel died), BIRD auto-rolls-back when the window expires — that is the
// point of the pattern.
func (a *Applier) reconfigure() (bird.ConfigureResult, error) {
	if a.confirmTimeout <= 0 {
		return a.bird.Configure()
	}
	res, err := a.bird.ConfigureTimeout(a.confirmTimeout)
	if err != nil || !res.Accepted() {
		return res, err
	}
	if _, err := a.bird.ConfigureConfirm(); err != nil {
		return res, fmt.Errorf("confirm failed (BIRD will auto-undo in %ds): %w", a.confirmTimeout, err)
	}
	return res, nil
}

// rollback restores the previous file content (best effort: BIRD is still
// running the old config; disk must match it again).
func (a *Applier) rollback(prev []byte) {
	if err := atomicWrite(a.path, prev); err != nil {
		a.log.Error("anchors rollback write failed; disk now diverges from BIRD state", "err", err)
	}
}

// atomicWrite writes content to path via temp file + fsync + rename + dir
// fsync, so a crash never leaves a torn include (which would fail the whole
// configure, §4.4).
func atomicWrite(path string, content []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".anchors-*.tmp")
	if err != nil {
		return fmt.Errorf("anchors: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// No-ops after successful rename.
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("anchors: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("anchors: fsync temp: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("anchors: chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("anchors: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("anchors: rename into place: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
