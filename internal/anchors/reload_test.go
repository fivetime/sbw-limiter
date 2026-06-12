package anchors

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fivetime/sbw-contract/model"
	"github.com/fivetime/sbw-limiter/internal/bird"
)

// fakeBird scripts ConfigureCheck/Configure results and counts calls.
type fakeBird struct {
	checkRes  bird.ConfigureResult
	checkErr  error
	confRes   bird.ConfigureResult
	confErr   error
	confirmOK bool

	checks, configures, timeouts, confirms int
}

func okCheck() bird.ConfigureResult  { return bird.ConfigureResult{Code: bird.CodeConfigOK} }
func okConfig() bird.ConfigureResult { return bird.ConfigureResult{Code: bird.CodeReconfigured} }
func newFakeBird() *fakeBird {
	return &fakeBird{checkRes: okCheck(), confRes: okConfig(), confirmOK: true}
}

func (f *fakeBird) ConfigureCheck(string) (bird.ConfigureResult, error) {
	f.checks++
	return f.checkRes, f.checkErr
}
func (f *fakeBird) Configure() (bird.ConfigureResult, error) {
	f.configures++
	return f.confRes, f.confErr
}
func (f *fakeBird) ConfigureTimeout(int) (bird.ConfigureResult, error) {
	f.timeouts++
	return f.confRes, f.confErr
}
func (f *fakeBird) ConfigureConfirm() (bird.ConfigureResult, error) {
	f.confirms++
	if !f.confirmOK {
		return bird.ConfigureResult{}, errors.New("confirm lost")
	}
	return bird.ConfigureResult{Code: bird.CodeReconfigConfirmed}, nil
}

func testSet() []model.Anchor {
	return []model.Anchor{{Prefix: netip.MustParsePrefix("203.0.113.10/32")}}
}

func newTestApplier(t *testing.T, opts ...ApplierOption) (*Applier, *fakeBird, string) {
	t.Helper()
	fb := newFakeBird()
	path := filepath.Join(t.TempDir(), "anchors.conf")
	a := NewApplier(path, fb, opts...)
	if err := a.EnsureFile(); err != nil {
		t.Fatalf("EnsureFile: %v", err)
	}
	return a, fb, path
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertNoTempFiles(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".anchors-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestEnsureFile(t *testing.T) {
	_, _, path := newTestApplier(t)
	content := mustRead(t, path)
	empty, _ := Render(nil)
	if content != string(empty) {
		t.Errorf("EnsureFile should write empty render, got:\n%s", content)
	}

	// Existing file must be left untouched.
	if err := os.WriteFile(path, []byte("# existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a2 := NewApplier(path, newFakeBird())
	if err := a2.EnsureFile(); err != nil {
		t.Fatalf("EnsureFile on existing: %v", err)
	}
	if got := mustRead(t, path); got != "# existing\n" {
		t.Errorf("EnsureFile overwrote existing file: %q", got)
	}
}

func TestApplyHappyPath(t *testing.T) {
	a, fb, path := newTestApplier(t)
	res, err := a.Apply(testSet())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Skipped {
		t.Fatal("first apply must not be skipped")
	}
	if fb.checks != 1 || fb.configures != 1 || fb.timeouts != 0 {
		t.Errorf("calls = %+v", fb)
	}
	want, _ := Render(testSet())
	if mustRead(t, path) != string(want) {
		t.Error("file content does not match rendered set")
	}
	assertNoTempFiles(t, path)
}

func TestApplySameSetSkipped(t *testing.T) {
	a, fb, _ := newTestApplier(t)
	if _, err := a.Apply(testSet()); err != nil {
		t.Fatal(err)
	}
	res, err := a.Apply(testSet())
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if !res.Skipped {
		t.Error("identical set should be skipped")
	}
	if fb.checks != 1 || fb.configures != 1 {
		t.Errorf("skip must not call BIRD again: %+v", fb)
	}

	// A changed set reconfigures again.
	grown := append(testSet(), model.Anchor{Prefix: netip.MustParsePrefix("203.0.113.11/32")})
	res, err = a.Apply(grown)
	if err != nil || res.Skipped {
		t.Fatalf("grown set: res=%+v err=%v", res, err)
	}
	if fb.configures != 2 {
		t.Errorf("configures = %d, want 2", fb.configures)
	}
}

func TestFreshApplierNeverSkips(t *testing.T) {
	a, _, path := newTestApplier(t)
	if _, err := a.Apply(testSet()); err != nil {
		t.Fatal(err)
	}
	// New process: same file on disk, but no in-memory lastGood → must reload.
	fb2 := newFakeBird()
	a2 := NewApplier(path, fb2)
	res, err := a2.Apply(testSet())
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped {
		t.Error("fresh applier must not skip (BIRD state unknown after restart)")
	}
	if fb2.configures != 1 {
		t.Errorf("configures = %d, want 1", fb2.configures)
	}
}

func TestCheckRejectionRollsBackFile(t *testing.T) {
	a, fb, path := newTestApplier(t)
	if _, err := a.Apply(testSet()); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, path)

	fb.checkErr = &bird.CommandError{Code: 8002, Message: "boom"}
	grown := append(testSet(), model.Anchor{Prefix: netip.MustParsePrefix("203.0.113.12/32")})
	_, err := a.Apply(grown)
	if !errors.Is(err, ErrCheckRejected) {
		t.Fatalf("err = %v, want ErrCheckRejected", err)
	}
	var cmdErr *bird.CommandError
	if !errors.As(err, &cmdErr) || cmdErr.Code != 8002 {
		t.Errorf("underlying CommandError not preserved: %v", err)
	}
	if mustRead(t, path) != before {
		t.Error("file must be rolled back to previous content on check rejection")
	}
	assertNoTempFiles(t, path)

	// Recovery: a good apply afterwards works and is not wrongly skipped.
	fb.checkErr = nil
	res, err := a.Apply(grown)
	if err != nil || res.Skipped {
		t.Fatalf("recovery apply: res=%+v err=%v", res, err)
	}
}

func TestConfigureFailureRollsBackFile(t *testing.T) {
	a, fb, path := newTestApplier(t)
	if _, err := a.Apply(testSet()); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, path)

	fb.confErr = &bird.CommandError{Code: 8001, Message: "raced"}
	grown := append(testSet(), model.Anchor{Prefix: netip.MustParsePrefix("203.0.113.13/32")})
	_, err := a.Apply(grown)
	if !errors.Is(err, ErrConfigureFailed) {
		t.Fatalf("err = %v, want ErrConfigureFailed", err)
	}
	if mustRead(t, path) != before {
		t.Error("file must be rolled back on configure failure")
	}
}

func TestConfirmWindowFlow(t *testing.T) {
	a, fb, _ := newTestApplier(t, WithConfirmTimeout(30))
	if _, err := a.Apply(testSet()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if fb.timeouts != 1 || fb.confirms != 1 || fb.configures != 0 {
		t.Errorf("confirm flow calls = %+v", fb)
	}
}

func TestConfirmDeliveryFailureSurfaces(t *testing.T) {
	a, fb, _ := newTestApplier(t, WithConfirmTimeout(30))
	fb.confirmOK = false
	_, err := a.Apply(testSet())
	if !errors.Is(err, ErrConfigureFailed) {
		t.Fatalf("err = %v, want ErrConfigureFailed (confirm lost)", err)
	}
	if !strings.Contains(err.Error(), "auto-undo") {
		t.Errorf("error should mention BIRD auto-undo: %v", err)
	}
}

func TestApplyWithoutEnsureFileErrors(t *testing.T) {
	fb := newFakeBird()
	a := NewApplier(filepath.Join(t.TempDir(), "missing.conf"), fb)
	if _, err := a.Apply(testSet()); err == nil {
		t.Fatal("Apply without EnsureFile should error")
	}
	if fb.checks != 0 {
		t.Error("must not reach BIRD when file is missing")
	}
}
