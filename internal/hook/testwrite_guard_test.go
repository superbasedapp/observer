package hook

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// TestRegistrarWriteOutsideTempDirIsRefused pins the write half of the
// incident 2026-10-20 guard at the registrar seam: a registration whose
// resolved config path lies outside the test temp directory writes nothing
// (not even the settings lock file), returns the guard's error, and is
// recorded so testwriteguard.Run would fail the run. The path used is
// /proc, which no test can write anyway, so the test is harmless even if the
// guard were missing. Not parallel: it drains the process-wide record.
func TestRegistrarWriteOutsideTempDirIsRefused(t *testing.T) {
	_ = testwriteguard.TakeViolationsForTest()
	home := filepath.Join(string(filepath.Separator)+"proc", "observer-hookgaps-guard")
	for _, target := range []string{"qwen-code", "qoder", "gemini-cli", "droid"} {
		t.Run(target, func(t *testing.T) {
			r, err := NewRegistry(Options{BinaryPath: "/bin/observer", HomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			res := r.Register(target)
			// The error text is the guard's, except where the target shares
			// a credential file and the detail is withheld; the recorded
			// violation below is the proof either way.
			if res.Error == nil {
				t.Fatalf("Register(%s) error = nil, want the test-binary write refusal", target)
			}
			if len(res.HooksAdded) != 0 {
				t.Errorf("Register(%s) reported hooks added: %v", target, res.HooksAdded)
			}
			v := testwriteguard.TakeViolationsForTest()
			if len(v) == 0 || !strings.Contains(v[0], home) {
				t.Errorf("violations = %v, want the refused %s path recorded", v, home)
			}
		})
	}
}
