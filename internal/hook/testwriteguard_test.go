package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// TestTestBinaryNeverWritesOutsideTempDir is the 2026-10-21 incident's
// regression: inside a test binary every hook writer refuses a config path
// outside the temp directory, before it creates anything there, whatever
// resolved the path (here a pinned non-temp home).
func TestTestBinaryNeverWritesOutsideTempDir(t *testing.T) {
	outside := filepath.Join(filepath.VolumeName(os.TempDir())+string(os.PathSeparator), "observer-test-write-guard-never-created")
	if _, err := os.Stat(outside); err == nil {
		t.Skipf("%s exists; refusing to run", outside)
	}
	reg, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: outside, ChecksumsPath: filepath.Join(t.TempDir(), "c.json")})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"claude-code", "ibm-bob", "dirac", "vtcode", "autohand", "kimi-code"} {
		res := reg.Register(target)
		if res.Skipped {
			continue
		}
		// A credential-file writer withholds the detail; the refusal is the
		// error either way.
		// Every writer goes through the one guard, testwriteguard.Check,
		// whose error names both incidents (2026-10-20, 2026-10-21).
		if res.Error == nil || (!hooksShareCredentialFile(target) && !strings.Contains(res.Error.Error(), "incident 2026-10-2")) {
			t.Errorf("%s: want the test-binary write refusal, got %+v", target, res)
		}
	}
	if _, err := os.Stat(outside); err == nil {
		_ = os.RemoveAll(outside)
		t.Fatalf("a test registration created %s", outside)
	}
	// The refusals above are provoked on purpose: take them off the
	// package-level record so testwriteguard.Run sees only unexpected
	// ones. Each must be under the pinned non-temp home.
	for _, v := range testwriteguard.TakeViolationsForTest() {
		if !strings.HasPrefix(v, outside) {
			t.Errorf("unexpected refused write %s", v)
		}
	}
}
