package hook

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// outsideTempDir returns a directory path that is not under os.TempDir and
// does not exist, or skips when the temp dir has no parent to put it in.
func outsideTempDir(t *testing.T) string {
	t.Helper()
	tmp := filepath.Clean(os.TempDir())
	parent := filepath.Dir(tmp)
	if parent == tmp {
		t.Skipf("os.TempDir %q is a filesystem root; no path outside it to probe", tmp)
	}
	dir := filepath.Join(parent, "sbo-fu102-guard-probe-"+strings.ReplaceAll(t.Name(), "/", "_"))
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Skipf("probe path %q unexpectedly exists (%v)", dir, err)
	}
	return dir
}

// forensicLogProbes are the forensic logs of optional parts of this
// package (the Cursor stop-debug log is compiled out with
// sbo_omit_adapter_cursor), each registered by its own tagged test file.
var forensicLogProbes []struct {
	name  string
	write func()
}

// TestHookForensicLogsRefuseWritesOutsideTheTestTempDir is the FU-102
// guard: inside a test binary the hook forensic logs (hook-events.jsonl,
// cursor-stop-debug.jsonl) refuse a location outside os.TempDir, create
// nothing there and record the refusal, so testwriteguard.Run fails the
// package run of any test that would append to a real ~/.observer.
func TestHookForensicLogsRefuseWritesOutsideTheTestTempDir(t *testing.T) {
	dir := outsideTempDir(t)
	SetStateDirResolver(func() string { return dir })
	t.Cleanup(func() { SetStateDirResolver(nil) })
	_ = testwriteguard.TakeViolationsForTest()

	appendHookEventLog(hookEvent{Event: "fu102:probe", SessionID: "fu102"})
	want := []string{"hook-events.jsonl"}
	for _, p := range forensicLogProbes {
		p.write()
		want = append(want, p.name)
	}

	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a forensic log created %q outside the test temp dir (stat err %v)", dir, err)
		_ = os.RemoveAll(dir)
	}
	got := testwriteguard.TakeViolationsForTest()
	for _, name := range want {
		found := false
		for _, v := range got {
			if strings.Contains(v, filepath.Join(dir, name)) {
				found = true
			}
		}
		if !found {
			t.Errorf("no refusal recorded for %s; recorded: %q", name, got)
		}
	}
}

// TestHookPackageHomeIsPinned pins the TestMain backstop: with no resolver
// and no per-test home, the forensic log resolves into the process temp
// home (internal/testhome, under os.TempDir), never the developer's real
// home.
func TestHookPackageHomeIsPinned(t *testing.T) {
	SetStateDirResolver(nil)
	path := hookEventLogPath()
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(path)))
	if err != nil {
		t.Fatalf("resolve home of %q: %v", path, err)
	}
	if rel, err := filepath.Rel(tmp, dir); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("hook-events.jsonl resolves to %q, outside os.TempDir %q: TestMain's home pin is missing", path, tmp)
	}
}
