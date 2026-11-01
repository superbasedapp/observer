package hookspool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// TestSpoolWritersRefuseOutsideTempDir (FU-118): inside a test binary the
// spool writers (Append, SetAside, TakeSkippedActivity) refuse a path
// outside the OS temp directory before they create or rename anything.
func TestSpoolWritersRefuseOutsideTempDir(t *testing.T) {
	outside := filepath.Join(filepath.VolumeName(os.TempDir())+string(os.PathSeparator), "observer-spool-write-guard-never-created")
	if _, err := os.Stat(outside); err == nil {
		t.Skipf("%s exists; refusing to run", outside)
	}
	t.Cleanup(func() {
		for _, v := range testwriteguard.TakeViolationsForTest() {
			if !strings.HasPrefix(v, outside) {
				t.Errorf("unexpected refused write %s", v)
			}
		}
	})
	spool := filepath.Join(outside, "hook-activity.jsonl")
	rec := Record{Tool: "claude-code", Kind: KindActivity, HookEvent: "PreToolUse"}
	if err := Append(spool, rec); !errors.Is(err, testwriteguard.ErrRefused) {
		t.Errorf("Append outside temp = %v, want testwriteguard.ErrRefused", err)
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("Append created %s", outside)
	}
	// Under the temp dir the same record is written.
	dir := t.TempDir()
	if err := Append(filepath.Join(dir, "hook-activity.jsonl"), rec); err != nil {
		t.Fatalf("Append under t.TempDir: %v", err)
	}
	if _, err := SetAside(filepath.Join(dir, "hook-activity.jsonl"), time.Now()); err != nil {
		t.Fatalf("SetAside under t.TempDir: %v", err)
	}
}
