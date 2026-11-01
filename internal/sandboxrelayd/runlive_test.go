package sandboxrelayd

import (
	"errors"
	"runtime"
	"testing"
)

// aliveLockOS reports whether goos has a liveness lock (alive_unix.go,
// alive_windows.go).
func aliveLockOS(goos string) bool {
	switch goos {
	case "linux", "darwin", "windows", "freebsd", "netbsd", "openbsd", "dragonfly":
		return true
	}
	return false
}

// TestRunLive (RERUN2 D4): a run with no record and no lock is not live; a
// record without a lock file is (the earlier rule); a held lock is.
func TestRunLive(t *testing.T) {
	obs := t.TempDir()
	if RunLive(obs, "run-x") {
		t.Fatal("no record and no lock, yet live")
	}
	if RunLive(obs, "../bad") {
		t.Fatal("an invalid run id is live")
	}
	rec, err := NewRunRecord(RunRecord{RunID: "run-x", Tool: "claude-code", WorkspaceDir: obs, Roots: []string{obs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	if !RunLive(obs, "run-x") {
		t.Fatal("a record without a lock file is not live")
	}
	release, err := HoldRun(obs, "run-x")
	if err != nil {
		// Only a platform with no liveness lock at all may skip (WINFIX4
		// audit finding 8): Linux, macOS and Windows have one, and a failure
		// there is a failure.
		if errors.Is(err, errAliveNotOffered) && !aliveLockOS(runtime.GOOS) {
			t.Skipf("no liveness lock on %s: %v", runtime.GOOS, err)
		}
		t.Fatalf("HoldRun: %v", err)
	}
	defer release()
	if !RunLive(obs, "run-x") {
		t.Fatal("a held lock is not live")
	}
}
