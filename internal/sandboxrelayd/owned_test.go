package sandboxrelayd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestHoldRunClaimsTheLockAndItsDirs (B2): the liveness lock and the runs
// directory HoldRun creates go through the ownership helper, so an elevated
// helper never leaves runs\<id>.alive owned by Administrators.
func TestHoldRunClaimsTheLockAndItsDirs(t *testing.T) {
	var claimed []string
	saved := claimOwned
	claimOwned = func(p string) error { claimed = append(claimed, filepath.Base(p)); return nil }
	t.Cleanup(func() { claimOwned = saved })

	obs := t.TempDir()
	release, err := HoldRun(obs, "run-alive1")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	want := []string{RelayDirName, runsDirName, ".run-alive1" + aliveSuffix}
	if !slices.Equal(claimed, want) {
		t.Fatalf("HoldRun claimed %q, want %q", claimed, want)
	}
	if _, err := os.Stat(filepath.Join(RunsDir(obs), "run-alive1"+aliveSuffix)); err != nil {
		t.Fatal(err)
	}
}

// TestMkdirAllClaimedOutermostFirst: every directory the call creates is
// claimed, outermost first, and one that existed is not.
func TestMkdirAllClaimedOutermostFirst(t *testing.T) {
	base := t.TempDir()
	var claimed []string
	claim := func(p string) error { claimed = append(claimed, p); return nil }
	deep := filepath.Join(base, "a", "b", "c")
	if err := MkdirAllClaimed(deep, claim); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b"), deep}
	if !slices.Equal(claimed, want) {
		t.Fatalf("claimed %q, want %q", claimed, want)
	}
	claimed = nil
	if err := MkdirAllClaimed(deep, claim); err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 0 {
		t.Fatalf("an existing directory was claimed: %q", claimed)
	}
}
