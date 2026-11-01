package sandboxrelayd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestWriteRunClaimsOnlyWhatItCreated (SBX-UPD audit finding 7): WriteRun
// claims the directories it created and the record it wrote, never a
// directory that already existed (which a daemon that is not elevated may
// not own).
func TestWriteRunClaimsOnlyWhatItCreated(t *testing.T) {
	var claimed []string
	saved := claimOwned
	claimOwned = func(p string) error { claimed = append(claimed, p); return nil }
	t.Cleanup(func() { claimOwned = saved })

	obs := t.TempDir()
	rec, err := NewRunRecord(RunRecord{RunID: "run-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	dir := RunsDir(obs)
	want := []string{filepath.Dir(dir), dir, filepath.Join(dir, "run-a.json")}
	if !slices.Equal(claimed, want) {
		t.Fatalf("fresh dirs claimed %q, want %q", claimed, want)
	}

	claimed = nil
	rec2, err := NewRunRecord(RunRecord{RunID: "run-b"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRun(obs, rec2); err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(dir, "run-b.json")}; !slices.Equal(claimed, want) {
		t.Fatalf("existing dirs claimed %q, want only the record %q", claimed, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "run-b.json")); err != nil {
		t.Fatal(err)
	}
}
