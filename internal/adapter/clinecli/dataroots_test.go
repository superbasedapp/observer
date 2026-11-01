package clinecli

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// TestRelocatedDataDirIsCaptured (FU-30, lane w4-homes-b): with
// CLINE_DATA_DIR set, Cline CLI keeps sessions.db, the per-session
// messages.json and hooks.jsonl in that directory, which no <home>/.cline
// root reaches. The adapter watches it and claims its files. Red before:
// the roots were <home>/.cline (+ CLINE_DIR) only, so capture missed them.
func TestRelocatedDataDirIsCaptured(t *testing.T) {
	data := filepath.Join(t.TempDir(), "cline-state")
	a := NewWithOptions(nil, filepath.Join(t.TempDir(), ".cline")).WithDataRoots(data)
	if !slices.Contains(a.WatchPaths(), data) {
		t.Fatalf("WatchPaths = %v, want the relocated data dir", a.WatchPaths())
	}
	for _, rel := range [][]string{{"db", "sessions.db"}, {"db", "sessions.db-wal"}, {"logs", "hooks.jsonl"}} {
		p := filepath.Join(append([]string{data}, rel...)...)
		if !a.IsSessionFile(p) {
			t.Errorf("IsSessionFile(%s) = false, want true", p)
		}
	}
	if a.IsSessionFile(filepath.Join(data, "data", "db", "sessions.db")) {
		t.Error("a data/ subtree under a data root is not Cline's layout")
	}
	if got, want := deriveRootDir(filepath.Join(data, "db", "sessions.db")), data; got != want {
		t.Errorf("deriveRootDir = %q, want %q", got, want)
	}
}

// TestDataRootsFromTheEnvironment: only an absolute CLINE_DATA_DIR adds a
// data root; CLINE_DIR is already a home root, and a relative value names
// no directory the daemon can watch.
func TestDataRootsFromTheEnvironment(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "d")
	for _, tc := range []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"unset", nil, nil},
		{"CLINE_DATA_DIR", map[string]string{"CLINE_DATA_DIR": abs}, []string{abs}},
		{"CLINE_DIR only", map[string]string{"CLINE_DIR": abs}, nil},
		{"relative CLINE_DATA_DIR", map[string]string{"CLINE_DATA_DIR": "rel"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if got := dataRootsFrom(func(k string) string { return env[k] }, runtime.GOOS); !slices.Equal(got, tc.want) {
				t.Errorf("dataRootsFrom = %v, want %v", got, tc.want)
			}
		})
	}
}
