package secinventory

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// TestSupersedes is one case per precedence row.
func TestSupersedes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	fresh := &Snapshot{Driver: "scalibr", ScanTime: now.Add(-time.Hour)}
	stale := &Snapshot{Driver: "scalibr", ScanTime: now.Add(-StaleAfter - time.Hour)}
	cases := []struct {
		name   string
		stored *Snapshot
		in     Snapshot
		want   bool
	}{
		{"nothing stored", nil, Snapshot{Driver: "osv"}, true},
		{"same driver", fresh, Snapshot{Driver: "scalibr"}, true},
		{"weaker over stronger, stale", stale, Snapshot{Driver: "osv"}, true},
		{"weaker over stronger, fresh", fresh, Snapshot{Driver: "osv"}, false},
		{"stronger over weaker", &Snapshot{Driver: "osv", ScanTime: now}, Snapshot{Driver: "scalibr"}, true},
	}
	for _, c := range cases {
		if got := Supersedes(c.stored, c.in, now); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestReplaceAndLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Now().UTC()
	ok, err := Replace(dir, "h1", Snapshot{Driver: "scalibr", ScanTime: now, Packages: []Package{
		{Ecosystem: "npm", Name: "b", Version: "1"}, {Ecosystem: "npm", Name: "a", Version: "1"}, {Ecosystem: "npm", Name: "a", Version: "1"}, {Ecosystem: "", Name: "x"},
	}}, now)
	if err != nil || !ok {
		t.Fatalf("replace: %v %v", ok, err)
	}
	s, ok := Load(dir, "h1")
	if !ok || len(s.Packages) != 2 || s.Packages[0].Name != "a" || s.Version != Version {
		t.Fatalf("load: %+v %v", s, ok)
	}
	// Windows reports 0666 for any writable file; the owner-only mode is a
	// POSIX property.
	if info, err := os.Stat(Path(dir, "h1")); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		t.Fatalf("mode: %v %v", info, err)
	}
	if ok, err := Replace(dir, "h1", Snapshot{Driver: "osv", ScanTime: now}, now); err != nil || ok {
		t.Fatalf("a fresh SCALIBR snapshot was replaced by osv-scanner's: %v %v", ok, err)
	}
	if err := os.WriteFile(Path(dir, "h2"), []byte(`{"version":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := Load(dir, "h2"); ok {
		t.Fatal("another format version read as a snapshot")
	}
	if err := Remove(dir, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := Load(dir, "h1"); ok {
		t.Fatal("removed snapshot still loads")
	}
}
