package fsatomic

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestKeepDisplacedCopy pins T-884: a displaced copy never overwrites an
// existing file (a user's own .bak, or an earlier copy with the same stamp),
// is written 0600, and at most keep copies of one artifact remain, while
// nothing that is not one of the artifact's own displaced copies is removed.
func TestKeepDisplacedCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "superbased-observer.ts")
	userBak := path + ".bak"
	neighbour := filepath.Join(dir, "other.ts"+displacedInfix+"20261017T090611.087864169Z")
	lookalike := path + displacedInfix + "not-a-stamp"
	plantedDir := path + displacedInfix + "20200101T000000.000000000Z"
	for p, body := range map[string]string{userBak: "user", neighbour: "n", lookalike: "l"} {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(plantedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 10, 17, 17, 18, 40, 0, time.UTC)
	var written []string
	for i := 0; i < 5; i++ {
		got, err := KeepDisplacedCopy(path, []byte{byte('a' + i)}, base.Add(time.Duration(i)*time.Minute), 3)
		if err != nil {
			t.Fatalf("copy %d: %v", i, err)
		}
		written = append(written, got)
	}

	// The cap: the three newest copies remain, oldest first.
	if got, want := DisplacedCopies(path), written[2:]; !equalStrings(got, want) {
		t.Fatalf("copies = %q, want %q", got, want)
	}
	for i, p := range written[2:] {
		body, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(body, []byte{byte('a' + i + 2)}) {
			t.Fatalf("%s = %q (%v)", p, body, err)
		}
		if runtime.GOOS != "windows" {
			if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode = %v (%v), want 0600", p, info.Mode().Perm(), err)
			}
		}
	}
	// Nothing else was touched.
	for p, body := range map[string]string{userBak: "user", neighbour: "n", lookalike: "l"} {
		if got, err := os.ReadFile(p); err != nil || string(got) != body {
			t.Fatalf("%s changed: %q (%v)", p, got, err)
		}
	}
	if info, err := os.Stat(plantedDir); err != nil || !info.IsDir() {
		t.Fatalf("a displaced directory was removed: %v", err)
	}
}

// TestKeepDisplacedCopyNeverOverwrites: a copy whose stamp is taken advances
// the stamp instead of replacing the existing file.
func TestKeepDisplacedCopyNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	now := time.Date(2026, 10, 17, 17, 18, 40, 5, time.UTC)
	taken := DisplacedName(path, now)
	if err := os.WriteFile(taken, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := KeepDisplacedCopy(path, []byte("second"), now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got == taken {
		t.Fatalf("copy reused the taken name %s", got)
	}
	if body, _ := os.ReadFile(taken); string(body) != "first" {
		t.Fatalf("existing copy overwritten: %q", body)
	}
	if body, _ := os.ReadFile(got); string(body) != "second" {
		t.Fatalf("new copy = %q", body)
	}
}

// TestDisplacedStamp: only an exact stamp is one of path's displaced copies.
func TestDisplacedStamp(t *testing.T) {
	base := "x.ts"
	cases := []struct {
		name string
		ok   bool
	}{
		{"x.ts.displaced-20261017T090611.087864169Z", true},
		{"x.ts.displaced-20261017T090611Z", false},
		{"x.ts.displaced-20261017T090611.087864169Zx", false},
		{"x.ts.displaced-2026101xT090611.087864169Z", false},
		{"y.ts.displaced-20261017T090611.087864169Z", false},
		{"x.ts.bak", false},
		{"x.ts", false},
	}
	for _, tc := range cases {
		if _, ok := displacedStamp(base, tc.name); ok != tc.ok {
			t.Errorf("displacedStamp(%q) = %v, want %v", tc.name, ok, tc.ok)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
