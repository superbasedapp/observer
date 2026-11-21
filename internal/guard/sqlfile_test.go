package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadSQLFileBounded pins the reader: a regular file within the cap is
// read; absent, a directory and an oversized file are not judged.
func TestReadSQLFileBounded(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := write("ok.sql", "SELECT 1;")
	exact := write("exact.sql", strings.Repeat("a", maxSQLFileBytes))
	big := write("big.sql", strings.Repeat("a", maxSQLFileBytes+1))
	for _, tc := range []struct {
		name, path string
		want       bool
	}{
		{"regular file", ok, true},
		{"exactly the cap", exact, true},
		{"one byte over the cap", big, false},
		{"absent", filepath.Join(dir, "absent.sql"), false},
		{"directory", dir, false},
		{"empty path", "", false},
	} {
		if _, got := readSQLFileBounded(tc.path); got != tc.want {
			t.Errorf("%s: ok = %v, want %v", tc.name, got, tc.want)
		}
	}
	if b, _ := readSQLFileBounded(ok); string(b) != "SELECT 1;" {
		t.Errorf("content = %q", b)
	}
}
