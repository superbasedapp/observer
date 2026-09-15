package clinecli

import (
	"path/filepath"
	"testing"
)

func TestIsSessionFileConfiguredRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "custom-cline")
	a := NewWithOptions(nil, root)
	for _, tc := range []struct {
		relative string
		want     bool
	}{
		{"data/db/sessions.db", true},
		{"data/db/sessions.db-wal", true},
		{"data/db/sessions.db-shm", true},
		{"data/logs/hooks.jsonl", true},
		{"nested/.cline/data/db/sessions.db", true},
		{"data/other/sessions.db", false},
		{"../other/data/db/sessions.db", false},
	} {
		t.Run(tc.relative, func(t *testing.T) {
			if got := a.IsSessionFile(filepath.Join(root, filepath.FromSlash(tc.relative))); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
