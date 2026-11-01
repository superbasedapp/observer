package antigravity

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStateDBPathForFindsTheMacOSIDEDir pins FU-104 (MAC-4): on macOS the
// IDE keeps its globalStorage under "Antigravity IDE"; the older
// "Antigravity" dir (now the Antigravity 2 agent app's, or an older IDE
// install's) is only the fallback.
func TestStateDBPathForFindsTheMacOSIDEDir(t *testing.T) {
	db := func(home string, dir ...string) string {
		parts := append(append([]string{home, "Library", "Application Support"}, dir...), "User", "globalStorage", "state.vscdb")
		return filepath.Join(parts...)
	}
	write := func(t *testing.T, p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		write []string
		want  string
	}{
		{"current IDE dir", []string{"Antigravity IDE"}, "Antigravity IDE"},
		{"older IDE dir as fallback", []string{"Antigravity"}, "Antigravity"},
		{"current dir wins over the old one", []string{"Antigravity", "Antigravity IDE"}, "Antigravity IDE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			session := filepath.Join(home, ".gemini", "antigravity", "conversations", "c.pb")
			for _, d := range tc.write {
				write(t, db(home, d))
			}
			if got, want := stateDBPathFor(session), db(home, tc.want); got != want {
				t.Errorf("stateDBPathFor = %q, want %q", got, want)
			}
		})
	}
}
