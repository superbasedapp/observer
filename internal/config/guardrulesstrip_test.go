package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRemoveGuardRuleDisables pins the managed-node strip: the named ids
// leave the `[guard.rules] disable` list, every other line and comment stays,
// an emptied list is deleted, and a file without the list is untouched.
func TestRemoveGuardRuleDisables(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		body        string
		drop        []string
		wantRemoved []string
		wantHas     []string
		wantNot     []string
		wantWrite   bool
	}{
		{
			name: "some removed",
			body: "# my config\n[guard]\nmode = \"observe\"\n\n[guard.rules]\n# turned off locally\ndisable = [\"S-791\", \"U-1\", \"S-792\"]\n",
			drop: []string{"S-791", "S-792"}, wantRemoved: []string{"S-791", "S-792"},
			wantHas: []string{"# my config", "# turned off locally", "\"U-1\""}, wantNot: []string{"S-791", "S-792"}, wantWrite: true,
		},
		{
			name: "all removed deletes the list",
			body: "[guard.rules]\ndisable = [\"S-791\"]\nuser_policy = \"~/.observer/guard-policy.toml\"\n",
			drop: []string{"S-791"}, wantRemoved: []string{"S-791"},
			wantHas: []string{"user_policy"}, wantNot: []string{"disable", "S-791"}, wantWrite: true,
		},
		{
			name: "nothing to remove",
			body: "[guard.rules]\ndisable = [\"U-1\"]\n",
			drop: []string{"S-791"}, wantHas: []string{"\"U-1\""},
		},
		{
			name: "no list",
			body: "[guard]\nmode = \"enforce\"\n",
			drop: []string{"S-791"}, wantHas: []string{"enforce"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			// A backup the same start's auto-migration wrote must survive
			// the strip (review finding 4).
			const migrationBak = "# the migration's backup\n"
			if err := os.WriteFile(path+".bak", []byte(migrationBak), 0o600); err != nil {
				t.Fatal(err)
			}
			removed, err := RemoveGuardRuleDisables(path, tc.drop)
			if err != nil {
				t.Fatalf("RemoveGuardRuleDisables: %v", err)
			}
			if strings.Join(removed, ",") != strings.Join(tc.wantRemoved, ",") {
				t.Errorf("removed = %v, want %v", removed, tc.wantRemoved)
			}
			got, _ := os.ReadFile(path)
			for _, s := range tc.wantHas {
				if !strings.Contains(string(got), s) {
					t.Errorf("file lost %q:\n%s", s, got)
				}
			}
			for _, s := range tc.wantNot {
				if strings.Contains(string(got), s) {
					t.Errorf("file still holds %q:\n%s", s, got)
				}
			}
			bak, bakErr := os.ReadFile(GuardStripBackupPath(path))
			if wrote := bakErr == nil; wrote != tc.wantWrite {
				t.Errorf("strip backup written = %v, want %v", wrote, tc.wantWrite)
			}
			if bakErr == nil && string(bak) != tc.body {
				t.Errorf("strip backup = %q, want the pre-strip file", bak)
			}
			if prior, _ := os.ReadFile(path + ".bak"); string(prior) != migrationBak {
				t.Errorf("config.toml.bak overwritten by the strip: %q", prior)
			}
		})
	}
	if _, err := RemoveGuardRuleDisables(filepath.Join(t.TempDir(), "absent.toml"), []string{"S-791"}); err != nil {
		t.Errorf("a missing file must not be an error: %v", err)
	}
}

// TestRemoveGuardRuleDisablesHoldsConfigLock (review finding 4): the strip's
// read-patch-write waits for the process-wide config lock, so it cannot
// interleave with a dashboard save.
func TestRemoveGuardRuleDisablesHoldsConfigLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[guard.rules]\ndisable = [\"S-791\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mu := WriteLock()
	mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := RemoveGuardRuleDisables(path, []string{"S-791"})
		done <- err
	}()
	select {
	case <-done:
		mu.Unlock()
		t.Fatal("the strip ran while the config lock was held")
	case <-time.After(100 * time.Millisecond):
	}
	mu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("RemoveGuardRuleDisables: %v", err)
	}
	if got, _ := os.ReadFile(path); strings.Contains(string(got), "S-791") {
		t.Errorf("not stripped after the lock was released:\n%s", got)
	}
}
