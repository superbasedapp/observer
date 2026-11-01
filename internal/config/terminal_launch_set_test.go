package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTerminalLaunchSetRecordsOnlyKeysSet (ruling P-203): Load records
// which agent keys of [terminal.launch] a file or an env override set, so
// a caller can tell an explicit allow_fresh_agent = false from the default.
func TestTerminalLaunchSetRecordsOnlyKeysSet(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		env  map[string]string
		want TerminalLaunchKeys
	}{
		{"no block", "", nil, TerminalLaunchKeys{}},
		{"unrelated launch key", "[terminal.launch]\nallow_install = false\n", nil, TerminalLaunchKeys{}},
		{"explicit false", "[terminal.launch]\nallow_fresh_agent = false\n", nil, TerminalLaunchKeys{AllowFreshAgent: true}},
		{"lists", "[terminal.launch]\nallowed_tools = []\nallowed_project_roots = [\"/x\"]\n", nil, TerminalLaunchKeys{AllowedTools: true, AllowedProjectRoots: true}},
		{"env", "", map[string]string{"OBSERVER_TERMINAL_LAUNCH_ALLOW_FRESH_AGENT": "true"}, TerminalLaunchKeys{AllowFreshAgent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n" + tc.body
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(LoadOptions{GlobalPath: path, Env: func(k string) string { return tc.env[k] }})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.TerminalLaunchSet != tc.want {
				t.Fatalf("set = %+v, want %+v", cfg.TerminalLaunchSet, tc.want)
			}
		})
	}
	if got := (TerminalLaunchKeys{}).withPinned([]string{"terminal.launch.allowed_tools", "guard.mode"}); got != (TerminalLaunchKeys{AllowedTools: true}) {
		t.Fatalf("a verified pin did not count as set: %+v", got)
	}
}
