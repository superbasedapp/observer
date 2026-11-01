package adapter

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestRelocatedToolHome (lane w4-homes-b): the helper names the relocated
// home only when the tool's own variable moves the artifact, and never for
// a relative value or an unset one.
func TestRelocatedToolHome(t *testing.T) {
	home := t.TempDir()
	alt := filepath.Join(t.TempDir(), "alt")
	for _, tc := range []struct {
		name, id string
		up       int
		env      map[string]string
		want     string
	}{
		{"unset", "grok/user-config", 0, nil, ""},
		{"GROK_HOME", "grok/user-config", 0, map[string]string{"GROK_HOME": alt}, alt},
		{"relative", "grok/user-config", 0, map[string]string{"GROK_HOME": "rel"}, ""},
		{"GEMINI_CLI_HOME holds .gemini", "gemini-cli/user-settings", 0, map[string]string{"GEMINI_CLI_HOME": alt}, filepath.Join(alt, ".gemini")},
		{"a directory row, one level up", "kiro-cli/user-hooks", 1, map[string]string{"KIRO_HOME": alt}, alt},
		{"unknown artifact", "no/such", 0, map[string]string{"GROK_HOME": alt}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if got := relocatedToolHome(tc.id, tc.up, home, func(k string) string { return env[k] }, runtime.GOOS); got != tc.want {
				t.Errorf("relocatedToolHome = %q, want %q", got, tc.want)
			}
		})
	}
}
