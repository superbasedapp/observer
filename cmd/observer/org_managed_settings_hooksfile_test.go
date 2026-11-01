package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmitManagedSettings_AdminHooksFiles pins IDE-5 and the IDE-6 managed
// row end to end: one administrator hooks file per OS with the per-node
// command text, and the README.
func TestEmitManagedSettings_AdminHooksFiles(t *testing.T) {
	for _, tc := range []struct{ provider, tool, linuxPath string }{
		{"cursor", "cursor", "/etc/cursor/hooks.json"},
		{"devin", "devin", "/etc/devin/hooks.json"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			out := t.TempDir()
			stdout, err := runEmitManagedSettings(t, "--provider", tc.provider, "--all-os", "--hook-binary", "/opt/observer/bin/observer", "--out", out)
			if err != nil {
				t.Fatalf("emit: %v\n%s", err, stdout)
			}
			for _, goos := range []string{"linux", "darwin", "windows"} {
				b, err := os.ReadFile(filepath.Join(out, "hooks."+goos+".json"))
				if err != nil {
					t.Fatalf("%s file: %v", goos, err)
				}
				if !strings.Contains(string(b), "/opt/observer/bin/observer hook "+tc.tool+" ") {
					t.Errorf("%s file does not run --hook-binary:\n%s", goos, b)
				}
			}
			readme, _ := os.ReadFile(filepath.Join(out, "README.md"))
			if !strings.Contains(string(readme), tc.linuxPath) {
				t.Errorf("README does not name %s:\n%s", tc.linuxPath, readme)
			}
		})
	}
}
