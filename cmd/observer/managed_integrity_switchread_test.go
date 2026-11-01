package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
)

// TestManagedIntegritySwitchReadIsCapped (R-188 F7): the managed-integrity
// cycle reads the hook-off switch files of up to hookdisable.MaxProjectRoots
// projects. A FIFO at a switch path must not hang the cycle and a file past
// the cap must not be read into memory (both are unreadable: never a
// finding), while a normal switch file in another project is still found.
// The FIFO row skips where the OS has no FIFO at a filesystem path.
func TestManagedIntegritySwitchReadIsCapped(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, path string)
		// found is whether the row's project reports its tool switched off.
		found bool
	}{
		{name: "normal file", setup: writeSwitchFile(`{"disableAllHooks":true}`), found: true},
		{name: "over the cap", setup: writeSwitchFile(`{"disableAllHooks":true}` + strings.Repeat(" ", int(agentconfigsvc.DefaultMaxFileBytes)))},
		{name: "fifo", setup: makeHookSwitchFIFO},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := pinToolHomes(t)
			project := t.TempDir()
			switchPath := filepath.Join(project, ".qwen", "settings.json")
			if err := os.MkdirAll(filepath.Dir(switchPath), 0o755); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, switchPath)
			// A second project with a normal switch file: the cycle keeps
			// reading past the refused one.
			other := t.TempDir()
			// Not Copilot CLI's disableAllHooks: that row is write-guard-only
			// (FU-159), so Detect never reports it.
			otherPath := filepath.Join(other, ".codebuddy", "settings.json")
			if err := os.MkdirAll(filepath.Dir(otherPath), 0o755); err != nil {
				t.Fatal(err)
			}
			writeSwitchFile(`{"disableAllHooks":true}`)(t, otherPath)

			host := configLayerHost{Home: home, Getenv: func(string) string { return "" }, SystemRoot: filepath.Join(home, "no-system")}
			src := newConfigLayerSource(&fakeRootLister{roots: []string{project, other}}, host)
			done := make(chan []string, 1)
			go func() {
				var tools []string
				for _, f := range src.Switches([]string{project, other}) {
					tools = append(tools, f.Tools...)
				}
				done <- tools
			}()
			var tools []string
			select {
			case tools = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the hook-switch read blocked (a FIFO at a switch path hung the managed-integrity cycle)")
			}
			if got := slices.Contains(tools, "qwen-code"); got != tc.found {
				t.Errorf("qwen-code switched off = %v, want %v (tools %v)", got, tc.found, tools)
			}
			if !slices.Contains(tools, "codebuddy") {
				t.Errorf("the other project's switch was not read: tools %v", tools)
			}
		})
	}
}

func writeSwitchFile(body string) func(t *testing.T, path string) {
	return func(t *testing.T, path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
