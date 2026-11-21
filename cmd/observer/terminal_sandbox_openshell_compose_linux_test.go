//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// TestOpenShellCheckInitArgv (review finding V5, tracker F-023): compose
// parses the in-box init's argv with the init's own parser, so a plan the
// init would refuse is refused before any box exists. One case per field
// the init checks.
func TestOpenShellCheckInitArgv(t *testing.T) {
	good := func() openShellPlanFile {
		return openShellPlanFile{
			ObserverBin: "/usr/bin/observer", SockDir: "/tmp/observer-sbx-RUN", CopyDir: "/tmp/observer-sbx-RUN/copy",
			CopySync: []sandboxopenshell.CopySync{{Source: "/home/dev/.claude.json", Target: "/home/dev/.claude.json"}},
			Seed:     []sandboxopenshell.CopySync{{Source: "/home/dev/.observer/config.toml", Target: "/home/dev/.observer/config.toml"}},
			Guest:    []string{"/usr/bin/observer", "sandbox-guest", "--"},
			Workdir:  "/home/dev/project",
		}
	}
	for _, tc := range []struct {
		name string
		mod  func(pf *openShellPlanFile)
		want string // "" accepts
	}{
		{"a canonical plan", func(*openShellPlanFile) {}, ""},
		{"no workdir (no --cwd)", func(pf *openShellPlanFile) { pf.Workdir = "" }, ""},
		{"no guest prefix", func(pf *openShellPlanFile) { pf.Guest = nil }, ""},
		{"a relative workdir", func(pf *openShellPlanFile) { pf.Workdir = "project" }, "working dir"},
		{"an unclean workdir", func(pf *openShellPlanFile) { pf.Workdir = "/home/dev/../dev/project" }, "working dir"},
		{"a trailing slash", func(pf *openShellPlanFile) { pf.Workdir = "/home/dev/project/" }, "working dir"},
		{"a relative socket dir", func(pf *openShellPlanFile) { pf.SockDir = "observer-sbx-RUN" }, "socket dir"},
		{"a relative copy dir", func(pf *openShellPlanFile) { pf.CopyDir = "copy" }, "env file"},
		{"a relative copy target", func(pf *openShellPlanFile) { pf.CopySync[0].Target = ".claude.json" }, "absolute paths"},
		{"a relative seed target", func(pf *openShellPlanFile) { pf.Seed[0].Target = "config.toml" }, "absolute paths"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pf := good()
			tc.mod(&pf)
			err := openShellCheckInitArgv(pf)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "the in-box init would refuse this plan") {
				t.Fatalf("err %v, want one naming %q", err, tc.want)
			}
		})
	}
}
