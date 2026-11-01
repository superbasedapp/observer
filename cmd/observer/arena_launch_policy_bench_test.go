//go:build !sbo_omit_benchmark

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/arena"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termcore"
)

// arenaProjectTarget carries an Arena launch target whose run project root
// is project.
func arenaProjectTarget(ctx context.Context, project string) context.Context {
	return arena.ContextWithLaunchTarget(ctx, &arena.LaunchTarget{Dir: project, ProjectRoot: project})
}

// TestArenaLaunchPolicyRows (OSH-R-004, ruling P-203): an Arena process
// answers to the org's tools.disallow always, and to each [terminal.launch]
// agent key only when the node set it. A default node (nothing set) runs
// Arena even though the shipped defaults would refuse a New Terminal
// launch; a key the node set refuses and names itself.
func TestArenaLaunchPolicyRows(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	base := config.Config{}
	base.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	makeFeaturesSidecarWriter(base, "v-test", nil)([]string{"codex"}, nil)
	all := config.TerminalLaunchKeys{AllowFreshAgent: true, AllowedTools: true, AllowedProjectRoots: true}
	configured := base
	configured.Terminal.Enabled = true
	configured.Terminal.Launch = config.TerminalLaunchConfig{AllowFreshAgent: true, AllowedTools: []string{"claude-code", "codex"}, AllowedProjectRoots: []string{root}}
	configured.TerminalLaunchSet = all
	freshOff := base
	freshOff.TerminalLaunchSet = config.TerminalLaunchKeys{AllowFreshAgent: true}

	cases := []struct {
		name    string
		cfg     config.Config
		loadErr error
		tool    string
		project string
		wantErr error
		want    string
	}{
		{"default node, nothing set", base, nil, "claude-code", root, nil, ""},
		{"org tools.disallow on a default node", base, nil, "codex", root, nil, "disallowed by org policy"},
		{"configured and allowed", configured, nil, "claude-code", root, nil, ""},
		{"allow_fresh_agent = false set", freshOff, nil, "claude-code", root, termcore.ErrFreshLaunchDisabled, "allow_fresh_agent setting"},
		{"tool not on a set allow-list", configured, nil, "gemini", root, termcore.ErrToolNotAllowed, "allowed_tools setting"},
		{"root outside set roots", configured, nil, "claude-code", other, termcore.ErrProjectRootDenied, "allowed_project_roots setting"},
		{"config unreadable", configured, errors.New("bad toml"), "claude-code", root, nil, "cannot read the launch policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := arenaLoadConfig
			arenaLoadConfig = func(string) (config.Config, error) { return tc.cfg, tc.loadErr }
			defer func() { arenaLoadConfig = prev }()
			for _, claim := range []bool{true, false} {
				err := arenaLaunchPolicyAdmission("", tc.tool, tc.project, claim)
				if tc.wantErr == nil && tc.want == "" {
					if err != nil {
						t.Fatalf("claim=%v: refused: %v", claim, err)
					}
					continue
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("claim=%v: err = %v, want %v", claim, err, tc.wantErr)
				}
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("claim=%v: err = %v, want ...%q...", claim, err, tc.want)
				}
			}
		})
	}
	// The seam reads the project root from the launch target.
	prev := arenaLoadConfig
	arenaLoadConfig = func(string) (config.Config, error) { return configured, nil }
	defer func() { arenaLoadConfig = prev }()
	if err := arenaBudgetAdmissionSeam("")(arenaProjectTarget(context.Background(), other), "claude-code", ""); !errors.Is(err, termcore.ErrProjectRootDenied) {
		t.Fatalf("the seam did not check the run's project root: %v", err)
	}
}

// TestArenaPreflightOnTheNodesOwnConfig (ruling P-203): the dashboard's
// pre-check over a real config file. A node that never configured
// [terminal.launch] passes (Arena behaves as before); one with
// allow_fresh_agent = false written explicitly is refused, naming the
// setting; an org tools.disallow entry is refused on any node.
func TestArenaPreflightOnTheNodesOwnConfig(t *testing.T) {
	for _, tc := range []struct {
		name     string
		extra    string
		disallow []string
		want     string
	}{
		{"default individual node", "", nil, ""},
		{"explicit allow_fresh_agent = false", "\n[terminal.launch]\nallow_fresh_agent = false\n", nil, "allow_fresh_agent setting"},
		{"org tools.disallow", "", []string{"claude-code"}, "disallowed by org policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := writeLaunchGateConfig(t, "off")
			if tc.extra != "" {
				f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = f.WriteString(tc.extra)
				_ = f.Close()
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
			if err != nil {
				t.Fatal(err)
			}
			if tc.disallow != nil {
				makeFeaturesSidecarWriter(cfg, "v-test", nil)(tc.disallow, nil)
			}
			err = arenaPreflightSeam(cfgPath)(context.Background(), "claude-code", t.TempDir())
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ...%q...", err, tc.want)
			}
		})
	}
}
