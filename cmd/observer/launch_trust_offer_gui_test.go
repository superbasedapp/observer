//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_terminals

package main

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// The dashboard New Terminal row of TestTrustOfferedByDefault: the dialog's
// launch on a fresh clone goes on in both modes (the ask is the inner
// launcher's, in the terminal; an enforce deny would refuse here).
func init() {
	trustOfferRows = append(trustOfferRows, func(e trustOfferEnv) {
		clone := e.newClone()
		oldCfg := daemonConfigPathSetting.Load()
		cfgPath := e.cfgPath
		daemonConfigPathSetting.Store(&cfgPath)
		e.t.Cleanup(func() { daemonConfigPathSetting.Store(oldCfg) })
		svc := termsvc.New(termsvc.Options{
			Recorder: assembledRecorder{},
			Launcher: &recordingLauncher{},
			Policy:   termsvc.Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{clone}},
		})
		a := &launchManagerAdapter{svc: svc, repoTrust: dashboardRepoTrust(e.cfg, nil)}
		if _, err := a.CreateFresh(dashapi.FreshLaunchSpec{Tool: "claude-code", Subcommand: "claude", ProjectRoot: clone}); err != nil {
			e.t.Fatalf("New Terminal on the clone: %v, want the launch to go on (the inner launcher asks)", err)
		}
	})
}

// The dashboard GUI launch row of TestTrustOfferedByDefault: the project
// root is checked as a daemon-started launch. Observe goes on (the trust row
// warns in the daemon log); enforce refuses before anything resolves and
// says where to accept; after the accept the trust row lets it through.
func init() {
	trustOfferRows = append(trustOfferRows, func(e trustOfferEnv) {
		t := e.t
		row, ok := integration.GUILaunchFor("vscode")
		if !ok {
			t.Fatal("test premise: the vscode GUI row")
		}
		resolved := 0
		g := &guiLauncher{
			configPath: func() string { return e.cfgPath },
			resolveEnv: func() toolresolve.Env { resolved++; return toolresolve.Env{} },
			isWSL:      func() bool { return false },
		}
		// spawn reports whether the launch got past the trust row, which is
		// whether it reached binary resolution (that then fails in a test
		// home), and the error when it did not. Only reaching resolution
		// counts as going on; any error before it is a failure of the row.
		spawn := func(root string) (bool, error) {
			before := resolved
			_, err := g.SpawnGUI(termsvc.GUISpawnRequest{ID: "vscode", Spec: row.Spec, ProjectRoot: root})
			return resolved > before, err
		}
		clone := e.newClone()
		passed, err := spawn(clone)
		switch e.mode {
		case "observe":
			if !passed {
				t.Fatalf("GUI, observe: %v, want the launch to go on to resolution", err)
			}
		case "enforce":
			if passed || err == nil || !strings.Contains(err.Error(), "S-701") || !strings.Contains(err.Error(), "observer security trust accept --all --dir "+clone) {
				t.Fatalf("GUI, enforce: passed %v, %v, want a refusal naming where to accept", passed, err)
			}
			e.accept(clone)
			if passed, err := spawn(clone); !passed {
				t.Fatalf("GUI, enforce, after the accept: %v, want the launch to go on to resolution", err)
			}
		}
	})
}
