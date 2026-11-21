//go:build !sbo_omit_org_update

package dashboard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// TestUpdateTerminalPlanFor pins one case per row of updateTerminalRules:
// the install method decides the fixed argv, Windows refuses (the running
// observer.exe is locked), and every refusal names what to do instead.
func TestUpdateTerminalPlanFor(t *testing.T) {
	npm := update.Detection{Method: update.MethodNPM, Advice: "npm i -g @superbased/observer@<version>"}
	pip := update.Detection{Method: update.MethodPip, Advice: "pip install -U superbased-observer"}
	brew := update.Detection{Method: update.MethodBrew, Advice: "brew upgrade superbased-observer"}
	binary := update.Detection{Method: update.MethodBinary, SelfApply: true}
	cases := []struct {
		name       string
		det        update.Detection
		exec       string
		goos       string
		wantArgv   []string
		wantReason []string
	}{
		{
			name:     "npm on linux",
			det:      npm,
			exec:     "/home/dev/.npm-global/lib/node_modules/@superbased/observer-linux-x64/bin/observer",
			goos:     "linux",
			wantArgv: []string{"npm", "i", "-g", "@superbased/observer@latest"},
		},
		{
			name:     "npm on darwin",
			det:      npm,
			exec:     "/opt/homebrew/lib/node_modules/@superbased/observer-darwin-arm64/bin/observer",
			goos:     "darwin",
			wantArgv: []string{"npm", "i", "-g", "@superbased/observer@latest"},
		},
		{
			name:     "pipx venv",
			det:      pip,
			exec:     "/home/dev/.local/share/pipx/venvs/superbased-observer/lib/python3.12/site-packages/observer/bin/observer",
			goos:     "linux",
			wantArgv: []string{"pipx", "upgrade", "superbased-observer"},
		},
		{
			name:       "plain pip is not run from here",
			det:        pip,
			exec:       "/usr/lib/python3/dist-packages/observer/bin/observer",
			goos:       "linux",
			wantReason: []string{"not installed with npm or pipx", "pip install -U superbased-observer"},
		},
		{
			name:       "windows npm is refused: the binary is locked",
			det:        npm,
			exec:       `C:\Users\dev\AppData\Roaming\npm\node_modules\@superbased\observer-win32-x64\bin\observer.exe`,
			goos:       "windows",
			wantReason: []string{"locked", "Stop the daemon", "@superbased/observer@latest"},
		},
		{
			name:       "homebrew names its own command",
			det:        brew,
			exec:       "/opt/homebrew/Cellar/superbased-observer/1.0.0/bin/observer",
			goos:       "darwin",
			wantReason: []string{"brew upgrade superbased-observer"},
		},
		{
			name:       "standalone binary points at the download page",
			det:        binary,
			exec:       "/usr/local/bin/observer",
			goos:       "linux",
			wantReason: []string{"https://superbased.app/download"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := updateTerminalPlanFor(tc.det, tc.exec, tc.goos)
			if p.Method != string(tc.det.Method) {
				t.Errorf("method = %q, want %q", p.Method, tc.det.Method)
			}
			if tc.wantArgv != nil {
				if !p.Available || strings.Join(p.argv, "\x00") != strings.Join(tc.wantArgv, "\x00") {
					t.Fatalf("plan = %+v (argv %q), want available argv %q", p, p.argv, tc.wantArgv)
				}
				if p.Command != strings.Join(tc.wantArgv, " ") || p.Reason != "" {
					t.Errorf("command/reason = %q / %q", p.Command, p.Reason)
				}
				return
			}
			if p.Available || len(p.argv) != 0 || p.Command != "" {
				t.Fatalf("plan = %+v, want not available", p)
			}
			for _, want := range tc.wantReason {
				if !strings.Contains(p.Reason, want) {
					t.Errorf("reason %q does not mention %q", p.Reason, want)
				}
			}
			if strings.Contains(p.Reason, "<version>") {
				t.Errorf("reason %q carries the raw version placeholder", p.Reason)
			}
		})
	}
}

// TestUpdateTerminalPlanArgvIsACopy keeps the table's rows immutable: a
// caller that edits a plan's argv must not change the next plan.
func TestUpdateTerminalPlanArgvIsACopy(t *testing.T) {
	det := update.Detection{Method: update.MethodNPM}
	p := updateTerminalPlanFor(det, "/x/node_modules/@superbased/observer/bin/observer", "linux")
	p.argv[0] = "rm"
	again := updateTerminalPlanFor(det, "/x/node_modules/@superbased/observer/bin/observer", "linux")
	if again.argv[0] != "npm" {
		t.Fatalf("the table row was mutated through a plan: %q", again.argv)
	}
}
