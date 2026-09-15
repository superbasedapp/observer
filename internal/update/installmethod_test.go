package update

import (
	"strings"
	"testing"
)

// fakePaths is the test's path resolver: a set of paths that "exist".
// It is what lets the install-method table be tested without os.Stat,
// dpkg or rpm — the seam PathProbe exists for (CLAUDE.md #1).
type fakePaths map[string]bool

// sibling answers the venv-marker question.
func (f fakePaths) sibling(dir, name string) bool { return f[dir+"/"+name] }

// TestDetectInstallMethod walks the §3.7 install-method table, one row
// per rule plus the two fall-through rows.
func TestDetectInstallMethod(t *testing.T) {
	cases := []struct {
		name       string
		probe      PathProbe
		wantMethod Method
		wantSelf   bool
		wantRule   string
		// wantAdvice is a substring the advice must contain when the
		// node cannot self-apply.
		wantAdvice string
	}{
		{
			name: "npm global install (the shim package)",
			probe: PathProbe{
				ExecPath: "/home/dev/.nvm/versions/node/v22.3.0/lib/node_modules/@superbased/observer/bin/observer",
				Writable: true,
			},
			wantMethod: MethodNPM, wantRule: "npm-package-path", wantAdvice: "npm i -g @superbased/observer@1.33.0",
		},
		{
			name: "npm platform package (the binary really lives here)",
			probe: PathProbe{
				ExecPath: "/usr/lib/node_modules/@superbased/observer-linux-x64/bin/observer",
				Writable: true,
			},
			wantMethod: MethodNPM, wantRule: "npm-package-path",
		},
		{
			name: "a project-local node_modules/.bin shim",
			probe: PathProbe{
				ExecPath: "/home/dev/app/node_modules/.bin/observer",
				Writable: true,
			},
			wantMethod: MethodNPM, wantRule: "npm-node-modules-bin",
		},
		{
			name: "the VS Code extension's bundled copy",
			probe: PathProbe{
				ExecPath: "/home/dev/.vscode/extensions/superbased.superbased-observer-1.32.0/bin/observer",
				Writable: true,
			},
			wantMethod: MethodVSCode, wantRule: "vscode-extension", wantAdvice: "extension",
		},
		{
			name: "the extension's globalStorage cache",
			probe: PathProbe{
				ExecPath: "/home/dev/.config/Code/User/globalStorage/superbased.superbased-observer/bin/observer",
				Writable: true,
			},
			wantMethod: MethodVSCode, wantRule: "vscode-extension",
		},
		{
			name: "a pip install into site-packages",
			probe: PathProbe{
				ExecPath: "/usr/lib/python3.12/site-packages/observer/bin/observer",
				Writable: true,
			},
			wantMethod: MethodPip, wantRule: "python-site-packages", wantAdvice: "pip install -U superbased-observer",
		},
		{
			name: "a Debian dist-packages install",
			probe: PathProbe{
				ExecPath: "/usr/lib/python3/dist-packages/observer/bin/observer",
				Writable: true,
			},
			wantMethod: MethodPip, wantRule: "python-site-packages",
		},
		{
			name: "a virtualenv bin, identified by its pyvenv.cfg marker",
			probe: PathProbe{
				ExecPath:      "/home/dev/venvs/obs/bin/observer",
				Writable:      true,
				SiblingExists: fakePaths{"/home/dev/venvs/obs/pyvenv.cfg": true}.sibling,
			},
			wantMethod: MethodPip, wantRule: "python-venv-bin",
		},
		{
			name: "a Windows venv Scripts directory",
			probe: PathProbe{
				ExecPath:      `C:\Users\dev\venvs\obs\Scripts\observer.exe`,
				GOOS:          "windows",
				Writable:      true,
				SiblingExists: fakePaths{"c:/users/dev/venvs/obs/pyvenv.cfg": true}.sibling,
			},
			wantMethod: MethodPip, wantRule: "python-venv-bin",
		},
		{
			name: "/usr/local/bin is NOT a virtualenv just because it is called bin",
			probe: PathProbe{
				ExecPath: "/usr/local/bin/observer",
				Writable: true,
			},
			wantMethod: MethodBinary, wantSelf: true, wantRule: "standalone-writable",
		},
		{
			name: "a Homebrew Cellar install",
			probe: PathProbe{
				ExecPath: "/opt/homebrew/Cellar/superbased-observer/1.32.0/bin/observer",
				Writable: true,
			},
			wantMethod: MethodBrew, wantRule: "homebrew-cellar", wantAdvice: "brew upgrade",
		},
		{
			name: "an Intel-mac Cellar install",
			probe: PathProbe{
				ExecPath: "/usr/local/Cellar/superbased-observer/1.32.0/bin/observer",
				Writable: true,
			},
			wantMethod: MethodBrew, wantRule: "homebrew-cellar",
		},
		{
			name: "a dpkg-owned path",
			probe: PathProbe{
				ExecPath: "/usr/bin/observer",
				Writable: true,
				PackageOwner: func(string) (Method, bool) {
					return MethodAPT, true
				},
			},
			wantMethod: MethodAPT, wantRule: "system-package-owned", wantAdvice: "system package manager",
		},
		{
			name: "an rpm-owned path reports rpm, not apt",
			probe: PathProbe{
				ExecPath: "/usr/bin/observer",
				Writable: true,
				PackageOwner: func(string) (Method, bool) {
					return MethodRPM, true
				},
			},
			wantMethod: MethodRPM, wantRule: "system-package-owned",
		},
		{
			name: "a standalone writable binary is the ONLY self-applying row",
			probe: PathProbe{
				ExecPath: "/home/dev/.local/bin/observer",
				Writable: true,
			},
			wantMethod: MethodBinary, wantSelf: true, wantRule: "standalone-writable",
		},
		{
			name: "a standalone binary this uid cannot replace says so honestly",
			probe: PathProbe{
				ExecPath: "/usr/local/bin/observer",
				Writable: false,
			},
			wantMethod: MethodBinaryReadOnly, wantRule: "standalone-readonly", wantAdvice: "not writable",
		},
		{
			name:       "no executable path is unknown, never a silent self-apply",
			probe:      PathProbe{ExecPath: "  "},
			wantMethod: MethodUnknown, wantRule: "no-executable-path", wantAdvice: "manually",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(tc.probe)
			if got.Method != tc.wantMethod {
				t.Errorf("Method = %q, want %q", got.Method, tc.wantMethod)
			}
			if got.SelfApply != tc.wantSelf {
				t.Errorf("SelfApply = %v, want %v", got.SelfApply, tc.wantSelf)
			}
			if got.Rule != tc.wantRule {
				t.Errorf("Rule = %q, want %q", got.Rule, tc.wantRule)
			}
			advice := AdviceFor(got, "v1.33.0")
			if tc.wantAdvice != "" && !strings.Contains(advice, tc.wantAdvice) {
				t.Errorf("advice = %q, want it to contain %q", advice, tc.wantAdvice)
			}
			if got.SelfApply && advice != "" {
				t.Errorf("a self-applying node should carry no advice, got %q", advice)
			}
		})
	}
}

// TestOnlyBinaryMethodSelfApplies pins the ruling itself rather than
// its per-row spelling: every packaging channel is drift-reported only
// (R6), so exactly one method may replace the binary.
func TestOnlyBinaryMethodSelfApplies(t *testing.T) {
	for _, r := range installRules {
		if r.self {
			t.Errorf("install rule %q self-applies; only the standalone-writable fall-through may", r.name)
		}
	}
}

// TestAdviceForSubstitutesTheVersionPlaceholder pins that no surface
// can print a literal "<version>".
func TestAdviceForSubstitutesTheVersionPlaceholder(t *testing.T) {
	d := Detect(PathProbe{ExecPath: "/x/node_modules/@superbased/observer/bin/observer"})
	if got := AdviceFor(d, "v1.33.0"); strings.Contains(got, "<version>") {
		t.Fatalf("advice still carries the placeholder: %q", got)
	}
	if got := AdviceFor(d, ""); !strings.Contains(got, "<version>") {
		t.Fatalf("with no target version the placeholder should remain, got %q", got)
	}
	if got := AdviceFor(Detection{}, "v1.33.0"); got != "" {
		t.Fatalf("empty advice should stay empty, got %q", got)
	}
}
