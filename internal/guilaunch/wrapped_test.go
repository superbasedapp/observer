package guilaunch

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestComposeExtraArgs pins how operator arguments (the `observer ide <id>
// [dir] -- args` form) reach each launch mechanism.
func TestComposeExtraArgs(t *testing.T) {
	t.Parallel()

	bundleSpec := integration.GUILaunchSpec{ID: "editor", DarwinApp: "Editor", ProjectDirArgv: true}
	aumidSpec := integration.GUILaunchSpec{
		ID:              "packaged",
		AppsFolderAUMID: "Vendor_abc!App",
		Wrap:            integration.WrapSpec{Reason: "explorer launch"},
	}
	extra := []string{"--new-window", "--verbose"}

	tests := []struct {
		name     string
		spec     integration.GUILaunchSpec
		in       Inputs
		wantArgv []string
		wantNote string
	}{
		{
			name:     "exe: extra args follow the project dir",
			spec:     specExe(),
			in:       Inputs{GOOS: "linux", Bin: "/usr/bin/editor", ProjectRoot: "/p", ExtraArgs: extra},
			wantArgv: []string{"/usr/bin/editor", "/p", "--new-window", "--verbose"},
		},
		{
			name:     "exe: extra args without a project dir",
			spec:     specExe(),
			in:       Inputs{GOOS: "linux", Bin: "/usr/bin/editor", ExtraArgs: extra},
			wantArgv: []string{"/usr/bin/editor", "--new-window", "--verbose"},
		},
		{
			name:     "darwin bundle: extra args share the single --args",
			spec:     bundleSpec,
			in:       Inputs{GOOS: "darwin", Bin: "/Applications/Editor.app", ProjectRoot: "/p", ExtraArgs: extra},
			wantArgv: []string{"open", "-a", "Editor", "--args", "/p", "--new-window", "--verbose"},
		},
		{
			name:     "darwin bundle: extra args alone open their own --args",
			spec:     bundleSpec,
			in:       Inputs{GOOS: "darwin", Bin: "/Applications/Editor.app", ExtraArgs: extra},
			wantArgv: []string{"open", "-a", "Editor", "--args", "--new-window", "--verbose"},
		},
		{
			name:     "packaged app: extra args are dropped with a note",
			spec:     aumidSpec,
			in:       Inputs{GOOS: "windows", ExtraArgs: extra},
			wantArgv: []string{"explorer.exe", `shell:AppsFolder\Vendor_abc!App`},
			wantNote: "extra arguments were ignored",
		},
		{
			name:     "no extra args leaves argv unchanged",
			spec:     specExe(),
			in:       Inputs{GOOS: "linux", Bin: "/usr/bin/editor", ProjectRoot: "/p"},
			wantArgv: []string{"/usr/bin/editor", "/p"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan, err := Compose(tt.spec, tt.in)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if !reflect.DeepEqual(plan.Argv, tt.wantArgv) {
				t.Errorf("Argv = %q, want %q", plan.Argv, tt.wantArgv)
			}
			if tt.wantNote != "" && !strings.Contains(strings.Join(plan.Notes, "|"), tt.wantNote) {
				t.Errorf("Notes = %q, want one containing %q", plan.Notes, tt.wantNote)
			}
		})
	}
}

// TestComposeHandoffLauncherIsNotWrapped pins the hand-off rule: a child-env
// row whose RESOLVED binary is a hand-off client (VS Code's remote-cli, which
// only asks a running window to open a folder) must record the wrap as not
// applied and inject nothing, whatever else is true.
func TestComposeHandoffLauncherIsNotWrapped(t *testing.T) {
	t.Parallel()

	spec := specExe()
	spec.Wrap.HandoffPathSegments = []string{"remote-cli"}

	tests := []struct {
		name        string
		bin         string
		wantApplied bool
	}{
		{"unix remote-cli segment", "/home/u/.vscode-server/bin/abc/bin/remote-cli/code", false},
		{"windows-spelled remote-cli segment", `C:\x\bin\remote-cli\code.cmd`, false},
		{"segment must match whole, not a substring", "/opt/not-remote-cli-thing/code", true},
		{"ordinary install", "/usr/bin/code", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan, err := Compose(spec, Inputs{GOOS: "linux", Bin: tt.bin, ProxyURL: "http://127.0.0.1:8820"})
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if plan.WrapApplied != tt.wantApplied {
				t.Fatalf("WrapApplied = %v, want %v (note %q)", plan.WrapApplied, tt.wantApplied, plan.WrapNote)
			}
			if !tt.wantApplied {
				if len(plan.Env) != 0 {
					t.Errorf("Env = %q, want none for a hand-off launcher", plan.Env)
				}
				if !strings.Contains(plan.WrapNote, "hand-off client") {
					t.Errorf("WrapNote = %q, want the hand-off reason", plan.WrapNote)
				}
			}
		})
	}

	// A row that declares no hand-off segments is never classified as one.
	plain := specExe()
	plan, err := Compose(plain, Inputs{GOOS: "linux", Bin: "/x/remote-cli/code", ProxyURL: "http://127.0.0.1:8820"})
	if err != nil || !plan.WrapApplied {
		t.Fatalf("row without HandoffPathSegments: applied=%v err=%v, want applied", plan.WrapApplied, err)
	}
}
