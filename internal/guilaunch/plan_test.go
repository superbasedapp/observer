package guilaunch

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// specExe is a synthetic GUI row that launches a plain executable and takes a
// project directory, wrapped through the child environment. The rows here are
// deliberately SYNTHETIC (never a live registry lookup) so this table pins the
// composition rules, not the current contents of the registry.
func specExe() integration.GUILaunchSpec {
	return integration.GUILaunchSpec{
		ID:             "editor",
		Label:          "Editor",
		Surface:        "ide",
		ProjectDirArgv: true,
		Wrap: integration.WrapSpec{
			Kind: integration.WrapChildEnv,
			Env: []integration.WrapEnvVar{
				{Name: "ANTHROPIC_BASE_URL"},
				{Name: "OPENAI_BASE_URL", Suffix: "/v1"},
			},
		},
	}
}

func TestComposeArgvMechanisms(t *testing.T) {
	t.Parallel()

	bundleSpec := integration.GUILaunchSpec{ID: "editor", DarwinApp: "Editor", ProjectDirArgv: true}
	bundleNoDir := integration.GUILaunchSpec{ID: "desk", DarwinApp: "Desk"}
	aumidSpec := integration.GUILaunchSpec{ID: "packaged", AppsFolderAUMID: "Vendor_abc!App"}

	tests := []struct {
		name     string
		spec     integration.GUILaunchSpec
		in       Inputs
		wantArgv []string
	}{
		{
			name:     "executable without a project dir",
			spec:     specExe(),
			in:       Inputs{GOOS: "linux", Bin: "/usr/bin/editor"},
			wantArgv: []string{"/usr/bin/editor"},
		},
		{
			name:     "executable with a project dir",
			spec:     specExe(),
			in:       Inputs{GOOS: "linux", Bin: "/usr/bin/editor", ProjectRoot: "/home/u/p"},
			wantArgv: []string{"/usr/bin/editor", "/home/u/p"},
		},
		{
			name: "row that takes no project dir ignores one",
			spec: func() integration.GUILaunchSpec {
				s := specExe()
				s.ProjectDirArgv = false
				return s
			}(),
			in:       Inputs{GOOS: "linux", Bin: "/usr/bin/editor", ProjectRoot: "/home/u/p"},
			wantArgv: []string{"/usr/bin/editor"},
		},
		{
			name:     "darwin bundle resolved as a .app directory",
			spec:     bundleSpec,
			in:       Inputs{GOOS: "darwin", Bin: "/Applications/Editor.app", ProjectRoot: "/Users/u/p"},
			wantArgv: []string{"open", "-a", "Editor", "--args", "/Users/u/p"},
		},
		{
			name:     "darwin bundle resolved, row takes no project dir",
			spec:     bundleNoDir,
			in:       Inputs{GOOS: "darwin", Bin: "/Applications/Desk.app", ProjectRoot: "/Users/u/p"},
			wantArgv: []string{"open", "-a", "Desk"},
		},
		{
			name:     "darwin with a real executable prefers the exe",
			spec:     bundleSpec,
			in:       Inputs{GOOS: "darwin", Bin: "/usr/local/bin/editor", ProjectRoot: "/Users/u/p"},
			wantArgv: []string{"/usr/local/bin/editor", "/Users/u/p"},
		},
		{
			name:     "windows packaged app",
			spec:     aumidSpec,
			in:       Inputs{GOOS: "windows"},
			wantArgv: []string{"explorer.exe", `shell:AppsFolder\Vendor_abc!App`},
		},
		{
			name:     "windows packaged app with a resolved exe prefers the exe",
			spec:     aumidSpec,
			in:       Inputs{GOOS: "windows", Bin: `C:\App\App.exe`},
			wantArgv: []string{`C:\App\App.exe`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plan, err := Compose(tc.spec, tc.in)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if !reflect.DeepEqual(plan.Argv, tc.wantArgv) {
				t.Errorf("argv = %q, want %q", plan.Argv, tc.wantArgv)
			}
		})
	}
}

// TestComposePackagedAppNotesTheStubPID pins the honesty note for the
// explorer-launched packaged-app mechanism: the pid and exit code the run row
// records belong to the launcher stub, not the application (live-verified
// 2026-09-03 — explorer exited 1 within a second while the app ran on). The
// note rides the MECHANISM, so it appears for any AUMID row and for no other.
func TestComposePackagedAppNotesTheStubPID(t *testing.T) {
	t.Parallel()
	spec := integration.GUILaunchSpec{ID: "packaged", AppsFolderAUMID: "Vendor_abc!App"}
	plan, err := Compose(spec, Inputs{GOOS: "windows"})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !hasNote(plan.Notes, "launcher stub") {
		t.Errorf("notes = %q, want the stub-pid note", plan.Notes)
	}

	// The same row resolved to a real executable is a normal exec — no stub,
	// so no note.
	plan, err = Compose(spec, Inputs{GOOS: "windows", Bin: `C:\App\App.exe`})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if hasNote(plan.Notes, "launcher stub") {
		t.Errorf("notes = %q, want no stub note when a real executable resolved", plan.Notes)
	}
}

// TestComposeDarwinBundleNotesTheStubPID pins the same caveat for the macOS
// bundle mechanism: `open -a` returns the launcher's pid/exit, not the app's.
// A darwin row that resolved to a real executable is a plain exec and carries
// no such note.
func TestComposeDarwinBundleNotesTheStubPID(t *testing.T) {
	t.Parallel()
	spec := integration.GUILaunchSpec{ID: "desk", DarwinApp: "Desk"}
	plan, err := Compose(spec, Inputs{GOOS: "darwin", Bin: "/Applications/Desk.app"})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !hasNote(plan.Notes, "open(1) launcher") {
		t.Errorf("notes = %q, want the open(1) stub-pid note", plan.Notes)
	}
	plan, err = Compose(spec, Inputs{GOOS: "darwin", Bin: "/usr/local/bin/desk"})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if hasNote(plan.Notes, "launcher") {
		t.Errorf("notes = %q, want no stub note for a real executable", plan.Notes)
	}
}

// hasNote reports whether any note contains sub.
func hasNote(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func TestComposeIgnoredProjectDirIsNoted(t *testing.T) {
	t.Parallel()
	spec := specExe()
	spec.ProjectDirArgv = false
	plan, err := Compose(spec, Inputs{GOOS: "linux", Bin: "/usr/bin/editor", ProjectRoot: "/p", ProxyURL: "http://127.0.0.1:8820"})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if len(plan.Notes) != 1 || !strings.Contains(plan.Notes[0], "takes no project-directory argument") {
		t.Errorf("notes = %q, want the ignored-directory advisory", plan.Notes)
	}
	// The ignored directory must not suppress the wrap.
	if !plan.WrapApplied {
		t.Errorf("wrap_applied = false, want true (an ignored dir is unrelated to the wrap)")
	}
}

func TestComposeWrapTable(t *testing.T) {
	t.Parallel()

	const proxy = "http://127.0.0.1:8820"
	coldSpec := func() integration.GUILaunchSpec {
		s := specExe()
		s.Wrap.ColdStartOnly = true
		return s
	}

	tests := []struct {
		name        string
		spec        integration.GUILaunchSpec
		in          Inputs
		wantApplied bool
		wantEnv     []string
		wantNote    string // substring
	}{
		{
			name:        "child env applies both variables with suffixes",
			spec:        specExe(),
			in:          Inputs{GOOS: "linux", Bin: "/b", ProxyURL: proxy},
			wantApplied: true,
			wantEnv:     []string{"ANTHROPIC_BASE_URL=" + proxy, "OPENAI_BASE_URL=" + proxy + "/v1"},
		},
		{
			name:        "cold-start-only qualifies an applied wrap",
			spec:        coldSpec(),
			in:          Inputs{GOOS: "linux", Bin: "/b", ProxyURL: proxy},
			wantApplied: true,
			wantEnv:     []string{"ANTHROPIC_BASE_URL=" + proxy, "OPENAI_BASE_URL=" + proxy + "/v1"},
			wantNote:    "cold-start only",
		},
		{
			name:        "interop launch cannot propagate the environment",
			spec:        specExe(),
			in:          Inputs{GOOS: "linux", Bin: "/mnt/c/App/Code.exe", ProxyURL: proxy, ViaInterop: true},
			wantApplied: false,
			wantNote:    "WSLENV not set",
		},
		{
			name:        "cold-start note still rides an unapplied interop wrap",
			spec:        coldSpec(),
			in:          Inputs{GOOS: "linux", Bin: "/mnt/c/App/Code.exe", ProxyURL: proxy, ViaInterop: true},
			wantApplied: false,
			wantNote:    "cold-start only",
		},
		{
			name: "explorer-launched packaged app inherits no environment",
			spec: func() integration.GUILaunchSpec {
				s := specExe()
				s.AppsFolderAUMID = "Vendor_abc!App"
				return s
			}(),
			in:          Inputs{GOOS: "windows", ProxyURL: proxy},
			wantApplied: false,
			wantNote:    "inherits no environment",
		},
		{
			name:        "no proxy url resolved",
			spec:        specExe(),
			in:          Inputs{GOOS: "linux", Bin: "/b"},
			wantApplied: false,
			wantNote:    "no observer proxy URL resolved",
		},
		{
			name: "child env row with no declared variables",
			spec: func() integration.GUILaunchSpec {
				s := specExe()
				s.Wrap.Env = nil
				return s
			}(),
			in:          Inputs{GOOS: "linux", Bin: "/b", ProxyURL: proxy},
			wantApplied: false,
			wantNote:    "no routing variables are declared",
		},
		{
			name: "config write names the config-lane writer",
			spec: integration.GUILaunchSpec{
				ID:   "desk",
				Wrap: integration.WrapSpec{Kind: integration.WrapConfigWrite, ConfigTool: "opencode"},
			},
			in:          Inputs{GOOS: "linux", Bin: "/b", ProxyURL: proxy},
			wantApplied: false,
			wantNote:    "written by the opencode config-lane writer",
		},
		{
			name: "wrap none carries the grounded reason",
			spec: integration.GUILaunchSpec{
				ID:   "ide",
				Wrap: integration.WrapSpec{Kind: integration.WrapNone, Reason: "native backend is hard-wired"},
			},
			in:          Inputs{GOOS: "linux", Bin: "/b", ProxyURL: proxy},
			wantApplied: false,
			wantNote:    "native backend is hard-wired",
		},
		{
			name:        "wrap none with no reason falls back to the honest floor",
			spec:        integration.GUILaunchSpec{ID: "ide"},
			in:          Inputs{GOOS: "linux", Bin: "/b", ProxyURL: proxy},
			wantApplied: false,
			wantNote:    "no grounded base-URL mechanism",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plan, err := Compose(tc.spec, tc.in)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if plan.WrapApplied != tc.wantApplied {
				t.Errorf("wrap_applied = %v, want %v (note %q)", plan.WrapApplied, tc.wantApplied, plan.WrapNote)
			}
			if tc.wantEnv == nil {
				if len(plan.Env) != 0 {
					t.Errorf("env = %q, want none for an unapplied wrap", plan.Env)
				}
			} else if !reflect.DeepEqual(plan.Env, tc.wantEnv) {
				t.Errorf("env = %q, want %q", plan.Env, tc.wantEnv)
			}
			if tc.wantNote != "" && !strings.Contains(plan.WrapNote, tc.wantNote) {
				t.Errorf("wrap_note = %q, want it to contain %q", plan.WrapNote, tc.wantNote)
			}
		})
	}
}

func TestComposeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec integration.GUILaunchSpec
		in   Inputs
		want error
	}{
		{
			name: "nothing to launch",
			spec: integration.GUILaunchSpec{ID: "ghost"},
			in:   Inputs{GOOS: "linux"},
			want: ErrNoLaunchMechanism,
		},
		{
			name: "aumid on a non-windows daemon is not a mechanism",
			spec: integration.GUILaunchSpec{ID: "packaged", AppsFolderAUMID: "Vendor_abc!App"},
			in:   Inputs{GOOS: "linux"},
			want: ErrNoLaunchMechanism,
		},
		{
			// A not_found resolution on darwin is a REFUSAL, never a 200 that
			// hands `open -a` a name nothing on the machine answers to.
			name: "darwin bundle with nothing resolved is refused",
			spec: integration.GUILaunchSpec{ID: "desk", DarwinApp: "Desk"},
			in:   Inputs{GOOS: "darwin"},
			want: ErrNoLaunchMechanism,
		},
		{
			name: "darwin bundle on a non-darwin daemon is not a mechanism",
			spec: integration.GUILaunchSpec{ID: "desk", DarwinApp: "Desk"},
			in:   Inputs{GOOS: "windows"},
			want: ErrNoLaunchMechanism,
		},
		{
			name: "non-http proxy url",
			spec: specExe(),
			in:   Inputs{GOOS: "linux", Bin: "/b", ProxyURL: "ftp://127.0.0.1:8820"},
			want: ErrProxyURLInvalid,
		},
		{
			name: "bare host proxy url",
			spec: specExe(),
			in:   Inputs{GOOS: "linux", Bin: "/b", ProxyURL: "127.0.0.1:8820"},
			want: ErrProxyURLInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Compose(tc.spec, tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestComposeHTTPSProxyAccepted pins that the URL guard is a scheme check, not
// an http-only check: an operator fronting the proxy with TLS must not be
// refused.
func TestComposeHTTPSProxyAccepted(t *testing.T) {
	t.Parallel()
	plan, err := Compose(specExe(), Inputs{GOOS: "linux", Bin: "/b", ProxyURL: "https://proxy.local:8820"})
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !plan.WrapApplied || plan.Env[0] != "ANTHROPIC_BASE_URL=https://proxy.local:8820" {
		t.Errorf("env = %q applied=%v, want the https URL injected", plan.Env, plan.WrapApplied)
	}
}
