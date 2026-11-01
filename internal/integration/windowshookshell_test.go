package integration

import (
	"strings"
	"testing"
)

// TestWindowsHookShellRowsAreGrounded pins which rows declare a Windows hook
// shell. A row joins only with a grounding (vendor version + source); VT Code
// is the one grounded today (Command::new("sh") in vtcode-core 0.180.2).
func TestWindowsHookShellRowsAreGrounded(t *testing.T) {
	got := WindowsHookShellTools()
	if strings.Join(got, ",") != "vtcode" {
		t.Fatalf("WindowsHookShellTools() = %v, want [vtcode]", got)
	}
	for _, tool := range got {
		req, ok := WindowsHookShellFor(tool)
		if !ok || req.Shell == "" || req.Grounding == "" || req.Fix == "" {
			t.Errorf("%s: requirement %+v must carry Shell, Fix and Grounding", tool, req)
		}
		c, _ := For(tool)
		if c.Hook.Mechanism == HookNone {
			t.Errorf("%s: a Windows hook shell on a row with no hook mechanism", tool)
		}
	}
}

func TestWindowsHookShellFor(t *testing.T) {
	cases := []struct {
		tool string
		want bool
	}{
		{"vtcode", true},
		{"vtcode-windows", true},
		{"codebuddy", false},
		{"codebuddy-windows", false},
		{"claude-code", false},
		{"no-such-tool", false},
	}
	for _, tc := range cases {
		req, ok := WindowsHookShellFor(tc.tool)
		if ok != tc.want {
			t.Errorf("WindowsHookShellFor(%q) ok = %v, want %v", tc.tool, ok, tc.want)
		}
		if ok && req.Shell != "sh" {
			t.Errorf("WindowsHookShellFor(%q).Shell = %q, want sh", tc.tool, req.Shell)
		}
	}
}

func TestWindowsHookShellWarning(t *testing.T) {
	for _, tool := range []string{"vtcode", "vtcode-windows"} {
		msg := WindowsHookShellWarning(tool)
		for _, want := range []string{"VT Code runs hooks with `sh`", "sh.exe is not on the Windows PATH", "outside Git Bash", `C:\Program Files\Git\bin`} {
			if !strings.Contains(msg, want) {
				t.Errorf("WindowsHookShellWarning(%q) = %q, missing %q", tool, msg, want)
			}
		}
	}
	if msg := WindowsHookShellWarning("claude-code"); msg != "" {
		t.Errorf("WindowsHookShellWarning(claude-code) = %q, want empty", msg)
	}
}

// TestWindowsHookRunnerRows pins the Windows hook-runner rows: each names a
// registry row with a hook mechanism and a Windows bridge, carries a Kind
// from the closed set with the fields that Kind needs, a Fix and a
// Grounding, and is the only Windows precondition its tool declares (one
// owner per tool: not also a HookSpec.WindowsHookShell row).
func TestWindowsHookRunnerRows(t *testing.T) {
	got := WindowsHookRunners()
	var tools []string
	for _, r := range got {
		tools = append(tools, r.Tool)
	}
	if strings.Join(tools, ",") != "codebuddy,dirac" {
		t.Fatalf("WindowsHookRunners() tools = %v, want [codebuddy dirac]", tools)
	}
	seen := map[string]bool{}
	for _, r := range got {
		if seen[r.Tool] {
			t.Errorf("%s: declared twice", r.Tool)
		}
		seen[r.Tool] = true
		c, ok := For(r.Tool)
		if !ok {
			t.Errorf("%s: not a registry row", r.Tool)
			continue
		}
		if c.Hook.Mechanism == HookNone || !c.Hook.CrossOSBridge {
			t.Errorf("%s: a Windows hook runner on a row with no hook mechanism or no Windows bridge", r.Tool)
		}
		if c.Hook.WindowsHookShell.Required() {
			t.Errorf("%s: declares both HookSpec.WindowsHookShell and a WindowsHookRunner", r.Tool)
		}
		// The registry row is the one owner: the accessor reads
		// HookSpec.WindowsRunner, and the row never names its own tool.
		if c.Hook.WindowsRunner.Kind != r.Kind {
			t.Errorf("%s: accessor Kind %q, HookSpec.WindowsRunner.Kind %q", r.Tool, r.Kind, c.Hook.WindowsRunner.Kind)
		}
		if c.Hook.WindowsRunner.Tool != "" {
			t.Errorf("%s: HookSpec.WindowsRunner.Tool = %q; the accessor fills it, the row leaves it empty", r.Tool, c.Hook.WindowsRunner.Tool)
		}
		if r.Fix == "" || r.Grounding == "" {
			t.Errorf("%s: row %+v must carry Fix and Grounding", r.Tool, r)
		}
		switch r.Kind {
		case RunnerPowerShellScript:
			if len(r.PowerShell) == 0 {
				t.Errorf("%s: a PowerShell script runner names no PowerShell executable", r.Tool)
			}
		case RunnerGitBash:
			if r.EnvOverride == "" {
				t.Errorf("%s: a Git Bash runner names no environment override", r.Tool)
			}
		default:
			t.Errorf("%s: Kind %q is not in the closed set", r.Tool, r.Kind)
		}
		switch r.OnFailure {
		case FailureUnverified, FailureOpen:
		default:
			t.Errorf("%s: OnFailure %q is not in the closed set", r.Tool, r.OnFailure)
		}
	}
}

func TestWindowsHookRunnerFor(t *testing.T) {
	cases := []struct {
		tool     string
		wantOK   bool
		wantKind WindowsHookRunnerKind
	}{
		{"dirac", true, RunnerPowerShellScript},
		{"dirac-windows", true, RunnerPowerShellScript},
		{"codebuddy", true, RunnerGitBash},
		{"codebuddy-windows", true, RunnerGitBash},
		{"vtcode", false, ""},
		{"claude-code", false, ""},
		{"no-such-tool", false, ""},
	}
	for _, tc := range cases {
		r, ok := WindowsHookRunnerFor(tc.tool)
		if ok != tc.wantOK || r.Kind != tc.wantKind {
			t.Errorf("WindowsHookRunnerFor(%q) = %+v, %v; want kind %q ok %v", tc.tool, r, ok, tc.wantKind, tc.wantOK)
		}
	}
	// Dirac passes -ExecutionPolicy Bypass and fails open (grounded).
	if r, _ := WindowsHookRunnerFor("dirac"); !r.BypassArg || r.OnFailure != FailureOpen {
		t.Errorf("dirac row = %+v, want BypassArg and FailureOpen", r)
	}
	// A returned row is a copy.
	r, _ := WindowsHookRunnerFor("dirac")
	r.PowerShell[0] = "edited"
	if again, _ := WindowsHookRunnerFor("dirac"); again.PowerShell[0] == "edited" {
		t.Error("WindowsHookRunnerFor returned the table's own slice")
	}
}
