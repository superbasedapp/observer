package diag

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// TestCopilotCLIPowerShellDoctorRow pins the FU-166 doctor row end to end
// through the registry: a Windows-native Observer whose own Copilot CLI hooks
// file is the stale bash-only shape gets a FAIL row naming the file, the
// event and the fix; the same file on Linux, and a home without the file,
// get no row.
func TestCopilotCLIPowerShellDoctorRow(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".copilot", "hooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "superbased-observer.json")
	stale := `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"C:/Users/developer/AppData/Local/SuperBased/Observer/bin/observer.exe hook copilot-cli preToolUse","timeoutSec":30}]}}`
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := checkCopilotCLIPowerShell("windows", home, "C:/Users/developer/AppData/Local/SuperBased/Observer/bin/observer.exe", nil)
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want one", rows)
	}
	c := rows[0]
	if c.Name != "copilot-cli.hooks.powershell" || c.Status != StatusFail {
		t.Fatalf("row = %+v, want a FAIL copilot-cli.hooks.powershell", c)
	}
	for _, want := range []string{path, "preToolUse", "powershell", "exits 127", "observer start", "observer init --all"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q does not name %q", c.Message, want)
		}
	}
	if len(c.Remediations) != 2 || c.Remediations[0].Action != remedy.RestartDaemon || c.Remediations[1] != remedy.Of(remedy.InitTool, "copilot-cli") {
		t.Errorf("remediations = %+v", c.Remediations)
	}
	if rows := checkCopilotCLIPowerShell("linux", home, "observer", nil); len(rows) != 0 {
		t.Errorf("linux rows = %+v, want none", rows)
	}
	if rows := checkCopilotCLIPowerShell("windows", t.TempDir(), "observer", nil); len(rows) != 0 {
		t.Errorf("rows without a hooks file = %+v, want none", rows)
	}
}

// TestCopilotCLIPowerShellCheckRendering covers the remaining report shapes.
func TestCopilotCLIPowerShellCheckRendering(t *testing.T) {
	if _, ok := copilotCLIPowerShellCheck(hook.CopilotCLIPowerShellReport{}); ok {
		t.Error("a report that does not apply rendered a row")
	}
	ok := hook.CopilotCLIPowerShellReport{Applies: true, ConfigPath: "C:/h/.copilot/hooks/superbased-observer.json", Registered: []string{"preToolUse", "userPromptSubmitted"}}
	if c, shown := copilotCLIPowerShellCheck(ok); !shown || c.Status != StatusOK {
		t.Errorf("clean report = %+v, %v; want an OK row", c, shown)
	}
	bad := hook.CopilotCLIPowerShellReport{Applies: true, Unreadable: true, ConfigPath: "C:/h/x.json"}
	if c, shown := copilotCLIPowerShellCheck(bad); !shown || c.Status != StatusWarn {
		t.Errorf("unreadable report = %+v, %v; want a WARN row", c, shown)
	}
}

// TestCopilotCLIPowerShellReadsTheDoctorEnv pins FU-173: the row reads
// COPILOT_HOME through the doctor's getenv (DoctorOptions.Getenv), never
// the process environment, and a sandboxed run reads neither.
func TestCopilotCLIPowerShellReadsTheDoctorEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var asked []string
	recording := func(k string) string {
		asked = append(asked, k)
		return ""
	}
	if rows := checkCopilotCLIPowerShell("windows", "", "C:/obs/observer.exe", recording); len(rows) != 0 {
		t.Fatalf("rows for a home with no hooks file = %+v, want none", rows)
	}
	if !slices.Contains(asked, "COPILOT_HOME") {
		t.Errorf("the doctor's getenv was asked %v, want COPILOT_HOME", asked)
	}
	// A process COPILOT_HOME the doctor's getenv does not carry is not read:
	// a relative value (which reads nothing and would render the
	// unreadable WARN) changes no answer.
	t.Setenv("COPILOT_HOME", "relative-copilot-home")
	if rows := checkCopilotCLIPowerShell("windows", "", "C:/obs/observer.exe", func(string) string { return "" }); len(rows) != 0 {
		t.Errorf("rows from the process COPILOT_HOME = %+v, want none", rows)
	}
	// A sandboxed run reads its own home and no environment.
	asked = nil
	if rows := checkCopilotCLIPowerShell("windows", t.TempDir(), "C:/obs/observer.exe", recording); len(rows) != 0 || len(asked) != 0 {
		t.Errorf("sandboxed rows = %+v, asked %v; want none and no variable read", rows, asked)
	}
}

// TestCopilotCLIPowerShellFollowsTheDoctorCopilotHome runs the row end to
// end on a Windows host: the stale file under the doctor's COPILOT_HOME is
// the one named (a POSIX path is not a Windows home, so this needs Windows).
func TestCopilotCLIPowerShellFollowsTheDoctorCopilotHome(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("COPILOT_HOME must be a Windows absolute path for a Windows registry")
	}
	t.Setenv("USERPROFILE", t.TempDir())
	relocated := t.TempDir()
	if err := os.MkdirAll(filepath.Join(relocated, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(relocated, "hooks", "superbased-observer.json")
	stale := `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"C:/obs/observer.exe hook copilot-cli preToolUse","timeoutSec":30}]}}`
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		if k == "COPILOT_HOME" {
			return relocated
		}
		return ""
	}
	rows := checkCopilotCLIPowerShell("windows", "", "C:/obs/observer.exe", env)
	if len(rows) != 1 || rows[0].Status != StatusFail || !strings.Contains(rows[0].Message, path) {
		t.Fatalf("rows = %+v, want one FAIL naming %s", rows, path)
	}
}

// TestCopilotCLIPowerShellFlagsTheWSLBridge (FU-166 tail): on a WSL
// Observer the doctor row reads the copilot-cli-windows bridge in the
// Windows home and fails a bash-only one the same way, naming the bridge.
func TestCopilotCLIPowerShellFlagsTheWSLBridge(t *testing.T) {
	home := t.TempDir()
	winHome := filepath.Join(home, "win")
	dir := filepath.Join(winHome, ".copilot", "hooks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "superbased-observer.json")
	stale := `{"version":1,"hooks":{"preToolUse":[{"type":"command","bash":"MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- /usr/local/bin/observer hook copilot-cli preToolUse","timeoutSec":30}]}}`
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := hook.NewRegistry(hook.Options{BinaryPath: "/usr/local/bin/observer", HomeDir: home, GOOS: "linux", WindowsCopilotHome: winHome, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	rows := copilotCLIPowerShellRows(reg)
	if len(rows) != 1 || rows[0].Name != "copilot-cli.hooks.powershell" || rows[0].Status != StatusFail {
		t.Fatalf("rows = %+v, want one FAIL copilot-cli.hooks.powershell", rows)
	}
	if !strings.Contains(rows[0].Message, path) || !strings.Contains(strings.Join(rows[0].Details, "\n"), "copilot-cli-windows bridge") {
		t.Errorf("row = %+v, want the bridge file and the bridge named", rows[0])
	}
	// The sandboxed doctor entry point resolves no Windows home.
	if rows := checkCopilotCLIPowerShell("linux", home, "/usr/local/bin/observer", nil); len(rows) != 0 {
		t.Errorf("sandboxed linux rows = %+v, want none", rows)
	}
}
