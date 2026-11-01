package diag

import (
	"strings"
	"testing"
)

func TestWindowsRelocationCheck(t *testing.T) {
	c, ok := windowsRelocationCheck([]string{"codex-windows", "cline-windows"}, map[string]string{"CODEX_HOME": `D:\secret-ish\codex`, "CLINE_DIR": `E:\c`}, true)
	if !ok || c.Status != StatusWarn || c.Name != "crossos.windows_env" {
		t.Fatalf("check = %+v, %v", c, ok)
	}
	if !strings.Contains(c.Message, "CLINE_DIR, CODEX_HOME") {
		t.Errorf("message = %q", c.Message)
	}
	for _, line := range append([]string{c.Message}, c.Details...) {
		if strings.Contains(line, `D:\`) || strings.Contains(line, `E:\`) {
			t.Errorf("a value leaked into %q", line)
		}
	}
	if !strings.Contains(c.Details[0], "cline-windows, codex-windows") {
		t.Errorf("details = %v", c.Details)
	}
	for _, tc := range []struct {
		name    string
		targets []string
		vals    map[string]string
		ok      bool
	}{
		{"unreadable", []string{"codex-windows"}, nil, false},
		{"nothing set", []string{"codex-windows"}, map[string]string{}, true},
		{"no targets", nil, map[string]string{"CODEX_HOME": "x"}, true},
	} {
		if _, got := windowsRelocationCheck(tc.targets, tc.vals, tc.ok); got {
			t.Errorf("%s: reported a row", tc.name)
		}
	}
	if got := windowsTargets([]string{"codex", "codex-windows", "cline-windows", "claude-code-wsl"}); strings.Join(got, ",") != "codex-windows,cline-windows" {
		t.Errorf("windowsTargets = %v", got)
	}
}

func TestCheckWindowsSideRelocationSandboxed(t *testing.T) {
	if _, ok := checkWindowsSideRelocation(t.TempDir(), "/x/observer"); ok {
		t.Error("a sandboxed run reported a row")
	}
}
