package crossmount

import (
	"strings"
	"testing"
)

func TestValidEnvNames(t *testing.T) {
	got := validEnvNames([]string{"CODEX_HOME", "CLAUDE_CONFIG_DIR", "bad name", "x;rm", "1ABC", "", "CODEX_HOME", "_OK9"})
	if strings.Join(got, ",") != "CLAUDE_CONFIG_DIR,CODEX_HOME,_OK9" {
		t.Errorf("validEnvNames = %v", got)
	}
}

func TestWindowsEnvScriptQuotesOnlyValidatedNames(t *testing.T) {
	s := windowsEnvScript([]string{"A_B", "CODEX_HOME"})
	if !strings.Contains(s, "@('A_B','CODEX_HOME')") {
		t.Errorf("script = %s", s)
	}
}

func TestParseEnvLines(t *testing.T) {
	out := "CODEX_HOME=D:\\codex\r\nCLAUDE_CONFIG_DIR=\r\nOTHER=x\r\nnoise\n"
	got := parseEnvLines(out, []string{"CODEX_HOME", "CLAUDE_CONFIG_DIR"})
	if len(got) != 1 || got["CODEX_HOME"] != `D:\codex` {
		t.Errorf("parseEnvLines = %v", got)
	}
}

func TestWindowsPersistentEnvWithMemoizes(t *testing.T) {
	calls := 0
	probe := func(script string) (string, bool) {
		calls++
		return "ZZ_TEST_ONE=v1\n", true
	}
	names := []string{"ZZ_TEST_ONE", "ZZ_TEST_TWO"}
	for i := 0; i < 2; i++ {
		got, ok := windowsPersistentEnvWith(names, probe)
		if !ok || got["ZZ_TEST_ONE"] != "v1" || len(got) != 1 {
			t.Fatalf("got %v, %v", got, ok)
		}
	}
	if calls != 1 {
		t.Errorf("probe ran %d times, want 1", calls)
	}
	failing := func(string) (string, bool) { return "", false }
	if _, ok := windowsPersistentEnvWith([]string{"ZZ_TEST_FAIL"}, failing); ok {
		t.Error("a failed probe must report ok=false")
	}
}

// TestWindowsPersistentEnvNeverProbesFromATestBinary pins the testguard
// rule: the exported entry point never runs the probe from a test binary,
// and a nil probe answers not ok.
func TestWindowsPersistentEnvNeverProbesFromATestBinary(t *testing.T) {
	probe := func(string) (string, bool) {
		t.Error("probe ran from a test binary")
		return "", false
	}
	if _, ok := WindowsPersistentEnv([]string{"CODEX_HOME"}, probe); ok {
		t.Error("WindowsPersistentEnv answered from a test binary")
	}
	if _, ok := WindowsPersistentEnv([]string{"CODEX_HOME"}, nil); ok {
		t.Error("a nil probe answered")
	}
}
