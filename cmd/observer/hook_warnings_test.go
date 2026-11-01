package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestHookResultWarningsRendered: a registration's non-fatal Warnings reach
// both `observer init` (printHookResult) and the `observer start`
// auto-register log (logAutoRegisterWarnings); an errored result prints only
// its error.
func TestHookResultWarningsRendered(t *testing.T) {
	const warn = "VT Code runs hooks with `sh`; sh.exe is not on the Windows PATH"
	res := hook.RegistrationResult{
		Tool: "vtcode-windows", ConfigPath: "/mnt/c/x/vtcode.toml",
		AlreadySet: []string{"PreToolUse"}, Warnings: []string{warn},
	}

	var initOut bytes.Buffer
	printHookResult(&initOut, "vtcode-windows", res, false)
	if !strings.Contains(initOut.String(), "hook ! "+warn) {
		t.Errorf("init output lost the warning:\n%s", initOut.String())
	}

	var startErr bytes.Buffer
	logAutoRegisterWarnings(&startErr, "vtcode-windows", res)
	if got := startErr.String(); got != "WARN auto-register vtcode-windows: "+warn+"\n" {
		t.Errorf("start output = %q", got)
	}

	res.Error = errors.New("boom")
	initOut.Reset()
	startErr.Reset()
	printHookResult(&initOut, "vtcode-windows", res, false)
	logAutoRegisterWarnings(&startErr, "vtcode-windows", res)
	if strings.Contains(initOut.String(), warn) || startErr.Len() != 0 {
		t.Errorf("errored result still rendered warnings: init=%q start=%q", initOut.String(), startErr.String())
	}
}
