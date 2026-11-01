package hook

import "testing"

// TestParseHookCommandReadsAnUnquotedWindowsPath (Windows 11 Pro live run,
// PT-02, T-725): an unquoted C:\... observer binary in an existing hook
// parsed as "C:Users...observer" (the POSIX tokenizer eats the
// separators), so an equivalent hook read as a non-observer binary and was
// rewritten. The path now parses as the path it is, on every OS.
func TestParseHookCommandReadsAnUnquotedWindowsPath(t *testing.T) {
	cases := []struct {
		cmd, binary, config string
	}{
		{`C:\Users\u\AppData\Local\SuperBased\bin\observer.exe hook claude-code session-start`, `C:/Users/u/AppData/Local/SuperBased/bin/observer.exe`, ""},
		{`C:\old\superbased-observer\bin\observer hook claude-code pre-tool --config 'C:\Users\u\.observer\config.toml'`, `C:/old/superbased-observer/bin/observer`, `C:\Users\u\.observer\config.toml`},
		{`/opt/observer/bin/observer hook claude-code stop`, `/opt/observer/bin/observer`, ""},
	}
	for _, c := range cases {
		inv, ok := parseObserverHookCommand(c.cmd)
		if !ok {
			t.Fatalf("%s: not parsed", c.cmd)
		}
		if inv.binary != c.binary || inv.tool != "claude-code" || !isObserverBinaryToken(inv.binary) {
			t.Errorf("%s: binary %q tool %q, want %q (an observer binary)", c.cmd, inv.binary, inv.tool, c.binary)
		}
		if effectiveHookConfig(inv.config, "") != effectiveHookConfig(c.config, "") {
			t.Errorf("%s: config %q, want %q", c.cmd, inv.config, c.config)
		}
	}
	if !driveLetterPath("C:/x") || !driveLetterPath(`d:\x`) || driveLetterPath("/c/x") || driveLetterPath("C:") {
		t.Fatal("driveLetterPath is wrong")
	}
}
