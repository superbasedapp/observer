package hook

import "testing"

// TestIsObserverHookCommand: the any-tool recogniser accepts every shape
// Observer registers (native, quoted Windows, the cross-OS bridge) for any
// tool token, and refuses a foreign command that merely mentions a hook.
func TestIsObserverHookCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"/usr/local/bin/observer hook claude-code pre-tool --config '/home/u/.observer/config.toml'", true},
		{"/home/u/bin/observer hook codex PreToolUse", true},
		{`C:\Users\u\observer.exe hook cursor stop --config C:\Users\u\.observer\config.toml`, true},
		{"MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu -- /home/u/observer hook gemini-cli BeforeTool", true},
		{"/opt/acme/audit --note \"run hook cursor stop\"", false},
		{"node ~/.cache/x/run.js", false},
		{"/usr/local/bin/observer statusline", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsObserverHookCommand(c.cmd); got != c.want {
			t.Errorf("IsObserverHookCommand(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
	if !IsObserverStatuslineCommand("/usr/local/bin/observer statusline") || IsObserverStatuslineCommand("node x.js statusline") {
		t.Fatal("status line recogniser")
	}
}
