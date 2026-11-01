package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
)

// TestFU154ClineDialectBlockIsCancel: the gate the PreToolUse file runs
// answers in the shape Cline CLI reads from a hook file's stdout: a block
// is {"cancel":true,"errorMessage":<reason>}, an allow writes nothing.
func TestFU154ClineDialectBlockIsCancel(t *testing.T) {
	d, ok := toolGateDialects[ToolGateDialectCline]
	if !ok {
		t.Fatal("no cline-pretool dialect")
	}
	out, err := json.Marshal(d.block(guard.Emission{Permission: "deny", Enforced: true, Reason: "fake gate deny"}, "PreToolUse"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"cancel":true,"errorMessage":"fake gate deny"}` {
		t.Errorf("block = %s", out)
	}
	if !d.silentAllow || d.allow != nil {
		t.Errorf("allow must write nothing (silentAllow %v, allow %v)", d.silentAllow, d.allow)
	}
}

// TestFU154ClineGateFileRunsObserversGate runs the written PreToolUse file
// end to end against a stub `observer` (POSIX): the payload reaches the
// gate on stdin, the argv is `hook cline-cli PreToolUse --config <cfg>`, and
// the gate's stdout (a cancel, or nothing) is the file's stdout.
func TestFU154ClineGateFileRunsObserversGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Cline gate file is a POSIX script (no Windows target)")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	home := t.TempDir()
	dir := t.TempDir()
	argvLog := filepath.Join(dir, "argv")
	stub := filepath.Join(dir, "observer")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvLog + "\n" +
		"if grep -q mac-tool-deny; then printf '{\"cancel\":true,\"errorMessage\":\"stub deny\"}'; fi\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil { //nolint:gosec // test stub executable
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".cline"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.toml")
	r, err := NewRegistry(Options{
		BinaryPath: stub, ConfigPath: cfg, HomeDir: home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cline-cli"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	gate := filepath.Join(home, ".cline", "hooks", "PreToolUse")
	for _, tc := range []struct{ payload, want string }{
		{`{"taskId":"t1","preToolUse":{"toolName":"execute_command","parameters":{"command":"echo mac-tool-deny"}}}`, `{"cancel":true,"errorMessage":"stub deny"}`},
		{`{"taskId":"t1","preToolUse":{"toolName":"execute_command","parameters":{"command":"ls"}}}`, ""},
	} {
		cmd := exec.Command(gate)
		cmd.Stdin = strings.NewReader(tc.payload)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("run gate file: %v", err)
		}
		if out.String() != tc.want {
			t.Errorf("stdout = %q, want %q", out.String(), tc.want)
		}
		argv, _ := os.ReadFile(argvLog)
		if got := strings.Fields(string(argv)); strings.Join(got, " ") != "hook cline-cli PreToolUse --config "+cfg {
			t.Errorf("argv = %q", got)
		}
	}
	if un := r.Unregister("cline-cli"); un.Error != nil {
		t.Fatalf("Unregister: %v", un.Error)
	}
	if _, err := os.Stat(gate); !os.IsNotExist(err) {
		t.Errorf("Unregister left the gate file: %v", err)
	}
}
