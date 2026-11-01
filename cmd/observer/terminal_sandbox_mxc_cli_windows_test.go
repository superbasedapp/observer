//go:build windows && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// writeMXCCLIConfig writes a config with the mxc-process driver selected
// and listed.
func writeMXCCLIConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n" +
		"[components]\nadd = [\"" + mxcComponent + "\"]\n" +
		"[terminal.sandbox]\nenabled = true\nbackends = [\"mxc-process\"]\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestMXCCLIRefusesAMissingBundle: with the MXC files missing the CLI
// launch is refused in one line naming the row and the verdict, with exit
// code 3, and nothing runs unsandboxed.
func TestMXCCLIRefusesAMissingBundle(t *testing.T) {
	t.Setenv(sandboxEnvMarker, "")
	countMXCProbes(t, "windows", sandboxmxc.ProbeResult{Verdict: sandboxmxc.Verdict{
		Code: sandboxmxc.VerdictArtifactMissing, Reason: "mxc_ffi.dll is not beside observer.exe",
	}})
	var stderr bytes.Buffer
	code := runSandboxCLI(context.Background(), sandboxCLIRequest{
		Verb: "claude", Tool: "claude-code", Profile: "mxc-process", ConfigPath: writeMXCCLIConfig(t),
	}, &stderr)
	if code != sandboxCLIUnavailable {
		t.Fatalf("exit = %d, want %d: %s", code, sandboxCLIUnavailable, stderr.String())
	}
	out := stderr.String()
	if !strings.Contains(out, "--observer-sandbox") || !strings.Contains(out, "mxc-process") || !strings.Contains(out, "mxc_ffi.dll") {
		t.Fatalf("refusal = %q", out)
	}
}
