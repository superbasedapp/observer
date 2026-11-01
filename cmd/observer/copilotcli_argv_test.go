// copilotcli_argv_test.go — hermetic argv/env-forwarding tests for
// `observer copilot-cli` under the shared DisableFlagParsing +
// launcherArgsOrDone parser (B6). NO copilot binary is spawned:
// --copilot-path points at a recording stub script that dumps its argv AND
// its environment to files and exits 0, so these tests pin exactly what the
// wrapper hands to the wrapped tool.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeArgvEnvRecorderStub writes an executable shell script to dir that
// records every argv token (one per line) to argvPath and the full child
// environment (one `KEY=value` per line, via `env`) to envPath, then exits
// 0. It stands in for the `copilot` binary so these tests never spawn a
// real tool.
func writeArgvEnvRecorderStub(t *testing.T, dir, argvPath, envPath string) string {
	t.Helper()
	script := filepath.Join(dir, "stub-copilot.sh")
	a, e := shellQuote(stubShPath(argvPath)), shellQuote(stubShPath(envPath))
	contents := "#!/bin/sh\n" +
		"rm -f " + a + " " + e + "\n" +
		"touch " + a + "\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> " + a + "; done\n" +
		"env > " + e + "\n" +
		"exit 0\n"
	return writeShellStub(t, script, contents)
}

// writeCopilotCLITestConfig writes a minimal config.toml pointing db_path at
// a throwaway file inside dir, sufficient for config.Load in the bare-launch
// path.
func writeCopilotCLITestConfig(t *testing.T, dir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "config.toml")
	// ToSlash: a Windows path in a TOML basic string would read "\U" as an
	// escape.
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// The launch gates open this DB; a migrated copy keeps each launch from
	// replaying the migration chain.
	preseedMigratedDB(t, filepath.Join(dir, "observer.db"))
	return cfgPath
}

// readRecordedEnvValue scans a `KEY=value` per-line env dump (as produced by
// the stub's `env >`) and returns the value for key, or "" plus false if
// absent. A key can legitimately appear once; this returns the FIRST match
// (env output has no duplicates).
func readRecordedEnvValue(t *testing.T, path, key string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read recorded env %s: %v", path, err)
	}
	prefix := key + "="
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix), true
		}
	}
	return "", false
}

// TestCopilotCLIModelIsReservedNotForwarded pins that `--model gpt-4` is
// wrapper-RESERVED on this launcher (registered on its own FlagSet as a
// StringVar, consumed by splitLauncherArgs): it must NOT appear in the
// child's argv, and instead sets COPILOT_MODEL in the child environment —
// the existing BYOK behavior preserved unchanged through the new
// DisableFlagParsing + launcherArgsOrDone parser.
func TestCopilotCLIModelIsReservedNotForwarded(t *testing.T) {
	requireComponents(t, "capture.proxy")
	dir := t.TempDir()
	cfgPath := writeCopilotCLITestConfig(t, dir)
	argvPath := filepath.Join(dir, "argv.out")
	envPath := filepath.Join(dir, "env.out")
	stub := writeArgvEnvRecorderStub(t, dir, argvPath, envPath)
	t.Setenv("COPILOT_PROVIDER_API_KEY", "test-key-not-a-secret")

	cmd := newCopilotCLICmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--copilot-path", stub,
		"--model", "gpt-4",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, out.String())
	}

	gotArgv := readRecordedArgv(t, argvPath)
	if len(gotArgv) != 0 {
		t.Fatalf("child argv = %v, want empty (--model must be consumed by the wrapper, not forwarded)", gotArgv)
	}
	gotModel, ok := readRecordedEnvValue(t, envPath, "COPILOT_MODEL")
	if !ok {
		t.Fatal("COPILOT_MODEL not set in child env")
	}
	if gotModel != "gpt-4" {
		t.Fatalf("COPILOT_MODEL = %q, want %q", gotModel, "gpt-4")
	}
}

// TestCopilotCLIUnknownFlagIsForwarded pins that an unrecognized flag
// (`--foo bar`, not one of this launcher's own reserved flags) reaches the
// child argv untouched — the DisableFlagParsing + launcherArgsOrDone
// contract every launcher gains from B6.
func TestCopilotCLIUnknownFlagIsForwarded(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeCopilotCLITestConfig(t, dir)
	argvPath := filepath.Join(dir, "argv.out")
	envPath := filepath.Join(dir, "env.out")
	stub := writeArgvEnvRecorderStub(t, dir, argvPath, envPath)
	t.Setenv("COPILOT_PROVIDER_API_KEY", "test-key-not-a-secret")
	// A routed BYOK launch needs an explicit model (copilot help providers);
	// without one the launcher refuses before copilot starts.
	t.Setenv("COPILOT_MODEL", "gpt-4o")

	cmd := newCopilotCLICmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--copilot-path", stub,
		"--foo", "bar",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, out.String())
	}

	got := readRecordedArgv(t, argvPath)
	want := []string{"--foo", "bar"}
	if !equalArgs(got, want) {
		t.Fatalf("child argv = %v, want %v", got, want)
	}
}
