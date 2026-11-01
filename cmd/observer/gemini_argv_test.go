// gemini_argv_test.go — hermetic argv-forwarding tests for `observer gemini`
// under the shared DisableFlagParsing + launcherArgsOrDone parser (B6). NO
// gemini binary is spawned: --gemini-path points at a recording stub script
// that dumps its argv to a file and exits 0, so these tests pin the exact
// bytes the wrapper hands to the wrapped tool.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeArgvRecorderStub writes an executable shell script to dir that
// records every argv token it receives, one per line, to outPath, then
// exits 0. It stands in for the `gemini` binary so these tests never spawn
// a real tool — only the argv the launcher hands to exec.Command is
// exercised.
func writeArgvRecorderStub(t *testing.T, dir, outPath string) string {
	t.Helper()
	script := filepath.Join(dir, "stub-gemini.sh")
	o := shellQuote(stubShPath(outPath))
	contents := "#!/bin/sh\n" +
		"rm -f " + o + "\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> " + o + "; done\n" +
		"exit 0\n"
	return writeShellStub(t, script, contents)
}

// shellQuote wraps s in single quotes for safe interpolation into the
// generated shell script (paths here are t.TempDir()-derived and contain no
// single quotes, but this keeps the generator honest regardless).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// readRecordedArgv reads the stub's recorded-argv file and splits it back
// into a []string, one token per line (trailing newline trimmed).
func readRecordedArgv(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read recorded argv %s: %v", path, err)
	}
	trimmed := strings.TrimSuffix(string(data), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// writeGeminiTestConfig writes a minimal config.toml pointing db_path at a
// throwaway file inside dir, sufficient for config.Load in the bare-launch
// path (no daemon, no proxy actually needs to be reachable — runEnvLauncher
// merely warns and continues).
func writeGeminiTestConfig(t *testing.T, dir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// TestGeminiArgvForwardsUnknownFlagsUntouched pins the B6 contract this
// launcher gains from DisableFlagParsing + launcherArgsOrDone: a forwarded
// `-i "custom"` with NO --continue-from reaches the child argv completely
// untouched. Pre-B6 this was IMPOSSIBLE — cobra's normal flag parse rejected
// `-i` outright as an unrecognized shorthand, since this launcher's own
// FlagSet never registers `-i` (that spelling belongs to gemini itself).
func TestGeminiArgvForwardsUnknownFlagsUntouched(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeGeminiTestConfig(t, dir)
	outPath := filepath.Join(dir, "argv.out")
	stub := writeArgvRecorderStub(t, dir, outPath)

	cmd := newGeminiCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--gemini-path", stub,
		"-i", "custom",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, out.String())
	}

	got := readRecordedArgv(t, outPath)
	want := []string{"-i", "custom"}
	if !equalArgs(got, want) {
		t.Fatalf("child argv = %v, want %v", got, want)
	}
}

// TestGeminiArgvForwardsUnknownFlagValuePairInOrder pins that an unrecognized
// long flag (`--model gemini-x`, not one of this launcher's own reserved
// flags) is forwarded to the child in order, exactly as typed.
func TestGeminiArgvForwardsUnknownFlagValuePairInOrder(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeGeminiTestConfig(t, dir)
	outPath := filepath.Join(dir, "argv.out")
	stub := writeArgvRecorderStub(t, dir, outPath)

	cmd := newGeminiCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--gemini-path", stub,
		"--model", "gemini-x",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (stderr=%q)", err, out.String())
	}

	got := readRecordedArgv(t, outPath)
	want := []string{"--model", "gemini-x"}
	if !equalArgs(got, want) {
		t.Fatalf("child argv = %v, want %v", got, want)
	}
}

// TestGeminiContinueFromWithForwardedFlagRejectsLoud pins the other half of
// the B6 contract: WITH --continue-from AND a forwarded `-i custom`, the
// existing promptConflict/injectPrompt reject-loud path in continuefrom.go
// must still fire — the new parser only changes how argv reaches RunE, not
// the two-prompt collision semantics. `-i` is gemini's own seed flag
// (ConflictFlags includes "-i"), so this collides with the seeded handover
// exactly like it did pre-B6.
//
// Fallback note: this does NOT construct a real source session (no DB is
// opened). continueFromArgs (continuefrom.go) checks promptConflict BEFORE
// calling resolveContinueFrom — the (comparatively expensive) handoff
// render that would need one — so an invalid/nonexistent --continue-from id
// still exercises the real reject-loud path end-to-end through the actual
// cobra command, hermetically.
func TestGeminiContinueFromWithForwardedFlagRejectsLoud(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeGeminiTestConfig(t, dir)
	stub := writeArgvRecorderStub(t, dir, filepath.Join(dir, "argv.out"))

	cmd := newGeminiCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--gemini-path", stub,
		"--continue-from", "no-such-session",
		"-i", "custom",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected the forwarded -i to collide with the seeded handover, got nil error")
	}
	if !strings.Contains(err.Error(), "forwarded a prompt") && !strings.Contains(err.Error(), "collides") {
		t.Errorf("error should mention the prompt conflict, got %q", err.Error())
	}
}
