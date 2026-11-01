package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
)

// TestFU185ExplicitConfigMissingOrUnreadable pins FU-185 (orchestrator
// ruling 2026-10-29): a gate hook given an explicit --config that names a
// missing or unreadable file is a "cannot evaluate" case. Under guard
// enforcement it fails closed with the internal-error reason (the
// hookFailClosed KindConfig path, docs/guard.md "Hook failure semantics");
// with enforcement off a missing file is said on stderr and the hook runs on
// the defaults and approves, as before. One row per posture and failure, for
// each gate receiver shape (Claude Code's own pre-tool and prompt receivers,
// the binding-driven tool gate through Cursor). The payloads are allowed
// calls, so a block is the config failure's, never a rule's.
func TestFU185ExplicitConfigMissingOrUnreadable(t *testing.T) {
	claudeBash := func(dir string) string {
		return fmt.Sprintf(`{"session_id":"s1","cwd":%q,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo fu185-ok"}}`, dir)
	}
	claudePrompt := func(dir string) string {
		return fmt.Sprintf(`{"session_id":"s1","cwd":%q,"hook_event_name":"UserPromptSubmit","prompt":"hello there"}`, dir)
	}
	cursorShell := func(dir string) string {
		return fmt.Sprintf(`{"conversation_id":"s1","generation_id":"g1","hook_event_name":"beforeShellExecution","command":"echo fu185-ok","cwd":%q,"workspace_roots":[%q]}`, dir, dir)
	}
	receivers := []struct {
		tool, event string
		payload     func(dir string) string
	}{
		{"claude-code", "pre-tool", claudeBash},
		{"claude-code", "user-prompt-submit", claudePrompt},
		{"cursor", "beforeShellExecution", cursorShell},
	}
	rows := []struct {
		name      string
		enforced  bool
		config    func(t *testing.T, dir string) string
		wantBlock bool
		// wantWarn is the stderr line that says the hook ran on the
		// defaults ("" for none).
		wantWarn string
	}{
		{"enforcing, missing", true, missingConfig, true, ""},
		{"enforcing, unreadable", true, unreadableConfig, true, ""},
		{"not enforcing, missing", false, missingConfig, false, "does not exist; running on the defaults"},
		// w12 row 9: an explicit config that exists but cannot be read or
		// parsed is said on stderr and the hook runs on the defaults, as
		// for a missing one, in every receiver.
		{"not enforcing, unreadable", false, unreadableConfig, false, "could not be read or parsed; running on the defaults"},
		{"not enforcing, unparseable", false, unparseableConfig, false, "could not be read or parsed; running on the defaults"},
	}
	const reason = "Observer could not evaluate this call because of an internal error"
	for _, rc := range receivers {
		for _, row := range rows {
			t.Run(rc.tool+" "+rc.event+"/"+row.name, func(t *testing.T) {
				dir := t.TempDir()
				home := filepath.Join(dir, "home")
				if err := os.MkdirAll(home, 0o755); err != nil {
					t.Fatal(err)
				}
				setTestHome(t, home)
				cp := row.config(t, dir)
				if row.enforced {
					writePosture(t, cp, enforcedPosture)
				} else {
					writePosture(t, cp, guardposture.Posture{Enforced: false, Source: guardposture.SourceLocal})
				}
				event := canonicalHookEvent(rc.tool, rc.event)
				h := newFailureHarness(t, resolveHookFailurePlan(rc.tool, event, cp))
				stderr := captureStderrT(t, func() {
					withStdinT(t, rc.payload(dir), func() { fu161Dispatch(rc.tool, event, cp) })
				})
				out := h.stdout.String()
				exited := false
				for _, c := range h.exitCodes() {
					exited = exited || c != 0
				}
				// The fail-closed line, or (an exit-code dialect, whose
				// stderr is the block reason) a nonzero exit with the reason.
				blocked := strings.Contains(stderr, "failed closed (config)") || exited && strings.Contains(stderr, reason)
				if blocked != row.wantBlock {
					t.Fatalf("failed closed = %v, want %v\nstdout: %s\nstderr: %s\nexits: %v", blocked, row.wantBlock, out, stderr, h.exitCodes())
				}
				if allowed := fu185Allowed(out) && !exited; allowed == row.wantBlock {
					t.Errorf("answer %q: allowed = %v with a block wanted = %v", out, allowed, row.wantBlock)
				}
				// A dialect with a reason field carries the fixed reason
				// (Cursor's beforeShellExecution block has none).
				if row.wantBlock && rc.tool == "claude-code" && !strings.Contains(out+stderr, reason) {
					t.Errorf("the block carries no reason:\nstdout: %s\nstderr: %s", out, stderr)
				}
				warned := strings.Contains(stderr, "running on the defaults")
				if warned != (row.wantWarn != "") || row.wantWarn != "" && !strings.Contains(stderr, row.wantWarn) {
					t.Errorf("stderr warning = %v, want %q:\n%s", warned, row.wantWarn, stderr)
				}
			})
		}
	}
}

// fu185Allowed reports an answer that lets the call through: an approve,
// an allow, or a continue with no block or deny in it.
func fu185Allowed(out string) bool {
	if strings.Contains(out, `"deny"`) || strings.Contains(out, `"block"`) {
		return false
	}
	return true
}

// missingConfig is an explicit --config path that names no file.
func missingConfig(_ *testing.T, dir string) string {
	return filepath.Join(dir, "no-such.toml")
}

// unreadableConfig is an explicit --config path that cannot be read (a
// directory: a chmod would not stop a test running as root).
func unreadableConfig(t *testing.T, dir string) string {
	p := filepath.Join(dir, "unreadable.toml")
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// unparseableConfig is an explicit --config file that is not TOML.
func unparseableConfig(t *testing.T, dir string) string {
	p := filepath.Join(dir, "broken.toml")
	if err := os.WriteFile(p, []byte("[guard\nenabled = = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// captureStderrT runs fn with os.Stderr a pipe and returns what it wrote.
func captureStderrT(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	func() {
		defer func() { os.Stderr = prev }()
		fn()
	}()
	_ = w.Close()
	return <-done
}
