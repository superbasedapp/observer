//go:build !sbo_omit_security && !sbo_omit_adapter_cursor && !sbo_omit_adapter_codex

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// commitGateNoCommand are the served tool-gate events that never carry a
// shell command, so the commit gate cannot fire there; each names where a
// commit on that host is gated instead. Anything not listed here must be
// covered by TestSecurityCommitGateOnEveryBindingVendor.
var commitGateNoCommand = map[string]string{
	"pre_write_code":   "Cascade's write event: its commits arrive on pre_run_command",
	"pre_read_code":    "Cascade's read event: its commits arrive on pre_run_command",
	"pre_mcp_tool_use": "Cascade's MCP event: no builtin shell form",
	"cursor preToolUse": "Cursor gates Shell on beforeShellExecution (TestSecurityGateOnEveryBlockingHost), " +
		"never on preToolUse",
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	os.Stderr = old
	_ = w.Close()
	return <-done
}

// TestSecurityCommitGateOnEveryBindingVendor (lane sec-gate3 milestone 2c):
// every served tool-gate binding, read from the registry, runs the
// security enrich step: a `git commit` in a dirty project whose quick scan
// cannot run is held by S-793 in the host's own reply. A host that can ask
// asks, a host that cannot denies, and an exit-code host (Cascade, Kiro)
// exits with its block code and nothing on stdout, with the S-793 reason
// on stderr. A fail-closed answer (the hook could not evaluate) never
// carries the S-793 reason, so it fails every case.
func TestSecurityCommitGateOnEveryBindingVendor(t *testing.T) {
	covered := 0
	for _, g := range servedToolGates(t) {
		if _, skip := commitGateNoCommand[g.b.NativeEvent]; skip {
			continue
		}
		if _, skip := commitGateNoCommand[g.tool+" "+g.b.NativeEvent]; skip {
			continue
		}
		covered++
		t.Run(g.tool+" "+g.b.NativeEvent, func(t *testing.T) {
			cp, root := newSecurityHostNode(t)
			writeDirtyPosture(t, cp, root)
			setInvocationHookContext(nil, cp)
			t.Cleanup(func() { setInvocationHookContext(nil, "") })
			body := strings.ReplaceAll(toolGateE2EFixture(g.tool, g.b.NativeEvent, g.b.Dialect, root), "rm -rf ~/", "git commit -m wip")
			if !strings.Contains(body, "git commit -m wip") {
				t.Fatalf("the fixture carries no command: %s", body)
			}
			h := newFailureHarness(t, resolveHookFailurePlan(g.tool, g.b.NativeEvent, cp))
			stderr := captureStderr(t, func() { driveToolGateReceiver(t, g.tool, g.b.NativeEvent, body, cp) })
			out := h.stdout.String()
			if fc, _ := hook.BuildFailClosedReply(g.b.Dialect, "x"); fc.ExitCode != 0 {
				codes := h.exitCodes()
				if out != "" || len(codes) == 0 || codes[0] != fc.ExitCode || !strings.Contains(stderr, s793Reason) {
					t.Fatalf("exit-code host: stdout %q exits %v stderr %q, want exit %d carrying S-793 on stderr", out, codes, stderr, fc.ExitCode)
				}
				return
			}
			if !toolGateBlockWords.MatchString(out) || !strings.Contains(out, s793Reason) {
				t.Fatalf("stdout %q, want the dialect's ask (or deny on a host that cannot ask) carrying S-793", out)
			}
		})
	}
	if covered < 10 {
		t.Fatalf("only %d bindings covered; the registry lost its tool gates or the exclusion list grew", covered)
	}
}

// TestSecurityCommitGateOnEveryPluginShimHost (lane sec-gate3 milestone
// 2c): every registered, wired plugin-shim tool gate, read from the
// registry, runs the security enrich step on its own receiver: a `git
// commit` in a dirty project whose quick scan cannot run is held by S-793
// in the plugin reply (an ask where the shim can ask, else a deny), never
// a fail-closed answer, which carries no S-793 reason.
func TestSecurityCommitGateOnEveryPluginShimHost(t *testing.T) {
	covered := 0
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if b.Cap != integration.HookCapToolGate || b.Dialect != hook.PluginDialectToolGate || !b.Wired {
				continue
			}
			covered++
			t.Run(c.Tool+" "+b.NativeEvent, func(t *testing.T) {
				shell := pluginShellTool[c.Tool]
				if shell == "" {
					shell = "bash"
				}
				cp, root := newSecurityHostNode(t)
				writeDirtyPosture(t, cp, root)
				setInvocationHookContext(nil, cp)
				t.Cleanup(func() { setInvocationHookContext(nil, "") })
				body := fmt.Sprintf(`{"host":%q,"event":%q,"session_id":"s1","cwd":%q,"tool_name":%q,"tool_input":{"command":"git commit -m wip"}}`,
					c.Tool, b.NativeEvent, root, shell)
				h := newFailureHarness(t, resolveHookFailurePlan(c.Tool, b.NativeEvent, cp))
				withStdinT(t, body, func() {
					if !dispatchBindingDialect(context.Background(), c.Tool, b.NativeEvent, cp) {
						t.Fatalf("%s %s: no plugin-shim receiver", c.Tool, b.NativeEvent)
					}
				})
				out := h.stdout.String()
				if !toolGateBlockWords.MatchString(out) || !strings.Contains(out, s793Reason) {
					t.Fatalf("stdout %q, want the plugin's ask or deny carrying S-793", out)
				}
			})
		}
	}
	if covered < 4 {
		t.Fatalf("only %d plugin-shim tool gates covered", covered)
	}
}
