package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// setSeededTestHome points HOME at a fresh directory whose default database
// (~/.observer/observer.db, where a config without db_path writes) is
// already migrated from the shared template (internal/db/dbtemplate). A
// cold first open runs the whole migration chain,
// about 20 s under -race on a CI runner: as long as the hook's whole
// max-runtime, so a test's first invocation timed out inside its guard
// persist (after the reply) or its reconsider-once lookup (before it). The
// plugin dialects are what these tests pin, not the cold migration.
func setSeededTestHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(home, ".observer", "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
}

// pluginDeny is the exact plugin-dialect fail-closed block for reason.
func pluginDeny(reason string) string {
	return fmt.Sprintf(`{"decision":"deny","reason":%q,"enforced":true}`+"\n", reason)
}

// runPluginHook runs one `observer hook <tool> <event>` invocation through
// the real dispatch with body on stdin and returns the reply and exits.
func runPluginHook(t *testing.T, tool, event, configPath, body string) (string, []int) {
	t.Helper()
	h := newFailureHarness(t, hookFailurePlan{})
	withStdinT(t, body, func() {
		runHookInvocation(context.Background(), []string{tool, event}, configPath, 20*time.Second, h.exit)
	})
	return h.stdout.String(), h.exitCodes()
}

func pluginReplyOf(t *testing.T, out string) hook.PluginReply {
	t.Helper()
	var r hook.PluginReply
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &r); err != nil {
		t.Fatalf("reply %q is not one plugin reply: %v", out, err)
	}
	return r
}

// TestPluginToolGateDialects: per plugin host, a guard-denied call gets the
// plugin deny (which the shim / Hermes plugin maps onto the host block), a
// benign call gets the plugin allow, both exit 0 with exactly one reply.
func TestPluginToolGateDialects(t *testing.T) {
	setSeededTestHome(t)
	cases := []struct {
		tool, event, mode string
		toolName          string
		input             map[string]any
		want              string // decision
		wantEnforced      bool
	}{
		{"opencode", "tool.execute.before", "enforce", "bash", map[string]any{"command": "cat ~/.ssh/id_rsa"}, "deny", true},
		{"opencode", "tool.execute.before", "enforce", "bash", map[string]any{"command": "ls -la"}, "allow", true},
		{"opencode", "tool.execute.before", "enforce", "read", map[string]any{"filePath": "~/.ssh/id_rsa"}, "deny", true},
		{"kilo-code-cli", "tool.execute.before", "enforce", "bash", map[string]any{"command": "cat ~/.ssh/id_rsa"}, "deny", true},
		// pi maps ask onto ctx.ui.confirm (the shim blocks where there is
		// no UI), so the overridable credential read stays an ask.
		{"pi", "tool_call", "enforce", "bash", map[string]any{"command": "cat ~/.ssh/id_rsa"}, "ask", true},
		{"pi", "tool_call", "enforce", "read", map[string]any{"path": "notes.txt"}, "allow", true},
		// Hermes maps ask onto its own approval prompt.
		{"hermes", "pre_tool_call", "enforce", "terminal", map[string]any{"command": "cat ~/.ssh/id_rsa"}, "ask", true},
		// commandcode Mods beforeToolCall: no documented ask, so a deny.
		{"command-code", "beforeToolCall", "enforce", "Bash", map[string]any{"command": "cat ~/.ssh/id_rsa"}, "deny", true},
		// observe: the guard records, never blocks.
		{"opencode", "tool.execute.before", "observe", "bash", map[string]any{"command": "rm -rf ~/x"}, "allow", false},
		// unknown tool name / no operand: unknown is never a violation.
		{"opencode", "tool.execute.before", "enforce", "frobnicate", map[string]any{"x": "rm -rf ~/x"}, "allow", true},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/%s/%s/%s", c.tool, c.mode, c.toolName, c.want), func(t *testing.T) {
			// An observe-mode reply is the host's own dialect only while the
			// adapter is active; an inactive one answers the generic allow.
			if c.mode == "observe" {
				requireActiveAdapters(t, c.tool)
			}
			cp := writeGuardConfig(t, c.mode)
			body, _ := json.Marshal(map[string]any{
				"host": c.tool, "event": c.event, "session_id": "s1", "cwd": "/tmp/proj", "pid": 4242,
				"tool_name": c.toolName, "tool_input": c.input, "call_id": "c1",
			})
			out, exits := runPluginHook(t, c.tool, c.event, cp, string(body))
			r := pluginReplyOf(t, out)
			if r.Decision != c.want {
				t.Fatalf("decision = %q (%s), want %q", r.Decision, out, c.want)
			}
			if c.want != "allow" && r.Reason == "" {
				t.Fatal("a deny must carry a reason")
			}
			if r.Enforced == nil || *r.Enforced != c.wantEnforced {
				t.Fatalf("enforced hint = %v, want %v", r.Enforced, c.wantEnforced)
			}
			if len(exits) != 0 {
				t.Fatalf("exits = %v, want none (the plugin dialect exits 0)", exits)
			}
		})
	}
}

// TestPluginToolGateFailureSemantics: garbage and truncated payloads are
// blocked with a reason under enforcement and allowed otherwise.
func TestPluginToolGateFailureSemantics(t *testing.T) {
	setTestHome(t, t.TempDir())
	for _, mode := range []string{"enforce", "observe"} {
		for name, body := range map[string]string{
			"garbage":   "not json at all",
			"truncated": `{"host":"pi","event":"tool_call","tool_name":"bash","tool_input":{"command":"` + strings.Repeat("A", promptSubmitBodyLimit+10) + `"}}`,
		} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				if mode == "observe" {
					requireActiveAdapters(t, "pi")
				}
				// No posture file: enforcement follows the config fallback.
				cp := writeGuardConfig(t, mode)
				out, _ := runPluginHook(t, "pi", "tool_call", cp, body)
				r := pluginReplyOf(t, out)
				want := map[string]string{"enforce": "deny", "observe": "allow"}[mode]
				if r.Decision != want {
					t.Fatalf("decision = %q (%s), want %q", r.Decision, out, want)
				}
				if want == "deny" && r.Reason != hook.FailClosedErrorReason {
					t.Fatalf("reason = %q, want the fail-closed reason", r.Reason)
				}
			})
		}
	}
}

// TestPluginPromptGate: OpenCode chat.message through the plugin prompt
// dialect: a secret is withheld (deny) under the prompt lane, a clean prompt
// passes; a non-prompt event on the dialect answers allow.
func TestPluginPromptGate(t *testing.T) {
	setSeededTestHome(t)
	dir := t.TempDir()
	cp := filepath.Join(dir, "config.toml")
	writeFileT(t, cp, "[guard]\nenabled = true\nmode = \"enforce\"\n[guard.prompt]\nenabled = true\nhook_lane = true\n")
	secret := "ghp_" + strings.Repeat("a1B2", 9)
	body := func(p string) string {
		b, _ := json.Marshal(map[string]any{"host": "opencode", "event": "chat.message", "session_id": "s1", "cwd": dir, "prompt": p})
		return string(b)
	}
	out, _ := runPluginHook(t, "opencode", "chat.message", cp, body("deploy with token "+secret))
	if r := pluginReplyOf(t, out); r.Decision != "deny" || r.Reason == "" || strings.Contains(r.Reason, secret) {
		t.Fatalf("secret prompt reply = %+v, want a deny whose reason never echoes the secret", r)
	}
	out, _ = runPluginHook(t, "opencode", "chat.message", cp, body("explain this function"))
	if r := pluginReplyOf(t, out); r.Decision == "deny" {
		t.Fatalf("clean prompt reply = %+v, want an allow", r)
	}
}

// TestPluginPromptGateWarnAndConfirm: both plugin prompt seams answer a
// stop with a reason that never echoes the secret, and under
// [guard.prompt] mode = "warn" an allow that carries the notice as message
// (the shim toasts / notifies it). pi `input` rides the confirm dialect.
func TestPluginPromptGateWarnAndConfirm(t *testing.T) {
	// The reconsider-once store lives in the default DB under ~/.observer,
	// seeded migrated so the first ask-once lookup is not a cold migration.
	setSeededTestHome(t)
	secret := "ghp_" + strings.Repeat("a1B2", 9)
	for _, host := range []struct{ tool, event string }{{"opencode", "chat.message"}, {"pi", "input"}} {
		b, ok := resolveHookBinding(host.tool, host.event)
		if !ok || !b.Wired {
			t.Fatalf("%s %s: binding = %+v %v, want a wired plugin prompt binding", host.tool, host.event, b, ok)
		}
		// github_pat ships as "block"; the detector row is set to the mode
		// under test so the global mode is what the seam resolves.
		for mode, want := range map[string]string{"ask-once": "ask", "warn": "allow", "block": "deny"} {
			t.Run(host.tool+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				cp := filepath.Join(dir, "config.toml")
				writeFileT(t, cp, "[guard]\nenabled = true\nmode = \"enforce\"\n[guard.prompt]\nenabled = true\nhook_lane = true\nmode = \""+mode+
					"\"\n[guard.prompt.detectors]\ngithub_pat = \""+mode+"\"\n")
				body, _ := json.Marshal(map[string]any{"host": host.tool, "event": host.event, "session_id": host.tool + "-" + mode, "cwd": dir, "prompt": "deploy with token " + secret})
				out, exits := runPluginHook(t, host.tool, host.event, cp, string(body))
				r := pluginReplyOf(t, out)
				if len(exits) != 0 {
					t.Fatalf("exits = %v, want none", exits)
				}
				if strings.Contains(out, secret) {
					t.Fatalf("reply %s echoes the secret", out)
				}
				if r.Decision != want {
					t.Fatalf("reply = %+v, want decision %q", r, want)
				}
				if want == "allow" && r.Message == "" {
					t.Fatalf("warn reply = %+v, want the notice as message", r)
				}
				if want != "allow" && r.Reason == "" {
					t.Fatalf("stop reply = %+v, want a reason", r)
				}
			})
		}
	}
	if b, _ := resolveHookBinding("pi", "input"); b.Dialect != hook.PromptDialectPluginShimConfirm {
		t.Fatalf("pi input dialect = %q, want the confirm dialect", b.Dialect)
	}
}

// TestPluginBindingsHaveAReceiver: every Wired plugin-dialect binding is
// served by bindingDialectReceivers (the dispatch the shim relies on).
func TestPluginBindingsHaveAReceiver(t *testing.T) {
	n := 0
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if !b.Wired || (b.Dialect != hook.PluginDialectToolGate && b.Dialect != hook.PromptDialectPluginShim &&
				b.Dialect != hook.PromptDialectPluginShimConfirm) {
				continue
			}
			n++
			got, ok := resolveHookBinding(c.Tool, b.NativeEvent)
			if !ok || got.Dialect != b.Dialect {
				t.Errorf("%s %s: resolveHookBinding = %+v %v", c.Tool, b.NativeEvent, got, ok)
			}
			if _, ok := bindingDialectReceivers[b.Dialect]; !ok {
				t.Errorf("%s %s: no receiver for dialect %q", c.Tool, b.NativeEvent, b.Dialect)
			}
		}
	}
	if n < 6 {
		t.Fatalf("only %d wired plugin bindings; want the opencode, kilo-code-cli, pi and hermes rows", n)
	}
}
