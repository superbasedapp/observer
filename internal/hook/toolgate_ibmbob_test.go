package hook

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestIBMBobToolGateBlocksByExitCode (surface-gap arc W-1, lane w2-c): the
// Bob IDE reads the same ~/.bob/settings/settings.json hooks as Bob Shell
// but ignores PreToolUse stdout, and only exit 2 blocks there
// (bob.ibm.com/docs/ide/configuration/lifecycle-hooks). So the dialect the
// registry names for Bob's PreToolUse must block with exit 2 and the reason
// alone on stderr, and allow with an empty stdout. The dialect is read from
// the registry binding, so a regression back to a stdout-JSON block fails
// here.
func TestIBMBobToolGateBlocksByExitCode(t *testing.T) {
	c, ok := integration.For(models.ToolIBMBob)
	if !ok {
		t.Fatal("no ibm-bob registry row")
	}
	b, ok := c.Hook.Binding("PreToolUse")
	if !ok || !b.Registered || b.Cap != integration.HookCapToolGate {
		t.Fatalf("ibm-bob PreToolUse binding = %+v, want a registered tool gate", b)
	}

	t.Run("deny exits 2 with the reason on stderr and nothing on stdout", func(t *testing.T) {
		var out, errb bytes.Buffer
		res := HandleToolGate(ToolGateRequest{
			Tool: models.ToolIBMBob, Dialect: b.Dialect, NativeEvent: "PreToolUse", Label: "ibm-bob:PreToolUse",
			Body: toolPayload("s1", "execute_command", map[string]any{"command": "rm -rf ~/x"}),
		}, &targetEvaluator{denyOn: "rm -rf"}, func(guard.ActionVerdict) {}, &out, &errb)
		if !res.Replied || res.ExitCode != 2 {
			t.Fatalf("Replied=%v ExitCode=%d, want a block carried by exit 2", res.Replied, res.ExitCode)
		}
		if out.Len() != 0 {
			t.Errorf("stdout = %q, want nothing (the Bob IDE ignores PreToolUse stdout)", out.String())
		}
		if got := errb.String(); got != wantStderrBlock(ruleReason) {
			t.Errorf("stderr = %q, want the header line and the reason %q", got, wantStderrBlock(ruleReason))
		}
		fc, ok := BuildFailClosedReply(b.Dialect, "why")
		if !ok || fc.ExitCode != 2 || len(fc.Stdout) != 0 || !fc.StderrReason {
			t.Errorf("fail-closed reply = %+v, want exit 2, no stdout, the reason on stderr", fc)
		}
	})

	t.Run("allow is silent", func(t *testing.T) {
		var out, errb bytes.Buffer
		res := HandleToolGate(ToolGateRequest{
			Tool: models.ToolIBMBob, Dialect: b.Dialect, NativeEvent: "PreToolUse", Label: "ibm-bob:PreToolUse",
			Body: toolPayload("s1", "execute_command", map[string]any{"command": "ls -la"}),
		}, &targetEvaluator{denyOn: "rm -rf"}, func(guard.ActionVerdict) {}, &out, &errb)
		if res.Replied || res.ExitCode != 0 || out.Len() != 0 {
			t.Fatalf("Replied=%v ExitCode=%d stdout=%q, want an unreplied allow", res.Replied, res.ExitCode, out.String())
		}
		if ToolGateAllowWritesStdout(b.Dialect) {
			t.Errorf("dialect %q writes an allow on stdout; Bob's allow must be silence", b.Dialect)
		}
		var allow bytes.Buffer
		HandleDialectAllow(b.Dialect, "ibm-bob:PreToolUse", strings.NewReader("{}"), &allow, &errb)
		if allow.Len() != 0 {
			t.Errorf("HandleDialectAllow wrote %q, want nothing", allow.String())
		}
	})
}
