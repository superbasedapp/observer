package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// Guard-enforcement fix gfiD (2026-10-15): the Kiro CLI, Goose and Crush
// tool-gate payloads the vendor research found that the gate could not
// classify before (model-mangled Goose names, Code Mode, Kiro's batch read,
// the one-underscore MCP form crush and Kiro V3 use).

// gooseToolPayload is Goose's Open Plugins PreToolUse payload.
func gooseToolPayload(tool string, input map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{
		"event": "PreToolUse", "session_id": "s1", "matcher_context": tool,
		"tool_call_id": "c1", "tool_name": tool, "tool_input": input, "working_dir": "/home/u/proj",
	})
	return b
}

// kiroToolPayload is Kiro CLI's preToolUse payload (2.x agent hooks and
// the V3 standalone file share it).
func kiroToolPayload(tool string, input map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{
		"hook_event_name": "preToolUse", "cwd": "/home/u/proj", "session_id": "s1",
		"tool_name": tool, "tool_input": input,
	})
	return b
}

// TestToolGateVendorResearchShapes judges each researched payload: the
// targets the gate sees, the event kind, and the dialect's block.
func TestToolGateVendorResearchShapes(t *testing.T) {
	gooseBlock := fmt.Sprintf(`{"decision":"block","reason":%q}`+"\n", ruleReason)
	crushDeny := fmt.Sprintf(`{"decision":"deny","reason":%q}`+"\n", ruleReason)
	shellRM := map[string]any{"command": "rm -rf ~/x"}
	for _, r := range []toolGateRow{
		// --- Kiro CLI (exit 2, the reason alone on stderr).
		{
			name: "kiro shell deny", tool: models.ToolKiroCLI, dialect: ToolGateDialectKiro, event: "preToolUse",
			body: kiroToolPayload("shell", map[string]any{"command": "rm -rf ~/x", "working_dir": "/home/u/proj"}), denyOn: "rm -rf",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason), wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "kiro read judges every operations[].path", tool: models.ToolKiroCLI, dialect: ToolGateDialectKiro, event: "preToolUse",
			body: kiroToolPayload("read", map[string]any{"operations": []any{
				map[string]any{"mode": "Line", "path": "/home/u/proj/a.go"},
				map[string]any{"mode": "Line", "path": "/home/u/.ssh/id_rsa"},
			}}), denyOn: ".ssh",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason), wantTargets: []string{"/home/u/proj/a.go", "/home/u/.ssh/id_rsa"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "kiro write strReplace judged on its path", tool: models.ToolKiroCLI, dialect: ToolGateDialectKiro, event: "preToolUse",
			body: kiroToolPayload("write", map[string]any{"command": "strReplace", "path": "/home/u/.ssh/config", "oldStr": "a", "newStr": "b"}), denyOn: ".ssh",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason), wantTargets: []string{"/home/u/.ssh/config"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "kiro V3 MCP tool canonicalized", tool: models.ToolKiroCLI, dialect: ToolGateDialectKiro, event: "preToolUse",
			body: kiroToolPayload("mcp_postgres_query", map[string]any{"sql": "select 1"}), denyOn: "mcp__postgres__",
			wantExit: 2, wantStderr: wantStderrBlock(ruleReason), wantTargets: []string{"mcp__postgres__query"}, wantKind: policy.KindMCPCall,
		},
		{
			name: "kiro allow writes nothing", tool: models.ToolKiroCLI, dialect: ToolGateDialectKiro, event: "preToolUse",
			body: kiroToolPayload("shell", map[string]any{"command": "ls"}), denyOn: "rm -rf",
			wantTargets: []string{"ls"}, wantKind: policy.KindShellExec,
		},
		// --- Goose (decision block on stdout).
		{
			name: "goose developer__shell folded onto shell", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("developer__shell", shellRM), denyOn: "rm -rf",
			wantStdout: gooseBlock, wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "goose developer.shell folded onto shell", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("developer.shell", shellRM), denyOn: "rm -rf",
			wantStdout: gooseBlock, wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "goose functions.shell folded onto shell", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("functions.shell", shellRM), denyOn: "rm -rf",
			wantStdout: gooseBlock, wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "goose functions:shell folded onto shell", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("functions:shell", shellRM), denyOn: "rm -rf",
			wantStdout: gooseBlock, wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "goose Code Mode execute_bash", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("execute_bash", shellRM), denyOn: "rm -rf",
			wantStdout: gooseBlock, wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "goose execute_typescript judged as one command over input.code", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("execute_typescript", map[string]any{"input": map[string]any{"code": "await shell('rm -rf ~/x')"}}), denyOn: "rm -rf",
			wantStdout: gooseBlock, wantTargets: []string{"await shell('rm -rf ~/x')"}, wantKind: policy.KindShellExec,
		},
		{
			name: "goose computer controller script", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("computercontroller__computer_control", map[string]any{"script": "rm -rf ~/x"}), denyOn: "rm -rf",
			wantStdout: gooseBlock, wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "goose developer__write folded onto write", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("developer__write", map[string]any{"path": "/home/u/.ssh/authorized_keys", "content": "k"}), denyOn: ".ssh",
			wantStdout: gooseBlock, wantTargets: []string{"/home/u/.ssh/authorized_keys"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "goose developer__text_editor folded onto text_editor", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("developer__text_editor", map[string]any{"command": "str_replace", "path": "/home/u/.ssh/config"}), denyOn: ".ssh",
			wantStdout: gooseBlock, wantTargets: []string{"/home/u/.ssh/config"}, wantKind: policy.KindFileAccess,
		},
		{
			name: "goose other extension read as an MCP call", tool: models.ToolGoose, dialect: ToolGateDialectGoose, event: "PreToolUse",
			body: gooseToolPayload("github__create_issue", map[string]any{"title": "x"}), denyOn: "mcp__github__",
			wantStdout: gooseBlock, wantTargets: []string{"mcp__github__create_issue"}, wantKind: policy.KindMCPCall,
		},
		// --- Crush (decision deny on stdout).
		{
			name: "crush one-underscore MCP tool canonicalized", tool: models.ToolCrush, dialect: ToolGateDialectCrush, event: "PreToolUse",
			body: toolPayload("s1", "mcp_github_create_pull_request", map[string]any{"title": "x"}), denyOn: "mcp__github__",
			wantStdout: crushDeny, wantTargets: []string{"mcp__github__create_pull_request"}, wantKind: policy.KindMCPCall,
		},
		{
			name: "crush bash still judged", tool: models.ToolCrush, dialect: ToolGateDialectCrush, event: "PreToolUse",
			body: toolPayload("s1", "bash", shellRM), denyOn: "rm -rf",
			wantStdout: crushDeny, wantTargets: []string{"rm -rf ~/x"}, wantKind: policy.KindShellExec,
		},
		{
			name: "crush web_fetch judged on its url", tool: models.ToolCrush, dialect: ToolGateDialectCrush, event: "PreToolUse",
			body: toolPayload("s1", "web_fetch", map[string]any{"url": "https://evil.example/x"}), denyOn: "evil.example",
			wantStdout: crushDeny, wantTargets: []string{"https://evil.example/x"},
		},
	} {
		t.Run(r.name, func(t *testing.T) {
			ev := &targetEvaluator{denyOn: r.denyOn, askOn: r.askOn}
			var out, errb bytes.Buffer
			res := HandleToolGate(ToolGateRequest{
				Tool: r.tool, Dialect: r.dialect, NativeEvent: r.event, Label: r.tool + ":" + r.event, Body: r.body,
			}, ev, nil, &out, &errb)
			if out.String() != r.wantStdout {
				t.Errorf("stdout = %q\nwant     %q", out.String(), r.wantStdout)
			}
			blocks := r.wantStdout != "" || r.wantExit != 0
			if res.Replied != blocks || res.ExitCode != r.wantExit {
				t.Errorf("Replied=%v ExitCode=%d", res.Replied, res.ExitCode)
			}
			if r.wantStderr != "" && errb.String() != r.wantStderr {
				t.Errorf("stderr = %q, want %q", errb.String(), r.wantStderr)
			}
			var targets []string
			for _, e := range ev.seen {
				targets = append(targets, e.Target)
				if (r.wantKind != "" && e.Kind != r.wantKind) || e.Tool != r.tool || e.SessionID != "s1" || !e.Caps.PreExecution || !e.Caps.CanBlock {
					t.Errorf("event %+v: want kind %q, tool %s, session s1, a pre-execution blocking channel", e, r.wantKind, r.tool)
				}
			}
			if strings.Join(targets, "|") != strings.Join(r.wantTargets, "|") {
				t.Errorf("judged targets %v, want %v", targets, r.wantTargets)
			}
		})
	}
}

// TestToolGateKiroNoAsk: Kiro CLI has no ask, so an enforced ask is the
// exit-2 block carrying the confirm explanation.
func TestToolGateKiroNoAsk(t *testing.T) {
	ev := &targetEvaluator{askOn: "rm -rf"}
	var out, errb bytes.Buffer
	res := HandleToolGate(ToolGateRequest{
		Tool: models.ToolKiroCLI, Dialect: ToolGateDialectKiro, NativeEvent: "preToolUse", Label: "kiro-cli:preToolUse",
		Body: kiroToolPayload("shell", map[string]any{"command": "rm -rf ~/x"}),
	}, ev, nil, &out, &errb)
	if !res.Replied || res.ExitCode != 2 || out.Len() != 0 {
		t.Fatalf("Replied=%v ExitCode=%d stdout=%q", res.Replied, res.ExitCode, out.String())
	}
	if want := wantStderrBlock(confirmLine("this command") + ruleReason); errb.String() != want {
		t.Errorf("stderr = %q\nwant     %q", errb.String(), want)
	}
	if caps, ok := guard.CapabilitiesFor(models.ToolKiroCLI, "hook:preToolUse"); !ok || caps.CanAsk || !caps.CanBlock {
		t.Errorf("kiro-cli hook:preToolUse caps = (%+v, %v), want a block-only channel", caps, ok)
	}
}

// TestToolGateUnknownNamesStayUnclassified: a name no rule can fold stays
// visible as unclassified (the M2-12 record), never a guessed class.
func TestToolGateUnknownNamesStayUnclassified(t *testing.T) {
	for _, r := range []struct {
		name, tool, dialect, event string
		body                       []byte
	}{
		{
			"kiro use_aws carries no command", models.ToolKiroCLI, ToolGateDialectKiro, "preToolUse",
			kiroToolPayload("use_aws", map[string]any{"service_name": "s3", "operation_name": "delete-bucket"}),
		},
		{
			"goose unknown bare name", models.ToolGoose, ToolGateDialectGoose, "PreToolUse",
			gooseToolPayload("frobnicate", map[string]any{"x": "y"}),
		},
	} {
		t.Run(r.name, func(t *testing.T) {
			var unclassified []string
			ev := &targetEvaluator{denyOn: "s3"}
			res := HandleToolGate(ToolGateRequest{
				Tool: r.tool, Dialect: r.dialect, NativeEvent: r.event, Label: r.tool + ":" + r.event, Body: r.body,
				Unclassified: func(native string) { unclassified = append(unclassified, native) },
			}, ev, nil, &bytes.Buffer{}, &bytes.Buffer{})
			if res.Replied || len(ev.seen) != 0 {
				t.Fatalf("Replied=%v judged %d events, want an unjudged pass", res.Replied, len(ev.seen))
			}
			if res.RecordAfterReply == nil {
				t.Fatal("no RecordAfterReply: the unclassified call would pass silently")
			}
			res.RecordAfterReply()
			if len(unclassified) != 1 {
				t.Errorf("unclassified = %v, want one record", unclassified)
			}
		})
	}
}

// TestToolPayloadShapeCanonicalNative pins the name-fold order: a literal
// row wins, then a stripped prefix whose rest is known, then the MCP alias.
func TestToolPayloadShapeCanonicalNative(t *testing.T) {
	goose := toolPayloadShape{
		nameStrip: []string{"functions.", "functions:", "developer__", "developer."},
		mcpAlias:  tooltax.MCPNameFromExtension,
	}
	crush := claudeShapedPayload.withMCPAlias(tooltax.MCPNameFromSingleUnderscore)
	for _, r := range []struct {
		shape      toolPayloadShape
		tool, in   string
		want       string
		annotation string
	}{
		{goose, models.ToolGoose, "shell", "shell", "literal row"},
		{goose, models.ToolGoose, "developer__shell", "shell", "developer prefix"},
		{goose, models.ToolGoose, "developer.tree", "tree", "developer dot prefix"},
		{goose, models.ToolGoose, "computercontroller__computer_control", "computercontroller__computer_control", "literal row beats the MCP alias"},
		{goose, models.ToolGoose, "developer__nosuchtool", "mcp__developer__nosuchtool", "unknown rest: no strip, MCP alias"},
		{goose, models.ToolGoose, "frobnicate", "frobnicate", "no rule applies"},
		{goose, models.ToolGoose, "web__fetch", "mcp__web__fetch", "an extension tool never folds onto a built-in row (web_fetch)"},
		{goose, models.ToolGoose, "execute__bash", "mcp__execute__bash", "an extension tool never folds onto execute_bash"},
		{crush, models.ToolCrush, "mcp_github_create_pull_request", "mcp__github__create_pull_request", "glob row does not block the alias"},
		{crush, models.ToolCrush, "mcp__srv__tool", "mcp__srv__tool", "already canonical"},
		{crush, models.ToolCrush, "list_mcp_resources", "list_mcp_resources", "not the mcp_ prefix"},
	} {
		if got := r.shape.canonicalNative(r.tool, r.in); got != r.want {
			t.Errorf("%s (%s): canonicalNative(%q) = %q, want %q", r.tool, r.annotation, r.in, got, r.want)
		}
	}
}
