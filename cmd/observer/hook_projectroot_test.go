//go:build !sbo_omit_adapter_codex

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Lane sec-p2a audit finding 1: Claude Code's PreToolUse, Codex and most tool
// gates carry only cwd, so before the merge fix the guard's org project
// layer and its project_unknown floor never applied on them. These tests
// drive the real receivers with a cached v3 org bundle on disk.

// claudeCodeFixturePayload is the recorded Claude Code PreToolUse Bash
// payload (internal/hook/testdata) with its cwd and command replaced.
func claudeCodeFixturePayload(t *testing.T, cwd, command string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "hook", "testdata", "guard", "claude-code", "pretool_bash_rmrf.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if _, ok := p["project_root"]; ok {
		t.Fatal("the recorded payload carries a project root; this test is about the hooks that do not")
	}
	p["cwd"] = cwd
	p["tool_input"].(map[string]any)["command"] = command
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// projectHookHosts are the receivers driven: Claude Code's own, Codex's, and
// a binding-routed one (Qwen Code), each with a payload carrying only cwd.
func projectHookHosts() []struct {
	name string
	run  func(t *testing.T, cwd, command, cp string)
} {
	shape := func(tool, cwd, command string) string {
		return fmt.Sprintf(`{"session_id":"s1","cwd":%q,"hook_event_name":"PreToolUse","tool_name":%q,"tool_input":{"command":%q}}`, cwd, tool, command)
	}
	return []struct {
		name string
		run  func(t *testing.T, cwd, command, cp string)
	}{
		{"claude-code PreToolUse (recorded payload)", func(t *testing.T, cwd, command, cp string) {
			handleClaudeCodePreTool(strings.NewReader(claudeCodeFixturePayload(t, cwd, command)), hookStdout, os.Stderr, "claude-code:pre-tool", cp)
		}},
		{"codex PreToolUse", func(t *testing.T, cwd, command, cp string) {
			driveToolGateReceiver(t, models.ToolCodex, "PreToolUse", shape("Bash", cwd, command), cp)
		}},
		{"qwen-code PreToolUse", func(t *testing.T, cwd, command, cp string) {
			driveToolGateReceiver(t, "qwen-code", "PreToolUse", shape("run_shell_command", cwd, command), cp)
		}},
	}
}

// TestHookProjectRootReachesTheProjectLayer: in a repository whose project
// has a published section, the section applies on a hook payload carrying
// only cwd (a subdirectory of the repository); with `unknown = "ask"` and the
// mapping past its offline lifetime, an unmatched repository gets the floor.
func TestHookProjectRootReachesTheProjectLayer(t *testing.T) {
	const remote = "https://github.com/acme/widget.git"
	for _, h := range projectHookHosts() {
		t.Run(h.name+"/project section applies", func(t *testing.T) {
			_, cwd := projectHookRepo(t, remote)
			cp := projectHookNode(t, "# floor\n", remote, time.Now())
			setInvocationHookContext(nil, cp)
			t.Cleanup(func() { setInvocationHookContext(nil, "") })
			hh := newFailureHarness(t, hookFailurePlan{})
			h.run(t, cwd, "curl https://billing.internal/export", cp)
			if out := hh.stdout.String(); !strings.Contains(out, "PRJ-HOOK1") || !toolGateBlockWords.MatchString(out) {
				t.Fatalf("stdout %q, want the dialect's block from the project section PRJ-HOOK1", out)
			}
		})
		t.Run(h.name+"/project_unknown floor in an unmatched repository", func(t *testing.T) {
			_, cwd := projectHookRepo(t, "https://github.com/acme/unlisted.git")
			cp := projectHookNode(t, "# floor\n[project_audience]\nunknown = \"ask\"\n", remote, time.Now().Add(-8*24*time.Hour))
			setInvocationHookContext(nil, cp)
			t.Cleanup(func() { setInvocationHookContext(nil, "") })
			hh := newFailureHarness(t, hookFailurePlan{})
			h.run(t, cwd, "make test", cp)
			if out := hh.stdout.String(); !strings.Contains(out, "cannot be confirmed") || !toolGateBlockWords.MatchString(out) {
				t.Fatalf("stdout %q, want the dialect's ask (or deny) from the project_unknown floor", out)
			}
		})
	}
}

// TestWithProjectLookupRootLeavesProjectRootAlone: the enrich step stamps
// only ProjectLookupRoot (the identity root of cwd), never ProjectRoot, and a
// root the host sent wins.
func TestWithProjectLookupRootLeavesProjectRootAlone(t *testing.T) {
	root, cwd := projectHookRepo(t, "https://github.com/acme/widget.git")
	ran := false
	ev := policy.Event{Cwd: cwd}
	withProjectLookupRoot(func(*policy.Event) { ran = true })(&ev)
	if !ran || ev.ProjectRoot != "" || ev.ProjectLookupRoot != root {
		t.Fatalf("event %+v (next ran %v), want ProjectLookupRoot %s and an empty ProjectRoot", ev, ran, root)
	}
	host := policy.Event{Cwd: cwd, ProjectRoot: "/host/sent"}
	withProjectLookupRoot(nil)(&host)
	if host.ProjectRoot != "/host/sent" || host.ProjectLookupRoot != "/host/sent" {
		t.Fatalf("a host root was not kept: %+v", host)
	}
}
