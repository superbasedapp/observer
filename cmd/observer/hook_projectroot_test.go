//go:build !sbo_omit_adapter_codex

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// TestCwdOnlyGatesJudgeOutsideProjectDelete (surface-gap FU-101, built as
// 833a533406, re-scoped onto Event.RepoRoot 2026-11-08): on the real
// receivers of hosts whose payload carries only cwd, a recursive delete
// outside the repository is blocked by R-101 at the gate and a `chown -R`
// outside it by R-141, while the same commands inside the repository pass.
// In a linked worktree that lives outside its main repository the worktree
// is its own tree (audit H1): a delete or chown inside it passes.
func TestCwdOnlyGatesJudgeOutsideProjectDelete(t *testing.T) {
	// Outside the repository and outside every default allow_paths entry
	// (temp directories are allowed); forward slashes read the same in
	// every shell dialect.
	outside := "/srv/fu101-outside-x"
	if runtime.GOOS == "windows" {
		outside = "C:/fu101-outside-x"
	}
	config := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		cp := filepath.Join(dir, "config.toml")
		writeFileT(t, cp, fmt.Sprintf("[observer]\ndb_path = %q\n[observer.hooks]\nauto_register = false\n[guard]\nenabled = true\nmode = \"enforce\"\n", filepath.ToSlash(filepath.Join(dir, "o.db"))))
		return cp
	}
	inside := func(root, name string) string { return filepath.ToSlash(filepath.Join(root, name)) }
	for _, h := range projectHookHosts() {
		for _, tc := range []struct {
			name      string
			command   func(root string) string
			wantBlock bool
			wantWhy   string
		}{
			{"rm outside the repository blocks", func(string) string { return "rm -rf " + outside }, true, "outside the project root"},
			{"rm inside the repository passes", func(root string) string { return "rm -rf " + inside(root, "build") }, false, ""},
			{"chown outside the repository blocks", func(string) string { return "chown -R u " + outside }, true, "chown -R outside project"},
			{"chown inside the repository passes", func(root string) string { return "chown -R u " + inside(root, "build") }, false, ""},
		} {
			t.Run(h.name+"/"+tc.name, func(t *testing.T) {
				setTestHome(t, t.TempDir())
				root, cwd := projectHookRepo(t, "https://github.com/acme/widget.git")
				cp := config(t)
				hh := newFailureHarness(t, hookFailurePlan{})
				h.run(t, cwd, tc.command(root), cp)
				out := hh.stdout.String()
				if blocked := toolGateBlockWords.MatchString(out); blocked != tc.wantBlock {
					t.Fatalf("stdout %q: blocked=%v, want %v", out, blocked, tc.wantBlock)
				}
				if tc.wantBlock && !strings.Contains(out, tc.wantWhy) {
					t.Errorf("stdout %q, want the reason %q", out, tc.wantWhy)
				}
			})
		}
		t.Run(h.name+"/linked worktree is its own tree (H1)", func(t *testing.T) {
			if _, err := exec.LookPath("git"); err != nil {
				t.Skip("git not on PATH")
			}
			setTestHome(t, t.TempDir())
			_, wt := linkedWorktreeOutside(t)
			for _, command := range []string{"rm -rf " + inside(wt, "build"), "chown -R u " + inside(wt, "build")} {
				cp := config(t)
				hh := newFailureHarness(t, hookFailurePlan{})
				h.run(t, wt, command, cp)
				if out := hh.stdout.String(); toolGateBlockWords.MatchString(out) {
					t.Errorf("%s from the worktree: stdout %q, want a pass (the worktree is its own checkout)", command, out)
				}
			}
		})
	}
}
