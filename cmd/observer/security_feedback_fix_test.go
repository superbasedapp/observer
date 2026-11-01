//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secipc"
)

// security_feedback_fix_test.go pins the merge fixes of lane sec-h (audit
// findings 1, 2 and 4).

// feedbackSelectedBlock selects security.feedback in a [components] block.
const feedbackSelectedBlock = "[components]\nadd = [\"security.feedback\"]\n"

// optInFeedbackHosts are the hosts whose feedback event Observer registers
// only while security.feedback is selected, with that host's own post-tool
// payload and the reply key its dialect carries the line in.
func optInFeedbackHosts(cwd string) []struct {
	tool, event, body, key string
} {
	claudeShaped := func(event string) string {
		b, _ := json.Marshal(map[string]any{
			"session_id": "s1", "cwd": cwd, "hook_event_name": event, "tool_name": "write_file",
			"tool_input": map[string]any{"file_path": filepath.Join(cwd, "config.py"), "content": "x = 1\n"},
		})
		return string(b)
	}
	cline, _ := json.Marshal(map[string]any{
		"hookName": "PostToolUse", "taskId": "s1", "sessionContext": map[string]any{"sessionId": "s1"},
		"workspaceRoots": []string{cwd},
		"tool_call":      map[string]any{"id": "t1", "name": "run_commands", "input": map[string]any{"command": "ls"}},
	})
	return []struct{ tool, event, body, key string }{
		{"gemini-cli", "AfterTool", claudeShaped("AfterTool"), `"hookEventName":"AfterTool"`},
		{"qwen-code", "PostToolUse", claudeShaped("PostToolUse"), `"hookSpecificOutput":{"additionalContext":"observer: found a GitHub token (high confidence) by rule secret.github_pat`},
		{"qoder", "PostToolUse", claudeShaped("PostToolUse"), `"hookSpecificOutput":{"additionalContext":"observer: found a GitHub token (high confidence) by rule secret.github_pat`},
		{"cline-cli", "PostToolUse", string(cline), `"contextModification":"observer: found a GitHub token (high confidence) by rule secret.github_pat`},
	}
}

// runDispatchedHook runs one `observer hook <tool> <event>` invocation
// through the real dispatcher (runHookInvocation) with body on stdin.
func runDispatchedHook(t *testing.T, tool, event, configPath, body string) string {
	t.Helper()
	h := newFailureHarness(t, hookFailurePlan{})
	withStdinT(t, body, func() {
		runHookInvocation(context.Background(), []string{tool, event}, configPath, 20*time.Second, h.exit)
	})
	return h.stdout.String()
}

// runReceiverDirect runs the tool's own hookReceivers entry with body on
// stdin: what the dispatcher answered before the feedback route existed.
func runReceiverDirect(t *testing.T, tool, event, configPath, body string) string {
	t.Helper()
	fn, ok := hookReceivers[tool]
	if !ok {
		t.Fatalf("%s has no receiver", tool)
	}
	h := newFailureHarness(t, hookFailurePlan{})
	withStdinT(t, body, func() { fn(context.Background(), event, configPath) })
	return h.stdout.String()
}

// TestFeedbackReachesOptInHostsThroughTheDispatcher (audit finding 1): for
// Gemini CLI, Qwen Code, Qoder and Cline CLI, whose feedback event has a
// receiver of the tool's own ahead of the binding path, the dispatcher
// serves the event with the feedback handler while security.feedback is
// selected (the line in the host's reply dialect), and while it is not, the
// reply is byte for byte the tool's own receiver's.
func TestFeedbackReachesOptInHostsThroughTheDispatcher(t *testing.T) {
	requireActiveAdapters(t, "gemini-cli", "qwen-code", "qoder", "cline-cli")
	setTestHome(t, t.TempDir())
	cwd := t.TempDir()
	for _, tc := range optInFeedbackHosts(cwd) {
		t.Run(tc.tool, func(t *testing.T) {
			if b, ok := feedbackPostBinding(tc.tool, tc.event); !ok || b.RegisterWhen == "" {
				t.Fatalf("%s %s: no opt-in feedback binding", tc.tool, tc.event)
			}
			on := writeFeedbackConfig(t, feedbackSelectedBlock)
			layout := pinHookSecurity(t, on, "security", securityFeedbackComponent)
			var asked atomic.Int32
			serveFeedbackAt(t, layout, func(_ context.Context, r secipc.FeedbackRequest) (secipc.FeedbackOffer, error) {
				if r.SessionID == "s1" && r.ProjectRoot != "" {
					asked.Add(1)
				}
				return secipc.FeedbackOffer{Hits: []policy.SecurityHit{{
					Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh,
					RuleID: "secret.github_pat", Path: "config.py", Line: 1,
				}}}, nil
			})
			got := runDispatchedHook(t, tc.tool, tc.event, on, tc.body)
			if !strings.Contains(got, tc.key) || !strings.Contains(got, "secret.github_pat") {
				t.Fatalf("selected: reply %q lacks %s", got, tc.key)
			}
			if asked.Load() != 1 {
				t.Fatalf("the daemon was asked %d times with the host's session and root", asked.Load())
			}

			off := writeFeedbackConfig(t, "")
			pinHookSecurity(t, off, "security", securityFeedbackComponent)
			before := runReceiverDirect(t, tc.tool, tc.event, off, tc.body)
			after := runDispatchedHook(t, tc.tool, tc.event, off, tc.body)
			if after != before {
				t.Fatalf("not selected: dispatcher reply %q, the receiver's own %q", after, before)
			}
			if strings.Contains(after, "secret.github_pat") {
				t.Fatalf("not selected: a feedback line went out: %q", after)
			}
		})
	}
}

// TestFeedbackUnselectedReadsNoPosture (audit finding 4): with
// security.feedback not selected (no [components] block), no post-tool
// path reads the signed posture or checks its MAC; the selection comes from
// the invocation's component snapshot. Selected, the posture is read.
func TestFeedbackUnselectedReadsNoPosture(t *testing.T) {
	var reads atomic.Int32
	prev := hookSecurityPostureLoad
	hookSecurityPostureLoad = func(posture, key string) guardposture.Loaded {
		reads.Add(1)
		return prev(posture, key)
	}
	t.Cleanup(func() { hookSecurityPostureLoad = prev })
	unpin := func() {
		hookSecMu.Lock()
		saved := hookSecCur
		hookSecCur = nil
		hookSecMu.Unlock()
		t.Cleanup(func() {
			hookSecMu.Lock()
			hookSecCur = saved
			hookSecMu.Unlock()
		})
	}
	unpin()
	resetHookInvocationComponents()
	t.Cleanup(resetHookInvocationComponents)

	cp := writeFeedbackConfig(t, "")
	ctx := context.Background()
	body := claudePostBody(t.TempDir(), "key = \""+fakeGitHubToken+"\"\n")
	reply := []byte(`{"decision":"approve"}` + "\n")
	for _, c := range []struct{ tool, event string }{
		{models.ToolClaudeCode, "PostToolUse"}, {models.ToolCodex, "PostToolUse"}, {models.ToolCursor, "postToolUse"},
	} {
		if got := postFeedbackBytes(ctx, c.tool, c.event, body, reply, cp); !bytes.Equal(got, reply) {
			t.Fatalf("%s: reply changed: %s", c.tool, got)
		}
		var w bytes.Buffer
		if securityPostFeedbackWriter(ctx, &w, c.tool, c.event, body, cp) != &w {
			t.Fatalf("%s: the writer was wrapped", c.tool)
		}
	}
	var out bytes.Buffer
	if !handlePostFeedbackHook(ctx, "gemini-cli", "AfterTool", "gemini-cli:AfterTool", cp, bytes.NewReader(body), &out, &bytes.Buffer{}) {
		t.Fatal("AfterTool has no feedback handler")
	}
	if feedbackOptInRoute("qwen-code", "PostToolUse", cp) {
		t.Fatal("the dispatcher would route an unselected install to the feedback handler")
	}
	if n := reads.Load(); n != 0 {
		t.Fatalf("an unselected install read the posture %d times on the post-tool paths", n)
	}

	// The counter works: a selected install reads the posture (once).
	on := writeFeedbackConfig(t, feedbackSelectedBlock)
	_ = postFeedbackBytes(ctx, models.ToolClaudeCode, "PostToolUse", body, reply, on)
	if n := reads.Load(); n != 1 {
		t.Fatalf("a selected install read the posture %d times, want 1", n)
	}
}

// feedbackHome is a sandbox home with the config directories the opt-in
// feedback writers need; HOME and XDG_CONFIG_HOME point into it, so no
// writer can reach a real tool config.
func feedbackHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, d := range []string{".gemini", ".qwen", ".qoder", ".cline", ".observer", filepath.Join(".config", "opencode", "plugins")} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	setTestHome(t, home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return home
}

// feedbackFiles reads every file an opt-in feedback writer touches.
func feedbackFiles(t *testing.T, home string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, rel := range []string{
		".gemini/settings.json", ".qwen/settings.json", ".qoder/settings.json",
		".cline/hooks/PostToolUse", ".config/opencode/plugins/superbased-observer.ts",
	} {
		data, err := os.ReadFile(filepath.Join(home, filepath.FromSlash(rel)))
		if err == nil {
			out[rel] = string(data)
		}
	}
	return out
}

// feedbackTools are the tools with an opt-in feedback event.
func feedbackTools() []string {
	tools := []string{"gemini-cli", "qwen-code", "qoder", "opencode"}
	if runtime.GOOS != "windows" {
		tools = append(tools, "cline-cli")
	}
	return tools
}

// TestFeedbackEntriesSurviveWritersWithoutSelection (audit finding 2,
// choice: nil Options.Selected leaves opt-in events alone): with
// security.feedback selected and registered, the interactive init's writers
// and the doctor probe's leave the Gemini, Qwen and Qoder entries, the
// shim's post block and the Cline script in place, and the probe reads
// them as current; on an install that never selected it they add nothing.
func TestFeedbackEntriesSurviveWritersWithoutSelection(t *testing.T) {
	requireComponents(t, "integration.hooks")
	requireActiveAdapters(t, "gemini-cli", "qwen-code", "qoder", "opencode", "cline-cli")
	home := feedbackHome(t)
	iopts := interactiveInitOptions{BinaryPath: "/opt/observer/bin/observer", HomeDir: home}

	// observer start's write, with the selection.
	sel := interactiveHookOptions(iopts, false)
	sel.Selected = func(c string) bool { return c == securityFeedbackComponent }
	start, err := hook.NewRegistry(sel)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range feedbackTools() {
		if res := start.Register(tool); res.Error != nil {
			t.Fatalf("%s: %v", tool, res.Error)
		}
	}
	want := feedbackFiles(t, home)
	for k, needle := range map[string]string{
		".gemini/settings.json": "hook gemini-cli AfterTool", ".qwen/settings.json": "hook qwen-code PostToolUse",
		".qoder/settings.json": "hook qoder PostToolUse", ".config/opencode/plugins/superbased-observer.ts": `"tool.execute.after":"context_inject"`,
	} {
		if !strings.Contains(want[k], needle) {
			t.Fatalf("%s: the selected registration wrote no feedback entry (%s):\n%s", k, needle, want[k])
		}
	}
	if runtime.GOOS != "windows" && want[".cline/hooks/PostToolUse"] == "" {
		t.Fatal("the selected registration wrote no Cline PostToolUse script")
	}

	// The interactive init's writers (no Selected) leave all of it.
	inter, err := hook.NewRegistry(interactiveHookOptions(iopts, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range feedbackTools() {
		if res := inter.Register(tool); res.Error != nil {
			t.Fatalf("interactive %s: %v", tool, res.Error)
		}
	}
	if got := feedbackFiles(t, home); !mapsEqual(got, want) {
		t.Fatalf("the interactive init changed the feedback files:\n%v\nwant\n%v", got, want)
	}

	// The doctor probe's options (no Selected, dry run) read the shim and
	// the opt-in entries as current and write nothing.
	popts := hookRegistrationOptions(iopts.BinaryPath, "")
	popts.HomeDir, popts.Getenv = home, os.Getenv
	probe, err := hook.NewRegistry(popts)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range feedbackTools() {
		res := probe.Register(tool)
		if res.Error != nil {
			t.Fatalf("probe %s: %v", tool, res.Error)
		}
		if len(res.HooksAdded) != 0 {
			t.Fatalf("probe %s reads %v as missing or stale", tool, res.HooksAdded)
		}
	}
	if got := feedbackFiles(t, home); !mapsEqual(got, want) {
		t.Fatal("the doctor probe changed a feedback file")
	}

	// A never-selected install: the same writers add nothing opt-in.
	fresh := feedbackHome(t)
	fopts := interactiveInitOptions{BinaryPath: iopts.BinaryPath, HomeDir: fresh}
	freg, err := hook.NewRegistry(interactiveHookOptions(fopts, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range feedbackTools() {
		if res := freg.Register(tool); res.Error != nil {
			t.Fatalf("fresh %s: %v", tool, res.Error)
		}
	}
	files := feedbackFiles(t, fresh)
	for k, v := range files {
		if strings.Contains(v, "hook gemini-cli AfterTool") || strings.Contains(v, "hook qwen-code PostToolUse") ||
			strings.Contains(v, "hook qoder PostToolUse") || strings.Contains(v, "tool.execute.after") {
			t.Fatalf("%s: a never-selected install gained a feedback entry:\n%s", k, v)
		}
	}
	if _, ok := files[".cline/hooks/PostToolUse"]; ok {
		t.Fatal("a never-selected install gained the Cline PostToolUse script")
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
