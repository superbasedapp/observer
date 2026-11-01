package dimcode

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// The hook-probe sessions (dimcode 0.5.21, 2026-10-21, both OSes) are the live
// grounding for the harness-row classification, the sub-agent session shape
// (own session id `subagent_<ms>_<rand>`, linked by session_relations),
// permission mode, the git branch and the transcript reader. The fixtures are
// anonymized real rows (testdata/dimcode/fixture-probe-*.sql).

const (
	probeParent = "sess_1792584986373_0mh41tjwd6wi"
	probeChild  = "subagent_1792584993523_1br3vikrb0w"
)

func eventsFor(res adapter.ParseResult, sid string) []models.ToolEvent {
	var out []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.SessionID == sid {
			out = append(out, e)
		}
	}
	return out
}

// execAll runs statements against the store at dbPath.
func execAll(t *testing.T, dbPath string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
}

// TestHarnessRowsAreNotUserPrompts is the P1 defect pin: role=user rows that
// carry `_dimTranscript` (run terminal status, runtime recovery notice,
// background-task notification) were emitted as user_prompt. They must land as
// the action they really are, and only the person's typed prompts remain.
func TestHarnessRowsAreNotUserPrompts(t *testing.T) {
	res, _ := parseAll(t, "fixture-probe-wsl.sql")

	for _, e := range eventsOfType(res, models.ActionUserPrompt) {
		for _, bad := range []string{"Previous run ended", "<runtime-recovery>", "<notification>"} {
			if strings.Contains(e.Target, bad) {
				t.Errorf("harness row emitted as a user prompt: %q", e.Target)
			}
		}
	}
	// Four typed prompts: 404 session, secret-word session, parent, sub-agent
	// (the delegated prompt is a root user message by the vendor's own rule).
	if n := len(eventsOfType(res, models.ActionUserPrompt)); n != 4 {
		t.Errorf("user prompts = %d, want 4", n)
	}

	byRaw := map[string]models.ToolEvent{}
	for _, e := range res.ToolEvents {
		byRaw[e.RawToolName+"|"+e.SessionID] = e
	}
	// run_terminal + provider_error -> api_error with the first error line.
	e404 := byRaw["dimcode.run_terminal|sess_1792584530786_bug74zlxtel"]
	if e404.ActionType != models.ActionAPIError || e404.Success {
		t.Errorf("404 run terminal = %+v", e404)
	}
	if !strings.Contains(e404.ErrorMessage, "Model not found") || strings.Contains(e404.ErrorMessage, "\n") {
		t.Errorf("404 ErrorMessage = %q (first error line only)", e404.ErrorMessage)
	}
	// run_terminal + SESSION_RUN_ABORTED (a hook-blocked prompt) -> turn_aborted.
	ab := byRaw["dimcode.run_terminal|sess_1792584894137_2su43wuw89o"]
	if ab.ActionType != models.ActionTurnAborted || ab.Success || ab.Target != "SESSION_RUN_ABORTED" {
		t.Errorf("aborted run = %+v", ab)
	}
	// runtime_continuation after provider_retry_exhausted -> api_error.
	rc := byRaw["dimcode.runtime_continuation|sess_1792584908663_ygypwdjzwfc"]
	if rc.ActionType != models.ActionAPIError || !strings.Contains(rc.ErrorMessage, "Retry exhausted") {
		t.Errorf("runtime continuation = %+v", rc)
	}
	// background_task_notification -> prompt_context, content-free target.
	bg := byRaw["dimcode.background_task_notification|"+probeParent]
	if bg.ActionType != models.ActionPromptContext || !bg.Success || strings.Contains(bg.Target, "probe") {
		t.Errorf("background notification = %+v", bg)
	}
}

// TestHarnessRules is one case per row of the ordered harnessRules table plus
// the userAuthored line.
func TestHarnessRules(t *testing.T) {
	abort := transcriptMeta{Kind: "run_terminal", Reason: "provider_error"}
	abort.Error.Code = "SESSION_RUN_ABORTED"
	cases := []struct {
		name   string
		meta   *transcriptMeta
		prompt bool
		want   string
		failed bool
		intr   bool
	}{
		{name: "plain user row", meta: nil, prompt: true},
		{name: "user_input", meta: &transcriptMeta{Kind: "user_input"}, prompt: true},
		{name: "user_steer", meta: &transcriptMeta{Kind: "user_steer", Owner: "user"}, prompt: true},
		{name: "user-owned steer bundle", meta: &transcriptMeta{Kind: "steer_bundle", Owner: "user"}, prompt: true},
		{name: "tool_context is dropped", meta: &transcriptMeta{Kind: "tool_context", Owner: "runtime"}, want: ""},
		{name: "user_interrupt", meta: &transcriptMeta{Kind: "user_interrupt", Owner: "user"}, want: models.ActionTurnAborted, failed: true, intr: true},
		{name: "run_terminal abort code beats provider_error", meta: &abort, want: models.ActionTurnAborted, failed: true},
		{name: "run_terminal cancelled", meta: &transcriptMeta{Kind: "run_terminal", Status: "cancelled"}, want: models.ActionTurnAborted, failed: true},
		{name: "run_terminal provider error", meta: &transcriptMeta{Kind: "run_terminal", Reason: "provider_error"}, want: models.ActionAPIError, failed: true},
		{name: "run_terminal tool error", meta: &transcriptMeta{Kind: "run_terminal", Reason: "tool_error"}, want: models.ActionTurnAborted, failed: true},
		{name: "provider_retry", meta: &transcriptMeta{Kind: "provider_retry"}, want: models.ActionAPIError, failed: true},
		{name: "continuation after provider failure", meta: &transcriptMeta{Kind: "runtime_continuation", RecoveryReason: "provider_retry_exhausted"}, want: models.ActionAPIError, failed: true},
		{name: "continuation, other reason", meta: &transcriptMeta{Kind: "runtime_continuation", RecoveryReason: "tool_loop"}, want: models.ActionPromptContext},
		{name: "background notification", meta: &transcriptMeta{Kind: "background_task_notification", Owner: "runtime"}, want: models.ActionPromptContext},
		{name: "runtime steer", meta: &transcriptMeta{Kind: "runtime_steer", Owner: "runtime"}, want: models.ActionPromptContext},
		{name: "unknown future kind is never a prompt", meta: &transcriptMeta{Kind: "brand_new_kind", Owner: "runtime"}, want: models.ActionPromptContext},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := userAuthored(tc.meta); got != tc.prompt {
				t.Fatalf("userAuthored = %v, want %v", got, tc.prompt)
			}
			if tc.prompt {
				return
			}
			d := classifyHarness(tc.meta)
			if d.Action != tc.want || d.Failed != tc.failed || d.Interrupt != tc.intr {
				t.Errorf("classifyHarness = %+v, want action %q failed %v interrupt %v", d, tc.want, tc.failed, tc.intr)
			}
		})
	}
}

// TestSubagentSession pins the live sub-agent shape: the child is its own
// session with a `subagent_` id (not `sess_`), linked to its parent through
// session_relations, and every event and token row it emits is a sidechain.
func TestSubagentSession(t *testing.T) {
	res, _ := parseAll(t, "fixture-probe-wsl.sql")

	child := eventsFor(res, probeChild)
	if len(child) == 0 {
		t.Fatal("no events for the sub-agent's own session")
	}
	for _, e := range child {
		if !e.IsSidechain {
			t.Errorf("child event %s not flagged sidechain", e.SourceEventID)
		}
		if e.Metadata == nil || !e.Metadata.IsSubagent || e.Metadata.ParentSessionID != probeParent {
			t.Errorf("child event %s metadata = %+v, want IsSubagent + ParentSessionID", e.SourceEventID, e.Metadata)
		}
	}
	for _, e := range eventsFor(res, probeParent) {
		if e.IsSidechain || (e.Metadata != nil && e.Metadata.IsSubagent) {
			t.Errorf("parent event %s must not be a sidechain: %+v", e.SourceEventID, e)
		}
	}
	var childTokens int
	for _, tk := range res.TokenEvents {
		if tk.SessionID == probeChild {
			childTokens++
			if !tk.IsSidechain {
				t.Errorf("child token row %s not flagged sidechain", tk.SourceEventID)
			}
		} else if tk.IsSidechain {
			t.Errorf("non-child token row %s flagged sidechain", tk.SourceEventID)
		}
	}
	if childTokens != 1 {
		t.Errorf("child token rows = %d, want 1", childTokens)
	}

	var found bool
	for _, l := range res.SessionLineages {
		if l.SessionID == probeChild && l.ParentThreadID == probeParent && l.ThreadSource == "subagent" {
			found = true
		}
	}
	if !found {
		t.Errorf("no subagent lineage child->parent in %+v", res.SessionLineages)
	}
}

// TestSubagentOriginWithoutRelationRow: the child's own settings carry the
// parent pointer, so the lineage and the sidechain flag do not depend on the
// relation row having been written yet.
func TestSubagentOriginWithoutRelationRow(t *testing.T) {
	dbPath, root := buildStore(t)
	execAll(t, dbPath,
		`INSERT INTO sessions VALUES('subagent_1_orphan','/x/p','Subagent w','active',NULL,NULL,NULL,'2026-10-21T12:00:00.000Z','2026-10-21T12:00:00.000Z',1)`,
		`INSERT INTO session_states VALUES('subagent_1_orphan','openrouter','m/x','start','{"metadata":{"__subagentOrigin":true,"subagentType":"tui_worker","parentSessionId":"sess_1_parent"}}','{}','agent',1)`,
		`INSERT INTO messages VALUES('msg_a','subagent_1_orphan','assistant','[{"type":"text","text":"done"}]',NULL,NULL,'{"runId":"run_a"}','0001-0','2026-10-21T12:00:01.000Z','2026-10-21T12:00:01.000Z')`,
	)
	res, err := NewWithOptions(nil, []string{root}).ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) != 1 || !res.ToolEvents[0].IsSidechain || res.ToolEvents[0].Metadata.ParentSessionID != "sess_1_parent" {
		t.Fatalf("events = %+v", res.ToolEvents)
	}
	if len(res.SessionLineages) != 1 || res.SessionLineages[0].ParentThreadID != "sess_1_parent" || res.SessionLineages[0].ThreadSource != "subagent" {
		t.Errorf("lineages = %+v", res.SessionLineages)
	}
}

// TestPermissionModeAndBranch: session_states.permissionSettings
// .humanApprovalMode -> PermissionMode, currentMode -> CollaborationMode,
// settings.metadata.lastUsedGitBranch -> GitBranch.
func TestPermissionModeAndBranch(t *testing.T) {
	res, _ := parseAll(t, "fixture-wsl.sql", "fixture-probe-wsl.sql")
	const sid = "sess_1792562933471_0gxgbenesl7a"
	if len(eventsFor(res, sid)) == 0 {
		t.Fatal("no events for the live WSL session")
	}
	for _, e := range eventsFor(res, sid) {
		if e.GitBranch != "master" {
			t.Errorf("%s GitBranch = %q, want master (lastUsedGitBranch)", e.SourceEventID, e.GitBranch)
		}
		if e.Metadata == nil || e.Metadata.PermissionMode != "auto" || e.Metadata.CollaborationMode != "agent" {
			t.Errorf("%s metadata = %+v, want permission auto / mode agent", e.SourceEventID, e.Metadata)
		}
	}
	for _, tk := range res.TokenEvents {
		if tk.SessionID == sid && tk.GitBranch != "master" {
			t.Errorf("token row %s GitBranch = %q", tk.SourceEventID, tk.GitBranch)
		}
	}
	for _, e := range eventsFor(res, probeParent) {
		if e.Metadata == nil || e.Metadata.PermissionMode != "never" {
			t.Errorf("%s metadata = %+v, want permission never", e.SourceEventID, e.Metadata)
		}
		if e.GitBranch != "" {
			t.Errorf("%s GitBranch = %q, want empty (no lastUsedGitBranch)", e.SourceEventID, e.GitBranch)
		}
	}
}

// TestThinkingBeforeTextOnlyMessage: a thinking -> text message (no tool call)
// keeps its reasoning on the assistant_message row; with a tool call present
// the reasoning still goes to the tool (what it explains).
func TestThinkingBeforeTextOnlyMessage(t *testing.T) {
	dbPath, root := buildStore(t)
	execAll(t, dbPath,
		`INSERT INTO sessions VALUES('sess_1_r','/x/p','t','active',NULL,NULL,NULL,'2026-10-21T12:00:00.000Z','2026-10-21T12:00:00.000Z',1)`,
		`INSERT INTO messages VALUES('msg_1','sess_1_r','assistant','[{"type":"thinking","thinking":"plan A"},{"type":"text","text":"answer"}]',NULL,NULL,'{"runId":"run_a"}','0001-0','2026-10-21T12:00:01.000Z','2026-10-21T12:00:01.000Z')`,
		`INSERT INTO messages VALUES('msg_2','sess_1_r','assistant','[{"type":"thinking","thinking":"plan B"},{"type":"text","text":"narration"},{"type":"tool_use","id":"c1","name":"read","input":{"path":"a.go"}}]',NULL,NULL,'{"runId":"run_a"}','0002-0','2026-10-21T12:00:02.000Z','2026-10-21T12:00:02.000Z')`,
	)
	res, err := NewWithOptions(nil, []string{root}).ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range res.ToolEvents {
		got[e.ActionType+"|"+e.Target] = e.PrecedingReasoning
	}
	if got[models.ActionAssistantMessage+"|answer"] != "plan A" {
		t.Errorf("text-only message reasoning = %q", got[models.ActionAssistantMessage+"|answer"])
	}
	if got[models.ActionAssistantMessage+"|narration"] != "" || got[models.ActionReadFile+"|a.go"] != "plan B" {
		t.Errorf("with a tool call the reasoning belongs to the tool: %+v", got)
	}
}

func TestInstallVersion(t *testing.T) {
	write := func(t *testing.T, dir, body string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("binaries dir, highest semver wins", func(t *testing.T) {
		home := t.TempDir()
		for _, v := range []string{"0.5.9", "0.5.21", "0.5.3", "notaversion"} {
			if err := os.MkdirAll(filepath.Join(home, ".dimcode", "binaries", "dimcode-linux-x64", v), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if got := installVersion(filepath.Join(home, ".dimcode", "v2")); got != "0.5.21" {
			t.Errorf("installVersion = %q, want 0.5.21", got)
		}
	})
	t.Run("npm package.json fallback", func(t *testing.T) {
		home := t.TempDir()
		write(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "dimcode"), `{"name":"dimcode","version":"0.5.21"}`)
		if got := installVersion(filepath.Join(home, ".dimcode", "v2")); got != "0.5.21" {
			t.Errorf("installVersion = %q, want 0.5.21", got)
		}
	})
	t.Run("a different package is not the tool", func(t *testing.T) {
		home := t.TempDir()
		write(t, filepath.Join(home, ".npm-global", "lib", "node_modules", "dimcode"), `{"name":"other","version":"9.9.9"}`)
		if got := installVersion(filepath.Join(home, ".dimcode", "v2")); got != "" {
			t.Errorf("installVersion = %q, want empty", got)
		}
	})
	t.Run("nothing installed", func(t *testing.T) {
		if got := installVersion(filepath.Join(t.TempDir(), ".dimcode", "v2")); got != "" {
			t.Errorf("installVersion = %q, want empty", got)
		}
	})
	if !semverLess("0.5.9", "0.5.21") || semverLess("1.0.0", "1.0.0-rc.1") || !semverLess("1.0.0-rc.1", "1.0.0") {
		t.Error("semverLess ordering")
	}
}

// TestEverySessionStampedWithInstalledVersion: the store records no
// per-session version, so every touched session (sub-agents included) gets the
// installed build (operator ruling 2026-10-21).
func TestEverySessionStampedWithInstalledVersion(t *testing.T) {
	dbPath, root := buildStore(t, "fixture-probe-wsl.sql")
	bin := filepath.Join(filepath.Dir(root), "binaries", "dimcode-linux-x64", "0.5.21")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, []string{root}).ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	stamped := map[string]string{}
	for _, v := range res.SessionToolVersions {
		stamped[v.SessionID] = v.Version
	}
	if len(stamped) != 5 {
		t.Errorf("stamped sessions = %d, want 5: %v", len(stamped), stamped)
	}
	for sid, v := range stamped {
		if v != "0.5.21" {
			t.Errorf("session %s version = %q", sid, v)
		}
	}
	if stamped[probeChild] == "" {
		t.Error("the sub-agent session must carry the version too")
	}
}

func TestReadTranscript(t *testing.T) {
	dbPath, root := buildStore(t, "fixture-probe-wsl.sql")
	a := NewWithOptions(nil, []string{root})
	ctx := context.Background()

	// Parent: the delegated spawn, its wait, and the final answer. The
	// background-task notification row is runtime-injected, not a message.
	msgs, err := a.ReadTranscript(ctx, models.Session{ID: probeParent}, []string{dbPath + "-wal"})
	if err != nil {
		t.Fatal(err)
	}
	var roles []string
	for _, m := range msgs {
		roles = append(roles, string(m.Role))
		if strings.Contains(m.Text, "<notification>") {
			t.Errorf("runtime notification leaked into the transcript: %q", m.Text)
		}
	}
	if strings.Join(roles, ",") != "user,assistant" {
		t.Fatalf("roles = %v, want [user assistant]", roles)
	}
	if msgs[0].ID == "" || msgs[0].Index != 0 || msgs[1].Index != 1 {
		t.Errorf("ids/indices = %+v", msgs)
	}
	asst := msgs[1]
	if len(asst.ToolCalls) != 2 || asst.ToolCalls[0].Name != "agent" || asst.ToolCalls[1].Name != "wait" {
		t.Fatalf("assistant tool calls = %+v", asst.ToolCalls)
	}
	for _, c := range asst.ToolCalls {
		if !c.Resolved {
			t.Errorf("call %s (%s) not resolved", c.ID, c.Name)
		}
	}
	if !strings.Contains(asst.Text, "probe file alpha") || asst.Model != "poolside/laguna-xs-2.1:free" {
		t.Errorf("assistant = %q model %q", asst.Text, asst.Model)
	}

	// Sub-agent session reads under its own id (no hint: derived from roots).
	sub, err := a.ReadTranscript(ctx, models.Session{ID: probeChild}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 2 || sub[0].Role != models.TranscriptUser || len(sub[1].ToolCalls) != 1 || sub[1].ToolCalls[0].Name != "read" || !sub[1].ToolCalls[0].Resolved {
		t.Fatalf("sub-agent transcript = %+v", sub)
	}
	if _, err := a.ReadTranscriptFull(ctx, models.Session{ID: probeChild}, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := NewWithOptions(nil, []string{filepath.Join(t.TempDir(), "none")}).ReadTranscript(ctx, models.Session{ID: probeChild}, nil); err == nil {
		t.Error("a missing store must error")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := a.ReadTranscript(cctx, models.Session{ID: probeChild}, nil); err == nil {
		t.Error("a cancelled context must error")
	}
}

func TestReadTranscriptFullIsUncapped(t *testing.T) {
	dbPath, root := buildStore(t)
	big := strings.Repeat("x", 9000)
	execAll(t, dbPath,
		`INSERT INTO sessions VALUES('sess_1_big','/x/p','t','active',NULL,NULL,NULL,'2026-10-21T12:00:00.000Z','2026-10-21T12:00:00.000Z',1)`,
		`INSERT INTO messages VALUES('m1','sess_1_big','assistant','[{"type":"tool_use","id":"c1","name":"read","input":{"path":"a"}}]',NULL,NULL,'{"runId":"r"}','0001-0','2026-10-21T12:00:01.000Z','2026-10-21T12:00:01.000Z')`,
		`INSERT INTO messages VALUES('m2','sess_1_big','tool_result','[{"type":"tool_result","tool_use_id":"c1","content":"`+big+`"}]',NULL,'{"runId":"r","toolCallId":"c1"}',NULL,'0002-0','2026-10-21T12:00:02.000Z','2026-10-21T12:00:02.000Z')`,
	)
	a := NewWithOptions(nil, []string{root})
	capped, err := a.ReadTranscript(context.Background(), models.Session{ID: "sess_1_big"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	full, err := a.ReadTranscriptFull(context.Background(), models.Session{ID: "sess_1_big"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(capped[0].ToolCalls[0].ResultExcerpt); got >= len(big) {
		t.Errorf("default reader result = %d bytes, want an excerpt", got)
	}
	if got := len(full[0].ToolCalls[0].ResultExcerpt); got != len(big) {
		t.Errorf("full reader result = %d bytes, want %d", got, len(big))
	}
}

// TestLiveWindowsProbe: the Windows-side probe store (raw C:\ cwd) parses the
// same way: harness rows classified, no user prompt from a recovery notice.
func TestLiveWindowsProbe(t *testing.T) {
	res, _ := parseAll(t, "fixture-probe-win.sql")
	for _, e := range eventsOfType(res, models.ActionUserPrompt) {
		if strings.Contains(e.Target, "runtime-recovery") || strings.Contains(e.Target, "Previous run ended") {
			t.Errorf("harness row as user prompt: %q", e.Target)
		}
	}
	if n := len(eventsOfType(res, models.ActionAPIError)); n != 1 {
		t.Errorf("api_error rows = %d, want 1 (runtime_continuation)", n)
	}
	if n := len(eventsOfType(res, models.ActionTurnAborted)); n != 1 {
		t.Errorf("turn_aborted rows = %d, want 1 (hook-blocked prompt)", n)
	}
	for _, e := range res.ToolEvents {
		if e.Metadata == nil || e.Metadata.PermissionMode != "never" {
			t.Errorf("%s metadata = %+v", e.SourceEventID, e.Metadata)
		}
	}
}
