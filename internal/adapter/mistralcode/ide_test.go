package mistralcode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	ideFixtureDir = "../../../testdata/mistralcode/ide/sessions"
	ideFixtureID  = "11111111-2222-4333-8444-555555555555"
)

// stageIDEStore copies the synthetic IDE fixture (document + index) into a
// temp `sessions` directory so watch-root gating behaves as it does on a
// real install.
func stageIDEStore(t *testing.T) (root, docPath string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), ideHomeDirName, ideSessionsDirName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ideFixtureID + ".json", ideIndexName} {
		body, err := os.ReadFile(filepath.Join(ideFixtureDir, name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(root, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(root, ideFixtureID+".json")
}

// TestClassifyLayout is the layout-sniffing table: one row per shape the
// package must route, including the near-misses that must NOT be tracked.
func TestClassifyLayout(t *testing.T) {
	tests := []struct {
		name string
		path string
		want layout
	}{
		{"vibe transcript", "/home/u/.vibe/logs/session/session_20260815_090512_a1b2c3d4/messages.jsonl", layoutVibe},
		{"vibe meta sibling", "/home/u/.vibe/logs/session/session_20260815_090512_a1b2c3d4/meta.json", layoutNone},
		{"ide document", "/home/u/.mistralcode/sessions/" + ideFixtureID + ".json", layoutIDE},
		{"ide document windows sep", `C:\Users\u\.mistralcode\sessions\` + ideFixtureID + `.json`, layoutIDE},
		{"ide index", "/home/u/.mistralcode/sessions/sessions.json", layoutNone},
		{"ide nested artifact", "/home/u/.mistralcode/sessions/index/chunks.json", layoutNone},
		{"env-root ide document", "/opt/mc/sessions/" + ideFixtureID + ".json", layoutIDE},
		{"unrelated json", "/home/u/.mistralcode/config.json", layoutNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyLayout(tc.path); got != tc.want {
				t.Errorf("classifyLayout(%q) = %d, want %d", tc.path, got, tc.want)
			}
		})
	}
}

// TestDefaultRoots_MistralCodeGlobalDirOverride covers the
// $MISTRALCODE_GLOBAL_DIR env override (audit class C7) and pins that the
// vibe roots survive alongside it, without duplicates.
func TestDefaultRoots_MistralCodeGlobalDirOverride(t *testing.T) {
	gd := t.TempDir()
	t.Setenv(ideGlobalDirEnv, gd)
	roots := defaultRoots()

	want := filepath.Clean(filepath.Join(gd, ideSessionsDirName))
	var sawOverride, sawIDEHome, sawVibeHome bool
	seen := map[string]int{}
	for _, r := range roots {
		seen[r]++
		if seen[r] > 1 {
			t.Errorf("defaultRoots() repeated %q", r)
		}
		slash := filepath.ToSlash(r)
		switch {
		case r == want:
			sawOverride = true
		case strings.HasSuffix(slash, "/.mistralcode/sessions"):
			sawIDEHome = true
		case strings.HasSuffix(slash, "/.vibe/logs/session"):
			sawVibeHome = true
		}
	}
	if !sawOverride {
		t.Errorf("defaultRoots() = %v, want the %s override %q", roots, ideGlobalDirEnv, want)
	}
	if !sawIDEHome {
		t.Errorf("defaultRoots() = %v, want a ~/.mistralcode/sessions default", roots)
	}
	if !sawVibeHome {
		t.Errorf("defaultRoots() = %v, want the vibe roots preserved", roots)
	}
}

// TestParseIDESession_Rows walks the synthetic Continue-fork document and
// pins every row the layout mints: prompts, assistant prose, one row per
// toolCalls[] entry with its action + target, and the tool-role outcomes
// folded back onto the calls they answer.
func TestParseIDESession_Rows(t *testing.T) {
	root, docPath := stageIDEStore(t)
	a := NewWithOptions(nil, root)

	if !a.IsSessionFile(docPath) {
		t.Fatalf("IsSessionFile(%q) = false, want true", docPath)
	}
	if a.IsSessionFile(filepath.Join(root, ideIndexName)) {
		t.Error("IsSessionFile accepted the sessions.json index")
	}

	res, err := a.ParseSessionFile(context.Background(), docPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}

	stat, err := os.Stat(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != stat.Size() {
		t.Errorf("NewOffset = %d, want the file size %d (whole-document store)", res.NewOffset, stat.Size())
	}

	byID := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		if _, dup := byID[ev.SourceEventID]; dup {
			t.Errorf("duplicate SourceEventID %q", ev.SourceEventID)
		}
		byID[ev.SourceEventID] = ev
		if ev.Tool != models.ToolMistralCode {
			t.Errorf("Tool = %q, want %q", ev.Tool, models.ToolMistralCode)
		}
		if ev.SessionID != ideFixtureID {
			t.Errorf("SessionID = %q, want %q", ev.SessionID, ideFixtureID)
		}
		if ev.ProjectRoot == "" || ev.ProjectRoot == "[mistral-code]" {
			t.Errorf("ProjectRoot = %q, want the workspaceDirectory", ev.ProjectRoot)
		}
	}

	tests := []struct {
		id         string
		action     string
		target     string
		rawTool    string
		wantOK     bool
		wantOutput string
	}{
		{id: ideFixtureID + ":0", action: models.ActionUserPrompt, target: "add a health endpoint to the server", wantOK: true},
		{id: ideFixtureID + ":1", action: models.ActionAssistantMessage, target: "Let me look at the server first.", wantOK: true},
		{
			id: ideFixtureID + ":1:tool:0", action: models.ActionReadFile, target: "server/main.go",
			rawTool: "builtin_read_file", wantOK: true, wantOutput: "package main",
		},
		{
			id: ideFixtureID + ":1:tool:1", action: models.ActionSearchText, target: "func registerRoutes",
			rawTool: "builtin_grep_search", wantOK: false, wantOutput: "Error: no matches",
		},
		{
			id: ideFixtureID + ":4:tool:0", action: models.ActionEditFile, target: "server/main.go",
			rawTool: "builtin_edit_existing_file", wantOK: true,
		},
		{
			id: ideFixtureID + ":4:tool:1", action: models.ActionRunCommand, target: "go build ./...",
			rawTool: "builtin_run_terminal_command", wantOK: true,
		},
		{
			id: ideFixtureID + ":4:tool:2", action: models.ActionMCPCall, target: "track the healthz rollout",
			rawTool: "mcp__linear__create_issue", wantOK: true,
		},
		{
			id: ideFixtureID + ":4:tool:3", action: models.ActionUnknown, target: "",
			rawTool: "some_future_tool", wantOK: true,
		},
		{id: ideFixtureID + ":5", action: models.ActionAssistantMessage, target: "Added a /healthz handler and the build is clean.", wantOK: true},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			ev, ok := byID[tc.id]
			if !ok {
				t.Fatalf("no event with SourceEventID %q (have %d events)", tc.id, len(byID))
			}
			if ev.ActionType != tc.action {
				t.Errorf("ActionType = %q, want %q", ev.ActionType, tc.action)
			}
			if ev.Target != tc.target {
				t.Errorf("Target = %q, want %q", ev.Target, tc.target)
			}
			if ev.RawToolName != tc.rawTool {
				t.Errorf("RawToolName = %q, want %q", ev.RawToolName, tc.rawTool)
			}
			if ev.Success != tc.wantOK {
				t.Errorf("Success = %v, want %v", ev.Success, tc.wantOK)
			}
			if tc.wantOutput != "" && !strings.Contains(ev.ToolOutput, tc.wantOutput) {
				t.Errorf("ToolOutput = %q, want it to contain %q", ev.ToolOutput, tc.wantOutput)
			}
		})
	}

	// role="tool" entries mint no row of their own.
	for _, id := range []string{ideFixtureID + ":2", ideFixtureID + ":3"} {
		if _, ok := byID[id]; ok {
			t.Errorf("tool-role history entry %s minted a row of its own", id)
		}
	}
	// An assistant entry with empty content mints no assistant_message row.
	if ev, ok := byID[ideFixtureID+":4"]; ok {
		t.Errorf("empty-content assistant entry minted %+v", ev)
	}
}

// TestParseIDESession_Tokens pins the per-message token tier: net input,
// cache read/write split, reasoning, and the promptLogs→chatModelTitle
// model ladder.
func TestParseIDESession_Tokens(t *testing.T) {
	root, docPath := stageIDEStore(t)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), docPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TokenEvents) != 3 {
		t.Fatalf("token events = %d, want 3", len(res.TokenEvents))
	}

	want := []models.TokenEvent{
		{
			SourceEventID: ideFixtureID + ":1:usage", Model: "mistral-medium-3.5",
			InputTokens: 2200, OutputTokens: 310, CacheReadTokens: 12000,
			CacheCreationTokens: 900, ReasoningTokens: 64,
		},
		{
			SourceEventID: ideFixtureID + ":4:usage", Model: "mistral-medium-3.5",
			InputTokens: 15100, OutputTokens: 205,
		},
		{
			// No promptLogs on this entry ⇒ the session's chatModelTitle.
			SourceEventID: ideFixtureID + ":5:usage", Model: "codestral-latest",
			InputTokens: 0, OutputTokens: 42, CacheReadTokens: 15800,
		},
	}
	for i, w := range want {
		got := res.TokenEvents[i]
		if got.SourceEventID != w.SourceEventID {
			t.Errorf("event %d SourceEventID = %q, want %q", i, got.SourceEventID, w.SourceEventID)
		}
		if got.Model != w.Model {
			t.Errorf("event %d Model = %q, want %q", i, got.Model, w.Model)
		}
		if got.InputTokens != w.InputTokens {
			t.Errorf("event %d InputTokens = %d, want %d (gross promptTokens netted vs cachedTokens)",
				i, got.InputTokens, w.InputTokens)
		}
		if got.OutputTokens != w.OutputTokens {
			t.Errorf("event %d OutputTokens = %d, want %d", i, got.OutputTokens, w.OutputTokens)
		}
		if got.CacheReadTokens != w.CacheReadTokens {
			t.Errorf("event %d CacheReadTokens = %d, want %d", i, got.CacheReadTokens, w.CacheReadTokens)
		}
		if got.CacheCreationTokens != w.CacheCreationTokens {
			t.Errorf("event %d CacheCreationTokens = %d, want %d", i, got.CacheCreationTokens, w.CacheCreationTokens)
		}
		if got.ReasoningTokens != w.ReasoningTokens {
			t.Errorf("event %d ReasoningTokens = %d, want %d", i, got.ReasoningTokens, w.ReasoningTokens)
		}
		if got.Tool != models.ToolMistralCode {
			t.Errorf("event %d Tool = %q, want %q", i, got.Tool, models.ToolMistralCode)
		}
		if got.Source != models.TokenSourceJSONL {
			t.Errorf("event %d Source = %q, want %q", i, got.Source, models.TokenSourceJSONL)
		}
	}
}

// TestParseIDESession_Timestamps pins the sessions.json index read: the
// document carries no timestamps, so entry 0 starts at the index's
// dateCreated and each later entry advances 1ms.
func TestParseIDESession_Timestamps(t *testing.T) {
	root, docPath := stageIDEStore(t)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), docPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := time.UnixMilli(1777720080000).UTC()
	first := res.ToolEvents[0]
	if !first.Timestamp.Equal(base) {
		t.Errorf("first Timestamp = %s, want the index dateCreated %s", first.Timestamp, base)
	}
	if got := res.TokenEvents[0].Timestamp; !got.Equal(base.Add(time.Millisecond)) {
		t.Errorf("history[1] Timestamp = %s, want base+1ms", got)
	}
}

// TestParseIDESession_NoIndexFallsBackToModTime pins the degraded path:
// with no sessions.json the document's own mtime stands in, and parsing
// still succeeds.
func TestParseIDESession_NoIndexFallsBackToModTime(t *testing.T) {
	root, docPath := stageIDEStore(t)
	if err := os.Remove(filepath.Join(root, ideIndexName)); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), docPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("no events parsed without the index")
	}
	info, err := os.Stat(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ToolEvents[0].Timestamp.Equal(info.ModTime().UTC()) {
		t.Errorf("first Timestamp = %s, want the document mtime %s",
			res.ToolEvents[0].Timestamp, info.ModTime().UTC())
	}
}

// TestParseIDESession_Idempotent pins the whole-document cursor contract:
// a second parse from the returned offset re-emits the SAME rows with the
// SAME ids, so the store's UNIQUE (source_file, source_event_id) index
// collapses them instead of duplicating the session.
func TestParseIDESession_Idempotent(t *testing.T) {
	root, docPath := stageIDEStore(t)
	a := NewWithOptions(nil, root)
	first, err := a.ParseSessionFile(context.Background(), docPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), docPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.ToolEvents) != len(first.ToolEvents) {
		t.Fatalf("second parse emitted %d tool events, want the same %d",
			len(second.ToolEvents), len(first.ToolEvents))
	}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != second.ToolEvents[i].SourceEventID {
			t.Errorf("event %d id drifted: %q then %q",
				i, first.ToolEvents[i].SourceEventID, second.ToolEvents[i].SourceEventID)
		}
	}
}

// TestParseIDESession_Malformed pins that a half-written document warns
// instead of erroring or panicking.
func TestParseIDESession_Malformed(t *testing.T) {
	root := filepath.Join(t.TempDir(), ideHomeDirName, ideSessionsDirName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "broken.json")
	if err := os.WriteFile(path, []byte(`{"sessionId":"broken","history":`), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("malformed document must not error: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf("malformed document emitted rows")
	}
	if len(res.Warnings) == 0 {
		t.Error("malformed document emitted no warning")
	}
}

// TestSurfaceTable is the per-layout surface table: one row per layout,
// each emitting exactly one stamp from the closed models vocabulary.
func TestSurfaceTable(t *testing.T) {
	ideRoot, docPath := stageIDEStore(t)
	vibeHome := t.TempDir()
	vibePath := writeVibeSession(t, vibeHome)

	tests := []struct {
		name      string
		adapter   *Adapter
		path      string
		wantID    string
		wantKind  string
		wantHost  string
		wantCount int
	}{
		{
			name: "ide layout", adapter: NewWithOptions(nil, ideRoot), path: docPath,
			wantID: ideFixtureID, wantKind: models.SurfaceIDE, wantHost: surfaceHostIDE, wantCount: 1,
		},
		{
			name:    "vibe layout",
			adapter: NewWithOptions(nil, filepath.Join(vibeHome, ".vibe", "logs", "session")),
			path:    vibePath,
			wantID:  "088a17fc", wantKind: models.SurfaceCLI, wantHost: surfaceHostCLI, wantCount: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.adapter.ParseSessionFile(context.Background(), tc.path, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.SessionSurfaces) != tc.wantCount {
				t.Fatalf("SessionSurfaces = %+v, want %d", res.SessionSurfaces, tc.wantCount)
			}
			got := res.SessionSurfaces[0]
			if got.SessionID != tc.wantID {
				t.Errorf("SessionID = %q, want %q", got.SessionID, tc.wantID)
			}
			if got.Surface != tc.wantKind {
				t.Errorf("Surface = %q, want %q", got.Surface, tc.wantKind)
			}
			if !models.KnownSurface(got.Surface) {
				t.Errorf("Surface %q is out of the models vocabulary", got.Surface)
			}
			if got.SurfaceHost != tc.wantHost {
				t.Errorf("SurfaceHost = %q, want %q", got.SurfaceHost, tc.wantHost)
			}
		})
	}
}

// TestMapIDETool is the tool-name table: one row per resolution rung.
func TestMapIDETool(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"builtin_read_file", models.ActionReadFile},
		{"builtin_create_new_file", models.ActionWriteFile},
		{"builtin_edit_existing_file", models.ActionEditFile},
		{"builtin_run_terminal_command", models.ActionRunCommand},
		{"builtin_grep_search", models.ActionSearchText},
		{"builtin_file_glob_search", models.ActionSearchFiles},
		{"builtin_ls", models.ActionSearchFiles},
		{"builtin_search_web", models.ActionWebSearch},
		{"builtin_fetch_url_content", models.ActionWebFetch},
		{"read_file", models.ActionReadFile},
		{"BUILTIN_READ_FILE", models.ActionReadFile},
		{"mcp__server__do_thing", models.ActionMCPCall},
		// Falls through to the vibe table (same vendor, shared names).
		{"bash", models.ActionRunCommand},
		{"ask_user_question", models.ActionAskUser},
		{"totally_unknown_tool", models.ActionUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapIDETool(tc.name); got != tc.want {
				t.Errorf("mapIDETool(%q) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// TestIDETargetFromArgs is the target-extraction table.
func TestIDETargetFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args string
		want string
	}{
		{"filepath", `{"filepath":"a/b.go"}`, "a/b.go"},
		{"camel filePath", `{"filePath":"a/b.go"}`, "a/b.go"},
		{"path", `{"path":"a/b.go"}`, "a/b.go"},
		{"dirpath", `{"dirpath":"a/"}`, "a/"},
		{"command", `{"command":"go test ./..."}`, "go test ./..."},
		{"query", `{"query":"needle"}`, "needle"},
		{"url", `{"url":"https://example.test"}`, "https://example.test"},
		{"filepath wins over query", `{"query":"q","filepath":"a/b.go"}`, "a/b.go"},
		{"no known key", `{"thing":"value"}`, ""},
		{"not json", `not json`, ""},
		{"empty", ``, ""},
		{"non-string value", `{"path":123}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ideTargetFromArgs(tc.args); got != tc.want {
				t.Errorf("ideTargetFromArgs(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

// TestContinueText covers both content shapes Continue writes.
func TestContinueText(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"bare string", `"hello"`, "hello"},
		{"text parts", `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "a\nb"},
		{"mixed parts skips non-text", `[{"type":"imageUrl","imageUrl":{"url":"x"}},{"type":"text","text":"a"}]`, "a"},
		{"null", `null`, ""},
		{"empty array", `[]`, ""},
		{"object", `{"unexpected":true}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := continueText(json.RawMessage(tc.raw)); got != tc.want {
				t.Errorf("continueText(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestParseFlexTime covers every index-timestamp spelling observed across
// Continue versions.
func TestParseFlexTime(t *testing.T) {
	want := time.UnixMilli(1777720080000).UTC()
	tests := []struct {
		name string
		raw  string
		want time.Time
	}{
		{"number ms", `1777720080000`, want},
		{"stringified ms", `"1777720080000"`, want},
		{"iso-8601", `"2026-08-24T09:00:00Z"`, time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)},
		{"null", `null`, time.Time{}},
		{"empty string", `""`, time.Time{}},
		{"garbage", `"not a time"`, time.Time{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseFlexTime(json.RawMessage(tc.raw))
			if !got.Equal(tc.want) {
				t.Errorf("parseFlexTime(%s) = %s, want %s", tc.raw, got, tc.want)
			}
		})
	}
}
