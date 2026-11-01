package deepseek

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fixture copies a testdata .zstd session log into a session-shaped path
// under a temp watch root and returns (adapter, path).
func fixture(t *testing.T, name string) (*Adapter, string) {
	t.Helper()
	return fixtureAs(t, name, sessionLogName)
}

// fixtureAs is fixture with an explicit on-disk basename, so a test can
// place a fixture under a versioned name (session.v4.jsonl.zstd).
func fixtureAs(t *testing.T, name, base string) (*Adapter, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), ".dsh", "sessions")
	dir := filepath.Join(root, "--work-project--", "session-019f1111-2222-7333-8444-555555555555")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := filepath.Join("..", "..", "..", "testdata", "deepseek", name)
	body, err := os.ReadFile(src) //nolint:gosec // test fixture path
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	dst := filepath.Join(dir, base)
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return NewWithOptions(nil, root), dst
}

func parse(t *testing.T, a *Adapter, path string, from int64) adapter.ParseResult {
	t.Helper()
	res, err := a.ParseSessionFile(context.Background(), path, from)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return res
}

func TestWatchPathsEndInDshSessions(t *testing.T) {
	for _, p := range New().WatchPaths() {
		if !strings.HasSuffix(filepath.ToSlash(p), "/.dsh/sessions") {
			t.Errorf("watch root %q does not end in .dsh/sessions", p)
		}
	}
}

// TestIsSessionFile pins BOTH halves of the predicate: the shape check
// alone (basename == session.jsonl.zstd under a .dsh/sessions path) is not
// enough — the path must also be under this adapter's own watch roots, or
// a foreign adapter's tree with a same-shaped file would be misclaimed.
func TestIsSessionFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".dsh", "sessions")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	a := NewWithOptions(nil, root)

	cases := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "in watch root, correct shape",
			path: filepath.Join(root, "--work-project--", "session-abc", sessionLogName),
			want: true,
		},
		{
			name: "in watch root, versioned basename (v4)",
			path: filepath.Join(root, "--work-project--", "session-abc", "session.v4.jsonl.zstd"),
			want: true,
		},
		{
			name: "in watch root, versioned basename upper-cased",
			path: filepath.Join(root, "--work-project--", "session-abc", "SESSION.V12.JSONL.ZSTD"),
			want: true,
		},
		{
			name: "in watch root, versioned basename with no digits",
			path: filepath.Join(root, "--work-project--", "session-abc", "session.v.jsonl.zstd"),
			want: false,
		},
		{
			name: "in watch root, wrong basename",
			path: filepath.Join(root, "--work-project--", "session-abc", "session.jsonl"),
			want: false,
		},
		{
			name: "correct shape, outside watch root",
			path: filepath.Join(t.TempDir(), ".dsh", "sessions", "--other--", "session-x", sessionLogName),
			want: false,
		},
		{
			name: "off-limits credentials file, never claimed",
			path: filepath.Join(filepath.Dir(root), ".credentials.yaml"),
			want: false,
		},
		{
			name: "off-limits settings file, never claimed",
			path: filepath.Join(filepath.Dir(root), "settings.yaml"),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestSessionLogRank pins the accepted session-log basenames and their
// version ranks, one row per shape.
func TestSessionLogRank(t *testing.T) {
	cases := []struct {
		base     string
		wantRank int
		wantOK   bool
	}{
		{"session.jsonl.zstd", unversionedRank, true},
		{"Session.JSONL.zstd", unversionedRank, true},
		{"session.v0.jsonl.zstd", 0, true},
		{"session.v4.jsonl.zstd", 4, true},
		{"session.v12.jsonl.zstd", 12, true},
		{"session.v999999.jsonl.zstd", 999999, true},
		{"session.v1234567.jsonl.zstd", 0, false},
		{"session.v.jsonl.zstd", 0, false},
		{"session.v+4.jsonl.zstd", 0, false},
		{"session.v-4.jsonl.zstd", 0, false},
		{"session.v4a.jsonl.zstd", 0, false},
		{"session.v4.jsonl", 0, false},
		{"session.jsonl", 0, false},
		{"session.v4.jsonl.zstd.tmp", 0, false},
		{".credentials.yaml", 0, false},
		{"settings.yaml", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.base, func(t *testing.T) {
			rank, ok := sessionLogRank(tc.base)
			if ok != tc.wantOK || (ok && rank != tc.wantRank) {
				t.Errorf("sessionLogRank(%q) = (%d, %v), want (%d, %v)", tc.base, rank, ok, tc.wantRank, tc.wantOK)
			}
		})
	}
}

// TestParseSessionFileV4 pins FU-93: a session log under the versioned
// basename session.v4.jsonl.zstd parses exactly like the unversioned one
// (same header keys, same record types).
func TestParseSessionFileV4(t *testing.T) {
	a, path := fixtureAs(t, "session.v4.jsonl.zstd", "session.v4.jsonl.zstd")
	if !a.IsSessionFile(path) {
		t.Fatalf("IsSessionFile(%q) = false, want true", path)
	}
	res := parse(t, a, path, 0)

	wantSession := "session-019f2222-3333-7444-8555-666666666666"
	actions := map[string]int{}
	for _, ev := range res.ToolEvents {
		if ev.SessionID != wantSession {
			t.Errorf("ToolEvent %q SessionID = %q, want %q", ev.SourceEventID, ev.SessionID, wantSession)
		}
		actions[ev.ActionType]++
	}
	if actions[models.ActionUserPrompt] != 1 {
		t.Errorf("user prompts = %d, want 1 (plugin-injected message filtered)", actions[models.ActionUserPrompt])
	}
	if actions[models.ActionReadFile] != 1 || actions[models.ActionRunCommand] != 1 {
		t.Errorf("actions = %v, want one read_file and one run_command", actions)
	}
	if len(res.TokenEvents) != 2 {
		t.Fatalf("got %d TokenEvents, want 2", len(res.TokenEvents))
	}
	if got := res.TokenEvents[1]; got.InputTokens != 900 || got.CacheReadTokens != 6144 || got.OutputTokens != 64 {
		t.Errorf("TokenEvents[1] = in %d / cache %d / out %d, want 900 / 6144 / 64",
			got.InputTokens, got.CacheReadTokens, got.OutputTokens)
	}
	for _, w := range res.Warnings {
		t.Errorf("unexpected warning: %s", w)
	}
}

// TestParseSessionFileHighestVersionWins pins the supersede rule: when one
// session directory holds more than one session log, only the
// highest-versioned one yields events, so an upgraded Harness that leaves
// its old log behind is never ingested twice.
func TestParseSessionFileHighestVersionWins(t *testing.T) {
	a, legacy := fixture(t, "session.jsonl.zstd")
	dir := filepath.Dir(legacy)
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "deepseek", "session.v4.jsonl.zstd"))
	if err != nil {
		t.Fatalf("read v4 fixture: %v", err)
	}
	v4 := filepath.Join(dir, "session.v4.jsonl.zstd")
	v10 := filepath.Join(dir, "session.v10.jsonl.zstd")
	for _, p := range []string{v4, v10} {
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	cases := []struct {
		name       string
		path       string
		wantEvents bool
	}{
		{"unversioned log superseded", legacy, false},
		{"v4 superseded by v10 (numeric, not lexical, order)", v4, false},
		{"v10 is the highest and is parsed", v10, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !a.IsSessionFile(tc.path) {
				t.Fatalf("IsSessionFile(%q) = false, want true (shape match is independent of siblings)", tc.path)
			}
			res := parse(t, a, tc.path, 0)
			got := len(res.ToolEvents)+len(res.TokenEvents) > 0
			if got != tc.wantEvents {
				t.Errorf("events emitted = %v (%d tool, %d token), want %v",
					got, len(res.ToolEvents), len(res.TokenEvents), tc.wantEvents)
			}
			fi, err := os.Stat(tc.path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if res.NewOffset != fi.Size() {
				t.Errorf("NewOffset = %d, want %d (a superseded log still advances its watermark)", res.NewOffset, fi.Size())
			}
		})
	}
}

func TestParseSessionFileEmptyOrUnchanged(t *testing.T) {
	a, path := fixture(t, "session.jsonl.zstd")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Re-parsing from the file's own current size is the "unchanged, whole
	// file already rewritten and re-seen" short-circuit — the whole-file-
	// rescan contract's core no-op case.
	res := parse(t, a, path, fi.Size())
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf("unchanged-offset parse produced events: %d tool, %d token", len(res.ToolEvents), len(res.TokenEvents))
	}
	if res.NewOffset != fi.Size() {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, fi.Size())
	}
}

func TestParseSessionFileHappyPath(t *testing.T) {
	a, path := fixture(t, "session.jsonl.zstd")
	res := parse(t, a, path, 0)

	// --- Session id / project root propagation ---
	wantSession := "session-019f1111-2222-7333-8444-555555555555"
	for i, ev := range res.ToolEvents {
		if ev.SessionID != wantSession {
			t.Errorf("ToolEvents[%d].SessionID = %q, want %q", i, ev.SessionID, wantSession)
		}
	}
	for i, ev := range res.TokenEvents {
		if ev.SessionID != wantSession {
			t.Errorf("TokenEvents[%d].SessionID = %q, want %q", i, ev.SessionID, wantSession)
		}
	}

	// --- Exactly one genuine user prompt captured; the plugin-injected
	// pseudo-user message must NOT appear. ---
	var prompts []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			prompts = append(prompts, ev)
		}
	}
	if len(prompts) != 1 {
		t.Fatalf("got %d ActionUserPrompt events, want 1 (plugin-injected user/message must be filtered)", len(prompts))
	}
	if !strings.Contains(prompts[0].Target, "List the files") {
		t.Errorf("prompt target = %q, want it to contain the real user text", prompts[0].Target)
	}
	for _, ev := range res.ToolEvents {
		if strings.Contains(ev.Target, "sandbox/approval-policy") || strings.Contains(ev.RawToolInput, "dsh-system-prompt") {
			t.Errorf("plugin-injected user/message leaked into a ToolEvent: %+v", ev)
		}
	}

	// --- Tool-call actions mapped correctly. ---
	byRawName := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "glob" || ev.RawToolName == "write" || ev.RawToolName == "totally_unknown_tool" {
			byRawName[ev.RawToolName] = ev
		}
	}
	glob, ok := byRawName["glob"]
	if !ok {
		t.Fatal("no glob ToolEvent found")
	}
	if glob.ActionType != models.ActionSearchFiles {
		t.Errorf("glob ActionType = %q, want %q", glob.ActionType, models.ActionSearchFiles)
	}
	if !glob.Success {
		t.Errorf("glob Success = false, want true")
	}
	if !strings.Contains(glob.ToolOutput, "README.md") {
		t.Errorf("glob ToolOutput = %q, want it to contain the result text", glob.ToolOutput)
	}

	write, ok := byRawName["write"]
	if !ok {
		t.Fatal("no write ToolEvent found")
	}
	if write.ActionType != models.ActionWriteFile {
		t.Errorf("write ActionType = %q, want %q", write.ActionType, models.ActionWriteFile)
	}
	if write.ContentBytes == 0 {
		t.Errorf("write ContentBytes = 0, want authored content length")
	}

	unknown, ok := byRawName["totally_unknown_tool"]
	if !ok {
		t.Fatal("no totally_unknown_tool ToolEvent found")
	}
	if unknown.ActionType != models.ActionUnknown {
		t.Errorf("unknown tool ActionType = %q, want %q", unknown.ActionType, models.ActionUnknown)
	}
	if unknown.Success {
		t.Errorf("unknown tool Success = true, want false (tool/result isError:true)")
	}
	if unknown.ErrorMessage == "" {
		t.Errorf("unknown tool ErrorMessage empty, want the tool/result error text")
	}
	var sawUnrecognisedWarning bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "unrecognised tool name") {
			sawUnrecognisedWarning = true
		}
	}
	if !sawUnrecognisedWarning {
		t.Errorf("expected an unrecognised-tool-name warning, got: %v", res.Warnings)
	}

	// --- Token events: NET input, no double-subtraction of cache. ---
	if len(res.TokenEvents) != 3 {
		t.Fatalf("got %d TokenEvents, want 3", len(res.TokenEvents))
	}
	// Row 2 (index 1) is the cacheReadTokens:7680 row proving inputTokens is
	// already NET of cache (4011 < 7680 is only possible if so).
	cacheRow := res.TokenEvents[1]
	if cacheRow.InputTokens != 4011 {
		t.Errorf("cacheRow.InputTokens = %d, want 4011 (no double-netting)", cacheRow.InputTokens)
	}
	if cacheRow.CacheReadTokens != 7680 {
		t.Errorf("cacheRow.CacheReadTokens = %d, want 7680", cacheRow.CacheReadTokens)
	}
	if cacheRow.OutputTokens != 96 {
		t.Errorf("cacheRow.OutputTokens = %d, want 96", cacheRow.OutputTokens)
	}
	for _, ev := range res.TokenEvents {
		if ev.Model != "deepseek/deepseek-v4-flash" {
			t.Errorf("TokenEvent.Model = %q, want deepseek/deepseek-v4-flash", ev.Model)
		}
		if ev.Source != models.TokenSourceJSONL {
			t.Errorf("TokenEvent.Source = %q, want %q", ev.Source, models.TokenSourceJSONL)
		}
		if ev.Reliability != models.ReliabilityApproximate {
			t.Errorf("TokenEvent.Reliability = %q, want %q", ev.Reliability, models.ReliabilityApproximate)
		}
	}

	// --- No aborted-turn event on a "completed" turn/end. ---
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionTurnAborted {
			t.Errorf("unexpected ActionTurnAborted on a completed turn: %+v", ev)
		}
	}

	// --- NewOffset watermark is the file's current size. ---
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if res.NewOffset != fi.Size() {
		t.Errorf("NewOffset = %d, want %d", res.NewOffset, fi.Size())
	}
}

func TestParseSessionFileAbortedTurn(t *testing.T) {
	a, path := fixture(t, "session-aborted.jsonl.zstd")
	res := parse(t, a, path, 0)

	var aborted []models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionTurnAborted {
			aborted = append(aborted, ev)
		}
	}
	if len(aborted) != 1 {
		t.Fatalf("got %d ActionTurnAborted events, want 1", len(aborted))
	}
	if aborted[0].Success {
		t.Errorf("aborted turn Success = true, want false")
	}
	if aborted[0].Target != "cancelled" {
		t.Errorf("aborted turn Target = %q, want %q", aborted[0].Target, "cancelled")
	}

	if len(res.TokenEvents) != 1 {
		t.Fatalf("got %d TokenEvents, want 1", len(res.TokenEvents))
	}
	if res.TokenEvents[0].Model != "deepseek/deepseek-v4-pro" {
		t.Errorf("TokenEvent.Model = %q, want deepseek/deepseek-v4-pro", res.TokenEvents[0].Model)
	}
}

func TestParseSessionFileWholeFileRescanIsDeterministic(t *testing.T) {
	// Re-parsing the SAME unchanged file from offset 0 twice must produce
	// identical SourceEventIDs both times — the store's dedup index relies
	// on this determinism since there is no meaningful byte offset to
	// resume from (the file is rewritten whole on every flush).
	a, path := fixture(t, "session.jsonl.zstd")
	first := parse(t, a, path, 0)
	second := parse(t, a, path, 0)

	if len(first.ToolEvents) != len(second.ToolEvents) {
		t.Fatalf("tool event count differs across identical re-parses: %d vs %d", len(first.ToolEvents), len(second.ToolEvents))
	}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != second.ToolEvents[i].SourceEventID {
			t.Errorf("ToolEvents[%d].SourceEventID differs across re-parses: %q vs %q",
				i, first.ToolEvents[i].SourceEventID, second.ToolEvents[i].SourceEventID)
		}
	}
	for i := range first.TokenEvents {
		if first.TokenEvents[i].SourceEventID != second.TokenEvents[i].SourceEventID {
			t.Errorf("TokenEvents[%d].SourceEventID differs across re-parses: %q vs %q",
				i, first.TokenEvents[i].SourceEventID, second.TokenEvents[i].SourceEventID)
		}
	}
}

var _ adapter.Adapter = (*Adapter)(nil)
