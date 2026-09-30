package cursor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// fixtureHooksLog is cut from REAL Cursor hooks output logs on the
// grounding host (2026-09-19 session 8be96a3f / generation ed2e9caf,
// Cursor 3.20.21; 2026-09-08 session cc8322af mislabelled stop, 3.17.21;
// 2026-09-22 Cloud Agent bc-4e387d38, 3.21.13), anonymised by
// ~/sbo-scratch/s10/cursor/mkfixture.py: prompt/text/content/tool I/O
// replaced, paths and emails rewritten. Usage numbers are verbatim.
const fixtureHooksLog = "../../../testdata/cursor/hooks-log/cursor.hooks.workspaceId-fixture.log"

// placeHooksLog copies body into a realistic Cursor logs tree under a
// temp dir and returns (logsRoot, filePath).
func placeHooksLog(t *testing.T, body []byte) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "AppData", "Roaming", "Cursor", "logs")
	dir := filepath.Join(root, "20260919T130539", "window1_wb4", "output_20260919T193726")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "cursor.hooks.workspaceId-09ea5b34a47ef267ab716b1e66210bf6.log")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, p
}

func readFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(fixtureHooksLog)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// isolateStash points the live on-disk reasoning stash at a temp dir so
// no test touches the operator's ~/.observer.
func isolateStash(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := pendingReasoningDir
	pendingReasoningDir = func() string { return dir }
	t.Cleanup(func() { pendingReasoningDir = prev })
	return dir
}

func TestParseHooksLogFixture(t *testing.T) {
	isolateStash(t)
	root, path := placeHooksLog(t, readFixture(t))
	a := NewWithOptions(nil, root)
	if !a.IsSessionFile(path) {
		t.Fatalf("IsSessionFile(%s) = false", path)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if res.NewOffset != fi.Size() {
		t.Fatalf("NewOffset = %d, want EOF %d", res.NewOffset, fi.Size())
	}
	if len(res.SessionSurfaces) != 0 {
		t.Fatalf("hooks log must not stamp a surface, got %+v", res.SessionSurfaces)
	}

	// The 8be96a3f request: afterAgentResponse + two stop blocks (the
	// claude-user and the cursor hook) all restate one usage record and
	// share ONE identity with the live hook.
	var ed []models.TokenEvent
	for _, tk := range res.TokenEvents {
		if tk.MessageID == "ed2e9caf-ed8d-4485-9865-8af0b65d037d" {
			ed = append(ed, tk)
		}
	}
	if len(ed) != 3 {
		t.Fatalf("ed2e9caf token events = %d, want 3 (aar + 2 stop blocks)", len(ed))
	}
	wantTS := time.Date(2026, 9, 19, 14, 15, 8, 420_000_000, time.UTC)
	for _, tk := range ed {
		if tk.SourceFile != "cursor:hook" || tk.SourceEventID != "ed2e9caf-ed8d-4485-9865-8af0b65d037d:stop" {
			t.Fatalf("identity = %s / %s, want the live hook's", tk.SourceFile, tk.SourceEventID)
		}
		if tk.SessionID != "8be96a3f-5490-4d9c-bb7c-8459b183a8bf" || tk.Model != "cursor-grok-4.6-high" {
			t.Fatalf("session/model = %s / %s", tk.SessionID, tk.Model)
		}
		if tk.InputTokens != 253719 || tk.OutputTokens != 21724 || tk.CacheReadTokens != 2529792 || tk.CacheCreationTokens != 0 {
			t.Fatalf("usage = %d/%d/%d/%d, want 253719/21724/2529792/0 (gross 2783511 netted)", tk.InputTokens, tk.OutputTokens, tk.CacheReadTokens, tk.CacheCreationTokens)
		}
		if tk.Source != models.TokenSourceHook || tk.Reliability != models.ReliabilityAccurate {
			t.Fatalf("tier = %s/%s", tk.Source, tk.Reliability)
		}
	}
	if !ed[0].Timestamp.Equal(wantTS) {
		t.Fatalf("afterAgentResponse ts = %s, want the log's %s", ed[0].Timestamp, wantTS)
	}

	// The hook KIND rides along (review finding F3, 2026-09-26), and a
	// real request's stops - which follow their OWN afterAgentResponse -
	// are never marked as restatements.
	for _, tk := range ed {
		if tk.HookEvent != EventAfterAgentResponse && tk.HookEvent != EventStop {
			t.Fatalf("ed2e9caf hook kind = %q", tk.HookEvent)
		}
		if tk.Restates != "" {
			t.Fatalf("ed2e9caf %s marked as restating %q; its own afterAgentResponse precedes it", tk.HookEvent, tk.Restates)
		}
	}

	// cc8322af: Cursor's mislabelled stop — identical usage under the
	// NEXT generation id. The replay sees both halves, so it PROVES the
	// pair and marks the stop events (the grounded case stays deduped).
	keys := map[string][4]int64{}
	var restating []string
	for _, tk := range res.TokenEvents {
		if tk.SessionID == "cc8322af-e062-47f1-a4ab-5055b938c963" {
			keys[tk.SourceEventID] = [4]int64{tk.InputTokens, tk.OutputTokens, tk.CacheReadTokens, tk.CacheCreationTokens}
			if tk.MessageID == "93c94255-d69d-4b19-a623-6ac06bb6f4b7" {
				if tk.HookEvent != EventStop {
					t.Fatalf("93c94255 kind = %q, want stop", tk.HookEvent)
				}
				restating = append(restating, tk.Restates)
			} else if tk.Restates != "" {
				t.Fatalf("%s marked as restating %q", tk.MessageID, tk.Restates)
			}
		}
	}
	a52, b93 := keys["52f30b63-3669-4351-a9a2-fb79404ff458:stop"], keys["93c94255-d69d-4b19-a623-6ac06bb6f4b7:stop"]
	if a52 != b93 || a52[0] != 15944697-15524224 {
		t.Fatalf("cc8322af pair = %v / %v", a52, b93)
	}
	if len(restating) == 0 {
		t.Fatal("cc8322af: no 93c94255 stop event")
	}
	for _, r := range restating {
		if r != "52f30b63-3669-4351-a9a2-fb79404ff458" {
			t.Fatalf("93c94255 stop Restates = %q, want the proven 52f30b63", r)
		}
	}

	// Action rows replay under the live identity; the root-less Cloud
	// Agent gets the synthetic root; stop mints no row; after-events
	// become outcome updates, never rows.
	byID := map[string]models.ToolEvent{}
	for _, ev := range res.ToolEvents {
		byID[ev.SourceEventID] = ev
		if ev.SourceFile != "cursor:hook" {
			t.Fatalf("replayed row source_file = %q", ev.SourceFile)
		}
	}
	if ev, ok := byID["ed2e9caf-ed8d-4485-9865-8af0b65d037d:beforeSubmitPrompt"]; !ok || ev.ActionType != models.ActionUserPrompt {
		t.Fatalf("user prompt row missing: %+v", byID)
	}
	var cloud *models.ToolEvent
	for _, ev := range res.ToolEvents {
		if ev.SessionID == "bc-4e387d38-4596-4b70-8ca8-5c1f2db7290a" {
			e := ev
			cloud = &e
		}
	}
	if cloud == nil || cloud.ProjectRoot != SyntheticProjectRoot || cloud.ActionType != models.ActionSubagentStart {
		t.Fatalf("cloud agent row = %+v", cloud)
	}
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == EventStop || ev.RawToolName == EventPostToolUse {
			t.Fatalf("event %s must not mint a row", ev.RawToolName)
		}
	}
	if len(res.OutcomeUpdates) != 1 || res.OutcomeUpdates[0].SourceFile != "cursor:hook" {
		t.Fatalf("outcome updates = %+v", res.OutcomeUpdates)
	}
}

func TestParseHooksLogResumesAcrossPartialBlock(t *testing.T) {
	isolateStash(t)
	full := readFixture(t)
	marker := []byte(`"hook_event_name": "afterAgentResponse"`)
	cut := strings.Index(string(full), string(marker))
	if cut < 0 {
		t.Fatal("fixture lacks afterAgentResponse")
	}
	root, path := placeHooksLog(t, full[:cut])
	a := NewWithOptions(nil, root)
	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range first.TokenEvents {
		if tk.MessageID == "ed2e9caf-ed8d-4485-9865-8af0b65d037d" {
			t.Fatalf("partial block emitted a token row")
		}
	}
	if first.NewOffset >= int64(cut) {
		t.Fatalf("NewOffset %d did not stop before the open block (cut %d)", first.NewOffset, cut)
	}
	if err := os.WriteFile(path, full, 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	var got *models.TokenEvent
	for _, tk := range second.TokenEvents {
		if tk.MessageID == "ed2e9caf-ed8d-4485-9865-8af0b65d037d" {
			tk := tk
			got = &tk
			break
		}
	}
	if got == nil || !got.Timestamp.Equal(time.Date(2026, 9, 19, 14, 15, 8, 420_000_000, time.UTC)) {
		t.Fatalf("resumed block = %+v, want the afterAgentResponse row with its log timestamp", got)
	}
}

func TestParseHooksLogRotationAndPartialLine(t *testing.T) {
	isolateStash(t)
	full := readFixture(t)
	root, path := placeHooksLog(t, full)
	a := NewWithOptions(nil, root)
	// A persisted offset beyond the (rotated, smaller) file resets to 0.
	res, err := a.ParseSessionFile(context.Background(), path, int64(len(full))*10)
	if err != nil || len(res.TokenEvents) == 0 {
		t.Fatalf("rotation reset: tokens=%d err=%v", len(res.TokenEvents), err)
	}
	// An unterminated final line is never consumed.
	if err := os.WriteFile(path, append(append([]byte{}, full...), []byte("[2026-09-19T15:00:00.000Z] Hook step requ")...), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = a.ParseSessionFile(context.Background(), path, 0)
	if err != nil || res.NewOffset != int64(len(full)) {
		t.Fatalf("NewOffset = %d, want %d (partial tail unconsumed), err=%v", res.NewOffset, len(full), err)
	}
}

func TestParseHooksLogOversizeTextLine(t *testing.T) {
	isolateStash(t)
	big := strings.Repeat("x", 3<<20)
	body := "[2026-09-19T14:15:08.420Z] Running hook 1 with timeout 60000ms\n" +
		"═══\nafterAgentResponse\n═══\nCommand: observer hook cursor afterAgentResponse (1ms) exit code: 0\n\nINPUT:\n{\n" +
		`  "conversation_id": "c1",` + "\n" +
		`  "generation_id": "g1",` + "\n" +
		`  "model": "cursor-grok-4.6-high",` + "\n" +
		`  "text": "` + big + `",` + "\n" +
		`  "input_tokens": 1000,` + "\n" +
		`  "output_tokens": 10,` + "\n" +
		`  "cache_read_tokens": 400,` + "\n" +
		`  "cache_write_tokens": 0,` + "\n" +
		`  "hook_event_name": "afterAgentResponse",` + "\n" +
		`  "workspace_roots": ["/r"]` + "\n}\n\nOUTPUT:\n{}\n═══\n"
	root, path := placeHooksLog(t, []byte(body))
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TokenEvents) != 1 || res.TokenEvents[0].InputTokens != 600 || res.TokenEvents[0].OutputTokens != 10 {
		t.Fatalf("oversize text dropped usage: %+v", res.TokenEvents)
	}
}

func TestHooksLogReplayNeverTouchesLiveStash(t *testing.T) {
	isolateStash(t)
	// A live Cursor session is mid-turn: its thought is stashed on disk
	// waiting for the next event of THAT conversation.
	defaultStash.stash("8be96a3f-5490-4d9c-bb7c-8459b183a8bf", "live thought")
	root, path := placeHooksLog(t, readFixture(t))
	if _, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), path, 0); err != nil {
		t.Fatal(err)
	}
	if got := defaultStash.take("8be96a3f-5490-4d9c-bb7c-8459b183a8bf", "live-next"); got != "live thought" {
		t.Fatalf("replay consumed or clobbered the live stash: %q", got)
	}
}

func TestMatchesHooksLog(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/mnt/c/Users/u/AppData/Roaming/Cursor/logs/20260919T130539/window1_wb4/output_20260919T193726/cursor.hooks.workspaceId-09ea.log", true},
		{"/mnt/c/Users/u/AppData/Roaming/Cursor/logs/20260908T121927/window1_wb6/output_20260908T123734/cursor.hooks.workspaceId-09ea.1.log", true},
		{`C:\Users\u\AppData\Roaming\Cursor\logs\20260922T144124\window1_wb0\output_20260922T144129\cursor.hooks.workspaceId-empty-window.log`, true},
		{"/home/u/.config/Cursor/logs/x/window1/output_y/cursor.hooks.log", true},
		{"/home/u/Library/Application Support/Cursor/logs/x/window1/output_y/cursor.hooks.workspaceId-a.log", true},
		{"/mnt/c/Users/u/AppData/Roaming/Cursor/logs/x/window1/output_y/cursor.requestTraces.log", false},
		{"/mnt/c/Users/u/AppData/Roaming/Cursor/logs/x/window1/exthost/cursor.hooks.workspaceId-a.log", false},
		{"/mnt/c/Users/u/AppData/Roaming/Code/logs/x/window1/output_y/cursor.hooks.workspaceId-a.log", false},
	}
	for _, tc := range cases {
		if got := matchesHooksLog(tc.path); got != tc.want {
			t.Errorf("matchesHooksLog(%q) = %v, want %v", tc.path, got, tc.want)
		}
		if tc.want && layoutFor(tc.path) != layoutHooksLog {
			t.Errorf("layoutFor(%q) = %v, want layoutHooksLog", tc.path, layoutFor(tc.path))
		}
	}
}

func TestHookProjectRoot(t *testing.T) {
	cases := []struct {
		event, roots, want string
	}{
		{EventBeforeReadFile, `["/repo"]`, "/repo"},
		{EventSubagentStart, `[]`, SyntheticProjectRoot},
		{EventStop, `[]`, SyntheticProjectRoot},
		{EventBeforeSubmitPrompt, ``, SyntheticProjectRoot},
		{EventSessionStart, `[]`, ""},
		{EventSessionEnd, `[]`, ""},
		{EventSessionEnd, `["/repo"]`, "/repo"},
	}
	for _, tc := range cases {
		if got := hookProjectRoot(tc.event, []byte(tc.roots)); got != tc.want {
			t.Errorf("hookProjectRoot(%s, %s) = %q, want %q", tc.event, tc.roots, got, tc.want)
		}
	}
}

// TestParseHooksLogRotationRereadsFromZero: a persisted cursor past EOF
// (Cursor restarted the same path empty after rotating it to .1.log)
// re-reads the new file from 0 and returns the LOWER offset, which the
// declared RewindsOnTruncate lets the watcher store as-is (the watcher
// half is pinned by internal/watcher TestPollerRewindsRotatedCursorHooksLog).
func TestParseHooksLogRotationRereadsFromZero(t *testing.T) {
	isolateStash(t)
	full := readFixture(t)
	root, path := placeHooksLog(t, full)
	a := NewWithOptions(nil, root)
	sem := a.CursorSemanticsFor(path)
	if !sem.RewindMeaningful() || !sem.DeltaGateMeaningful() {
		t.Fatalf("hooks log semantics = %+v, want a rewinding, streaming byte-count cursor", sem)
	}
	stale := int64(50 << 20)
	res, err := a.ParseSessionFile(context.Background(), path, stale)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != int64(len(full)) {
		t.Fatalf("NewOffset = %d, want the new file's EOF %d", res.NewOffset, len(full))
	}
	found := false
	for _, tk := range res.TokenEvents {
		if tk.MessageID == "ed2e9caf-ed8d-4485-9865-8af0b65d037d" {
			found = true
		}
	}
	if !found {
		t.Fatal("rotated file not re-read from 0")
	}
}

// TestReplayReportsUnusableBlocks pins Codex pass-2 finding 6: a block
// the replay cannot use is reported as a content-safe warning (offset +
// event name, never payload bytes) instead of being silently advanced
// past; good blocks around it still replay.
func TestReplayReportsUnusableBlocks(t *testing.T) {
	isolateStash(t)
	log := strings.Join([]string{
		"[2026-09-19T14:15:08.420Z] Running hook 1 with timeout 60000ms",
		"INPUT:",
		`{"hook_event_name":"stop","conversation_id":"c1", "secret-ish": "sk-live-NOT-IN-WARNING",`, // truncated JSON
		"OUTPUT:",
		"{}",
		"[2026-09-19T14:15:09.420Z] Running hook 1 with timeout 60000ms",
		"INPUT:",
		`{"hook_event_name":"afterAgentResponse","conversation_id":"c1","generation_id":"g1","model":"m","workspace_roots":["/repo"],"text":"ok","input_tokens":10,"output_tokens":2,"cache_read_tokens":0,"cache_write_tokens":0}`,
		"OUTPUT:",
		"{}",
		"",
	}, "\n")
	root, path := placeHooksLog(t, []byte(log))
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "offset ") || !strings.Contains(res.Warnings[0], "undecodable") {
		t.Fatalf("warnings = %q, want one content-safe undecodable-block warning", res.Warnings)
	}
	if strings.Contains(res.Warnings[0], "sk-live") {
		t.Fatal("warning leaked payload bytes")
	}
	if len(res.TokenEvents) != 1 {
		t.Fatalf("good block not replayed: %d token events", len(res.TokenEvents))
	}
}

// TestMarkProvenRestatements walks the proof rule for Cursor's mislabelled
// stop one row per case (review finding F3, 2026-09-26): a stop is marked
// only when the SAME conversation's afterAgentResponse for a DIFFERENT
// generation precedes it within 10 s with the same model and byte-identical
// usage, AND its own generation's afterAgentResponse has not fired.
func TestMarkProvenRestatements(t *testing.T) {
	t0 := time.Date(2026, 9, 8, 4, 36, 42, 860_000_000, time.UTC)
	ev := func(kind, gen string, at time.Duration, in int64) models.TokenEvent {
		return models.TokenEvent{
			SessionID: "cc", MessageID: gen, HookEvent: kind, Model: "m", Timestamp: t0.Add(at),
			InputTokens: in, OutputTokens: 53139, CacheReadTokens: 15524224,
		}
	}
	aar, stop := EventAfterAgentResponse, EventStop
	cases := []struct {
		name string
		evs  []models.TokenEvent
		want []string // Restates per event
	}{
		{"grounded mislabelled stop", []models.TokenEvent{ev(aar, "A", 0, 1), ev(stop, "B", 1380*time.Millisecond, 1)}, []string{"", "A"}},
		{"real request: stop follows its own afterAgentResponse", []models.TokenEvent{ev(aar, "A", 0, 1), ev(stop, "A", 400*time.Millisecond, 1)}, []string{"", ""}},
		{"two real requests with equal counters", []models.TokenEvent{
			ev(aar, "A", 0, 1), ev(stop, "A", 400*time.Millisecond, 1), ev(aar, "B", 2*time.Second, 1), ev(stop, "B", 2400*time.Millisecond, 1),
		}, []string{"", "", "", ""}},
		{"different usage", []models.TokenEvent{ev(aar, "A", 0, 1), ev(stop, "B", time.Second, 2)}, []string{"", ""}},
		{"outside 10 s", []models.TokenEvent{ev(aar, "A", 0, 1), ev(stop, "B", 11*time.Second, 1)}, []string{"", ""}},
		{"a stop-to-stop match is not a proven pair", []models.TokenEvent{ev(stop, "A", 0, 1), ev(stop, "B", time.Second, 1)}, []string{"", ""}},
		{"another conversation", func() []models.TokenEvent {
			b := ev(stop, "B", time.Second, 1)
			b.SessionID = "other"
			return []models.TokenEvent{ev(aar, "A", 0, 1), b}
		}(), []string{"", ""}},
		{"another model", func() []models.TokenEvent {
			b := ev(stop, "B", time.Second, 1)
			b.Model = "n"
			return []models.TokenEvent{ev(aar, "A", 0, 1), b}
		}(), []string{"", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			markProvenRestatements(tc.evs)
			for i, e := range tc.evs {
				if e.Restates != tc.want[i] {
					t.Fatalf("event %d (%s %s) Restates = %q, want %q", i, e.HookEvent, e.MessageID, e.Restates, tc.want[i])
				}
			}
		})
	}
}
