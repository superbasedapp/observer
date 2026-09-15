package cowork

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// fixturePath returns the absolute path of testdata/cowork relative
// to this test file. Used by every fixture-driven test below.
func fixturePath(t *testing.T, rel string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "cowork", rel))
	if err != nil {
		t.Fatalf("fixturePath: %v", err)
	}
	return abs
}

func TestName(t *testing.T) {
	t.Parallel()
	if got := New().Name(); got != models.ToolCowork {
		t.Fatalf("Name=%q want %q", got, models.ToolCowork)
	}
}

// TestIsSessionFile_RequiresAuditBasename pins the shape gate.
// Only files named exactly audit.jsonl inside a local_<id>/ dir count.
func TestIsSessionFile_RequiresAuditBasename(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "cowork-aaaa/dev-bbbb")
	// The WatchPaths override must be the cowork root, not the inner dir.
	a := NewWithOptions(nil, fixturePath(t, ""))
	_ = root

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"happy", filepath.Join(root, "local_cccc-dddd-eeee", "audit.jsonl"), true},
		{"wrong-basename", filepath.Join(root, "local_cccc-dddd-eeee", "other.jsonl"), false},
		{"missing-local-prefix", filepath.Join(root, "other-dir", "audit.jsonl"), false},
		{"outside-watch-root", "/tmp/foreign/local_x/audit.jsonl", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Fatalf("IsSessionFile(%q)=%v want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestParseSessionFile_FullFixture is the end-to-end replay against
// the synthetic 6-record audit.jsonl. Asserts the expected event
// counts plus a few specific field values.
func TestParseSessionFile_FullFixture(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	// Expected events:
	//   - 1 user_prompt    (uuser-0001)
	//   - 1 assistant_text (uasst-0001, text block)
	//   - 1 tool_use       (uasst-0001, Read)  → paired with tool_result on uuser-0002
	//   - 1 rate_limit     (url-0001, M2)
	//   - 1 assistant_text (uasst-sidechain — IsSidechain=true per subagent fixture)
	//   - 1 result         (ures-0001)
	// Total ToolEvents: 6. (tool_use_summary modifies the Read row in
	// place — does NOT add a new event.)
	if got, want := len(res.ToolEvents), 6; got != want {
		t.Fatalf("ToolEvents=%d want %d (have: %#v)", got, want, summarizeEvents(res.ToolEvents))
	}
	// Token events: 2 assistant rows with non-zero usage.
	if got, want := len(res.TokenEvents), 2; got != want {
		t.Fatalf("TokenEvents=%d want %d", got, want)
	}
	if res.NewOffset == 0 {
		t.Fatalf("NewOffset stayed at 0 — parser didn't advance")
	}
}

// TestParseSessionFile_ToolResultPairing pins the tool_use ↔ tool_result
// pairing logic. The Read tool_use must have ToolOutput populated
// from the matching user-tool_result and DurationMs set from the
// timestamp gap.
func TestParseSessionFile_ToolResultPairing(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var read *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "Read" {
			read = &res.ToolEvents[i]
			break
		}
	}
	if read == nil {
		t.Fatalf("no Read tool_use event emitted; got %#v", summarizeEvents(res.ToolEvents))
	}
	if !strings.Contains(read.ToolOutput, "package foo") {
		t.Fatalf("Read.ToolOutput missing tool_result body; got %q", read.ToolOutput)
	}
	if read.DurationMs <= 0 {
		t.Fatalf("Read.DurationMs not set from timestamp gap; got %d", read.DurationMs)
	}
}

// TestParseSessionFile_CacheCreationSplit pins that the 5m/1h
// cache_creation tier split is derived from result.usage.cache_creation
// and applied proportionally to each modelUsage entry's
// cacheCreationInputTokens. The fixture's result top-level usage has
// 500/1500 (5m/1h) of 2000 total = 0.75 1h-fraction; applied to opus
// modelUsage cw=2000 yields cw1h=1500. ActionMetadata.CacheCreate5mTok
// and CacheCreate1hTok still lift from per-assistant-row usage (those
// fields decorate ActionTaskComplete rows for diagnostics, not
// billing).
func TestParseSessionFile_CacheCreationSplit(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// Find the opus TokenEvent — it's the one with cw=2000 in modelUsage.
	var opusEv *models.TokenEvent
	for i := range res.TokenEvents {
		if res.TokenEvents[i].Model == "claude-opus-4-6" {
			opusEv = &res.TokenEvents[i]
			break
		}
	}
	if opusEv == nil {
		t.Fatalf("no opus TokenEvent emitted from result.modelUsage; got %d TokenEvents", len(res.TokenEvents))
	}
	if got, want := opusEv.CacheCreationTokens, int64(2000); got != want {
		t.Fatalf("opus TokenEvent.CacheCreationTokens=%d want %d (from modelUsage)", got, want)
	}
	if got, want := opusEv.CacheCreation1hTokens, int64(1500); got != want {
		t.Fatalf("opus TokenEvent.CacheCreation1hTokens=%d want %d (0.75 fraction × 2000)", got, want)
	}
	// Find the Read tool_use and check its metadata carries the 5m/1h
	// split — these decorate the ActionTaskComplete row for diagnostic
	// purposes, lifted from the assistant row's per-message usage block
	// (NOT used for billing — see handleResult comment).
	var read *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "Read" {
			read = &res.ToolEvents[i]
			break
		}
	}
	if read == nil || read.Metadata == nil {
		t.Fatalf("Read.Metadata nil; expected cache fields populated")
	}
	if read.Metadata.CacheCreate5mTok != 500 {
		t.Fatalf("CacheCreate5mTok=%d want 500", read.Metadata.CacheCreate5mTok)
	}
	if read.Metadata.CacheCreate1hTok != 1500 {
		t.Fatalf("CacheCreate1hTok=%d want 1500", read.Metadata.CacheCreate1hTok)
	}
}

// TestParseSessionFile_ModelUsageEmitsTokenEventPerModel pins the
// v1.4.54 cost-drift fix (docs/cowork-cost-drift-investigation-
// 2026-05-15.md): TokenEvents come from result.modelUsage, NOT from
// per-assistant-row message.usage. The fixture result carries
// modelUsage with both opus-4-6 and haiku-4-5-20251001 entries; the
// haiku entry has zero corresponding assistant rows in audit.jsonl
// (simulating Cowork's internal haiku dispatch) and MUST still emit a
// TokenEvent.
func TestParseSessionFile_ModelUsageEmitsTokenEventPerModel(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	byModel := map[string]*models.TokenEvent{}
	for i := range res.TokenEvents {
		byModel[res.TokenEvents[i].Model] = &res.TokenEvents[i]
	}

	opus, ok := byModel["claude-opus-4-6"]
	if !ok {
		t.Fatalf("no opus TokenEvent emitted from result.modelUsage")
	}
	if opus.InputTokens != 22 || opus.OutputTokens != 68 || opus.CacheReadTokens != 12000 || opus.CacheCreationTokens != 2000 {
		t.Fatalf("opus TokenEvent tokens mismatch: in=%d out=%d cr=%d cw=%d (want 22/68/12000/2000)",
			opus.InputTokens, opus.OutputTokens, opus.CacheReadTokens, opus.CacheCreationTokens)
	}
	if opus.Reliability != models.ReliabilityAccurate {
		t.Errorf("opus Reliability=%q want %q (modelUsage is Cowork-authoritative)", opus.Reliability, models.ReliabilityAccurate)
	}
	if opus.SourceEventID != "ures-0001:claude-opus-4-6" {
		t.Errorf("opus SourceEventID=%q want %q", opus.SourceEventID, "ures-0001:claude-opus-4-6")
	}
	if opus.MessageID != "result:ures-0001:claude-opus-4-6" {
		t.Errorf("opus MessageID=%q want %q", opus.MessageID, "result:ures-0001:claude-opus-4-6")
	}

	haiku, ok := byModel["claude-haiku-4-5-20251001"]
	if !ok {
		t.Fatalf("no haiku TokenEvent emitted from result.modelUsage — shadow-cost fix not landing")
	}
	if haiku.InputTokens != 4500 || haiku.OutputTokens != 120 {
		t.Fatalf("haiku TokenEvent tokens mismatch: in=%d out=%d (want 4500/120)", haiku.InputTokens, haiku.OutputTokens)
	}

	// No assistant rows in the fixture carry model="claude-haiku-4-5-20251001"
	// — the haiku invocations Cowork does internally never land in
	// audit.jsonl as assistant rows. Token capture from modelUsage is
	// what bridges that visibility gap.
}

// TestParseSessionFile_ModelUsageEmitsWebSearchRequests pins the Phase 2
// cost-drift fix: result.modelUsage[*].webSearchRequests propagates onto
// the emitted TokenEvent's WebSearchRequests field so the cost engine can
// apply Anthropic's $10/1000 server-side-tool fee. The fixture sets
// haiku.webSearchRequests=3 (with corresponding +$0.03 in haiku.costUSD).
func TestParseSessionFile_ModelUsageEmitsWebSearchRequests(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	byModel := map[string]*models.TokenEvent{}
	for i := range res.TokenEvents {
		byModel[res.TokenEvents[i].Model] = &res.TokenEvents[i]
	}
	haiku, ok := byModel["claude-haiku-4-5-20251001"]
	if !ok {
		t.Fatalf("no haiku TokenEvent emitted")
	}
	if got, want := haiku.WebSearchRequests, int64(3); got != want {
		t.Fatalf("haiku TokenEvent.WebSearchRequests=%d want %d (from modelUsage)", got, want)
	}
	// Opus modelUsage in the fixture has webSearchRequests=0 — pin that
	// zero-valued fields don't accidentally propagate from another model.
	opus, ok := byModel["claude-opus-4-6"]
	if !ok {
		t.Fatalf("no opus TokenEvent emitted")
	}
	if opus.WebSearchRequests != 0 {
		t.Errorf("opus TokenEvent.WebSearchRequests=%d want 0", opus.WebSearchRequests)
	}
}

// TestParseSessionFile_AssistantRowsDoNotEmitTokenEvents pins the
// other half of the v1.4.54 cost-drift fix: assistant-row usage
// blocks are NO LONGER emitted as TokenEvents (they're streaming
// snapshots with stale output_tokens — see investigation doc).
// Without a result record carrying modelUsage, a cowork session that
// only has assistant rows produces zero TokenEvents.
func TestParseSessionFile_AssistantRowsDoNotEmitTokenEvents(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	instDir := filepath.Join(dir, "local_test_no_result")
	if err := os.MkdirAll(instDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sidecar := `{"sessionId":"local_test_no_result","cwd":"/tmp/cw","userSelectedFolders":["/tmp/cw"]}`
	if err := os.WriteFile(filepath.Join(dir, "local_test_no_result.json"), []byte(sidecar), 0o644); err != nil {
		t.Fatal(err)
	}
	// Assistant row with rich usage but NO result record following it.
	body := `{"type":"assistant","uuid":"a1","session_id":"s1","message":{"id":"msg1","role":"assistant","model":"claude-opus-4-6","content":[{"type":"text","text":"hi"}],"usage":{"input_tokens":100,"output_tokens":50,"cache_read_input_tokens":1000,"cache_creation_input_tokens":500,"cache_creation":{"ephemeral_5m_input_tokens":500,"ephemeral_1h_input_tokens":0}}},"_audit_timestamp":"2026-05-15T10:00:00.000Z"}` + "\n"
	auditPath := filepath.Join(instDir, "audit.jsonl")
	if err := os.WriteFile(auditPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, dir)
	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Fatalf("got %d TokenEvents from assistant-only audit.jsonl, want 0 (modelUsage is the only token source now)", len(res.TokenEvents))
	}
	// Assistant content is still parsed for ToolEvents (assistant_text).
	if len(res.ToolEvents) == 0 {
		t.Fatalf("got 0 ToolEvents — assistant content parsing should be unaffected")
	}
}

// TestParseSessionFile_SidecarMetadata pins that sidecar fields
// (processName, title, hostLoopMode) land on every emitted event's
// Metadata.
func TestParseSessionFile_SidecarMetadata(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for i, ev := range res.ToolEvents {
		if ev.Metadata == nil {
			t.Fatalf("event %d (%s) has nil Metadata", i, ev.ActionType)
		}
		if ev.Metadata.CoworkProcessName != "happy-test-fixture" {
			t.Fatalf("event %d CoworkProcessName=%q want %q", i, ev.Metadata.CoworkProcessName, "happy-test-fixture")
		}
		if ev.Metadata.CoworkTitle != "Fixture session for adapter tests" {
			t.Fatalf("event %d CoworkTitle=%q", i, ev.Metadata.CoworkTitle)
		}
		if !ev.Metadata.HostLoopMode {
			t.Fatalf("event %d HostLoopMode false; sidecar says true", i)
		}
	}
}

// TestParseSessionFile_ResultCarriesTotalCost pins that the `result`
// record's total_cost_usd lands on the corresponding ActionTaskComplete
// event's Metadata.TotalCostUSD.
func TestParseSessionFile_ResultCarriesTotalCost(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var resultEv *models.ToolEvent
	for i := range res.ToolEvents {
		if res.ToolEvents[i].RawToolName == "cowork.result" {
			resultEv = &res.ToolEvents[i]
			break
		}
	}
	if resultEv == nil {
		t.Fatalf("no cowork.result event emitted")
	}
	if resultEv.Metadata == nil || resultEv.Metadata.TotalCostUSD != 0.0425 {
		t.Fatalf("TotalCostUSD=%v want 0.0425", resultEv.Metadata)
	}
	if resultEv.DurationMs != 9000 {
		t.Fatalf("DurationMs=%d want 9000", resultEv.DurationMs)
	}
}

// TestParseSessionFile_SessionIDIsLocalInstance pins that every event
// uses the local-instance directory name as the SessionID, NOT the
// audit-internal session_id which varies within one file.
func TestParseSessionFile_SessionIDIsLocalInstance(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	const want = "local_cccc-dddd-eeee"
	for i, ev := range res.ToolEvents {
		if ev.SessionID != want {
			t.Fatalf("ToolEvents[%d].SessionID=%q want %q", i, ev.SessionID, want)
		}
	}
	for i, ev := range res.TokenEvents {
		if ev.SessionID != want {
			t.Fatalf("TokenEvents[%d].SessionID=%q want %q", i, ev.SessionID, want)
		}
	}
}

// TestParseSessionFile_ResumeFromOffset pins idempotent re-parsing:
// running with fromOffset == prior NewOffset emits zero new events.
func TestParseSessionFile_ResumeFromOffset(t *testing.T) {
	t.Parallel()
	root := fixturePath(t, "")
	auditPath := fixturePath(t, "cowork-aaaa/dev-bbbb/local_cccc-dddd-eeee/audit.jsonl")
	a := NewWithOptions(nil, root)

	res1, err := a.ParseSessionFile(context.Background(), auditPath, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	res2, err := a.ParseSessionFile(context.Background(), auditPath, res1.NewOffset)
	if err != nil {
		t.Fatalf("resumed parse: %v", err)
	}
	if len(res2.ToolEvents) != 0 || len(res2.TokenEvents) != 0 {
		t.Fatalf("resumed parse emitted %d ToolEvents / %d TokenEvents — want 0/0", len(res2.ToolEvents), len(res2.TokenEvents))
	}
	if res2.NewOffset != res1.NewOffset {
		t.Fatalf("NewOffset moved on resumed parse: %d → %d", res1.NewOffset, res2.NewOffset)
	}
}

// TestProjectRootResolution_PrefersUserSelectedFolders pins the priority:
// userSelectedFolders[0] > sidecar.cwd > "".
//
// Pre-populates the resolver cache so git.Resolve is bypassed — keeps
// the test about the priority logic, not whether /tmp happens to have
// a .git dir from host pollution.
func TestProjectRootResolution_PrefersUserSelectedFolders(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		sc        sidecar
		seedCache map[string]projectGitInfo
		want      string
	}{
		{
			name:      "selected-folders-wins",
			sc:        sidecar{UserSelectedFolders: []string{"/synthetic/ws"}, Cwd: "/synthetic/cwd"},
			seedCache: map[string]projectGitInfo{"/synthetic/ws": {Root: "/synthetic/ws"}},
			want:      "/synthetic/ws",
		},
		{
			name:      "cwd-fallback",
			sc:        sidecar{Cwd: "/synthetic/cwd"},
			seedCache: map[string]projectGitInfo{"/synthetic/cwd": {Root: "/synthetic/cwd"}},
			want:      "/synthetic/cwd",
		},
		{
			name: "empty-empty",
			sc:   sidecar{},
			want: "",
		},
		{
			name:      "empty-folders-fallback",
			sc:        sidecar{UserSelectedFolders: []string{""}, Cwd: "/synthetic/cwd"},
			seedCache: map[string]projectGitInfo{"/synthetic/cwd": {Root: "/synthetic/cwd"}},
			want:      "/synthetic/cwd",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := tc.seedCache
			if cache == nil {
				cache = map[string]projectGitInfo{}
			}
			got, _, _ := resolveProjectRoot(tc.sc, cache)
			if got != tc.want {
				t.Fatalf("resolveProjectRoot=%q want %q", got, tc.want)
			}
		})
	}
}

// TestResolveProjectRoot_WindowsPathDoesNotLeakToCWD pins the
// v1.4.54 fix: a Cowork sidecar with a Windows-native
// userSelectedFolders path must NOT be passed to git.Resolve on a
// Linux/WSL2 host when the translated path is unreachable. Before
// the fix, filepath.Abs prepended the observer process's CWD to the
// Windows path and findGitRoot walked up to find the observer's
// own .git, mis-attributing every host-loop Cowork session to the
// observer's repo.
//
// We use drive letter Z: which is virtually never mounted under
// /mnt/z on any host (CI or maintainer), so the translated path
// fails to Stat and the resolver must preserve the original.
func TestResolveProjectRoot_WindowsPathDoesNotLeakToCWD(t *testing.T) {
	t.Parallel()
	sc := sidecar{
		UserSelectedFolders: []string{`Z:\nonexistent\someproject`},
	}
	cache := map[string]projectGitInfo{}
	got, _, _ := resolveProjectRoot(sc, cache)
	want := `Z:\nonexistent\someproject`
	if got != want {
		t.Fatalf("resolveProjectRoot(unreachable windows path)=%q, want %q (must NOT walk CWD's git tree)", got, want)
	}
	// Verify cache is sealed too, so a repeat call doesn't re-trigger
	// the bad path.
	got2, _, _ := resolveProjectRoot(sc, cache)
	if got2 != want {
		t.Fatalf("repeat call resolved differently: %q vs %q", got2, want)
	}
}

// TestResolveProjectRoot_CoworkInternalCwdSynthesisesSandbox pins that
// when the user didn't pick a workspace (userSelectedFolders empty)
// AND cwd points inside Cowork's own session storage tree (i.e.
// `.../local-agent-mode-sessions/.../local_<id>/outputs`), the
// project root is synthesised as `/sessions/<processName>` rather
// than the literal storage path. The storage path is meaningless to
// the user — it's just where Cowork stored scratch files. Matches
// Cowork's own `/sessions/<adj-adj-name>` convention for non-host-
// loop sessions so the two flavours of project-less sessions group
// together on the dashboard.
func TestResolveProjectRoot_CoworkInternalCwdSynthesisesSandbox(t *testing.T) {
	t.Parallel()
	sc := sidecar{
		SessionID:           "local_aaaa",
		ProcessName:         "gifted-kind-euler",
		UserSelectedFolders: []string{},
		Cwd:                 `C:\Users\u\AppData\Roaming\Claude\local-agent-mode-sessions\sess\dev\local_aaaa\outputs`,
	}
	cache := map[string]projectGitInfo{}
	got, _, _ := resolveProjectRoot(sc, cache)
	want := "/sessions/gifted-kind-euler"
	if got != want {
		t.Fatalf("resolveProjectRoot(cowork-internal cwd, no workspace picked)=%q, want %q", got, want)
	}
}

// TestResolveProjectRoot_CoworkInternalCwdRespectsUserChoice pins that
// when userSelectedFolders IS set, the cowork-internal-cwd synthesis
// is bypassed and the user's choice wins — even if cwd also happens
// to point inside Cowork's storage tree.
func TestResolveProjectRoot_CoworkInternalCwdRespectsUserChoice(t *testing.T) {
	t.Parallel()
	sc := sidecar{
		SessionID:           "local_aaaa",
		ProcessName:         "gifted-kind-euler",
		UserSelectedFolders: []string{`Z:\workspace`},
		Cwd:                 `C:\Users\u\AppData\Roaming\Claude\local-agent-mode-sessions\sess\dev\local_aaaa\outputs`,
	}
	cache := map[string]projectGitInfo{}
	got, _, _ := resolveProjectRoot(sc, cache)
	want := `Z:\workspace`
	if got != want {
		t.Fatalf("got=%q, want %q (user's selection must override cwd-fallback synthesis)", got, want)
	}
}

// TestResolveProjectRoot_SandboxPathPreserved pins that Cowork's
// sandbox-synthetic paths like "/sessions/<adj-adj-name>" are
// returned verbatim — they don't exist on disk so git.Resolve must
// NOT be called (its CWD-fallback would otherwise return the
// observer's own repo for paths inside the running CWD's tree).
func TestResolveProjectRoot_SandboxPathPreserved(t *testing.T) {
	t.Parallel()
	sc := sidecar{Cwd: "/sessions/clever-festive-mendel"}
	cache := map[string]projectGitInfo{}
	got, _, _ := resolveProjectRoot(sc, cache)
	if got != "/sessions/clever-festive-mendel" {
		t.Fatalf("resolveProjectRoot(sandbox path)=%q, want %q", got, "/sessions/clever-festive-mendel")
	}
}

// TestInstanceSessionID pins the path → session-id extraction.
func TestInstanceSessionID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want string
	}{
		{"/x/y/local_abc-123/audit.jsonl", "local_abc-123"},
		{"/x/y/not-a-local/audit.jsonl", ""},
		{"/x/y/local_/audit.jsonl", "local_"}, // edge: empty UUID still has the prefix
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := instanceSessionID(tc.path)
			if got != tc.want {
				t.Fatalf("instanceSessionID(%q)=%q want %q", tc.path, got, tc.want)
			}
		})
	}
}

// summarizeEvents returns a compact debug view of ToolEvents for
// failure messages.
func summarizeEvents(evs []models.ToolEvent) []string {
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.ActionType + "/" + ev.RawToolName
	}
	return out
}

// TestParseSessionFile_ThinkingMintsNoRowAndFansOut pins the B3
// convergence for cowork (2026-07-31). A `thinking` content block used
// to emit its own `cowork.reasoning` task_complete row AND accumulate
// into the per-message reasoning buffer. The row is gone; the FAN-OUT
// accumulate semantics are untouched — one thinking block precedes two
// tool_use blocks in the same message and BOTH carry it.
func TestParseSessionFile_ThinkingMintsNoRowAndFansOut(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "cowork-zzzz", "dev-yyyy", "local_1111-2222-3333")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	lines := []string{
		`{"type":"system","subtype":"init","cwd":"/tmp/cowork-think","session_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","tools":["Read","Bash"],"_audit_timestamp":"2026-07-31T10:00:00.000Z"}`,
		`{"type":"user","uuid":"u-1","session_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","message":{"role":"user","content":"do it"},"_audit_timestamp":"2026-07-31T10:00:01.000Z"}`,
		`{"type":"assistant","uuid":"a-1","session_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","message":{"id":"msg_think","role":"assistant","model":"claude-opus-4-6","content":[{"type":"thinking","thinking":"I should read the file, then list the dir."},{"type":"tool_use","id":"toolu_a","name":"Read","input":{"file_path":"/tmp/cowork-think/foo.go"}},{"type":"tool_use","id":"toolu_b","name":"Bash","input":{"command":"ls"}}]},"_audit_timestamp":"2026-07-31T10:00:02.000Z"}`,
		"",
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var threaded int
	for _, ev := range res.ToolEvents {
		if ev.RawToolName == "cowork.reasoning" {
			t.Fatalf("cowork.reasoning row minted: %+v", ev)
		}
		if ev.SourceEventID == "toolu_a" || ev.SourceEventID == "toolu_b" {
			if !strings.Contains(ev.PrecedingReasoning, "read the file, then list the dir") {
				t.Errorf("%s PrecedingReasoning = %q, want the thinking text", ev.SourceEventID, ev.PrecedingReasoning)
			}
			threaded++
		}
	}
	if threaded != 2 {
		t.Fatalf("tool rows carrying the fanned-out reasoning = %d, want 2; events=%+v", threaded, res.ToolEvents)
	}
}
