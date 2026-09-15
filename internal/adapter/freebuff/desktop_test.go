package freebuff

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	fixtureThreadID   = "00000000-1111-2222-3333-444444444444"
	fixtureProjectDir = "demo-11111111-2222-3333-4444-555555555555"
	fixtureModel      = "deepseek/deepseek-v4-flash"
	fixtureProjectRow = "/home/dev/code/demo-project"
)

// desktopFixtureSeed is the anonymized dump derived from the LIVE Freebuff
// Desktop capture of 2026-09-03 — see testdata/freebuff/README.md for the
// derivation rules and what was withheld. It is a text .sql seed rather than
// a .db because the repo tracks no SQLite binaries (tree-wide *.db
// gitignore); the same convention as testdata/devin/desktop/sessions.sql.
func desktopFixtureSeed(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "freebuff",
		"freebuff-desktop", "projects", fixtureProjectDir, "desktop-v2.sql"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return p
}

// desktopFixture materializes the seed into a store whose path mirrors the
// real layout exactly (`<home>/.config/freebuff-desktop/projects/<dir>/
// desktop-v2.db`), so IsSessionFile, layoutFor and the watch root behave as
// they do in production. Returns (watch root, db path). Cached per t.TempDir,
// so each test gets its own copy.
func desktopFixture(t *testing.T) (root, dbPath string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), ".config", "freebuff-desktop", "projects")
	dir := filepath.Join(root, fixtureProjectDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	seed, err := os.ReadFile(desktopFixtureSeed(t))
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	dbPath = filepath.Join(dir, desktopDBName)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, execErr := db.Exec(string(seed))
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if execErr != nil {
		t.Fatalf("load seed: %v", execErr)
	}
	sidecar, err := os.ReadFile(filepath.Join(filepath.Dir(desktopFixtureSeed(t)), desktopProjectJSONName))
	if err != nil {
		t.Fatalf("read project.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, desktopProjectJSONName), sidecar, 0o600); err != nil {
		t.Fatalf("write project.json: %v", err)
	}
	return root, dbPath
}

// TestDesktopIsSessionFile is the dispatch matrix for both layouts: the
// desktop store is claimed, its WAL siblings and every off-limits file are
// not, and the CLI chats transcript still routes to the CLI layout.
func TestDesktopIsSessionFile(t *testing.T) {
	desktopRoot, _ := desktopFixture(t)
	cliRoot := fixtureRoot(t)
	a := NewWithOptions(nil, desktopRoot, cliRoot)

	join := func(root string, parts ...string) string {
		return filepath.Join(append([]string{root}, parts...)...)
	}

	tests := []struct {
		name       string
		path       string
		wantClaim  bool
		wantLayout layout
	}{
		{"desktop store", join(desktopRoot, fixtureProjectDir, desktopDBName), true, layoutDesktop},
		// Sidecars are claimed: the live capture lives in the WAL and the
		// cursor poll cannot re-fire a watermark-cursor file.
		{"desktop wal sibling", join(desktopRoot, fixtureProjectDir, desktopDBName+"-wal"), true, layoutDesktop},
		{"desktop shm sibling", join(desktopRoot, fixtureProjectDir, desktopDBName+"-shm"), true, layoutDesktop},
		{"desktop state.json (auth token)", join(desktopRoot, desktopStateName), false, layoutUnknown},
		{"desktop orchestrator lock", join(desktopRoot, desktopStateLockDBName), false, layoutUnknown},
		{"desktop project.json sidecar", join(desktopRoot, fixtureProjectDir, desktopProjectJSONName), false, layoutUnknown},
		{"cli transcript routes to the CLI layout", join(cliRoot, "needlehaystack", "chats", "2026-08-11T07-07-38.552Z", messagesName), true, layoutCLIChats},
		{"cli run-state sibling", join(cliRoot, "needlehaystack", "chats", "2026-08-11T07-07-38.552Z", runStateName), false, layoutUnknown},
		{"a desktop-v2.db outside a freebuff-desktop projects dir", filepath.Join(t.TempDir(), "elsewhere", desktopDBName), false, layoutUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.IsSessionFile(tt.path); got != tt.wantClaim {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tt.path, got, tt.wantClaim)
			}
			if tt.wantClaim {
				if got := layoutFor(tt.path); got != tt.wantLayout {
					t.Errorf("layoutFor(%q) = %v, want %v", tt.path, got, tt.wantLayout)
				}
			}
		})
	}
}

// TestDesktopParseFixture is the end-to-end assertion over the checked-in
// anonymized capture: one thread, its full action histogram, the netted token
// row and the desktop surface stamp.
func TestDesktopParseFixture(t *testing.T) {
	root, dbPath := desktopFixture(t)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}

	if res.NewOffset != 1788430059891 {
		t.Errorf("NewOffset = %d, want the epoch-millis watermark 1788430059891", res.NewOffset)
	}

	// §2.1: every row of BOTH layouts reports the same tool id.
	for i, e := range res.ToolEvents {
		if e.Tool != models.ToolFreebuff {
			t.Fatalf("ToolEvents[%d].Tool = %q, want %q", i, e.Tool, models.ToolFreebuff)
		}
		if e.SessionID != fixtureThreadID {
			t.Fatalf("ToolEvents[%d].SessionID = %q, want the thread id %q", i, e.SessionID, fixtureThreadID)
		}
		if e.Model != fixtureModel {
			t.Errorf("ToolEvents[%d].Model = %q, want %q", i, e.Model, fixtureModel)
		}
		if e.ProjectRoot != fixtureProjectRow {
			t.Errorf("ToolEvents[%d].ProjectRoot = %q, want %q", i, e.ProjectRoot, fixtureProjectRow)
		}
	}

	wantCounts := map[string]int{
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 4,
		models.ActionSearchFiles:      1, // list_directory
		models.ActionRunCommand:       4,
		models.ActionReadFile:         2,
		models.ActionWriteFile:        1,
		models.ActionEditFile:         1, // str_replace; the `changes` part is deduped away
		models.ActionUnknown:          1, // suggest_prompts — honestly unmapped
	}
	got := map[string]int{}
	for _, e := range res.ToolEvents {
		got[e.ActionType]++
	}
	if len(got) != len(wantCounts) {
		t.Errorf("action types = %v, want %v", countKeys(got), countKeys(wantCounts))
	}
	for k, want := range wantCounts {
		if got[k] != want {
			t.Errorf("action %q count = %d, want %d", k, got[k], want)
		}
	}
	if total := len(res.ToolEvents); total != 15 {
		t.Errorf("len(ToolEvents) = %d, want 15", total)
	}

	// Deterministic SourceEventIDs, unique per row.
	seen := map[string]bool{}
	for _, e := range res.ToolEvents {
		if seen[e.SourceEventID] {
			t.Errorf("duplicate SourceEventID %q", e.SourceEventID)
		}
		seen[e.SourceEventID] = true
	}

	// Reasoning parts thread onto the next actionable row, CLI-layout parity.
	var withReasoning int
	for _, e := range res.ToolEvents {
		if e.PrecedingReasoning != "" {
			withReasoning++
		}
	}
	if withReasoning == 0 {
		t.Error("no row carried PrecedingReasoning; the reasoning parts were dropped")
	}

	// Token netting: input is GROSS and must be netted against the cached half.
	if len(res.TokenEvents) != 1 {
		t.Fatalf("len(TokenEvents) = %d, want 1", len(res.TokenEvents))
	}
	te := res.TokenEvents[0]
	if te.InputTokens != 108245-94208 {
		t.Errorf("InputTokens = %d, want %d (gross 108245 − cached 94208)", te.InputTokens, 108245-94208)
	}
	if te.CacheReadTokens != 94208 {
		t.Errorf("CacheReadTokens = %d, want 94208", te.CacheReadTokens)
	}
	if te.OutputTokens != 1622 {
		t.Errorf("OutputTokens = %d, want 1622", te.OutputTokens)
	}
	if te.CacheCreationTokens != 0 {
		t.Errorf("CacheCreationTokens = %d, want 0 (the envelope has no write counterpart)", te.CacheCreationTokens)
	}
	if te.Model != fixtureModel {
		t.Errorf("token Model = %q, want %q", te.Model, fixtureModel)
	}
	if te.Tool != models.ToolFreebuff {
		t.Errorf("token Tool = %q, want %q", te.Tool, models.ToolFreebuff)
	}
	if te.EstimatedCostUSD != 0 {
		t.Errorf("EstimatedCostUSD = %v, want 0 (costUsd was 0 — let the cost engine price it)", te.EstimatedCostUSD)
	}
	if te.Source != models.TokenSourceJSONL || te.Reliability != models.ReliabilityAccurate {
		t.Errorf("token source/reliability = %q/%q", te.Source, te.Reliability)
	}

	// Surface stamp: the path shape IS the discriminator.
	want := models.SessionSurface{
		SessionID: fixtureThreadID, Surface: models.SurfaceDesktop, SurfaceHost: "freebuff-desktop",
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
		t.Errorf("SessionSurfaces = %+v, want [%+v]", res.SessionSurfaces, want)
	}
}

// TestDesktopParseIsIdempotent pins the watermark cursor: re-parsing at the
// returned offset emits nothing new.
func TestDesktopParseIsIdempotent(t *testing.T) {
	root, dbPath := desktopFixture(t)
	a := NewWithOptions(nil, root)
	first, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if len(second.ToolEvents) != 0 || len(second.TokenEvents) != 0 || len(second.SessionSurfaces) != 0 {
		t.Errorf("second parse emitted %d tool / %d token / %d surface rows, want 0/0/0",
			len(second.ToolEvents), len(second.TokenEvents), len(second.SessionSurfaces))
	}
	if second.NewOffset != first.NewOffset {
		t.Errorf("NewOffset moved on an idle store: %d → %d", first.NewOffset, second.NewOffset)
	}

	// A cursor one millisecond behind re-covers the boundary thread and
	// re-emits the SAME deterministic ids (the store dedupes them).
	replay, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset-1)
	if err != nil {
		t.Fatalf("replay parse: %v", err)
	}
	if len(replay.ToolEvents) != len(first.ToolEvents) {
		t.Fatalf("replay emitted %d rows, want %d", len(replay.ToolEvents), len(first.ToolEvents))
	}
	for i := range replay.ToolEvents {
		if replay.ToolEvents[i].SourceEventID != first.ToolEvents[i].SourceEventID {
			t.Errorf("row %d SourceEventID drifted on replay: %q vs %q",
				i, replay.ToolEvents[i].SourceEventID, first.ToolEvents[i].SourceEventID)
		}
	}
}

// TestDesktopAdPartsNeverPersisted pins the advertising carve-out: `ad` parts
// carry a per-user signed click URL and must never reach a row. The fixture
// keeps three ad parts (with placeholder payloads) so the skip is exercised.
func TestDesktopAdPartsNeverPersisted(t *testing.T) {
	root, dbPath := desktopFixture(t)
	a := NewWithOptions(nil, root)
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// The fixture really does contain ad parts.
	raw := readFixtureParts(t, dbPath)
	if !strings.Contains(raw, `"kind":"ad"`) {
		t.Fatal("fixture no longer contains an `ad` part; the carve-out is untested")
	}
	sentinels := []string{"example.invalid", "Desktop-Inline-Chat", "first_party", "See plans"}
	for _, e := range res.ToolEvents {
		hay := e.Target + " " + e.RawToolInput + " " + e.ToolOutput + " " +
			e.PrecedingReasoning + " " + e.RawToolName + " " + e.SourceEventID
		for _, s := range sentinels {
			if strings.Contains(hay, s) {
				t.Errorf("ad payload %q leaked into a row: %+v", s, e)
			}
		}
	}
}

// TestDesktopOffLimitsFilesNeverDispatchedOrIngested is the security guard
// for the Desktop store's secret siblings: `state.json` holds an auth TOKEN
// plus the operator's name and email, and `threads.harness_state` holds a
// large engine-internal blob the adapter has no reason to read.
func TestDesktopOffLimitsFilesNeverDispatchedOrIngested(t *testing.T) {
	root, dbPath := desktopFixture(t)
	projDir := filepath.Dir(dbPath)

	// Secret sentinels, built at runtime so no secret-shaped literal exists
	// in source.
	fakeToken := "desktop-guard-fake-token-" + t.Name()
	piiEmail := "leaked.dev@secret-example.invalid"
	piiName := "SECRET-OPERATOR-NAME-a1b2c3"
	state := `{"authSessions":[{"accessToken":"` + fakeToken +
		`","user":{"email":"` + piiEmail + `","name":"` + piiName + `"}}]}`
	offLimits := map[string]string{
		desktopStateName:       state,
		desktopStateLockDBName: "SQLite format 3\x00" + fakeToken,
	}
	for name, body := range offLimits {
		// Plant them both beside the store and one level up (the real
		// layout puts state.json at the freebuff-desktop root).
		for _, dir := range []string{projDir, filepath.Dir(root)} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatalf("write off-limits %s: %v", name, err)
			}
		}
	}

	a := NewWithOptions(nil, root)

	// (1) Never dispatched.
	for name := range offLimits {
		for _, dir := range []string{projDir, filepath.Dir(root)} {
			p := filepath.Join(dir, name)
			if a.IsSessionFile(p) {
				t.Errorf("IsSessionFile(%q) = true, want false", p)
			}
		}
	}

	// (2) Never ingested — and neither is threads.harness_state.
	res, err := a.ParseSessionFile(context.Background(), filepath.Join(projDir, desktopDBName), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("guard parse produced no rows; the test would prove nothing")
	}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, s := range []string{fakeToken, piiEmail, piiName, "HARNESS-STATE-SENTINEL"} {
		if strings.Contains(string(blob), s) {
			t.Errorf("off-limits value %q reached an emitted row", s)
		}
	}
}

// TestTouchedPathsDedupesChanges pins the changes-vs-tool-parts decision: a
// file a tool part already wrote or edited is suppressed, a file only the
// `changes` panel names survives, and a merely-READ file does not count as
// coverage.
func TestTouchedPathsDedupesChanges(t *testing.T) {
	parts := []desktopPart{
		{Kind: "tool", ToolName: "write_file", Input: json.RawMessage(`{"path":"a.py"}`)},
		{Kind: "tool", ToolName: "str_replace", Input: json.RawMessage(`{"path":"./b.py"}`)},
		{Kind: "tool", ToolName: "read_files", Input: json.RawMessage(`{"paths":["c.py"]}`)},
	}
	touched := touchedPaths(parts)
	tests := []struct {
		path string
		want bool
	}{
		{"a.py", true},
		{"b.py", true},
		{`.\b.py`, true},
		{"c.py", false}, // read only — not coverage
		{"d.py", false},
	}
	for _, tt := range tests {
		if got := touched[normalizePathKey(tt.path)]; got != tt.want {
			t.Errorf("touched[%q] = %v, want %v", tt.path, got, tt.want)
		}
	}

	// An uncovered changes file DOES produce a neutral edit row.
	a := NewWithOptions(nil, t.TempDir())
	var res adapter.ParseResult
	full := append(append([]desktopPart{}, parts...), desktopPart{
		Kind: "changes", ID: "p1", Files: []desktopChange{
			{Path: "a.py", Status: "added"},
			{Path: "shell-made.py", Status: "modified"},
		},
	})
	a.emitDesktopParts(&res, "s.db", desktopThread{ID: "t1"}, "root", "", "", time.Time{}, 2, full)
	var changeRows []models.ToolEvent
	for _, e := range res.ToolEvents {
		if e.RawToolName == "changes" {
			changeRows = append(changeRows, e)
		}
	}
	if len(changeRows) != 1 {
		t.Fatalf("changes rows = %d, want 1 (a.py deduped, shell-made.py kept)", len(changeRows))
	}
	if changeRows[0].Target != "shell-made.py" {
		t.Errorf("changes row target = %q, want shell-made.py", changeRows[0].Target)
	}
	if changeRows[0].ActionType != models.ActionEditFile {
		t.Errorf("changes row action = %q, want %q (status is not trusted)",
			changeRows[0].ActionType, models.ActionEditFile)
	}
}

// TestPickDesktopProjectPath pins the project-root ladder.
func TestPickDesktopProjectPath(t *testing.T) {
	tests := []struct {
		name        string
		projectPath string
		rootPath    string
		sidecar     string
		want        string
	}{
		{"threads.project_path wins", "/a", "/b", "/c", "/a"},
		{"projects.root_path is the first fallback", "  ", "/b", "/c", "/b"},
		{"project.json is the last fallback", "", "", "/c", "/c"},
		{"nothing grounded", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := 0
			got := pickDesktopProjectPath(tt.projectPath, tt.rootPath, func() string {
				called++
				return tt.sidecar
			})
			if got != tt.want {
				t.Errorf("pickDesktopProjectPath = %q, want %q", got, tt.want)
			}
			if tt.projectPath != "" && strings.TrimSpace(tt.projectPath) != "" && called != 0 {
				t.Errorf("sidecar opened %d times despite a grounded project_path", called)
			}
		})
	}
}

// TestDesktopOutcome pins the status mapping, including the grounded fact
// that most tool parts carry NO status by design.
func TestDesktopOutcome(t *testing.T) {
	tests := []struct {
		status  string
		output  string
		wantOK  bool
		wantMsg string
	}{
		{"success", "stdout:\nok\n", true, ""},
		{"", "", true, ""},
		{"error", "boom", false, "boom"},
		{"failed", "nope", false, "nope"},
	}
	for _, tt := range tests {
		ok, msg := desktopOutcome(tt.status, tt.output)
		if ok != tt.wantOK || msg != tt.wantMsg {
			t.Errorf("desktopOutcome(%q, %q) = (%v, %q), want (%v, %q)",
				tt.status, tt.output, ok, msg, tt.wantOK, tt.wantMsg)
		}
	}
}

// TestLayoutSurfaces keeps the surface attribution table-driven and pins the
// CLI layout's own stamp, which this ticket added alongside the desktop one.
func TestLayoutSurfaces(t *testing.T) {
	tests := []struct {
		l        layout
		wantKind string
		wantHost string
	}{
		{layoutCLIChats, models.SurfaceCLI, "freebuff"},
		{layoutDesktop, models.SurfaceDesktop, "freebuff-desktop"},
	}
	for _, tt := range tests {
		got := surfaceFor(tt.l, "sess-1")
		if got.SessionID != "sess-1" || got.Surface != tt.wantKind || got.SurfaceHost != tt.wantHost {
			t.Errorf("surfaceFor(%v) = %+v, want {sess-1 %s %s}", tt.l, got, tt.wantKind, tt.wantHost)
		}
		if got.Hosted {
			t.Errorf("surfaceFor(%v).Hosted = true; freebuff emits an ordinary self-report stamp", tt.l)
		}
	}
	if got := surfaceFor(layoutUnknown, "x"); got != (models.SessionSurface{}) {
		t.Errorf("surfaceFor(layoutUnknown) = %+v, want the zero value", got)
	}
}

// TestCLILayoutStampsCLISurface parses the existing CLI fixture and asserts
// the new surface stamp rides along without disturbing the rows.
func TestCLILayoutStampsCLISurface(t *testing.T) {
	a := NewWithOptions(nil, fixtureRoot(t))
	res, err := a.ParseSessionFile(context.Background(), fixtureMessagesPath(t), 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	want := models.SessionSurface{
		SessionID: "2026-08-11T07-07-38.552Z", Surface: models.SurfaceCLI, SurfaceHost: "freebuff",
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
		t.Errorf("SessionSurfaces = %+v, want [%+v]", res.SessionSurfaces, want)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("CLI layout emitted %d TokenEvents, want 0 (it has no usage accounting)",
			len(res.TokenEvents))
	}
}

// TestCursorSemantics pins that neither layout's cursor is a byte offset.
func TestCursorSemantics(t *testing.T) {
	root, dbPath := desktopFixture(t)
	a := NewWithOptions(nil, root, fixtureRoot(t))
	tests := []struct {
		name string
		path string
		want adapter.CursorKind
	}{
		{"desktop store", dbPath, adapter.CursorWatermark},
		{"cli transcript", fixtureMessagesPath(t), adapter.CursorWatermark},
		{"unclaimed path", filepath.Join(t.TempDir(), "nope.json"), adapter.CursorByteOffset},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.CursorSemanticsFor(tt.path).Kind; got != tt.want {
				t.Errorf("CursorSemanticsFor(%q).Kind = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestDefaultRootsCoverBothLayouts asserts both stores are watched on every
// OS under `.config`, with no per-OS branch.
func TestDefaultRootsCoverBothLayouts(t *testing.T) {
	roots := defaultRoots()
	var cli, desktop bool
	for _, r := range roots {
		slashed := filepath.ToSlash(r)
		if strings.HasSuffix(slashed, "/.config/manicode/projects") {
			cli = true
		}
		if strings.HasSuffix(slashed, "/.config/freebuff-desktop/projects") {
			desktop = true
		}
	}
	if !cli || !desktop {
		t.Errorf("defaultRoots() = %v; want both a manicode and a freebuff-desktop projects root", roots)
	}
}

func countKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readFixtureParts returns the assistant message's raw parts_json.
func readFixtureParts(t *testing.T, dbPath string) string {
	t.Helper()
	db, err := openDesktopDB(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	var parts string
	if err := db.QueryRow(`SELECT parts_json FROM messages WHERE role='assistant' ORDER BY seq LIMIT 1`).
		Scan(&parts); err != nil {
		if err == sql.ErrNoRows {
			t.Fatal("fixture has no assistant message")
		}
		t.Fatalf("query: %v", err)
	}
	return parts
}
