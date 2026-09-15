package qoder

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// workFixtureClock is the fixed "now" every Work test runs against. The
// fixture's own row timestamps are old enough that every session is
// outside the freshness window unless the builder is told to make one
// fresh, so the two gates are exercised deliberately rather than by
// wall-clock accident.
var workFixtureClock = time.UnixMilli(1788440000000)

// buildWorkDB renders testdata/qoder/work/main-sqlite-fixture.sql into a
// main.sqlite inside the Qoder Work data directory under home, and
// returns its path. freshSessions names the sessions whose message rows
// are rewritten to `now` so they fall inside workFreshnessWindow.
func buildWorkDB(t *testing.T, home string, now time.Time, freshSessions ...string) string {
	t.Helper()
	dir := filepath.Join(home, "AppData", "Roaming", workAppDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, workDBName)

	script, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "qoder", "work", "main-sqlite-fixture.sql"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(script)); err != nil {
		t.Fatalf("apply fixture: %v", err)
	}
	for _, sid := range freshSessions {
		if _, err := db.Exec(
			`UPDATE chat_session_messages SET updated_at = ?, created_at = ? WHERE session_id = ?`,
			now.UnixMilli(), now.UnixMilli(), sid); err != nil {
			t.Fatalf("freshen %s: %v", sid, err)
		}
	}
	return path
}

// newWorkAdapter builds an adapter rooted at a synthetic home with a
// frozen clock.
func newWorkAdapter(t *testing.T, home string, now time.Time) *Adapter {
	t.Helper()
	fakeHome(t, home)
	a := NewWithOptions(nil, defaultRoots()...)
	a.now = func() time.Time { return now }
	return a
}

// writeCLITwin creates an (empty) qodercli transcript for sessionID, which
// is all hasCLITwin looks for — the ownership check is a filesystem stat,
// never a read of the other store.
func writeCLITwin(t *testing.T, home, slug, sessionID string) {
	t.Helper()
	dir := filepath.Join(home, ".qoder", projectsDir, slug)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sessionID+".jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestWorkDBStampsHostedSurfaceForEverySession pins the primary product
// of the Work parser: one HOSTED desktop stamp per session in the read
// window, whatever the twin verdict.
// TestWorkDBImportedSessionsAreSuppressed pins the review fix: a session
// Work IMPORTED from the Qoder IDE (extra_json.importedFrom set,
// execution_kind NULL, messages source=cli-import) gets NO hosted stamp
// and NO fallback rows even without a CLI twin — the IDE original is
// captured from its own transcript under ide/qoder, and a host-wins
// stamp on the import would mislabel a copy of that task.
func TestWorkDBImportedSessionsAreSuppressed(t *testing.T) {
	home := t.TempDir()
	a := newWorkAdapter(t, home, workFixtureClock)
	path := buildWorkDB(t, home, workFixtureClock)

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, s := range res.SessionSurfaces {
		if s.SessionID == "sess-import" {
			t.Errorf("imported session must not be stamped: %+v", s)
		}
	}
	for _, e := range res.ToolEvents {
		if e.SessionID == "sess-import" {
			t.Errorf("imported session must not emit rows: %+v", e)
		}
	}
	// The discriminator table, both signals.
	for _, tc := range []struct {
		name  string
		kind  sql.NullString
		extra string
		want  bool
	}{
		{"live import shape", sql.NullString{}, `{"importedFrom":"quest"}`, true},
		{"importedFrom alone", sql.NullString{String: "local", Valid: true}, `{"importedFrom":"quest"}`, true},
		{"null execution_kind alone", sql.NullString{}, `{}`, true},
		{"driven session", sql.NullString{String: "local", Valid: true}, `{"cliSessionReady":true}`, false},
		{"driven, empty extra", sql.NullString{String: "local", Valid: true}, ``, false},
		{"driven, malformed extra", sql.NullString{String: "local", Valid: true}, `{`, false},
	} {
		if got := workSessionImported(tc.kind, tc.extra); got != tc.want {
			t.Errorf("%s: imported = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestWorkDBStampsHostedSurfaceForEverySession(t *testing.T) {
	home := t.TempDir()
	a := newWorkAdapter(t, home, workFixtureClock)
	path := buildWorkDB(t, home, workFixtureClock)
	writeCLITwin(t, home, "c--Users-dev-proj", "sess-with-twin")

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	got := map[string]models.SessionSurface{}
	for _, s := range res.SessionSurfaces {
		if _, dup := got[s.SessionID]; dup {
			t.Errorf("duplicate stamp for %s", s.SessionID)
		}
		got[s.SessionID] = s
	}
	for _, sid := range []string{"sess-with-twin", "sess-no-twin", "sess-fresh"} {
		s, ok := got[sid]
		if !ok {
			t.Fatalf("no surface stamp for %s (got %+v)", sid, res.SessionSurfaces)
		}
		want := models.SessionSurface{
			SessionID: sid, Surface: models.SurfaceDesktop,
			SurfaceHost: hostQoderWork, Hosted: true,
		}
		if s != want {
			t.Errorf("stamp for %s = %+v, want %+v", sid, s, want)
		}
	}
}

// TestWorkDBNeverEmitsTokensOrModel pins the two honest gaps: Qoder Work
// reports tokenCountsAvailable:false, and its `model` column holds a BYOK
// credential-profile id or the tier alias `auto` — neither is a model.
func TestWorkDBNeverEmitsTokensOrModel(t *testing.T) {
	home := t.TempDir()
	a := newWorkAdapter(t, home, workFixtureClock)
	path := buildWorkDB(t, home, workFixtureClock)

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("Work store produced %d token events, want 0", len(res.TokenEvents))
	}
	for _, e := range res.ToolEvents {
		if e.Model != "" {
			t.Errorf("event %s carries model %q; the Work store has no model name", e.SourceEventID, e.Model)
		}
	}
}

// TestWorkDBTwinRuleBothBranches is the ownership pin: a session whose
// qodercli transcript exists contributes ONLY a stamp, while a twin-less
// session's conversation is emitted in full.
func TestWorkDBTwinRuleBothBranches(t *testing.T) {
	home := t.TempDir()
	a := newWorkAdapter(t, home, workFixtureClock)
	path := buildWorkDB(t, home, workFixtureClock)
	writeCLITwin(t, home, "c--Users-dev-proj", "sess-with-twin")

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	bySession := map[string][]models.ToolEvent{}
	for _, e := range res.ToolEvents {
		bySession[e.SessionID] = append(bySession[e.SessionID], e)
	}
	if n := len(bySession["sess-with-twin"]); n != 0 {
		t.Errorf("twinned session emitted %d events, want 0 (qodercli owns them)", n)
	}
	events := bySession["sess-no-twin"]
	if len(events) != 2 {
		t.Fatalf("twin-less session emitted %d events, want 2 (session_start + prompt): %+v", len(events), events)
	}
	if events[0].ActionType != models.ActionSessionStart || events[0].SourceEventID != "session_start:sess-no-twin" {
		t.Errorf("first event = %+v, want the session_start marker", events[0])
	}
	prompt := events[1]
	if prompt.ActionType != models.ActionUserPrompt {
		t.Errorf("second event action = %q, want %q", prompt.ActionType, models.ActionUserPrompt)
	}
	// SourceEventID reuses the transcript parser's scheme, and the id is
	// the transcript record uuid (the two stores share an id space).
	if prompt.SourceEventID != "prompt:00000000-0000-4000-8000-0000000000b1" {
		t.Errorf("prompt SourceEventID = %q", prompt.SourceEventID)
	}
	if prompt.Tool != models.ToolQoder {
		t.Errorf("prompt tool = %q, want %q (Work is a surface, not a tool id)", prompt.Tool, models.ToolQoder)
	}
	if prompt.SourceFile != path {
		t.Errorf("SourceFile = %q, want the canonical main.sqlite path", prompt.SourceFile)
	}
	if !hasPathSuffix(prompt.ProjectRoot, "Users/dev/scratch") {
		t.Errorf("project root = %q, want */Users/dev/scratch (from chat_sessions.cwd)", prompt.ProjectRoot)
	}
	// The hook-activity system row is harness bookkeeping, not
	// conversation: it must not become an action.
	for _, e := range events {
		if e.RawToolName == "hook" || e.ActionType == models.ActionUnknown {
			t.Errorf("hook-activity leaked into the conversation: %+v", e)
		}
	}
}

// TestWorkDBTwinBranchIncludesIDETranscriptDir pins that the twin scan
// also looks in the IDE's `transcript/` subdirectory, so an IDE-owned
// session is never claimed either.
func TestWorkDBTwinBranchIncludesIDETranscriptDir(t *testing.T) {
	home := t.TempDir()
	a := newWorkAdapter(t, home, workFixtureClock)
	dir := filepath.Join(home, ".qoder", projectsDir, "c-Users-dev-scratch", transcriptDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sess-no-twin.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !a.hasCLITwin("sess-no-twin") {
		t.Error("hasCLITwin missed a transcript in the IDE subdirectory")
	}
	if a.hasCLITwin("sess-never-written") {
		t.Error("hasCLITwin claimed a twin that does not exist")
	}
	// A glob-metacharacter id is treated as twinned (never claimed).
	if !a.hasCLITwin("sess-*") {
		t.Error("hasCLITwin must refuse to expand a glob pattern")
	}
}

// TestWorkDBFreshnessGateBothBranches pins §4.7: an in-flight session
// keeps the file on the poll loop and is never claimed; once it has been
// quiet for the whole window, RetrySuggested drops and the twin-less
// conversation is emitted.
func TestWorkDBFreshnessGateBothBranches(t *testing.T) {
	t.Run("fresh session retries and is not claimed", func(t *testing.T) {
		home := t.TempDir()
		a := newWorkAdapter(t, home, workFixtureClock)
		path := buildWorkDB(t, home, workFixtureClock, "sess-no-twin")

		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		if !res.RetrySuggested {
			t.Error("RetrySuggested = false with an in-flight session")
		}
		for _, e := range res.ToolEvents {
			if e.SessionID == "sess-no-twin" {
				t.Fatalf("in-flight session claimed early: %+v", e)
			}
		}
		// The stamp still goes out — that is the whole point of
		// re-emitting inside the window.
		var stamped bool
		for _, s := range res.SessionSurfaces {
			if s.SessionID == "sess-no-twin" {
				stamped = true
			}
		}
		if !stamped {
			t.Error("in-flight session got no surface stamp")
		}
	})

	t.Run("settled session stops retrying and is claimed", func(t *testing.T) {
		home := t.TempDir()
		a := newWorkAdapter(t, home, workFixtureClock)
		path := buildWorkDB(t, home, workFixtureClock)

		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		if res.RetrySuggested {
			t.Error("RetrySuggested = true with every session settled")
		}
		var claimed bool
		for _, e := range res.ToolEvents {
			if e.SessionID == "sess-no-twin" {
				claimed = true
			}
		}
		if !claimed {
			t.Error("settled twin-less session was not claimed")
		}
	})
}

// TestWorkDBWatermarkIdempotence pins the cursor contract: the watermark
// advances to the newest updated_at, a re-parse from it produces the SAME
// rows (the read reaches back one freshness window on purpose) and never
// regresses the cursor, and a watermark past every row still re-stamps.
func TestWorkDBWatermarkIdempotence(t *testing.T) {
	home := t.TempDir()
	a := newWorkAdapter(t, home, workFixtureClock)
	path := buildWorkDB(t, home, workFixtureClock)

	first, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if first.NewOffset != 1788431890613 {
		t.Errorf("NewOffset = %d, want 1788431890613 (MAX(updated_at))", first.NewOffset)
	}

	second, err := a.ParseSessionFile(context.Background(), path, first.NewOffset)
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if second.NewOffset < first.NewOffset {
		t.Errorf("cursor regressed: %d < %d", second.NewOffset, first.NewOffset)
	}
	if len(second.ToolEvents) != len(first.ToolEvents) {
		t.Errorf("re-parse emitted %d events, want the same %d (deterministic ids, idempotent upserts)",
			len(second.ToolEvents), len(first.ToolEvents))
	}
	for i := range first.ToolEvents {
		if first.ToolEvents[i].SourceEventID != second.ToolEvents[i].SourceEventID {
			t.Fatalf("event %d id drifted: %q vs %q", i,
				first.ToolEvents[i].SourceEventID, second.ToolEvents[i].SourceEventID)
		}
	}

	// Far past every row: the window no longer covers them, so nothing
	// is read and the cursor holds.
	far, err := a.ParseSessionFile(context.Background(), path, first.NewOffset+workFreshnessWindow.Milliseconds()+1)
	if err != nil {
		t.Fatalf("far parse: %v", err)
	}
	if len(far.ToolEvents) != 0 || len(far.SessionSurfaces) != 0 {
		t.Errorf("watermark past the window still read rows: %d events, %d stamps",
			len(far.ToolEvents), len(far.SessionSurfaces))
	}
	if far.NewOffset < first.NewOffset {
		t.Errorf("cursor regressed on an empty read: %d", far.NewOffset)
	}
}

// TestWorkDBToolEventShape pins the tool projection on a twinned session
// by claiming it (no twin written), which is also the only place the
// fixture's tools[] entry is reachable.
func TestWorkDBToolEventShape(t *testing.T) {
	home := t.TempDir()
	a := newWorkAdapter(t, home, workFixtureClock)
	path := buildWorkDB(t, home, workFixtureClock)

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var tool *models.ToolEvent
	var assistant *models.ToolEvent
	for i := range res.ToolEvents {
		switch res.ToolEvents[i].SourceEventID {
		case "tool:call_twinnedtoolcall000000":
			tool = &res.ToolEvents[i]
		case "assistant:00000000-0000-4000-8000-0000000000a1":
			assistant = &res.ToolEvents[i]
		}
	}
	if tool == nil {
		t.Fatalf("no tool event emitted: %+v", res.ToolEvents)
	}
	if tool.ActionType != models.ActionRunCommand || tool.RawToolName != "Bash" || tool.Target != "ls" {
		t.Errorf("tool event = %+v, want a run_command/Bash/ls row", tool)
	}
	if !tool.Success || tool.ToolOutput != "README.md" {
		t.Errorf("tool verdict/output = %v/%q, want true/README.md", tool.Success, tool.ToolOutput)
	}
	if tool.DurationMs != 7230 {
		t.Errorf("DurationMs = %d, want 7230", tool.DurationMs)
	}
	if !tool.Timestamp.Equal(parseTimestamp("2026-09-03T10:36:18.915Z")) {
		t.Errorf("tool timestamp = %v, want the tool's own startedAt", tool.Timestamp)
	}
	if assistant == nil {
		t.Fatalf("no assistant message event; the prefix strip regressed")
	}
	// The failed assistant with no text produces nothing.
	for _, e := range res.ToolEvents {
		if e.SessionID == "sess-fresh" && e.ActionType == models.ActionAssistantMessage {
			t.Errorf("empty failed assistant message emitted a row: %+v", e)
		}
	}
}

// TestWorkDBMissingTablesTolerated pins that a fresh Qoder Work install
// (schema present but not yet migrated to the chat tables) is a no-op,
// not a poll-tick error.
func TestWorkDBMissingTablesTolerated(t *testing.T) {
	home := t.TempDir()
	a := newWorkAdapter(t, home, workFixtureClock)
	dir := filepath.Join(home, "AppData", "Roaming", workAppDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, workDBName)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile on a pre-migration store: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.SessionSurfaces) != 0 {
		t.Errorf("pre-migration store produced rows: %+v", res)
	}
}

// TestWorkDBRootsPerOS pins that each home gets the shape belonging to
// ITS logical OS and nothing else — the crossmount root-hygiene contract
// (2026-09-03). A Windows home reached over /mnt/c used to also produce
// a "Library/Application Support" and a ".config" root, neither of which
// can exist under a Windows profile.
func TestWorkDBRootsPerOS(t *testing.T) {
	base := t.TempDir()
	win := filepath.Join(base, "win")
	mac := filepath.Join(base, "mac")
	lin := filepath.Join(base, "lin")
	fakeHomes(t,
		crossmount.HomeRoot{Path: win, OS: crossmount.OSWindows, Origin: "wsl-mnt:win"},
		crossmount.HomeRoot{Path: mac, OS: crossmount.OSDarwin, Origin: "native"},
		crossmount.HomeRoot{Path: lin, OS: crossmount.OSLinux, Origin: "native"},
	)

	got := workDBRoots()
	want := []string{
		filepath.Join(win, "AppData", "Roaming", workAppDir),
		filepath.Join(mac, "Library", "Application Support", workAppDir),
		filepath.Join(lin, ".config", workAppDir),
	}
	if len(got) != len(want) {
		t.Fatalf("workDBRoots: got %d roots %v, want exactly %v", len(got), got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("root %d: got %q want %q", i, got[i], w)
		}
	}

	// The shapes that must NOT be composed for a foreign Windows home.
	for _, forbidden := range []string{
		filepath.Join(win, "Library", "Application Support", workAppDir),
		filepath.Join(win, ".config", workAppDir),
	} {
		for _, r := range got {
			if r == forbidden {
				t.Errorf("windows home produced an impossible root %q", r)
			}
		}
	}

	seen := map[string]bool{}
	for _, r := range got {
		if seen[r] {
			t.Errorf("duplicate root %q", r)
		}
		seen[r] = true
	}
}
