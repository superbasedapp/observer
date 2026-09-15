package devin

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// desktopFixtureSQL is the anonymized dump derived from a LIVE Devin
// Desktop 2.3.15 run (Windows, 2026-09-03) — see
// testdata/devin/README.md for the derivation rules. It is a text .sql
// file rather than a .db because the repo tracks no SQLite binaries
// (tree-wide *.db gitignore); the test materializes it per-run.
const desktopFixtureSQL = "../../../testdata/devin/desktop/sessions.sql"

// desktopStore materializes the derived fixture into a sessions.db under
// a `cli` directory, mirroring the real store layout so IsSessionFile
// and the watch root behave exactly as in production.
func desktopStore(t *testing.T) string {
	t.Helper()
	sqlText, err := os.ReadFile(desktopFixtureSQL)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "cli")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "sessions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(sqlText)); err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return dbPath
}

func parseDesktop(t *testing.T) (string, adapterResult) {
	t.Helper()
	dbPath := desktopStore(t)
	a := NewWithOptions(nil, []string{filepath.Dir(dbPath)})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	return dbPath, adapterResult{
		tools:     res.ToolEvents,
		tokens:    res.TokenEvents,
		surfaces:  res.SessionSurfaces,
		lineages:  res.SessionLineages,
		warnings:  res.Warnings,
		newOffset: res.NewOffset,
	}
}

type adapterResult struct {
	tools     []models.ToolEvent
	tokens    []models.TokenEvent
	surfaces  []models.SessionSurface
	lineages  []models.SessionLineage
	warnings  []string
	newOffset int64
}

// TestDesktopFixtureShape pins what the parser emits for the real
// desktop run: both sessions parse, the user session's five prompts and
// its tool calls land, and no node is dropped as malformed.
func TestDesktopFixtureShape(t *testing.T) {
	_, res := parseDesktop(t)

	if len(res.warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.warnings)
	}
	if res.newOffset != 216 {
		t.Errorf("NewOffset = %d, want 216 (MAX(row_id) in the derived store)", res.newOffset)
	}

	perSession := map[string]map[string]int{}
	for _, e := range res.tools {
		if e.Tool != models.ToolDevin {
			t.Fatalf("event %q tagged tool %q", e.SourceEventID, e.Tool)
		}
		m := perSession[e.SessionID]
		if m == nil {
			m = map[string]int{}
			perSession[e.SessionID] = m
		}
		m[e.ActionType]++
	}

	user := perSession["amber-lantern"]
	if user == nil {
		t.Fatal("no events for the user session amber-lantern")
	}
	// The live run was a 5-step prompt kit sent as 2 user messages
	// (the kit, then a follow-up), driving exec/read/write/edit calls.
	for _, want := range []struct {
		action string
		n      int
	}{
		{models.ActionUserPrompt, 2},
		{models.ActionRunCommand, 5},
		{models.ActionReadFile, 1},
		{models.ActionWriteFile, 1},
		{models.ActionEditFile, 1},
		{models.ActionTaskComplete, 2},
	} {
		if got := user[want.action]; got != want.n {
			t.Errorf("amber-lantern %s = %d, want %d (all: %v)", want.action, got, want.n, user)
		}
	}
	if got := user[models.ActionUnknown]; got != 0 {
		t.Errorf("amber-lantern produced %d unknown actions, want 0", got)
	}

	// The summary-agent session is KEPT (marked, not dropped).
	if sidecar := perSession["tidy-marmot"]; len(sidecar) == 0 {
		t.Error("summary-agent session tidy-marmot produced no events — it must be kept, only marked")
	}
}

// TestDesktopFixtureTokens pins the token capture for the real run.
// cache_read_tokens is populated on every assistant node here, which the
// pre-desktop capture never saw (all cache fields were NULL then).
func TestDesktopFixtureTokens(t *testing.T) {
	_, res := parseDesktop(t)

	var in, out, cacheRead, cacheCreate int64
	models := map[string]int{}
	perSession := map[string]int{}
	for _, tok := range res.tokens {
		in += tok.InputTokens
		out += tok.OutputTokens
		cacheRead += tok.CacheReadTokens
		cacheCreate += tok.CacheCreationTokens
		models[tok.Model]++
		perSession[tok.SessionID]++
	}
	if got, want := perSession["amber-lantern"], 10; got != want {
		t.Errorf("amber-lantern token rows = %d, want %d", got, want)
	}
	if got, want := perSession["tidy-marmot"], 1; got != want {
		t.Errorf("tidy-marmot token rows = %d, want %d", got, want)
	}
	if in != 3188 || out != 1327 {
		t.Errorf("totals = %d in / %d out, want 3188 in / 1327 out", in, out)
	}
	if cacheRead == 0 {
		t.Error("cache_read_tokens summed to 0 — the desktop capture DOES carry cache reads")
	}
	if cacheCreate != 0 {
		t.Errorf("cache_creation_tokens = %d, want 0 (NULL in every live row)", cacheCreate)
	}
	if models["swe-1-6-slow"] == 0 {
		t.Errorf("no rows carried the generation model swe-1-6-slow: %v", models)
	}
	if models["summarizer"] != 1 {
		t.Errorf("summarizer rows = %d, want 1 (the summary-agent session)", models["summarizer"])
	}
}

// TestDesktopFixtureSurfaceAndLineage pins the session-lane attribution:
// the desktop-opened session is stamped ide/devin-desktop from its
// client_meta tab id, and the hidden summary-agent session is marked a
// machine-spawned sidecar (and carries NO surface, since the store holds
// no evidence of which client spawned it).
func TestDesktopFixtureSurfaceAndLineage(t *testing.T) {
	_, res := parseDesktop(t)

	if len(res.surfaces) != 1 {
		t.Fatalf("surfaces = %+v, want exactly 1", res.surfaces)
	}
	got := res.surfaces[0]
	want := models.SessionSurface{SessionID: "amber-lantern", Surface: models.SurfaceIDE, SurfaceHost: "devin-desktop"}
	if got != want {
		t.Errorf("surface = %+v, want %+v", got, want)
	}

	if len(res.lineages) != 1 {
		t.Fatalf("lineages = %+v, want exactly 1", res.lineages)
	}
	lin := res.lineages[0]
	if lin.SessionID != "tidy-marmot" || lin.ThreadSource != threadSourceSubagent {
		t.Errorf("lineage = %+v, want {tidy-marmot, subagent}", lin)
	}
	if lin.ParentThreadID != "" || lin.ForkedFromID != "" {
		t.Errorf("lineage = %+v, want empty parent links (the link lives in the desktop globalStorage, not this store)", lin)
	}
}

// TestDesktopFixtureProjectRoot pins the raw Windows working_directory
// carried through the crossmount translation.
func TestDesktopFixtureProjectRoot(t *testing.T) {
	_, res := parseDesktop(t)
	for _, e := range res.tools {
		if e.SessionID != "amber-lantern" {
			continue
		}
		if !strings.Contains(strings.ToLower(e.ProjectRoot), "demo") {
			t.Errorf("ProjectRoot = %q, want the session's workspace dir", e.ProjectRoot)
		}
		return
	}
	t.Fatal("no events for amber-lantern")
}

// TestDesktopFixtureWatermark pins incrementality against the derived
// store: a re-parse at the returned offset is a no-op.
func TestDesktopFixtureWatermark(t *testing.T) {
	dbPath := desktopStore(t)
	a := NewWithOptions(nil, []string{filepath.Dir(dbPath)})
	first, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.ParseSessionFile(context.Background(), dbPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.ToolEvents) != 0 || len(again.TokenEvents) != 0 ||
		len(again.SessionSurfaces) != 0 || len(again.SessionLineages) != 0 {
		t.Errorf("re-parse at the watermark emitted %d tools / %d tokens / %d surfaces / %d lineages, want none",
			len(again.ToolEvents), len(again.TokenEvents), len(again.SessionSurfaces), len(again.SessionLineages))
	}
	if again.NewOffset != first.NewOffset {
		t.Errorf("NewOffset drifted: %d then %d", first.NewOffset, again.NewOffset)
	}
}
