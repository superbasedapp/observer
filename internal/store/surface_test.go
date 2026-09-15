package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSetSessionSurface pins the capture-surface columns (migration
// 094) under FIRST-WINS-UNLESS-EMPTY semantics: the first grounded
// stamp lands, an identical re-stamp reports no change, empty fields
// preserve what is stored, a DIFFERING later stamp is a no-op (a
// re-parse never rewrites a captured origin), a stamp that fills a
// still-empty column IS a change, an out-of-vocabulary kind is refused
// loudly, and a missing session id is a silent no-op.
func TestSetSessionSurface(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/surface", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "surf-sess", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	read := func() (string, string) {
		var kind, host string
		if err := database.QueryRowContext(ctx,
			`SELECT COALESCE(surface,''), COALESCE(surface_host,'') FROM sessions WHERE id='surf-sess'`,
		).Scan(&kind, &host); err != nil {
			t.Fatal(err)
		}
		return kind, host
	}

	cases := []struct {
		name        string
		in          models.SessionSurface
		wantChanged bool
		wantErr     bool
		wantKind    string
		wantHost    string
	}{
		{
			name:        "first stamp, kind only",
			in:          models.SessionSurface{SessionID: "surf-sess", Surface: models.SurfaceIDE},
			wantChanged: true, wantKind: "ide", wantHost: "",
		},
		{
			name:        "later stamp FILLS the still-empty host",
			in:          models.SessionSurface{SessionID: "surf-sess", SurfaceHost: "vscode"},
			wantChanged: true, wantKind: "ide", wantHost: "vscode",
		},
		{
			name:        "identical re-stamp is a no-op",
			in:          models.SessionSurface{SessionID: "surf-sess", Surface: models.SurfaceIDE, SurfaceHost: "vscode"},
			wantChanged: false, wantKind: "ide", wantHost: "vscode",
		},
		{
			name:        "empty fields preserve",
			in:          models.SessionSurface{SessionID: "surf-sess"},
			wantChanged: false, wantKind: "ide", wantHost: "vscode",
		},
		{
			// First-wins: a later parse re-deriving the surface from
			// less context must not rewrite the captured origin.
			name:        "differing later host does NOT overwrite",
			in:          models.SessionSurface{SessionID: "surf-sess", SurfaceHost: "cursor"},
			wantChanged: false, wantKind: "ide", wantHost: "vscode",
		},
		{
			name:        "differing later kind + host does NOT overwrite",
			in:          models.SessionSurface{SessionID: "surf-sess", Surface: models.SurfaceCLI, SurfaceHost: "cursor"},
			wantChanged: false, wantKind: "ide", wantHost: "vscode",
		},
		{
			name:     "vendor token as kind is refused",
			in:       models.SessionSurface{SessionID: "surf-sess", Surface: "codex_vscode"},
			wantErr:  true,
			wantKind: "ide", wantHost: "vscode",
		},
		{
			name:        "missing session is a silent no-op",
			in:          models.SessionSurface{SessionID: "nope", Surface: models.SurfaceCLI},
			wantChanged: false, wantKind: "ide", wantHost: "vscode",
		},
	}
	for _, tc := range cases {
		changed, err := s.SetSessionSurface(ctx, tc.in)
		switch {
		case tc.wantErr:
			if err == nil {
				t.Errorf("%s: want error, got nil", tc.name)
			}
		case err != nil:
			t.Fatalf("%s: %v", tc.name, err)
		case changed != tc.wantChanged:
			t.Errorf("%s: changed=%v want %v", tc.name, changed, tc.wantChanged)
		}
		if k, h := read(); k != tc.wantKind || h != tc.wantHost {
			t.Errorf("%s: stored %q/%q want %q/%q", tc.name, k, h, tc.wantKind, tc.wantHost)
		}
	}

	if _, err := s.SetSessionSurface(ctx, models.SessionSurface{Surface: models.SurfaceCLI}); err == nil {
		t.Error("empty SessionID: want error")
	}

	// Loader round-trips; unknown session propagates sql.ErrNoRows.
	got, err := s.LoadSessionSurface(ctx, "surf-sess")
	if err != nil {
		t.Fatal(err)
	}
	if got.Surface != models.SurfaceIDE || got.SurfaceHost != "vscode" {
		t.Errorf("LoadSessionSurface = %+v", got)
	}
	if _, err := s.LoadSessionSurface(ctx, "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("LoadSessionSurface(missing) err = %v; want sql.ErrNoRows", err)
	}
}

// TestSetSessionSurfaceHosted pins the HOST-WINS branch a stamp with
// models.SessionSurface.Hosted takes: it REPLACES a differing
// self-reported value (the agent's `sdk`/`ts` under an IDE
// orchestrator becomes `ide`/`jetbrains-idea`), an identical hosted
// re-stamp reports no change, empty hosted fields still preserve what
// is stored, a LATER self-report (Hosted=false) can no longer displace
// the hosted value (first-wins-unless-empty sees populated columns), a
// hosted stamp fills an empty row like any other, and the vocabulary /
// missing-session rules are unchanged.
func TestSetSessionSurfaceHosted(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/surface-hosted", "")
	for _, id := range []string{"hosted-a", "hosted-b"} {
		if err := s.UpsertSession(ctx, models.Session{
			ID: id, ProjectID: pid, Tool: models.ToolClaudeCode,
			StartedAt: time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC),
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(id string) (string, string) {
		var kind, host string
		if err := database.QueryRowContext(ctx,
			`SELECT COALESCE(surface,''), COALESCE(surface_host,'') FROM sessions WHERE id=?`, id,
		).Scan(&kind, &host); err != nil {
			t.Fatal(err)
		}
		return kind, host
	}

	cases := []struct {
		name        string
		in          models.SessionSurface
		wantChanged bool
		wantErr     bool
		wantKind    string
		wantHost    string
	}{
		{
			name:        "agent self-report lands first (sdk/ts)",
			in:          models.SessionSurface{SessionID: "hosted-a", Surface: models.SurfaceSDK, SurfaceHost: "ts"},
			wantChanged: true, wantKind: "sdk", wantHost: "ts",
		},
		{
			name:        "hosted stamp REPLACES the self-report",
			in:          models.SessionSurface{SessionID: "hosted-a", Surface: models.SurfaceIDE, SurfaceHost: "jetbrains-idea", Hosted: true},
			wantChanged: true, wantKind: "ide", wantHost: "jetbrains-idea",
		},
		{
			name:        "identical hosted re-stamp is a no-op",
			in:          models.SessionSurface{SessionID: "hosted-a", Surface: models.SurfaceIDE, SurfaceHost: "jetbrains-idea", Hosted: true},
			wantChanged: false, wantKind: "ide", wantHost: "jetbrains-idea",
		},
		{
			name:        "hosted stamp with empty fields preserves",
			in:          models.SessionSurface{SessionID: "hosted-a", Hosted: true},
			wantChanged: false, wantKind: "ide", wantHost: "jetbrains-idea",
		},
		{
			name:        "hosted host-only stamp replaces only the host",
			in:          models.SessionSurface{SessionID: "hosted-a", SurfaceHost: "jetbrains-pycharm", Hosted: true},
			wantChanged: true, wantKind: "ide", wantHost: "jetbrains-pycharm",
		},
		{
			name:        "later self-report re-parse cannot displace the hosted value",
			in:          models.SessionSurface{SessionID: "hosted-a", Surface: models.SurfaceSDK, SurfaceHost: "ts"},
			wantChanged: false, wantKind: "ide", wantHost: "jetbrains-pycharm",
		},
		{
			name:        "hosted stamp on an empty row fills it",
			in:          models.SessionSurface{SessionID: "hosted-b", Surface: models.SurfaceDesktop, SurfaceHost: "qoder-work", Hosted: true},
			wantChanged: true, wantKind: "desktop", wantHost: "qoder-work",
		},
		{
			name:     "hosted vendor token as kind is still refused",
			in:       models.SessionSurface{SessionID: "hosted-b", Surface: "codex_vscode", Hosted: true},
			wantErr:  true,
			wantKind: "desktop", wantHost: "qoder-work",
		},
		{
			name:        "hosted stamp on a missing session is a silent no-op",
			in:          models.SessionSurface{SessionID: "nope", Surface: models.SurfaceIDE, Hosted: true},
			wantChanged: false, wantKind: "desktop", wantHost: "qoder-work",
		},
	}
	for _, tc := range cases {
		changed, err := s.SetSessionSurface(ctx, tc.in)
		switch {
		case tc.wantErr:
			if err == nil {
				t.Errorf("%s: want error, got nil", tc.name)
			}
		case err != nil:
			t.Fatalf("%s: %v", tc.name, err)
		case changed != tc.wantChanged:
			t.Errorf("%s: changed=%v want %v", tc.name, changed, tc.wantChanged)
		}
		id := tc.in.SessionID
		if id == "nope" {
			id = "hosted-b"
		}
		if k, h := read(id); k != tc.wantKind || h != tc.wantHost {
			t.Errorf("%s: stored %q/%q want %q/%q", tc.name, k, h, tc.wantKind, tc.wantHost)
		}
	}
}

// TestIngestAppliesSessionSurfaces pins the Ingest plumbing: surfaces
// passed through IngestOptions land on the upserted session, an entry
// with no session id is skipped, and an out-of-vocabulary kind is
// BEST-EFFORT — the ingest succeeds (its actions/tokens already landed
// before this seam runs), the surface stays untouched, and the rejected
// stamp is counted in IngestResult.SessionSurfacesSkipped rather than
// vanishing.
func TestIngestAppliesSessionSurfaces(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 9, 2, 11, 0, 0, 0, time.UTC)
	ev := models.ToolEvent{
		SourceFile: "/tmp/x.jsonl", SourceEventID: "e1", SessionID: "ing-sess",
		ProjectRoot: "/tmp/ing", Timestamp: ts, Tool: models.ToolCodex,
		ActionType: models.ActionUserPrompt, Target: "hi", Success: true,
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{ev}, nil, IngestOptions{
		SessionSurfaces: []models.SessionSurface{
			{SessionID: "ing-sess", Surface: models.SurfaceCLI, SurfaceHost: "codex-exec"},
			{SessionID: ""}, // skipped
		},
	}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	var kind, host string
	if err := database.QueryRowContext(ctx,
		`SELECT COALESCE(surface,''), COALESCE(surface_host,'') FROM sessions WHERE id='ing-sess'`,
	).Scan(&kind, &host); err != nil {
		t.Fatal(err)
	}
	if kind != models.SurfaceCLI || host != "codex-exec" {
		t.Errorf("surface after Ingest = %q/%q", kind, host)
	}

	// Out-of-vocabulary kind on a session with NO surface yet: the
	// ingest still succeeds, the column stays empty (never a vendor
	// token), and the skip is counted.
	ev2 := ev
	ev2.SourceEventID = "e2"
	ev2.SessionID = "ing-sess-2"
	res, err := s.Ingest(ctx, []models.ToolEvent{ev2}, nil, IngestOptions{
		SessionSurfaces: []models.SessionSurface{{SessionID: "ing-sess-2", Surface: "bogus"}},
	})
	if err != nil {
		t.Fatalf("Ingest with out-of-vocabulary surface must not fail the ingest: %v", err)
	}
	if res.SessionSurfacesSkipped != 1 {
		t.Errorf("SessionSurfacesSkipped = %d, want 1", res.SessionSurfacesSkipped)
	}
	if res.ActionsInserted != 1 {
		t.Errorf("ActionsInserted = %d, want 1 (the action must still land)", res.ActionsInserted)
	}
	var kind2 string
	if err := database.QueryRowContext(ctx,
		`SELECT COALESCE(surface,'') FROM sessions WHERE id='ing-sess-2'`,
	).Scan(&kind2); err != nil {
		t.Fatal(err)
	}
	if kind2 != "" {
		t.Errorf("out-of-vocabulary surface persisted as %q; want empty", kind2)
	}
}

// TestLoadSurfaceCounts pins the per-(tool, surface, host) rollup: two
// tools across two surfaces, a session no adapter stamped (rolling up
// under the honest empty surface), the deduped-per-session spend sum,
// and the `since` window filter.
func TestLoadSurfaceCounts(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/surfcounts", "")
	if err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	seed := []struct {
		id      string
		tool    string
		started time.Time
		surface models.SessionSurface
		cost    []float64 // one token_usage row per entry
	}{
		{"s-cc-ide", models.ToolClaudeCode, base, models.SessionSurface{Surface: models.SurfaceIDE, SurfaceHost: "vscode"}, []float64{0.25, 0.25}},
		{"s-cc-cli", models.ToolClaudeCode, base.Add(time.Hour), models.SessionSurface{Surface: models.SurfaceCLI}, []float64{1.0}},
		{"s-cx-ide", models.ToolCodex, base.Add(2 * time.Hour), models.SessionSurface{Surface: models.SurfaceIDE, SurfaceHost: "vscode"}, nil},
		{"s-cx-cli", models.ToolCodex, base.Add(3 * time.Hour), models.SessionSurface{Surface: models.SurfaceCLI, SurfaceHost: "codex-exec"}, []float64{2.0}},
		// No adapter stamped this one — the honest unknown.
		{"s-cx-none", models.ToolCodex, base.Add(4 * time.Hour), models.SessionSurface{}, nil},
	}
	for _, row := range seed {
		if err := s.UpsertSession(ctx, models.Session{
			ID: row.id, ProjectID: pid, Tool: row.tool, StartedAt: row.started,
		}); err != nil {
			t.Fatal(err)
		}
		if row.surface.Surface != "" || row.surface.SurfaceHost != "" {
			sf := row.surface
			sf.SessionID = row.id
			if _, err := s.SetSessionSurface(ctx, sf); err != nil {
				t.Fatal(err)
			}
		}
		for i, c := range row.cost {
			if _, err := s.InsertTokenEvents(ctx, []models.TokenEvent{{
				SessionID: row.id, Tool: row.tool, Model: "m",
				Timestamp:     row.started,
				SourceFile:    "/tmp/x.jsonl",
				SourceEventID: fmt.Sprintf("%s-t%d", row.id, i),
				InputTokens:   10, OutputTokens: 10,
				EstimatedCostUSD: c,
			}}); err != nil {
				t.Fatal(err)
			}
		}
	}

	counts, err := s.LoadSurfaceCounts(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	type key struct{ tool, surface, host string }
	got := map[key]SurfaceCount{}
	for _, c := range counts {
		got[key{c.Tool, c.Surface, c.SurfaceHost}] = c
	}
	if len(counts) != 5 {
		t.Fatalf("rows=%d want 5: %+v", len(counts), counts)
	}
	for _, want := range []struct {
		k        key
		sessions int64
		cost     float64
	}{
		{key{models.ToolClaudeCode, models.SurfaceIDE, "vscode"}, 1, 0.5},
		{key{models.ToolClaudeCode, models.SurfaceCLI, ""}, 1, 1.0},
		{key{models.ToolCodex, models.SurfaceIDE, "vscode"}, 1, 0},
		{key{models.ToolCodex, models.SurfaceCLI, "codex-exec"}, 1, 2.0},
		{key{models.ToolCodex, "", ""}, 1, 0}, // unstamped rolls up honestly
	} {
		c, ok := got[want.k]
		if !ok {
			t.Errorf("missing row %+v; got %+v", want.k, counts)
			continue
		}
		if c.Sessions != want.sessions {
			t.Errorf("%+v sessions=%d want %d", want.k, c.Sessions, want.sessions)
		}
		if diff := c.CostUSD - want.cost; diff > 1e-9 || diff < -1e-9 {
			t.Errorf("%+v cost=%v want %v", want.k, c.CostUSD, want.cost)
		}
	}

	// Ordering is (tool, surface, host) so the rollup renders stably.
	for i := 1; i < len(counts); i++ {
		prev, cur := counts[i-1], counts[i]
		if prev.Tool > cur.Tool ||
			(prev.Tool == cur.Tool && prev.Surface > cur.Surface) ||
			(prev.Tool == cur.Tool && prev.Surface == cur.Surface && prev.SurfaceHost > cur.SurfaceHost) {
			t.Errorf("rows out of order at %d: %+v then %+v", i, prev, cur)
		}
	}

	// `since` filters on started_at: only the last two codex sessions.
	since := base.Add(3 * time.Hour).Format(time.RFC3339)
	windowed, err := s.LoadSurfaceCounts(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(windowed) != 2 {
		t.Fatalf("since=%s rows=%d want 2: %+v", since, len(windowed), windowed)
	}
	for _, c := range windowed {
		if c.Tool != models.ToolCodex {
			t.Errorf("since filter leaked %+v", c)
		}
	}
}
