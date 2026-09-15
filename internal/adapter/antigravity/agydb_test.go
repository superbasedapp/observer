package antigravity

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/protowire"
)

// Fixture uuids (testdata/antigravity/README.md).
const (
	vscodeFixtureConversationID = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	cliFixtureConversationID    = "2b3c4d5e-6f70-4a8b-9c0d-1e2f3a4b5c6e"
)

// agyDBSpec is what buildAgyDB materialises: the grounded 2026-09-03
// schema (all seven tables) with synthetic blobs.
type agyDBSpec struct {
	path      string
	uuid      string
	model     string
	gens      int
	source    int64 // trajectory_meta.source; skipped when noMeta
	noMeta    bool  // omit the trajectory_meta table entirely
	projectID string
}

// buildAgyDB writes a .db with the exact table set both live copies carry.
func buildAgyDB(t *testing.T, spec agyDBSpec) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(spec.path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+spec.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, ddl := range []string{
		"CREATE TABLE `battle_mode_infos` (`idx` integer,`data` blob,PRIMARY KEY (`idx`))",
		"CREATE TABLE `executor_metadata` (`idx` integer,`data` blob,PRIMARY KEY (`idx`))",
		"CREATE TABLE `gen_metadata` (`idx` integer,`data` blob,`size` integer NOT NULL DEFAULT 0,PRIMARY KEY (`idx`))",
		"CREATE TABLE `parent_references` (`idx` integer,`data` blob,PRIMARY KEY (`idx`))",
		"CREATE TABLE `steps` (`idx` integer,`step_type` integer NOT NULL DEFAULT 0,`status` integer NOT NULL DEFAULT 0,`has_subtrajectory` numeric NOT NULL DEFAULT false,`metadata` blob,`error_details` blob,`permissions` blob,`task_details` blob,`render_info` blob,`step_payload` blob,`step_format` integer NOT NULL DEFAULT 0,PRIMARY KEY (`idx`))",
		"CREATE TABLE `trajectory_metadata_blob` (`id` text DEFAULT \"main\",`data` blob,PRIMARY KEY (`id`))",
	} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("%s: %v", ddl, err)
		}
	}
	if !spec.noMeta {
		if _, err := db.Exec("CREATE TABLE `trajectory_meta` (`trajectory_id` text,`cascade_id` text,`trajectory_type` integer,`source` integer,PRIMARY KEY (`trajectory_id`))"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("INSERT INTO trajectory_meta VALUES(?,?,4,?)", "traj-"+spec.uuid, spec.uuid, spec.source); err != nil {
			t.Fatal(err)
		}
	}
	// steps: 14 then alternating 15/132, status 3 — the live sequence.
	for i := 0; i < 2*spec.gens; i++ {
		st := 15
		switch {
		case i == 0:
			st = 14
		case i%2 == 0:
			st = 132
		}
		if _, err := db.Exec("INSERT INTO steps(idx,step_type,status,step_payload) VALUES(?,?,3,?)", i, st, []byte("opaque")); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < spec.gens; i++ {
		blob := genBlob(spec.model, 1071, 16556, uint64(12210*i), 228, uint64(55+i))
		if _, err := db.Exec("INSERT INTO gen_metadata(idx,data,size) VALUES(?,?,?)", i, blob, len(blob)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("INSERT INTO executor_metadata(idx,data) VALUES(0,?)", []byte("opaque")); err != nil {
		t.Fatal(err)
	}
	if spec.projectID != "" {
		traj := protowire.AppendBytesField(nil, 6, []byte(spec.uuid))
		traj = protowire.AppendBytesField(traj, 18, []byte(spec.projectID))
		if _, err := db.Exec("INSERT INTO trajectory_metadata_blob(id,data) VALUES('main',?)", traj); err != nil {
			t.Fatal(err)
		}
	}
}

// copyFixtureTranscript places a checked-in transcript under
// <tree>/brain/<uuid>/.system_generated/logs/ and returns its path.
func copyFixtureTranscript(t *testing.T, fixtureDir, tree, uuid string) string {
	t.Helper()
	src := filepath.Join("..", "..", "..", "testdata", "antigravity", fixtureDir, "brain", uuid, ".system_generated", "logs", "transcript.jsonl")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dir := filepath.Join(tree, "brain", uuid, ".system_generated", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "transcript.jsonl")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// eventKeys returns the (SourceFile, SourceEventID) pairs of a result in
// order — the identity the store's UNIQUE index dedupes on.
func eventKeys(evs []models.ToolEvent) []string {
	out := make([]string, 0, len(evs))
	for _, ev := range evs {
		out = append(out, ev.SourceFile+"|"+ev.SourceEventID)
	}
	return out
}

func TestClassifyLayoutAgyDBBothTrees(t *testing.T) {
	cases := []struct {
		path string
		want Layout
	}{
		{"/home/u/.gemini/antigravity-cli/conversations/" + cliFixtureConversationID + ".db", LayoutCLIDB},
		{"/home/u/.gemini/antigravity-acp/conversations/" + cliFixtureConversationID + ".db", LayoutCLIDB},
		{"/home/u/.gemini/antigravity-acp/conversations/" + cliFixtureConversationID + ".db-wal", LayoutCLIDB},
		{`C:\Users\u\.gemini\antigravity\conversations\` + vscodeFixtureConversationID + `.db`, LayoutDesktopDB},
		{"/mnt/c/Users/u/.gemini/antigravity/conversations/" + vscodeFixtureConversationID + ".db", LayoutDesktopDB},
		// WAL sidecars are claimed (the cline-cli precedent) and mapped
		// back onto the main file.
		{"/home/u/.gemini/antigravity/conversations/" + vscodeFixtureConversationID + ".db-wal", LayoutDesktopDB},
		{"/home/u/.gemini/antigravity-cli/conversations/" + cliFixtureConversationID + ".db-shm", LayoutCLIDB},
		{"/home/u/.gemini/antigravity/implicit/" + vscodeFixtureConversationID + ".db", LayoutUnknown},
	}
	for _, tc := range cases {
		if got := classifyLayout(tc.path); got != tc.want {
			t.Errorf("classifyLayout(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
	if got := agyDBMainPath("/x/y.db-wal"); got != "/x/y.db" {
		t.Errorf("agyDBMainPath(-wal) = %q", got)
	}
	if got := agyDBMainPath("/x/y.db"); got != "/x/y.db" {
		t.Errorf("agyDBMainPath(.db) = %q", got)
	}
	// Desktop adapter claims the desktop .db; the CLI adapter does not
	// (and vice versa).
	home := t.TempDir()
	desktopDB := filepath.Join(home, ".gemini", "antigravity", "conversations", vscodeFixtureConversationID+".db")
	cliDB := filepath.Join(home, ".gemini", "antigravity-cli", "conversations", cliFixtureConversationID+".db")
	desktop := NewWithOptions(nil, filepath.Dir(desktopDB), filepath.Join(home, ".gemini", "antigravity", "brain"))
	cli := NewCLI()
	cli.roots = []string{filepath.Dir(cliDB)}
	if !desktop.IsSessionFile(desktopDB) || desktop.IsSessionFile(cliDB) {
		t.Error("desktop adapter must claim exactly the desktop-tree .db")
	}
	if cli.IsSessionFile(desktopDB) {
		t.Error("cli adapter must not claim the desktop-tree .db")
	}
	// Watermark, not size, is the cursor kind for the .db and its sidecars.
	for _, p := range []string{desktopDB, desktopDB + "-wal"} {
		if desktop.CursorSemanticsFor(p).Kind != adapter.CursorWatermark {
			t.Errorf("%s: cursor kind must be watermark", p)
		}
	}
}

func TestParseDesktopDB_VSCodeExtension(t *testing.T) {
	home := t.TempDir()
	tree := filepath.Join(home, ".gemini", "antigravity")
	convRoot := filepath.Join(tree, "conversations")
	brainRoot := filepath.Join(tree, "brain")
	transcript := copyFixtureTranscript(t, "desktop-vscode", tree, vscodeFixtureConversationID)
	dbPath := filepath.Join(convRoot, vscodeFixtureConversationID+".db")
	const projectID = "fb000000-0000-4000-8000-000000000001"
	buildAgyDB(t, agyDBSpec{path: dbPath, uuid: vscodeFixtureConversationID, model: "gemini-3.6-flash", gens: 10, source: 1, projectID: projectID})
	// The extension's project file: folderUri at the RESOURCE level.
	projectsDir := filepath.Join(home, ".gemini", "config", "projects")
	if err := os.MkdirAll(projectsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	projJSON := `{"id":"` + projectID + `","name":"stepin-vscode","projectResources":{"resources":[{"folderUri":"file:///c%3A/Users/dev/work/stepin-vscode"}]},"settings":{},"isWorkspaceOnly":false}`
	if err := os.WriteFile(filepath.Join(projectsDir, projectID+".json"), []byte(projJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, convRoot, brainRoot)
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
	if res.NewOffset != agyDBWatermark(dbPath) || res.NewOffset < 1_000_000_000_000 {
		t.Errorf("NewOffset = %d, want the mtime watermark %d", res.NewOffset, agyDBWatermark(dbPath))
	}
	// Tokens: one row per generation, real model id.
	if len(res.TokenEvents) != 10 {
		t.Fatalf("TokenEvents = %d, want 10", len(res.TokenEvents))
	}
	wantRoot, _, _ := decodeFileURIToRoot("file:///c%3A/Users/dev/work/stepin-vscode")
	for _, te := range res.TokenEvents {
		if te.Model != "gemini-3.6-flash" || te.SessionID != vscodeFixtureConversationID || te.ProjectRoot != wantRoot || te.SourceFile != dbPath {
			t.Errorf("token row = model %q session %q root %q src %q", te.Model, te.SessionID, te.ProjectRoot, te.SourceFile)
		}
	}
	// Surface: trajectory_meta.source=1 → ide/vscode.
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != (models.SessionSurface{SessionID: vscodeFixtureConversationID, Surface: models.SurfaceIDE, SurfaceHost: "vscode"}) {
		t.Errorf("surfaces = %+v, want one ide/vscode stamp", res.SessionSurfaces)
	}
	// Text + actions from the sibling transcript, keyed on the TRANSCRIPT
	// (source_file + the shared id namespace), with the .db's model id
	// and the raw source on the prompt.
	counts := map[string]int{}
	for _, ev := range res.ToolEvents {
		counts[ev.ActionType]++
		if !strings.HasPrefix(ev.SourceEventID, transcriptEventIDPrefix+vscodeFixtureConversationID+":step:") {
			t.Errorf("%s: not in the shared transcript namespace", ev.SourceEventID)
		}
		if ev.SourceFile != transcript {
			t.Errorf("%s: SourceFile = %q, want the transcript %q", ev.SourceEventID, ev.SourceFile, transcript)
		}
		if ev.Model != "gemini-3.6-flash" {
			t.Errorf("%s: Model = %q, want the .db model id over the display name", ev.SourceEventID, ev.Model)
		}
		if ev.ProjectRoot != wantRoot {
			t.Errorf("%s: ProjectRoot = %q, want %q", ev.SourceEventID, ev.ProjectRoot, wantRoot)
		}
		if ev.ActionType == models.ActionUserPrompt {
			if ev.Metadata == nil || ev.Metadata.CaptureSource != "trajectory_meta.source=1" || ev.Metadata.IsZero() {
				t.Errorf("user_prompt must record the raw source in a non-zero metadata: %+v", ev.Metadata)
			}
		}
		if ev.ActionType == models.ActionRunCommand && (!ev.Success || ev.ErrorMessage != "") {
			t.Errorf("%s: exit code 0 must be success: %v %q", ev.SourceEventID, ev.Success, ev.ErrorMessage)
		}
	}
	want := map[string]int{
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 1,
		models.ActionSearchFiles:      3, // list_dir ×2 + find_by_name
		models.ActionReadFile:         1,
		models.ActionWriteFile:        1,
		models.ActionEditFile:         1,
		models.ActionRunCommand:       3,
	}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s = %d, want %d (%v)", k, counts[k], v, counts)
		}
	}
	if len(res.ToolEvents) != 11 {
		t.Errorf("ToolEvents = %d, want 11", len(res.ToolEvents))
	}
	if !strings.HasSuffix(res.ToolEvents[0].SourceEventID, ":step:0:user") {
		t.Errorf("first row = %s", res.ToolEvents[0].SourceEventID)
	}

	// The -wal sidecar path parses the same store.
	if err := os.WriteFile(dbPath+"-wal", []byte("wal"), 0o644); err != nil {
		t.Fatal(err)
	}
	viaWal, err := a.ParseSessionFile(context.Background(), dbPath+"-wal", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(viaWal.TokenEvents) != 10 || len(viaWal.ToolEvents) != 11 {
		t.Errorf("-wal path parse = %d tokens, %d events", len(viaWal.TokenEvents), len(viaWal.ToolEvents))
	}
}

func TestAgyDBWatermarkCursor(t *testing.T) {
	home := t.TempDir()
	tree := filepath.Join(home, ".gemini", "antigravity-cli")
	copyFixtureTranscript(t, "cli", tree, cliFixtureConversationID)
	dbPath := filepath.Join(tree, "conversations", cliFixtureConversationID+".db")
	buildAgyDB(t, agyDBSpec{path: dbPath, uuid: cliFixtureConversationID, model: "gemini-3.8-flash", gens: 2, source: 17})
	a := NewWithOptions(nil, filepath.Join(tree, "conversations")).WithName(models.ToolAntigravityCLI)
	ctx := context.Background()

	first, err := a.ParseSessionFile(ctx, dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.TokenEvents) != 2 {
		t.Fatalf("first parse: %d tokens", len(first.TokenEvents))
	}
	// Cursor at the watermark: no work, cursor held.
	same, err := a.ParseSessionFile(ctx, dbPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(same.TokenEvents)+len(same.ToolEvents) != 0 || same.NewOffset != first.NewOffset {
		t.Errorf("parse at watermark must be a no-op: %d/%d, offset %d vs %d", len(same.TokenEvents), len(same.ToolEvents), same.NewOffset, first.NewOffset)
	}
	// A WAL write bumps only the sidecar's mtime; the main file is
	// untouched — the watermark still moves and the parse re-fires.
	future := time.Now().Add(2 * time.Second)
	if err := os.WriteFile(dbPath+"-wal", []byte("turn"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dbPath+"-wal", future, future); err != nil {
		t.Fatal(err)
	}
	if wm := agyDBWatermark(dbPath); wm <= first.NewOffset {
		t.Fatalf("watermark did not advance on a -wal write: %d vs %d", wm, first.NewOffset)
	}
	again, err := a.ParseSessionFile(ctx, dbPath, first.NewOffset)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.TokenEvents) != 2 || again.NewOffset <= first.NewOffset {
		t.Errorf("re-parse after a -wal write = %d tokens, offset %d (was %d)", len(again.TokenEvents), again.NewOffset, first.NewOffset)
	}
}

func TestParseCLIDB_SourceSurfaceTable(t *testing.T) {
	type tc struct {
		name      string
		tree      string // "cli" | "desktop"
		source    int64
		noMeta    bool
		wantStamp *models.SessionSurface
		wantWarn  bool
	}
	cases := []tc{
		{name: "cli source 17", tree: "cli", source: 17, wantStamp: &models.SessionSurface{Surface: models.SurfaceCLI, SurfaceHost: "antigravity-cli"}},
		{name: "cli unknown source → no stamp + warning", tree: "cli", source: 5, wantStamp: nil, wantWarn: true},
		{name: "cli no trajectory_meta → no stamp, no warning", tree: "cli", noMeta: true, wantStamp: nil},
		{name: "desktop source 1", tree: "desktop", source: 1, wantStamp: &models.SessionSurface{Surface: models.SurfaceIDE, SurfaceHost: "vscode"}},
		{name: "desktop source 17 (agy pointed at the desktop tree)", tree: "desktop", source: 17, wantStamp: &models.SessionSurface{Surface: models.SurfaceCLI, SurfaceHost: "antigravity-cli"}},
		{name: "desktop unknown source → tree default + warning", tree: "desktop", source: 99, wantStamp: &models.SessionSurface{Surface: models.SurfaceIDE, SurfaceHost: "antigravity"}, wantWarn: true},
		{name: "desktop no trajectory_meta yet → no stamp (first-wins must not freeze a guess)", tree: "desktop", noMeta: true, wantStamp: nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			sub, uuid, fixture := "antigravity-cli", cliFixtureConversationID, "cli"
			if c.tree == "desktop" {
				sub, uuid, fixture = "antigravity", vscodeFixtureConversationID, "desktop-vscode"
			}
			tree := filepath.Join(home, ".gemini", sub)
			copyFixtureTranscript(t, fixture, tree, uuid)
			dbPath := filepath.Join(tree, "conversations", uuid+".db")
			buildAgyDB(t, agyDBSpec{path: dbPath, uuid: uuid, model: "gemini-3.8-flash", gens: 2, source: c.source, noMeta: c.noMeta})
			var a *Adapter
			if c.tree == "desktop" {
				a = NewWithOptions(nil, filepath.Join(tree, "conversations"), filepath.Join(tree, "brain"))
			} else {
				a = NewWithOptions(nil, filepath.Join(tree, "conversations")).WithName(models.ToolAntigravityCLI)
			}
			res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
			if err != nil {
				t.Fatal(err)
			}
			if c.wantStamp == nil {
				if len(res.SessionSurfaces) != 0 {
					t.Errorf("expected no stamp, got %+v", res.SessionSurfaces)
				}
			} else {
				want := *c.wantStamp
				want.SessionID = uuid
				if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
					t.Errorf("surfaces = %+v, want %+v", res.SessionSurfaces, want)
				}
			}
			gotWarn := false
			for _, w := range res.Warnings {
				if strings.Contains(w, "unmapped trajectory_meta.source") {
					gotWarn = true
				}
			}
			if gotWarn != c.wantWarn {
				t.Errorf("warning = %v, want %v (%v)", gotWarn, c.wantWarn, res.Warnings)
			}
			if c.wantWarn {
				// The warning is a first-parse notice, not a per-poll one.
				later, err := a.ParseSessionFile(context.Background(), dbPath, 1)
				if err != nil {
					t.Fatal(err)
				}
				for _, w := range later.Warnings {
					if strings.Contains(w, "unmapped trajectory_meta.source") {
						t.Errorf("warning repeated on a later parse: %v", later.Warnings)
					}
				}
			}
			if len(res.TokenEvents) != 2 {
				t.Errorf("TokenEvents = %d, want 2", len(res.TokenEvents))
			}
			if len(res.ToolEvents) != 11 {
				t.Errorf("ToolEvents = %d, want 11 (text + actions from the transcript)", len(res.ToolEvents))
			}
			// CLI tree: default-cli-project has no workspace, so the root
			// comes from the transcript's Cwd.
			if c.tree == "cli" {
				wantRoot, _ := rootFromWorkingDir(`C:\Users\dev\work\stepin`)
				if got := res.TokenEvents[0].ProjectRoot; got != wantRoot {
					t.Errorf("cli project root = %q, want the tool-call Cwd %q", got, wantRoot)
				}
			}
		})
	}
}

func TestConversationPrecedenceBothTrees(t *testing.T) {
	ctx := context.Background()

	t.Run("desktop tree: .db and transcript key identically; .pb defers", func(t *testing.T) {
		home := t.TempDir()
		tree := filepath.Join(home, ".gemini", "antigravity")
		transcript := copyFixtureTranscript(t, "desktop-vscode", tree, vscodeFixtureConversationID)
		dbPath := filepath.Join(tree, "conversations", vscodeFixtureConversationID+".db")
		pbPath := filepath.Join(tree, "conversations", vscodeFixtureConversationID+".pb")
		a := NewWithOptions(nil, filepath.Join(tree, "conversations"), filepath.Join(tree, "brain"))

		// Transcript FIRST, no .db yet (the standalone-IDE shape, or a
		// late-.db client): tree-default stamp, display-name model.
		before, err := a.ParseSessionFile(ctx, transcript, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(before.ToolEvents) != 11 || len(before.SessionSurfaces) != 1 || before.SessionSurfaces[0].SurfaceHost != "antigravity" {
			t.Fatalf("transcript-only parse = %d events, surfaces %+v", len(before.ToolEvents), before.SessionSurfaces)
		}
		if before.ToolEvents[0].Model != "Gemini 3.6 Flash (High)" {
			t.Errorf("transcript-only model = %q", before.ToolEvents[0].Model)
		}

		// The .db appears LATER: its rows carry the SAME (source_file,
		// source_event_id) keys, so the store's UNIQUE index absorbs them
		// — nothing re-lists.
		buildAgyDB(t, agyDBSpec{path: dbPath, uuid: vscodeFixtureConversationID, model: "gemini-3.6-flash", gens: 1, source: 1})
		viaDB, err := a.ParseSessionFile(ctx, dbPath, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(viaDB.TokenEvents) != 1 || len(viaDB.ToolEvents) != 11 {
			t.Fatalf(".db parse = %d tokens, %d events", len(viaDB.TokenEvents), len(viaDB.ToolEvents))
		}
		if got, want := strings.Join(eventKeys(viaDB.ToolEvents), "\n"), strings.Join(eventKeys(before.ToolEvents), "\n"); got != want {
			t.Errorf("transcript→.db keys differ:\n%s\n---\n%s", got, want)
		}
		// And the transcript re-parsed AFTER the .db exists now reads the
		// .db's enrichment, so its rows are byte-identical to the .db's.
		after, err := a.ParseSessionFile(ctx, transcript, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(after.ToolEvents) != 11 || len(after.SessionSurfaces) != 1 || after.SessionSurfaces[0].SurfaceHost != "vscode" {
			t.Errorf("transcript parse with a .db sibling = %d events, surfaces %+v", len(after.ToolEvents), after.SessionSurfaces)
		}
		for i := range after.ToolEvents {
			x, y := after.ToolEvents[i], viaDB.ToolEvents[i]
			if x.SourceFile != y.SourceFile || x.SourceEventID != y.SourceEventID || x.Model != y.Model || x.Target != y.Target ||
				(x.Metadata == nil) != (y.Metadata == nil) || (x.Metadata != nil && x.Metadata.CaptureSource != y.Metadata.CaptureSource) {
				t.Errorf("row %d differs between owners:\n%+v\n%+v", i, x, y)
			}
		}
		// The encrypted .pb defers to whichever plaintext sibling exists.
		if err := os.WriteFile(pbPath, []byte("encrypted-opaque"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := a.ParseSessionFile(ctx, pbPath, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.ToolEvents)+len(res.TokenEvents)+len(res.SessionSurfaces) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "out-ranked by its sibling "+vscodeFixtureConversationID+".db") {
			t.Errorf(".pb must defer to the .db: %d events, %v", len(res.ToolEvents), res.Warnings)
		}
		if err := os.Remove(dbPath); err != nil {
			t.Fatal(err)
		}
		res, err = a.ParseSessionFile(ctx, pbPath, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.ToolEvents) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "transcript.jsonl") {
			t.Errorf(".pb must defer to the transcript: %d events, %v", len(res.ToolEvents), res.Warnings)
		}
	})

	t.Run("cli tree: .db > .pb; transcript is never a session file", func(t *testing.T) {
		home := t.TempDir()
		tree := filepath.Join(home, ".gemini", "antigravity-cli")
		transcript := copyFixtureTranscript(t, "cli", tree, cliFixtureConversationID)
		dbPath := filepath.Join(tree, "conversations", cliFixtureConversationID+".db")
		pbPath := filepath.Join(tree, "conversations", cliFixtureConversationID+".pb")
		buildAgyDB(t, agyDBSpec{path: dbPath, uuid: cliFixtureConversationID, model: "gemini-3.8-flash", gens: 1, source: 17})
		if err := os.WriteFile(pbPath, []byte("encrypted-opaque"), 0o644); err != nil {
			t.Fatal(err)
		}
		cli := NewCLI()
		cli.roots = []string{filepath.Join(tree, "conversations"), filepath.Join(tree, "brain")}
		desktop := NewWithOptions(nil, filepath.Join(tree, "conversations"), filepath.Join(tree, "brain"))
		if cli.IsSessionFile(transcript) || desktop.IsSessionFile(transcript) {
			t.Error("the CLI tree's transcript must not be a session file for either adapter (the .db owns it)")
		}
		res, err := cli.ParseSessionFile(ctx, pbPath, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.ToolEvents)+len(res.TokenEvents) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], ".db") {
			t.Errorf("CLI .pb must defer to the .db: %d/%d events, %v", len(res.ToolEvents), len(res.TokenEvents), res.Warnings)
		}
		res, err = cli.ParseSessionFile(ctx, dbPath, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.TokenEvents) != 1 || len(res.ToolEvents) != 11 {
			t.Errorf("CLI .db = %d tokens, %d events", len(res.TokenEvents), len(res.ToolEvents))
		}
		for _, ev := range res.ToolEvents {
			if ev.Tool != models.ToolAntigravityCLI {
				t.Errorf("%s: Tool = %q", ev.SourceEventID, ev.Tool)
			}
			if ev.SourceFile != transcript {
				t.Errorf("%s: SourceFile = %q, want the CLI transcript", ev.SourceEventID, ev.SourceFile)
			}
		}
		if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].SurfaceHost != "antigravity-cli" {
			t.Errorf("surfaces = %+v", res.SessionSurfaces)
		}
	})
}

// TestParseCLIDB_LegacyTextRowsAreCovered pins the upgrade path: text
// rows an older build persisted under source_file = the .db (the
// text-only augmentation) suppress the transcript-keyed re-emit by
// Target; tool rows (never emitted before) still land.
func TestParseCLIDB_LegacyTextRowsAreCovered(t *testing.T) {
	home := t.TempDir()
	tree := filepath.Join(home, ".gemini", "antigravity-cli")
	copyFixtureTranscript(t, "cli", tree, cliFixtureConversationID)
	dbPath := filepath.Join(tree, "conversations", cliFixtureConversationID+".db")
	buildAgyDB(t, agyDBSpec{path: dbPath, uuid: cliFixtureConversationID, model: "gemini-3.8-flash", gens: 1, source: 17})
	reader := &fakeCoverageReader{
		user: []string{truncate("Summarise this repository in one paragraph.\n\nCreate a Python hello script and run it.\nChange it to print \"Hello Universe\" and run it again.\nDelete the script and confirm the directory no longer has it.", 200)},
	}
	a := NewWithOptions(nil, filepath.Join(tree, "conversations")).WithName(models.ToolAntigravityCLI).WithTargetCoverageReader(reader)
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.askedFor) != 1 || reader.askedFor[0] != dbPath {
		t.Errorf("coverage must be read for the legacy .db source_file: %v", reader.askedFor)
	}
	for _, ev := range res.ToolEvents {
		if ev.ActionType == models.ActionUserPrompt {
			t.Errorf("covered user_prompt re-emitted: %q", ev.Target)
		}
	}
	if len(res.ToolEvents) != 10 {
		t.Errorf("ToolEvents = %d, want 10 (11 minus the covered prompt)", len(res.ToolEvents))
	}
}

func TestCommandOutcomeRules(t *testing.T) {
	cases := []struct {
		content string
		ok      bool
		msg     string
	}{
		{"Created At: x\nCompleted At: y\n\nThe command exited with code 0.\nOutput:\nhi\n", true, ""},
		{"The command exited with code 1.\nStderr:\nboom", false, "exit code 1"},
		{"\t\t\t\tThe command completed successfully.\n\t\t\t\tOutput:\n", true, ""},
		{"no vocabulary at all", true, ""},
	}
	for _, c := range cases {
		ok, msg := commandOutcome(c.content)
		if ok != c.ok || msg != c.msg {
			t.Errorf("commandOutcome(%q) = %v %q, want %v %q", c.content, ok, msg, c.ok, c.msg)
		}
	}
	// End to end through the synthesizer: a failing command is a failed row.
	out := synthesizeDesktopTranscriptEvents(transcriptSynthInput{
		sessionPath: "/x", conversationID: "c", projectRoot: "/p",
		entries: []cliTranscriptEntry{
			{StepIndex: 0, Source: "MODEL", Type: "PLANNER_RESPONSE", Status: "DONE", CreatedAt: "2026-01-17T08:50:25Z", ToolCalls: []byte(`[{"name":"run_command","args":{"CommandLine":"\"false\""}}]`)},
			{StepIndex: 1, Source: "MODEL", Type: "GENERIC", Status: "DONE", CreatedAt: "2026-01-17T08:50:26Z", Content: "Created At: 2026-01-17T14:20:26+05:30\nCompleted At: 2026-01-17T14:20:27+05:30\n\nThe command exited with code 2.\nStderr:\nnope\n"},
		},
	})
	if len(out) != 1 || out[0].Success || out[0].ErrorMessage != "exit code 2" || out[0].DurationMs != 1000 {
		t.Errorf("failed command row = %+v", out)
	}
}

// TestParseACPTreeDB pins capture of the JetBrains antigravity-acp tree:
// an agy .db under ~/.gemini/antigravity-acp/conversations/<uuid>.db is
// classified LayoutCLIDB, read by the CLI adapter, and every emitted row
// carries SessionID == the conversation uuid — the exact id the JetBrains
// enricher's acpAgents["antigravity-acp"] rule matches to stamp
// ide/jetbrains-idea. source=0 (the value this tree carries, grounded
// 2026-09-04) is unmapped, so there is no self-stamp and a warning is
// emitted; the enricher supplies the real host. The real run's brain/
// transcript is empty, so this is a token-only capture by design.
func TestParseACPTreeDB(t *testing.T) {
	home := t.TempDir()
	uuid := cliFixtureConversationID
	tree := filepath.Join(home, ".gemini", "antigravity-acp")
	dbPath := filepath.Join(tree, "conversations", uuid+".db")
	buildAgyDB(t, agyDBSpec{path: dbPath, uuid: uuid, model: "gemini-3.8-flash", gens: 2, source: 0})

	a := NewWithOptions(nil, filepath.Join(tree, "conversations")).WithName(models.ToolAntigravityCLI)
	if !a.IsSessionFile(dbPath) {
		t.Fatalf("CLI adapter must claim the antigravity-acp .db: %s", dbPath)
	}
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	// source=0 is unmapped for the CLI-classified tree → no self-stamp.
	if len(res.SessionSurfaces) != 0 {
		t.Errorf("source=0 must not self-stamp; got %+v", res.SessionSurfaces)
	}
	// Every emitted row is keyed on the conversation uuid, so the enricher
	// Load(uuid) hits.
	var rows int
	for _, ev := range res.TokenEvents {
		rows++
		if ev.SessionID != uuid {
			t.Errorf("token event SessionID = %q, want %q", ev.SessionID, uuid)
		}
	}
	for _, ev := range res.ToolEvents {
		if ev.SessionID != uuid {
			t.Errorf("tool event SessionID = %q, want %q", ev.SessionID, uuid)
		}
	}
	if rows == 0 {
		t.Fatal("no token events emitted from the agy .db")
	}
}
