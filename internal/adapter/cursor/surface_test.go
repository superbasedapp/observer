package cursor

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

// TestSurfaceByLayout is the one-row-per-shape table for cursor's
// store-shape -> capture-surface mapping (IDE-05 / class C3).
func TestSurfaceByLayout(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantLayout storeLayout
		wantKind   string
		wantHost   string
	}{
		{
			name:       "agent transcript is the Cursor IDE",
			path:       `/home/u/.cursor/projects/c-repo/agent-transcripts/conv-1/conv-1.jsonl`,
			wantLayout: layoutTranscript,
			wantKind:   models.SurfaceIDE,
			wantHost:   "cursor",
		},
		{
			name:       "global state.vscdb is the Cursor IDE",
			path:       `/home/u/.config/Cursor/User/globalStorage/state.vscdb`,
			wantLayout: layoutStateDB,
			wantKind:   models.SurfaceIDE,
			wantHost:   "cursor",
		},
		{
			name:       "windows-spelled state.vscdb is the Cursor IDE",
			path:       `C:\Users\u\AppData\Roaming\Cursor\User\globalStorage\state.vscdb`,
			wantLayout: layoutStateDB,
			wantKind:   models.SurfaceIDE,
			wantHost:   "cursor",
		},
		{
			name:       "chats store.db is the cursor-agent CLI",
			path:       `/home/u/.cursor/chats/44caa9d80fcb6818/conv-1/store.db`,
			wantLayout: layoutStoreDB,
			wantKind:   models.SurfaceCLI,
			wantHost:   "cursor-agent",
		},
		{
			name:       "unrecognized shape gets no stamp",
			path:       `/home/u/.cursor/projects/c-repo/notes.txt`,
			wantLayout: layoutUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLayout := layoutFor(tc.path)
			if gotLayout != tc.wantLayout {
				t.Fatalf("layoutFor(%q) = %v, want %v", tc.path, gotLayout, tc.wantLayout)
			}
			sf, ok := surfaceByLayout[gotLayout]
			if tc.wantKind == "" {
				if ok {
					t.Fatalf("surfaceByLayout[%v] = %+v, want no entry", gotLayout, sf)
				}
				return
			}
			if !ok {
				t.Fatalf("surfaceByLayout has no entry for %v", gotLayout)
			}
			if sf.Surface != tc.wantKind || sf.SurfaceHost != tc.wantHost {
				t.Errorf("surface = %q/%q, want %q/%q", sf.Surface, sf.SurfaceHost, tc.wantKind, tc.wantHost)
			}
			if !models.KnownSurface(sf.Surface) {
				t.Errorf("surface kind %q is outside the models.Surface* vocabulary — the store refuses it", sf.Surface)
			}
		})
	}
}

// pinCursorHome points crossmount.AllHomes()'s native-home resolution at
// home. os.UserHomeDir reads $HOME on Linux/macOS and %USERPROFILE% on
// Windows, so both are set — the suite runs on a Windows host against
// Linux-shaped fixtures.
func pinCursorHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

// writeCursorAgentStore creates a `cursor-agent` CLI store for convID
// under home — the marker that the conversation was a CLI run.
func writeCursorAgentStore(t *testing.T, home, convID string) {
	t.Helper()
	dir := filepath.Join(home, ".cursor", "chats", "ws-hash-1", convID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "store.db"), []byte("not a real db"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSurfacePrecedence_CLIStoreWins is the U1 regression pin.
//
// Store.SetSessionSurface is first-wins-unless-empty, so whichever file
// the watcher parses first would otherwise decide a conversation's
// surface. A `cursor-agent` run leaves a transcript AND (sometimes) a
// state.vscdb row, so the IDE stamp could win by parse order and never
// be corrected. The store.db sibling — written by exactly one client —
// is the tiebreaker, applied at emission.
func TestSurfacePrecedence_CLIStoreWins(t *testing.T) {
	const convID = "aaaaaaaa-1111-4444-8888-bbbbbbbbbbbb"

	tests := []struct {
		name          string
		layout        storeLayout
		withCLIStore  bool
		wantSurface   string
		wantHost      string
		wantNoStampOK bool
	}{
		{
			name:        "transcript without a store.db sibling stays ide/cursor",
			layout:      layoutTranscript,
			wantSurface: models.SurfaceIDE, wantHost: "cursor",
		},
		{
			name:         "transcript WITH a store.db sibling is a CLI run",
			layout:       layoutTranscript,
			withCLIStore: true,
			wantSurface:  models.SurfaceCLI, wantHost: "cursor-agent",
		},
		{
			name:        "state.vscdb without a store.db sibling stays ide/cursor",
			layout:      layoutStateDB,
			wantSurface: models.SurfaceIDE, wantHost: "cursor",
		},
		{
			name:         "state.vscdb WITH a store.db sibling is a CLI run",
			layout:       layoutStateDB,
			withCLIStore: true,
			wantSurface:  models.SurfaceCLI, wantHost: "cursor-agent",
		},
		{
			name:        "store.db always stamps cli/cursor-agent",
			layout:      layoutStoreDB,
			wantSurface: models.SurfaceCLI, wantHost: "cursor-agent",
		},
		{
			name:         "store.db is never 'overridden' by its own presence",
			layout:       layoutStoreDB,
			withCLIStore: true,
			wantSurface:  models.SurfaceCLI, wantHost: "cursor-agent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			pinCursorHome(t, home)
			if tc.withCLIStore {
				writeCursorAgentStore(t, home, convID)
			}

			res := adapter.ParseResult{ToolEvents: []models.ToolEvent{{SessionID: convID}}}
			stampSurfaces(&res, tc.layout, convID)

			if len(res.SessionSurfaces) != 1 {
				t.Fatalf("got %d surfaces, want exactly 1: %+v", len(res.SessionSurfaces), res.SessionSurfaces)
			}
			got := res.SessionSurfaces[0]
			if got.SessionID != convID {
				t.Errorf("SessionID = %q, want %q", got.SessionID, convID)
			}
			if got.Surface != tc.wantSurface || got.SurfaceHost != tc.wantHost {
				t.Errorf("stamp = %q/%q, want %q/%q", got.Surface, got.SurfaceHost, tc.wantSurface, tc.wantHost)
			}
		})
	}
}

// TestParseTranscriptStampsCLIWhenStoreDBExists is the end-to-end half
// of U1: a real transcript parse for a conversation that also has a
// `cursor-agent` store.db must stamp cli/cursor-agent, not ide/cursor.
func TestParseTranscriptStampsCLIWhenStoreDBExists(t *testing.T) {
	const convID = "cccccccc-2222-4444-8888-dddddddddddd"
	home := t.TempDir()
	pinCursorHome(t, home)

	dir := filepath.Join(home, ".cursor", "projects", "slug-1", "agent-transcripts", convID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(dir, convID+".jsonl")
	if err := os.WriteFile(transcript, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, filepath.Join(home, ".cursor"))

	before, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil {
		t.Fatalf("parse without store.db: %v", err)
	}
	if len(before.SessionSurfaces) != 1 ||
		before.SessionSurfaces[0].Surface != models.SurfaceIDE ||
		before.SessionSurfaces[0].SurfaceHost != "cursor" {
		t.Fatalf("transcript with no store.db sibling stamped %+v, want one ide/cursor", before.SessionSurfaces)
	}

	writeCursorAgentStore(t, home, convID)

	after, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil {
		t.Fatalf("parse with store.db: %v", err)
	}
	if len(after.SessionSurfaces) != 1 ||
		after.SessionSurfaces[0].Surface != models.SurfaceCLI ||
		after.SessionSurfaces[0].SurfaceHost != "cursor-agent" {
		t.Fatalf("transcript WITH a store.db sibling stamped %+v, want one cli/cursor-agent — "+
			"the IDE stamp would win by parse order under first-wins-unless-empty", after.SessionSurfaces)
	}
}

// TestStampSurfaces_DedupesWithinResult pins "exactly one stamp per
// session id": many events for one session collapse to one row, and the
// path-derived hint never duplicates an id the events already carry.
func TestStampSurfaces_DedupesWithinResult(t *testing.T) {
	// Pin the home so resolveSurface's store.db lookup globs an empty
	// fixture tree rather than the real host home.
	pinCursorHome(t, t.TempDir())

	res := adapter.ParseResult{ToolEvents: []models.ToolEvent{
		{SessionID: "conv-a"},
		{SessionID: "conv-a"},
		{SessionID: "conv-b"},
		{SessionID: ""}, // an event with no session id contributes nothing
	}}
	stampSurfaces(&res, layoutStateDB, "conv-a")
	if len(res.SessionSurfaces) != 2 {
		t.Fatalf("got %d surfaces, want 2: %+v", len(res.SessionSurfaces), res.SessionSurfaces)
	}
	seen := map[string]models.SessionSurface{}
	for _, sf := range res.SessionSurfaces {
		if _, dup := seen[sf.SessionID]; dup {
			t.Fatalf("duplicate stamp for %q", sf.SessionID)
		}
		seen[sf.SessionID] = sf
		if sf.Surface != models.SurfaceIDE || sf.SurfaceHost != "cursor" {
			t.Errorf("stamp for %q = %q/%q, want ide/cursor", sf.SessionID, sf.Surface, sf.SurfaceHost)
		}
	}
	if _, ok := seen["conv-a"]; !ok {
		t.Error("missing stamp for conv-a")
	}
	if _, ok := seen["conv-b"]; !ok {
		t.Error("missing stamp for conv-b")
	}

	// An unmapped layout adds nothing, even with a hint.
	var unknown adapter.ParseResult
	stampSurfaces(&unknown, layoutUnknown, "conv-c")
	if len(unknown.SessionSurfaces) != 0 {
		t.Errorf("layoutUnknown produced %+v, want no stamps", unknown.SessionSurfaces)
	}
}

// TestParseSessionFile_StampsSurface walks the three real shapes end to
// end: each parse must carry the surface for its own store shape.
func TestParseSessionFile_StampsSurface(t *testing.T) {
	convID := "5f1a0c2e-1111-4444-8888-abcdefabcdef"

	t.Run("transcript", func(t *testing.T) {
		dir := t.TempDir()
		transcriptDir := filepath.Join(dir, ".cursor", "projects", "c-repo", "agent-transcripts", convID)
		if err := os.MkdirAll(transcriptDir, 0o755); err != nil {
			t.Fatal(err)
		}
		transcript := filepath.Join(transcriptDir, convID+".jsonl")
		body := strings.Join([]string{
			`{"role":"assistant","message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"main.go"}}]}}`,
			"",
		}, "\n")
		if err := os.WriteFile(transcript, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := (&Adapter{}).ParseSessionFile(context.Background(), transcript, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		assertSingleSurface(t, res, convID, models.SurfaceIDE, "cursor")
	})

	t.Run("store.db", func(t *testing.T) {
		dir := t.TempDir()
		storeDB := filepath.Join(dir, ".cursor", "chats", "44caa9d80fcb6818", convID, "store.db")
		writeCursorStoreDB(t, storeDB, map[string][]byte{
			"sys001": []byte(`{"role":"system","content":"You are an AI coding assistant."}`),
		})
		res, err := (&Adapter{}).ParseSessionFile(context.Background(), storeDB, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		assertSingleSurface(t, res, convID, models.SurfaceCLI, "cursor-agent")
	})

	t.Run("state.vscdb", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "Cursor", "User", "globalStorage")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "state.vscdb")
		db, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{
			`CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)`,
			`CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)`,
		} {
			if _, err := db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Exec(
			`INSERT INTO cursorDiskKV VALUES(?, ?)`,
			"composerData:"+convID,
			[]byte(`{"name":"Empty window","createdAt":"2026-08-30T11:04:07.318Z","modelConfig":{"modelName":"default"}}`),
		); err != nil {
			t.Fatal(err)
		}
		db.Close()

		res, err := New().ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("ParseSessionFile: %v", err)
		}
		assertSingleSurface(t, res, convID, models.SurfaceIDE, "cursor")
	})
}

// assertSingleSurface checks that res carries exactly one surface stamp
// and that it is the expected one.
func assertSingleSurface(t *testing.T, res adapter.ParseResult, sessionID, kind, host string) {
	t.Helper()
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("got %d surfaces, want 1: %+v", len(res.SessionSurfaces), res.SessionSurfaces)
	}
	got := res.SessionSurfaces[0]
	want := models.SessionSurface{SessionID: sessionID, Surface: kind, SurfaceHost: host}
	if got != want {
		t.Errorf("surface = %+v, want %+v", got, want)
	}
}
