package copilot

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

const emptyWindowFixture = "../../../testdata/copilot/emptywindow-document.json"

// emptyWindowSID is the session id both staged shapes carry (it is the
// `sessionId` inside the fixture, and the basename the parse derives from).
const emptyWindowSID = "49182160-5508-4f15-be59-53d14169a21a"

// readEmptyWindowFixture returns the fixture's raw bytes and its decoded
// form (the latter is what a kind=0 snapshot wraps as `v`).
func readEmptyWindowFixture(t *testing.T) ([]byte, map[string]any) {
	t.Helper()
	body, err := os.ReadFile(emptyWindowFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	return body, doc
}

// stageEmptyWindowDoc writes the `.json` session DOCUMENT VS Code writes
// for a folder-less chat into its own globalStorage root.
func stageEmptyWindowDoc(t *testing.T) (root, docPath string) {
	t.Helper()
	body, _ := readEmptyWindowFixture(t)
	root = filepath.Join(t.TempDir(), "globalStorage", emptyWindowDirName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	docPath = filepath.Join(root, emptyWindowSID+".json")
	if err := os.WriteFile(docPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, docPath
}

// stageEmptyWindowLog writes the SAME session state wrapped in a kind=0
// snapshot line as the `.jsonl` snapshot+patches log, into its own
// globalStorage root.
func stageEmptyWindowLog(t *testing.T) (root, logPath string) {
	t.Helper()
	_, doc := readEmptyWindowFixture(t)
	root = filepath.Join(t.TempDir(), "globalStorage", emptyWindowDirName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	snapshot, err := json.Marshal(map[string]any{"kind": 0, "v": doc})
	if err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(root, emptyWindowSID+".jsonl")
	if err := os.WriteFile(logPath, append(snapshot, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, logPath
}

// TestEmptyWindowDocumentMatchesSnapshotParse is the IDE-10 regression pin:
// the `.json` empty-window document IS the kind-0 snapshot payload, so
// parsing it must produce exactly the rows the equivalent `.jsonl` snapshot
// produces — same actions, same tokens, same surface — differing only in
// SourceFile.
//
// The two shapes are staged as SEPARATE installs (own root, own adapter)
// on purpose. This test is about "same content ⇒ same rows", NOT about
// what should happen when both files exist for one session id — that case
// is a double-ingest hazard and is pinned by
// TestEmptyWindowLogSuppressesDocument below.
func TestEmptyWindowDocumentMatchesSnapshotParse(t *testing.T) {
	docRoot, docPath := stageEmptyWindowDoc(t)
	logRoot, logPath := stageEmptyWindowLog(t)
	docAdapter := NewWithOptions(nil, []string{docRoot})
	logAdapter := NewWithOptions(nil, []string{logRoot})

	if !docAdapter.IsSessionFile(docPath) {
		t.Fatalf("IsSessionFile(%q) = false, want true for the empty-window .json document", docPath)
	}
	if !logAdapter.IsSessionFile(logPath) {
		t.Fatalf("IsSessionFile(%q) = false, want true for the empty-window .jsonl log", logPath)
	}

	docRes, err := docAdapter.ParseSessionFile(context.Background(), docPath, 0)
	if err != nil {
		t.Fatalf("parse document: %v", err)
	}
	logRes, err := logAdapter.ParseSessionFile(context.Background(), logPath, 0)
	if err != nil {
		t.Fatalf("parse snapshot log: %v", err)
	}

	if len(docRes.ToolEvents) == 0 {
		t.Fatal("document parse emitted no tool events")
	}
	if len(docRes.ToolEvents) != len(logRes.ToolEvents) {
		t.Fatalf("tool events: document %d, snapshot %d", len(docRes.ToolEvents), len(logRes.ToolEvents))
	}
	for i := range docRes.ToolEvents {
		got, want := docRes.ToolEvents[i], logRes.ToolEvents[i]
		got.SourceFile, want.SourceFile = "", ""
		if !reflect.DeepEqual(got, want) {
			t.Errorf("tool event %d differs:\n document = %+v\n snapshot = %+v", i, got, want)
		}
	}

	if len(docRes.TokenEvents) != len(logRes.TokenEvents) {
		t.Fatalf("token events: document %d, snapshot %d", len(docRes.TokenEvents), len(logRes.TokenEvents))
	}
	for i := range docRes.TokenEvents {
		got, want := docRes.TokenEvents[i], logRes.TokenEvents[i]
		got.SourceFile, want.SourceFile = "", ""
		if !reflect.DeepEqual(got, want) {
			t.Errorf("token event %d differs:\n document = %+v\n snapshot = %+v", i, got, want)
		}
	}

	if !reflect.DeepEqual(docRes.SessionSurfaces, logRes.SessionSurfaces) {
		t.Errorf("surfaces differ: document %+v, snapshot %+v", docRes.SessionSurfaces, logRes.SessionSurfaces)
	}
	if len(docRes.Warnings) != 0 {
		t.Errorf("document parse warnings = %v, want none", docRes.Warnings)
	}
}

// TestEmptyWindowDocumentContent pins the substance of the document parse
// (the equality test above would be satisfied by two empty results).
func TestEmptyWindowDocumentContent(t *testing.T) {
	root, docPath := stageEmptyWindowDoc(t)
	a := NewWithOptions(nil, []string{root})

	res, err := a.ParseSessionFile(context.Background(), docPath, 0)
	if err != nil {
		t.Fatal(err)
	}

	stat, err := os.Stat(docPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.NewOffset != stat.Size() {
		t.Errorf("NewOffset = %d, want the file size %d", res.NewOffset, stat.Size())
	}

	counts := map[string]int{}
	for _, ev := range res.ToolEvents {
		counts[ev.ActionType]++
		if ev.SessionID != "49182160-5508-4f15-be59-53d14169a21a" {
			t.Errorf("SessionID = %q, want the basename-derived id", ev.SessionID)
		}
		if ev.Tool != models.ToolCopilot {
			t.Errorf("Tool = %q, want %q", ev.Tool, models.ToolCopilot)
		}
	}
	for action, want := range map[string]int{
		models.ActionUserPrompt:   2,
		models.ActionTaskComplete: 2,
		models.ActionReadFile:     1, // view_image
		models.ActionSearchFiles:  1, // list_dir
	} {
		if counts[action] != want {
			t.Errorf("%s rows = %d, want %d (all: %v)", action, counts[action], want, counts)
		}
	}

	if len(res.TokenEvents) != 2 {
		t.Fatalf("token events = %d, want 2", len(res.TokenEvents))
	}
	first := res.TokenEvents[0]
	if first.InputTokens != 30401 || first.OutputTokens != 137 || first.ReasoningTokens != 53 {
		t.Errorf("first token event = (in %d, out %d, reasoning %d), want (30401, 137, 53)",
			first.InputTokens, first.OutputTokens, first.ReasoningTokens)
	}
	if first.Model != "claude-haiku-4-5-20251001" {
		t.Errorf("Model = %q, want the resolvedModel", first.Model)
	}
}

// TestEmptyWindowLogSuppressesDocument is the C1 regression pin. Both
// modern shapes derive their SourceEventIDs from the same request ids but
// carry DIFFERENT SourceFiles (`<sid>.json` vs `<sid>.jsonl`), so the
// store's UNIQUE(source_file, source_event_id) index cannot dedupe them —
// a session with both on disk would land 2× actions and 2× token rows.
// The `.jsonl` log wins (it is append-structured and therefore the
// strictly better record); the document contributes only its watermark
// and its idempotent surface stamp.
func TestEmptyWindowLogSuppressesDocument(t *testing.T) {
	body, doc := readEmptyWindowFixture(t)
	snapshot, err := json.Marshal(map[string]any{"kind": 0, "v": doc})
	if err != nil {
		t.Fatal(err)
	}

	// Layouts a `<sid>.jsonl` can occupy, relative to the watch root.
	// nil = no log at all (the control row).
	cases := []struct {
		name        string
		logRel      []string // path components under the root; nil = absent
		wantSuppres bool
	}{
		{"no log at all", nil, false},
		{"log beside the document", []string{emptyWindowSID + ".jsonl"}, true},
		{"log under a workspace chatSessions dir", []string{"ws-1", chatSessionsDirName, emptyWindowSID + ".jsonl"}, true},
		{"log for a DIFFERENT session id", []string{"other-session.jsonl"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "globalStorage", emptyWindowDirName)
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatal(err)
			}
			docPath := filepath.Join(root, emptyWindowSID+".json")
			if err := os.WriteFile(docPath, body, 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.logRel != nil {
				logPath := filepath.Join(append([]string{root}, tc.logRel...)...)
				if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(logPath, append(snapshot, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			a := NewWithOptions(nil, []string{root})
			res, err := a.ParseSessionFile(context.Background(), docPath, 0)
			if err != nil {
				t.Fatalf("parse document: %v", err)
			}

			emitted := len(res.ToolEvents) > 0 || len(res.TokenEvents) > 0
			if tc.wantSuppres && emitted {
				t.Errorf("a coexisting .jsonl must suppress the .json document, but it emitted "+
					"%d tool / %d token events — those would double-ingest under a second source_file",
					len(res.ToolEvents), len(res.TokenEvents))
			}
			if !tc.wantSuppres && !emitted {
				t.Errorf("no coexisting .jsonl for this session id, so the document must still be ingested")
			}

			// Either way the cursor advances (so the watcher does not
			// re-read every tick) and the surface is stamped (it says the
			// same thing the log's own stamp would).
			stat, err := os.Stat(docPath)
			if err != nil {
				t.Fatal(err)
			}
			if res.NewOffset != stat.Size() {
				t.Errorf("NewOffset = %d, want the file size %d", res.NewOffset, stat.Size())
			}
			if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].SessionID != emptyWindowSID {
				t.Errorf("surfaces = %+v, want exactly one for %q", res.SessionSurfaces, emptyWindowSID)
			}
		})
	}
}

// TestModernLogSiblingLookupIsPathSafe pins that a session id which is not
// a plain filename component is refused rather than joined/globbed: it
// cannot name a real VS Code session file, and feeding it to filepath.Glob
// or filepath.Join would be a traversal-shaped read.
func TestModernLogSiblingLookupIsPathSafe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "globalStorage", emptyWindowDirName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// A log that a traversal or a glob would otherwise reach.
	if err := os.WriteFile(filepath.Join(root, "reachable.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, []string{root})

	for _, sid := range []string{"", ".", "..", "*", "?", "[a-z]", "sub/reachable", `sub\reachable`, "../reachable"} {
		if a.modernLogSiblingExists(sid, filepath.Join(root, "x.json")) {
			t.Errorf("modernLogSiblingExists(%q) = true, want false for a non-component session id", sid)
		}
	}
	// The honest positive control: a real component id does resolve.
	if !a.modernLogSiblingExists("reachable", filepath.Join(root, "reachable.json")) {
		t.Error("modernLogSiblingExists(\"reachable\") = false, want true")
	}
}

// TestEmptyWindowDocumentDegraded pins the malformed-document path: a
// warning, no rows, no panic — and the surface stamp survives, because the
// session's KIND is knowable from the path alone.
func TestEmptyWindowDocumentDegraded(t *testing.T) {
	root := filepath.Join(t.TempDir(), "globalStorage", emptyWindowDirName)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "broken-session.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("a malformed document must not error: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf("malformed document emitted rows: %+v / %+v", res.ToolEvents, res.TokenEvents)
	}
	if len(res.Warnings) == 0 {
		t.Error("malformed document emitted no warning")
	}
	if len(res.SessionSurfaces) != 1 {
		t.Fatalf("surfaces = %+v, want exactly one", res.SessionSurfaces)
	}
}

// TestIsSessionFileJSONShapes is the table for the widened matcher: the
// `.json` document is accepted ONLY under emptyWindowChatSessions, and the
// pre-existing `.jsonl` shapes are untouched.
func TestIsSessionFileJSONShapes(t *testing.T) {
	base := t.TempDir()
	ws := filepath.Join(base, "workspaceStorage")
	gs := filepath.Join(base, "globalStorage", emptyWindowDirName)
	a := NewWithOptions(nil, []string{ws, gs})

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"empty-window document", filepath.Join(gs, "abc.json"), true},
		{"empty-window snapshot log", filepath.Join(gs, "abc.jsonl"), true},
		{"workspace chatSessions log", filepath.Join(ws, "ws-1", "chatSessions", "abc.jsonl"), true},
		{"workspace chatSessions .json", filepath.Join(ws, "ws-1", "chatSessions", "abc.json"), false},
		{"legacy debug log", filepath.Join(ws, "ws-1", "GitHub.copilot-chat", "debug-logs", "s1", "main.jsonl"), true},
		{"workspace.json metadata", filepath.Join(ws, "ws-1", "workspace.json"), false},
		{"unrelated .json under workspaceStorage", filepath.Join(ws, "ws-1", "state.json"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestSurfaceHostTable is the one-row-per-product pin for the IDE surface
// stamp: kind is always models.SurfaceIDE (Copilot Chat has no CLI writing
// these stores), and the host token comes from the vscodehost product
// table — a fork host must never be reported as plain "vscode".
func TestSurfaceHostTable(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"desktop Code", `C:\Users\u\AppData\Roaming\Code\User\globalStorage\emptyWindowChatSessions\s.json`, "vscode"},
		{"Insiders", `C:\Users\u\AppData\Roaming\Code - Insiders\User\globalStorage\emptyWindowChatSessions\s.json`, "vscode-insiders"},
		{"VSCodium", "/home/u/.config/VSCodium/User/globalStorage/emptyWindowChatSessions/s.json", "vscodium"},
		{"Cursor", "/Users/u/Library/Application Support/Cursor/User/workspaceStorage/w/chatSessions/s.jsonl", "cursor"},
		{"Windsurf", "/home/u/.config/Windsurf/User/workspaceStorage/w/chatSessions/s.jsonl", "windsurf"},
		{"remote server", "/home/u/.vscode-server/data/User/workspaceStorage/w/chatSessions/s.jsonl", "vscode-remote"},
		{"unattributable path", "/tmp/fixtures/emptyWindowChatSessions/s.json", defaultSurfaceHost},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := surfaceHostFor(tc.path); got != tc.want {
				t.Errorf("surfaceHostFor(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestSurfaceStampedOnEveryShape pins that all three on-disk shapes stamp
// exactly one ide surface per parse.
func TestSurfaceStampedOnEveryShape(t *testing.T) {
	docRoot, docPath := stageEmptyWindowDoc(t)
	logRoot, logPath := stageEmptyWindowLog(t)
	docAdapter := NewWithOptions(nil, []string{docRoot})
	logAdapter := NewWithOptions(nil, []string{logRoot})

	legacyDir := filepath.Join(t.TempDir(), "workspaceStorage", "ws-1", "GitHub.copilot-chat", "debug-logs", "sess-legacy")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	legacyPath := filepath.Join(legacyDir, "main.jsonl")
	if err := os.WriteFile(legacyPath, []byte(`{"v":1,"ts":1777720090607,"sid":"sess-legacy","type":"user_message","attrs":{"content":"hi"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyAdapter := NewWithOptions(nil, []string{filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(legacyDir))))})

	for _, tc := range []struct {
		name string
		a    *Adapter
		path string
		want string
	}{
		{"empty-window document", docAdapter, docPath, emptyWindowSID},
		{"empty-window snapshot log", logAdapter, logPath, emptyWindowSID},
		{"legacy debug log", legacyAdapter, legacyPath, "sess-legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.a.ParseSessionFile(context.Background(), tc.path, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.SessionSurfaces) != 1 {
				t.Fatalf("SessionSurfaces = %+v, want exactly one", res.SessionSurfaces)
			}
			got := res.SessionSurfaces[0]
			if got.SessionID != tc.want {
				t.Errorf("SessionID = %q, want %q", got.SessionID, tc.want)
			}
			if got.Surface != models.SurfaceIDE {
				t.Errorf("Surface = %q, want %q", got.Surface, models.SurfaceIDE)
			}
			if !models.KnownSurface(got.Surface) {
				t.Errorf("Surface %q is out of the models vocabulary", got.Surface)
			}
			if got.SurfaceHost == "" || strings.ToLower(got.SurfaceHost) != got.SurfaceHost {
				t.Errorf("SurfaceHost = %q, want a non-empty lowercase token", got.SurfaceHost)
			}
		})
	}
}

// TestDefaultRootsCoverForkHosts pins the IDE-14 widening: the hand-rolled
// Code-only roots are gone, so every VS Code-family product contributes
// both a workspaceStorage root and an emptyWindowChatSessions root, with
// no duplicates.
func TestDefaultRootsCoverForkHosts(t *testing.T) {
	roots := defaultRoots()
	if len(roots) == 0 {
		t.Fatal("defaultRoots() returned nothing")
	}

	seen := map[string]int{}
	var wsCount, ewCount int
	for _, r := range roots {
		slash := filepath.ToSlash(r)
		seen[slash]++
		if seen[slash] > 1 {
			t.Errorf("defaultRoots() repeated %q", slash)
		}
		switch {
		case strings.HasSuffix(slash, "/workspaceStorage"):
			wsCount++
		case strings.HasSuffix(slash, "/globalStorage/"+emptyWindowDirName):
			ewCount++
		default:
			t.Errorf("unexpected root shape %q", slash)
		}
	}
	if wsCount != ewCount {
		t.Errorf("workspaceStorage roots = %d, emptyWindowChatSessions roots = %d; want a pair per product", wsCount, ewCount)
	}

	joined := strings.ToLower(strings.Join(roots, "|"))
	joined = strings.ReplaceAll(joined, `\`, "/")
	for _, product := range []string{"code - insiders", "vscodium", "cursor", "windsurf", "kiro", "qoder", "trae", ".vscode-server"} {
		if !strings.Contains(joined, "/"+product+"/") {
			t.Errorf("defaultRoots() has no root for the %q host: %v", product, roots)
		}
	}
}
