package qoder

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// hasPathSuffix reports whether got ends with the slash-shaped want. Used
// instead of equality wherever the value passed through git.Resolve,
// which makes a POSIX fixture path absolute against the current drive on
// a Windows host (`/home/dev/proj` → `D:\home\dev\proj`).
func hasPathSuffix(got, want string) bool {
	return strings.HasSuffix(filepath.ToSlash(got), want)
}

// fakeHome points allHomesFunc at a single synthetic native home for the
// duration of a test, so root discovery and the foreign-mount check are
// asserted without depending on the host's real profile.
func fakeHome(t *testing.T, home string) {
	t.Helper()
	fakeHomes(t, crossmount.HomeRoot{Path: home, OS: crossmount.OSWindows, Origin: "native"})
}

// fakeHomes stages an arbitrary home set, so a test can exercise the
// per-OS root ladder without depending on the host's own OS.
func fakeHomes(t *testing.T, homes ...crossmount.HomeRoot) {
	t.Helper()
	prev := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot { return homes }
	t.Cleanup(func() { allHomesFunc = prev })
}

// TestClassifyMatrix pins the layout classifier: which shapes this
// adapter claims, and which sibling files in the same trees it must
// structurally refuse.
func TestClassifyMatrix(t *testing.T) {
	cases := []struct {
		name string
		path string
		want layout
	}{
		{"cli flat transcript", "/home/u/.qoder/projects/c--home-u-proj/11111111-2222-3333-4444-555555555555.jsonl", layoutCLITranscript},
		{"cli flat transcript windows sep", `C:\Users\u\.qoder\projects\c--Users-u-proj\11111111-2222-3333-4444-555555555555.jsonl`, layoutCLITranscript},
		{"ide transcript", "/home/u/.qoder/projects/c-home-u-proj/transcript/task-1111222233334444aaaa.session.execution.jsonl", layoutIDETranscript},
		{"ide transcript windows sep", `C:\Users\u\.qoder\projects\c-Users-u-proj\transcript\task-1111222233334444aaaa.session.execution.jsonl`, layoutIDETranscript},
		{"run-log segment", "/home/u/.qoder/logs/sessions/c--home-u-proj/11111111-2222-3333-4444-555555555555/segments/1-a-p1.jsonl", layoutSegment},
		{"work db", "/home/u/.config/com.qoder.app.stable/main.sqlite", layoutWorkDB},
		{"work db windows", `C:\Users\u\AppData\Roaming\com.qoder.app.stable\main.sqlite`, layoutWorkDB},

		{"work db wal sidecar", `C:\Users\u\AppData\Roaming\com.qoder.app.stable\main.sqlite-wal`, layoutUnknown},
		{"work db shm sidecar", `C:\Users\u\AppData\Roaming\com.qoder.app.stable\main.sqlite-shm`, layoutUnknown},
		{"work sessionMigration store", `C:\Users\u\AppData\Roaming\com.qoder.app.stable\sessionMigration.sqlite`, layoutUnknown},
		{"work data json", `C:\Users\u\AppData\Roaming\com.qoder.app.stable\qoder-data.v1.json`, layoutUnknown},
		{"main.sqlite in a foreign dir", `C:\Users\u\AppData\Roaming\SomethingElse\main.sqlite`, layoutUnknown},
		{"ide shared-cache local.db", `C:\Users\u\AppData\Roaming\Qoder\SharedClientCache\cache\db\local.db`, layoutUnknown},
		{"ide workspace state.vscdb", `C:\Users\u\AppData\Roaming\Qoder\User\workspaceStorage\ws-9e8c\state.vscdb`, layoutUnknown},
		{"encrypted per-session state", "/home/u/.qoder/projects/c--home-u-proj/11111111-2222-3333-4444-555555555555/state.json", layoutUnknown},
		{"compression-v2 state", "/home/u/.qoder/projects/c--home-u-proj/1111/compression-v2/state.json", layoutUnknown},
		{"memory note", "/home/u/.qoder/projects/c--home-u-proj/memory/MEMORY.md", layoutUnknown},
		{"unrelated jsonl", "/home/u/.somewhere/x.jsonl", layoutUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.path); got != tc.want {
				t.Errorf("classify(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestIsSessionFileRequiresWatchRoot pins that shape alone is not enough:
// the same-shaped path outside every root is refused, and the Work DB is
// accepted only once its own root is present.
func TestIsSessionFileRequiresWatchRoot(t *testing.T) {
	base := t.TempDir()
	win := filepath.Join(base, "win")
	mac := filepath.Join(base, "mac")
	lin := filepath.Join(base, "lin")
	fakeHomes(t,
		crossmount.HomeRoot{Path: win, OS: crossmount.OSWindows, Origin: "wsl-mnt:win"},
		crossmount.HomeRoot{Path: mac, OS: crossmount.OSDarwin, Origin: "native"},
		crossmount.HomeRoot{Path: lin, OS: crossmount.OSLinux, Origin: "native"},
	)
	a := NewWithOptions(nil, defaultRoots()...)

	accept := []string{
		// The dot-directory transcript roots are OS-agnostic: Qoder
		// writes <home>/.qoder everywhere, so every home gets them.
		filepath.Join(win, ".qoder", "projects", "c--u-proj", "1111.jsonl"),
		filepath.Join(lin, ".qoder", "projects", "c-u-proj", "transcript", "task-aaaa.session.execution.jsonl"),
		filepath.Join(mac, ".qoder", "logs", "sessions", "c--u-proj", "1111", "segments", "s.jsonl"),
		// The Work store is OS-shaped: one shape per home, its own.
		filepath.Join(win, "AppData", "Roaming", workAppDir, workDBName),
		filepath.Join(mac, "Library", "Application Support", workAppDir, workDBName),
		filepath.Join(lin, ".config", workAppDir, workDBName),
	}
	for _, p := range accept {
		if !a.IsSessionFile(p) {
			t.Errorf("IsSessionFile(%q) = false, want true", p)
		}
	}
	reject := []string{
		filepath.Join(win, "AppData", "Roaming", workAppDir, workDBName+"-wal"),
		filepath.Join(win, "AppData", "Roaming", workAppDir, "sessionMigration.sqlite"),
		filepath.Join(win, ".qoder", "projects", "c--u-proj", "1111", "state.json"),
		// Right shape, wrong OS for the home: a Windows profile has no
		// Application Support / .config data directory, so no such root
		// is composed and the path is unclaimed.
		filepath.Join(win, "Library", "Application Support", workAppDir, workDBName),
		filepath.Join(win, ".config", workAppDir, workDBName),
		filepath.Join(lin, "AppData", "Roaming", workAppDir, workDBName),
		// Right shape, wrong home: not under any watch root.
		filepath.Join(t.TempDir(), "elsewhere", ".qoder", "projects", "p", "1111.jsonl"),
	}
	for _, p := range reject {
		if a.IsSessionFile(p) {
			t.Errorf("IsSessionFile(%q) = true, want false", p)
		}
	}
}

// TestSurfaceForTable pins the layout → surface mapping, including the
// session-id override and the Hosted flag placement: Hosted must be set
// on the Qoder Work stamp and ONLY there, because only that stamp comes
// from a hosting layer's own record.
func TestSurfaceForTable(t *testing.T) {
	const cliID = "11111111-2222-3333-4444-555555555555"
	const ideID = "task-1111222233334444aaaa.session.execution"
	cliSurface := models.SessionSurface{SessionID: cliID, Surface: models.SurfaceCLI, SurfaceHost: hostQoder}
	ideSurface := models.SessionSurface{SessionID: ideID, Surface: models.SurfaceIDE, SurfaceHost: hostQoder}
	workSurface := models.SessionSurface{SessionID: cliID, Surface: models.SurfaceDesktop, SurfaceHost: hostQoderWork, Hosted: true}

	cases := []struct {
		name    string
		layout  layout
		session string
		want    models.SessionSurface
	}{
		{"cli transcript", layoutCLITranscript, cliID, cliSurface},
		{"run-log segment", layoutSegment, cliID, cliSurface},
		{"ide transcript", layoutIDETranscript, ideID, ideSurface},
		{"ide id overrides a cli layout", layoutCLITranscript, ideID, ideSurface},
		{"ide id overrides a segment layout", layoutSegment, ideID, ideSurface},
		{"work db is hosted desktop", layoutWorkDB, cliID, workSurface},
		{"unknown layout yields nothing", layoutUnknown, cliID, models.SessionSurface{}},
		{"empty session yields nothing", layoutCLITranscript, "", models.SessionSurface{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := surfaceFor(tc.layout, tc.session)
			if got != tc.want {
				t.Errorf("surfaceFor(%v, %q) = %+v, want %+v", tc.layout, tc.session, got, tc.want)
			}
			if got.Hosted && got.SurfaceHost != hostQoderWork {
				t.Errorf("Hosted set on a non-Work stamp: %+v", got)
			}
		})
	}
	// Every emitted surface kind must be in the store's vocabulary.
	for l, s := range layoutSurfaces {
		if !models.KnownSurface(s.Surface) {
			t.Errorf("layout %v maps to unknown surface kind %q", l, s.Surface)
		}
	}
}

// TestParseIDETranscript walks the live-derived IDE fixture end to end:
// the shared record shape parses through the same transcript parser as a
// CLI session, and the parse stamps the IDE surface (never Hosted).
func TestParseIDETranscript(t *testing.T) {
	const sessionID = "task-1111222233334444aaaa.session.execution"
	home := t.TempDir()
	fakeHome(t, home)

	dst := filepath.Join(home, ".qoder", "projects", "c-u-proj", transcriptDir, sessionID+".jsonl")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join("..", "..", "..", "testdata", "qoder", "ide", "transcript", sessionID+".jsonl")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatal(err)
	}

	a := NewWithOptions(nil, defaultRoots()...)
	if !a.IsSessionFile(dst) {
		t.Fatalf("IsSessionFile(%q) = false", dst)
	}
	res, err := a.ParseSessionFile(context.Background(), dst, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != int64(len(body)) {
		t.Errorf("NewOffset = %d, want %d (whole file)", res.NewOffset, len(body))
	}
	if len(res.TokenEvents) != 0 {
		t.Errorf("IDE transcript produced %d token events, want 0", len(res.TokenEvents))
	}

	// Surface: exactly one IDE stamp, self-reported.
	want := models.SessionSurface{SessionID: sessionID, Surface: models.SurfaceIDE, SurfaceHost: hostQoder}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0] != want {
		t.Fatalf("SessionSurfaces = %+v, want [%+v]", res.SessionSurfaces, want)
	}

	byAction := map[string]int{}
	byRaw := map[string]models.ToolEvent{}
	for _, e := range res.ToolEvents {
		if e.SessionID != sessionID {
			t.Fatalf("event session id = %q, want %q", e.SessionID, sessionID)
		}
		if e.Tool != models.ToolQoder {
			t.Errorf("event tool = %q, want %q (one tool id across surfaces)", e.Tool, models.ToolQoder)
		}
		if e.Model != "" {
			t.Errorf("model must stay empty (server-side only), got %q", e.Model)
		}
		byAction[e.ActionType]++
		if e.RawToolName != "" {
			byRaw[e.RawToolName] = e
		}
	}
	for action, want := range map[string]int{
		models.ActionSessionStart:     1,
		models.ActionUserPrompt:       1,
		models.ActionAssistantMessage: 2,
		models.ActionReadFile:         1,
		models.ActionWriteFile:        1,
		models.ActionRunCommand:       1,
		// SearchReplace is the IDE's own edit tool; internal/tooltax
		// carries the row (grounded live 2026-09-03), so it normalizes to
		// edit_file with the raw name preserved.
		models.ActionEditFile: 1,
	} {
		if byAction[action] != want {
			t.Errorf("%s count = %d, want %d (all: %v)", action, byAction[action], want, byAction)
		}
	}
	if got := byRaw["SearchReplace"]; got.ActionType != models.ActionEditFile || got.RawToolName != "SearchReplace" {
		t.Errorf("SearchReplace event = %+v, want edit_file with the raw name preserved", got)
	}
	// The IDE spells Write's body `file_content`; authored bytes must
	// still be counted.
	if got := byRaw["Write"]; got.ContentBytes != int64(len(`print("Hello World")`)) {
		t.Errorf("Write ContentBytes = %d, want %d", got.ContentBytes, len(`print("Hello World")`))
	}
	if got := byRaw["Read"]; !got.Success || got.ToolOutput == "" {
		t.Errorf("Read event lost its tool_result: %+v", got)
	}
	if got := byRaw["Bash"]; got.Target != "python hello_world.py" {
		t.Errorf("Bash target = %q", got.Target)
	}
	// Project root comes from the record's raw cwd, never the slug.
	for _, e := range res.ToolEvents {
		if e.ProjectRoot == "" {
			continue
		}
		if !hasPathSuffix(e.ProjectRoot, "Users/dev/proj") {
			t.Errorf("project root = %q, want */Users/dev/proj", e.ProjectRoot)
			break
		}
	}
}

// TestCursorSemanticsPerLayout pins the three cursor shapes this adapter
// mixes, which the dashboard's watcher-health panel reads verbatim.
func TestCursorSemanticsPerLayout(t *testing.T) {
	home := filepath.Join(t.TempDir(), "u")
	fakeHome(t, home)
	a := NewWithOptions(nil, defaultRoots()...)

	cases := []struct {
		path string
		want adapter.CursorKind
	}{
		{filepath.Join(home, ".qoder", "projects", "p", "1111.jsonl"), adapter.CursorByteOffset},
		{filepath.Join(home, ".qoder", "projects", "p", transcriptDir, "task-a.session.execution.jsonl"), adapter.CursorByteOffset},
		{filepath.Join(home, ".qoder", "logs", "sessions", "p", "1111", "segments", "s.jsonl"), adapter.CursorNoActions},
		{filepath.Join(home, "AppData", "Roaming", workAppDir, workDBName), adapter.CursorWatermark},
	}
	for _, tc := range cases {
		if got := a.CursorSemanticsFor(tc.path).Kind; got != tc.want {
			t.Errorf("CursorSemanticsFor(%q).Kind = %v, want %v", tc.path, got, tc.want)
		}
	}
	// A path this adapter does not claim gets the zero value.
	if got := a.CursorSemanticsFor(filepath.Join(home, "nope.jsonl")); got.Kind != adapter.CursorByteOffset || got.Detail != "" {
		t.Errorf("unclaimed path semantics = %+v, want zero value", got)
	}
}
