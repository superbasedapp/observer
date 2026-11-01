package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/captureprogress"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// firstRunFixture is a server over a temp database with a three-tool
// catalog: "tool-scanning" and "tool-done" have session folders here,
// "tool-absent" does not. The progress model is injected as a fixed
// snapshot (the watcher's side is pinned in internal/watcher).
type firstRunFixture struct {
	server *Server
	dbPath string
	store  *store.Store
	snap   *captureprogress.Snapshot
}

func newFirstRunFixture(t *testing.T, withWatcher bool) *firstRunFixture {
	t.Helper()
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(
		"[observer.watch]\nenabled_adapters = [\"tool-scanning\", \"tool-done\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mk := func(name string) string {
		p := filepath.Join(tdir, name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	scanningDir, doneDir := mk("scanning-home"), mk("done-home")
	dbPath := filepath.Join(tdir, "observer.db")
	database, err := openTestDB(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	f := &firstRunFixture{dbPath: dbPath, store: store.New(database)}
	f.snap = &captureprogress.Snapshot{State: captureprogress.ScanIdle}
	opts := Options{
		DB:         database,
		DBPath:     dbPath,
		ConfigPath: cfgPath,
		ToolCatalog: []ToolCatalogEntry{
			{Tool: "tool-scanning", WatchPaths: []string{scanningDir}},
			{Tool: "tool-done", WatchPaths: []string{doneDir}},
			{Tool: "tool-absent", WatchPaths: []string{filepath.Join(tdir, "nope")}},
		},
	}
	if withWatcher {
		opts.CaptureProgress = func() captureprogress.Snapshot { return *f.snap }
	}
	f.server, err = New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *firstRunFixture) seedSession(t *testing.T, id, tool, root string) {
	t.Helper()
	ctx := context.Background()
	pid, err := f.store.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpsertSession(ctx, models.Session{
		ID: id, ProjectID: pid, Tool: tool, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *firstRunFixture) get(t *testing.T) firstRunResponse {
	t.Helper()
	var out firstRunResponse
	getModelJSON(t, f.server, "/api/firstrun", &out)
	return out
}

func (f *firstRunFixture) postSeen(t *testing.T, body string) int {
	t.Helper()
	rr := httptest.NewRecorder()
	req := armLocalWrite(httptest.NewRequest(http.MethodPost, "/api/firstrun/seen", strings.NewReader(body)))
	f.server.Handler().ServeHTTP(rr, req)
	return rr.Code
}

func findFirstRunTool(r firstRunResponse, tool string) (firstRunTool, bool) {
	for _, t := range r.Tools {
		if t.Tool == tool {
			return t, true
		}
	}
	return firstRunTool{}, false
}

// TestFirstRunReportsWatcherProgress: detected tools are listed with the
// watcher's per-tool progress, the absent one is only counted, and the
// overall capture state is the snapshot's.
func TestFirstRunReportsWatcherProgress(t *testing.T) {
	f := newFirstRunFixture(t, true)
	f.seedSession(t, "s1", "tool-done", "/work/alpha")
	f.seedSession(t, "s2", "tool-done", "/work/beta")
	*f.snap = captureprogress.Snapshot{
		State: captureprogress.ScanRunning, FilesFound: 12, FilesProcessed: 7,
		StartedAt: time.Now().Add(-time.Minute),
		Tools: []captureprogress.ToolProgress{
			{Tool: "tool-done", State: captureprogress.ToolDone, FilesFound: 2, FilesProcessed: 2},
			{Tool: "tool-scanning", State: captureprogress.ToolScanning, FilesFound: 10, FilesProcessed: 5},
		},
	}
	r := f.get(t)
	if r.Capture.State != "scanning" || r.Capture.FilesFound != 12 || r.Capture.FilesProcessed != 7 {
		t.Fatalf("capture = %+v", r.Capture)
	}
	if !r.WatcherRunning || r.ConfirmToken == "" {
		t.Fatalf("watcher_running=%v confirm_token=%q", r.WatcherRunning, r.ConfirmToken)
	}
	if len(r.Tools) != 2 || r.SupportedNotFound != 1 {
		t.Fatalf("tools=%d not_found=%d, want 2 and 1: %+v", len(r.Tools), r.SupportedNotFound, r.Tools)
	}
	done, _ := findFirstRunTool(r, "tool-done")
	if done.History.State != "done" || done.Sessions != 2 || done.Projects != 2 || !done.WatcherActive {
		t.Fatalf("tool-done = %+v", done)
	}
	scanning, _ := findFirstRunTool(r, "tool-scanning")
	if scanning.History.State != "scanning" || scanning.History.FilesFound != 10 || scanning.History.FilesProcessed != 5 {
		t.Fatalf("tool-scanning = %+v", scanning)
	}
	if !scanning.Detected || scanning.DetectedPath == "" {
		t.Fatalf("tool-scanning should say how it was detected: %+v", scanning)
	}
	if r.Sessions != 2 || r.ProjectCount != 2 || len(r.Projects) != 2 {
		t.Fatalf("sessions=%d projects=%d list=%d", r.Sessions, r.ProjectCount, len(r.Projects))
	}
	names := map[string]bool{}
	for _, p := range r.Projects {
		names[p.Name] = true
		if len(p.Tools) != 1 || p.Tools[0] != "tool-done" {
			t.Fatalf("project %+v tools", p)
		}
	}
	if !names["alpha"] || !names["beta"] {
		t.Fatalf("project names = %v, want alpha and beta (root base names)", names)
	}
}

// TestFirstRunBriefSkipsToolsAndProjects: the every-page-load decision read
// carries the state and totals but no per-tool rows or project list.
func TestFirstRunBriefSkipsToolsAndProjects(t *testing.T) {
	f := newFirstRunFixture(t, true)
	f.seedSession(t, "s1", "tool-done", "/work/alpha")
	var r firstRunResponse
	getModelJSON(t, f.server, "/api/firstrun?brief=1", &r)
	if len(r.Tools) != 0 || len(r.Projects) != 0 || r.SupportedNotFound != 0 {
		t.Fatalf("brief read carried rows: tools=%d projects=%d", len(r.Tools), len(r.Projects))
	}
	if r.Sessions != 1 || r.ProjectCount != 1 || !r.WatcherRunning || r.Capture.State != "idle" {
		t.Fatalf("brief read = %+v", r)
	}
}

// TestFirstRunAllListsEveryTool: the Tools page coverage read (all=1, T-935)
// lists the supported tools that were not found here as well, still counts
// them, and reports the catalog size; the default read is unchanged.
func TestFirstRunAllListsEveryTool(t *testing.T) {
	f := newFirstRunFixture(t, true)
	f.seedSession(t, "s1", "tool-done", "/work/alpha")
	var r firstRunResponse
	getModelJSON(t, f.server, "/api/firstrun?all=1", &r)
	if len(r.Tools) != 3 || r.SupportedNotFound != 1 || r.Supported != 3 {
		t.Fatalf("tools=%d not_found=%d supported=%d, want 3, 1, 3", len(r.Tools), r.SupportedNotFound, r.Supported)
	}
	absent, ok := findFirstRunTool(r, "tool-absent")
	if !ok || absent.Detected || absent.DetectedPath != "" || absent.Sessions != 0 || absent.WatcherActive {
		t.Fatalf("tool-absent = %+v (listed=%v)", absent, ok)
	}
	if absent.Enabled {
		t.Fatalf("tool-absent is not in enabled_adapters: %+v", absent)
	}
	def := f.get(t)
	if len(def.Tools) != 2 || def.Supported != 3 {
		t.Fatalf("default read: tools=%d supported=%d, want 2 and 3", len(def.Tools), def.Supported)
	}
	var brief firstRunResponse
	getModelJSON(t, f.server, "/api/firstrun?brief=1&all=1", &brief)
	if len(brief.Tools) != 0 || brief.Supported != 0 {
		t.Fatalf("brief read carried rows: tools=%d supported=%d", len(brief.Tools), brief.Supported)
	}
}

// TestFirstRunToolCarriesConnectedToolsCells: a coverage row carries the same
// MCP probe and wiring the Connected-tools row has, and the launchable flag
// from the integration registry, so the coverage view never re-derives them.
func TestFirstRunToolCarriesConnectedToolsCells(t *testing.T) {
	rows := []toolStatusRow{
		{
			Tool: "claude-code", Detected: true, Enabled: true,
			MCP:    &toolProbe{Registered: true, Detail: "observer MCP server registered"},
			Wiring: &toolWiring{Hooks: wiringPart{Register: true}},
		},
		{Tool: "tool-without-registry-row"},
	}
	tools, notFound := firstRunTools(rows, true, true, captureprogress.Snapshot{State: captureprogress.ScanDone}, nil, true)
	if len(tools) != 2 || notFound != 1 {
		t.Fatalf("tools=%d notFound=%d", len(tools), notFound)
	}
	cc := tools[0]
	if cc.MCP == nil || !cc.MCP.Registered || cc.Wiring == nil || !cc.Wiring.Hooks.Register {
		t.Fatalf("claude-code cells not carried: %+v", cc)
	}
	if !cc.Launchable {
		t.Fatalf("claude-code has a grounded launcher and should be launchable")
	}
	if tools[1].Launchable || tools[1].MCP != nil || tools[1].Wiring != nil {
		t.Fatalf("a tool with no registry row must stay honest zero: %+v", tools[1])
	}
}

// TestFirstRunWithoutWatcher: a dashboard with no watcher in the process
// says so for the capture and for every tool, rather than claiming a scan.
func TestFirstRunWithoutWatcher(t *testing.T) {
	f := newFirstRunFixture(t, false)
	r := f.get(t)
	if r.WatcherRunning || r.Capture.State != "not_running" {
		t.Fatalf("watcher_running=%v capture=%+v", r.WatcherRunning, r.Capture)
	}
	for _, tool := range r.Tools {
		if tool.History.State != "not_running" || tool.WatcherActive {
			t.Fatalf("%s = %+v, want not_running", tool.Tool, tool)
		}
	}
}

// TestFirstRunAutoOpenAndSeen walks the persistence rules: a recorded fresh
// install opens by itself until marked seen; the mark survives a new server
// over the same database (a second browser, a restart) and can be cleared.
func TestFirstRunAutoOpenAndSeen(t *testing.T) {
	f := newFirstRunFixture(t, true)
	if _, err := firstrunstate.New(firstrunstate.Path(f.dbPath)).RecordInstall(true, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.seedSession(t, "s1", "tool-done", "/work/alpha") // capture under way: still fresh
	r := f.get(t)
	if !r.AutoOpen || r.Seen || r.Install != "fresh" {
		t.Fatalf("before seen: auto=%v seen=%v install=%q", r.AutoOpen, r.Seen, r.Install)
	}
	if code := f.postSeen(t, `{"seen":true}`); code != http.StatusOK {
		t.Fatalf("POST seen = %d", code)
	}
	again := newFirstRunFixtureOver(t, f)
	r = again.get(t)
	if r.AutoOpen || !r.Seen {
		t.Fatalf("after seen (new server): auto=%v seen=%v", r.AutoOpen, r.Seen)
	}
	if code := f.postSeen(t, `{"seen":false}`); code != http.StatusOK {
		t.Fatalf("POST unseen = %d", code)
	}
	if r = f.get(t); !r.AutoOpen || r.Seen {
		t.Fatalf("after clearing: auto=%v seen=%v", r.AutoOpen, r.Seen)
	}
}

// newFirstRunFixtureOver builds a second server over the first fixture's
// database path.
func newFirstRunFixtureOver(t *testing.T, f *firstRunFixture) *firstRunFixture {
	t.Helper()
	s, err := New(Options{DB: f.server.opts.DB, DBPath: f.dbPath, ToolCatalog: f.server.opts.ToolCatalog})
	if err != nil {
		t.Fatal(err)
	}
	return &firstRunFixture{server: s, dbPath: f.dbPath, store: f.store, snap: f.snap}
}

func TestFirstRunAutoOpenRules(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		st       firstrunstate.State
		sessions int64
		want     bool
	}{
		{"fresh, unseen", firstrunstate.State{Install: firstrunstate.InstallFresh}, 40, true},
		{"fresh, seen", firstrunstate.State{Install: firstrunstate.InstallFresh, SeenAt: &now}, 0, false},
		{"existing install never opens by itself", firstrunstate.State{Install: firstrunstate.InstallExisting}, 0, false},
		{"unrecorded, empty database", firstrunstate.State{}, 0, true},
		{"unrecorded, database with sessions", firstrunstate.State{}, 3, false},
		{"unrecorded, seen", firstrunstate.State{SeenAt: &now}, 0, false},
	}
	for _, c := range cases {
		if got := firstRunAutoOpen(c.st, c.sessions); got != c.want {
			t.Errorf("%s: auto_open = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFirstRunHistoryRules(t *testing.T) {
	cases := []struct {
		rule  string
		facts historyFacts
		state string
	}{
		{"the watcher reported this tool", historyFacts{hasProgress: true, progress: captureprogress.ToolProgress{State: captureprogress.ToolFailed}}, "failed"},
		{"no watcher in this process", historyFacts{enabled: true}, "not_running"},
		{"capture turned off", historyFacts{watcherRunning: true}, "off"},
		{"first pass not started yet", historyFacts{watcherRunning: true, enabled: true, captureState: captureprogress.ScanIdle}, "waiting"},
		{"nothing to read yet", historyFacts{watcherRunning: true, enabled: true, captureState: captureprogress.ScanDone}, "waiting"},
	}
	if len(cases) != len(historyRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(historyRules))
	}
	for i, c := range cases {
		if historyRules[i].name != c.rule {
			t.Fatalf("row %d is %q, case says %q", i, historyRules[i].name, c.rule)
		}
		if got := firstRunHistoryOf(c.facts); got.State != c.state {
			t.Errorf("%s: state = %q, want %q", c.rule, got.State, c.state)
		}
	}
}

func TestFirstRunSeenRejectsBadBodies(t *testing.T) {
	f := newFirstRunFixture(t, true)
	for _, body := range []string{`{}`, `not json`, `{"seen":"yes"}`} {
		if code := f.postSeen(t, body); code != http.StatusBadRequest {
			t.Errorf("body %q: %d, want 400", body, code)
		}
	}
	rr := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/firstrun", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/firstrun = %d, want 405", rr.Code)
	}
}

func TestFirstRunResponseShapeIsStable(t *testing.T) {
	f := newFirstRunFixture(t, true)
	rr := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/firstrun", nil))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"auto_open", "seen", "install", "watcher_running", "capture", "tools", "supported_not_found", "supported", "sessions", "project_count", "projects", "generated_at", "confirm_token"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("response is missing %q", k)
		}
	}
	if string(raw["tools"]) == "null" || string(raw["projects"]) == "null" {
		t.Fatalf("tools/projects must be arrays, got %s / %s", raw["tools"], raw["projects"])
	}
}

func TestProjectBaseName(t *testing.T) {
	for in, want := range map[string]string{
		"/home/u/work/alpha":  "alpha",
		"/home/u/work/alpha/": "alpha",
		`C:\Users\u\beta`:     "beta",
		"":                    "",
	} {
		if got := projectBaseName(in); got != want {
			t.Errorf("projectBaseName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDashboardNoticeDismissalsPersistOnTheDaemon (WINNODE2 16b): the tour
// and the "Review components" card dismissed with {"dismiss": key} stay
// dismissed in the daemon's state file (a second server over the same
// database sees them), so a browser whose own storage does not persist
// does not bring them back; an unknown key is refused.
func TestDashboardNoticeDismissalsPersistOnTheDaemon(t *testing.T) {
	f := newFirstRunFixture(t, true)
	if got := f.get(t).Dismissed; len(got) != 0 {
		t.Fatalf("dismissed before any = %v", got)
	}
	for _, body := range []string{`{"dismiss":"tour"}`, `{"dismiss":"components_setup"}`, `{"dismiss":"tour"}`} {
		if code := f.postSeen(t, body); code != http.StatusOK {
			t.Fatalf("POST %s = %d", body, code)
		}
	}
	if code := f.postSeen(t, `{"dismiss":"anything_else"}`); code != http.StatusBadRequest {
		t.Fatalf("unknown notice = %d, want 400", code)
	}
	again := newFirstRunFixtureOver(t, f)
	if got := strings.Join(again.get(t).Dismissed, ","); got != "components_setup,tour" {
		t.Fatalf("dismissed after reload = %q, want components_setup,tour", got)
	}
}
