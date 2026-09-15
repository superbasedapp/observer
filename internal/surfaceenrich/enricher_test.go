package surfaceenrich

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// fakeFS is a map-backed FS: dirs → names, files → bytes, mtimes.
type fakeFS struct {
	dirs   map[string][]string
	files  map[string][]byte
	mtimes map[string]time.Time
}

func (f *fakeFS) FS() FS {
	return FS{
		ReadDir: func(p string) ([]string, error) {
			if names, ok := f.dirs[filepath.Clean(p)]; ok {
				return names, nil
			}
			return nil, errors.New("ENOENT " + p)
		},
		ReadFile: func(p string) ([]byte, error) {
			if b, ok := f.files[filepath.Clean(p)]; ok {
				return b, nil
			}
			return nil, errors.New("ENOENT " + p)
		},
		ModTime: func(p string) (time.Time, error) {
			if t, ok := f.mtimes[filepath.Clean(p)]; ok {
				return t, nil
			}
			return time.Time{}, errors.New("ENOENT " + p)
		},
	}
}

// fakeStore records Load/Stamp traffic against an in-memory session set.
type fakeStore struct {
	mu       sync.Mutex
	sessions map[string]models.SessionSurface // id → stored (Hosted ignored)
	stamps   []models.SessionSurface
	loadErr  error
	stampErr error
}

func (s *fakeStore) load(_ context.Context, id string) (models.SessionSurface, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return models.SessionSurface{}, false, s.loadErr
	}
	sf, ok := s.sessions[id]
	return sf, ok, nil
}

func (s *fakeStore) stamp(_ context.Context, sf models.SessionSurface) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stampErr != nil {
		return false, s.stampErr
	}
	s.stamps = append(s.stamps, sf)
	cur := s.sessions[sf.SessionID]
	changed := cur.Surface != sf.Surface || cur.SurfaceHost != sf.SurfaceHost
	cur.SessionID = sf.SessionID
	cur.Surface, cur.SurfaceHost = sf.Surface, sf.SurfaceHost
	s.sessions[sf.SessionID] = cur
	return changed, nil
}

const (
	sidJunie   = "session-260101-120000-ab12"
	sidClaude  = "11111111-2222-4333-8444-555555555555"
	sidCodex   = "01900000-0000-7000-8000-000000000001"
	sidCopilot = "22222222-3333-4444-8555-666666666666"
)

// linuxFixture lays the grounded IntelliJ 2026.2 task-history shape
// under a Linux home in the fake FS: four agents' pointer files (one
// per grounded ACP agent), one unknown-agent pointer, one malformed
// pointer, and the non-pointer siblings (.events/.usage/.lastid) that
// must be ignored.
func linuxFixture(now time.Time) (*fakeFS, crossmount.HomeRoot, string) {
	home := crossmount.HomeRoot{Path: "/home/dev", OS: crossmount.OSLinux, Origin: "native"}
	vendor := filepath.Join("/home/dev", ".config", "JetBrains")
	hist := filepath.Join(vendor, "IntelliJIdea2026.2", "aia-task-history")
	f := &fakeFS{
		dirs: map[string][]string{
			vendor: {"IntelliJIdea2026.2", "IdeaIC2025.2", "acp-agents", "consentOptions"},
			hist: {
				"t-junie.agentsession", "t-junie.events", "t-junie.usage", "t-junie.lastid",
				"t-claude.agentsession", "t-codex.agentsession", "t-copilot.agentsession",
				"t-unknown.agentsession", "t-broken.agentsession",
				"t-noagent.events", "t-noagent.lastid",
			},
			// IdeaIC2025.2 has no aia-task-history dir → ReadDir fails → skipped.
		},
		files: map[string][]byte{
			filepath.Join(hist, "t-junie.agentsession"):   []byte("acp.registry.junie:" + sidJunie),
			filepath.Join(hist, "t-claude.agentsession"):  []byte("acp.registry.claude-acp:" + sidClaude + "\n"),
			filepath.Join(hist, "t-codex.agentsession"):   []byte("acp.registry.codex-acp:" + sidCodex),
			filepath.Join(hist, "t-copilot.agentsession"): []byte("acp.registry.github-copilot:" + sidCopilot),
			filepath.Join(hist, "t-unknown.agentsession"): []byte("acp.registry.qwen-code:abc-123"),
			filepath.Join(hist, "t-broken.agentsession"):  []byte("not a pointer"),
			filepath.Join(hist, "t-junie.usage"):          []byte(`{"used":18209,"size":1000000}`),
		},
		mtimes: map[string]time.Time{},
	}
	for name := range f.files {
		f.mtimes[name] = now.Add(-time.Minute)
	}
	return f, home, hist
}

func TestJetBrainsSourceListsPointerFiles(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	f, home, hist := linuxFixture(now)
	cands := jetbrainsSource(home, f.FS())
	if len(cands) != 6 {
		t.Fatalf("got %d candidates, want 6 (.agentsession files only): %+v", len(cands), cands)
	}
	byPath := map[string]Candidate{}
	for _, c := range cands {
		byPath[filepath.Base(c.Path)] = c
	}
	want := map[string]struct{ tool, sid, host string }{
		"t-junie.agentsession":   {models.ToolJunie, sidJunie, "jetbrains-idea"},
		"t-claude.agentsession":  {models.ToolClaudeCode, sidClaude, "jetbrains-idea"},
		"t-codex.agentsession":   {models.ToolCodex, sidCodex, "jetbrains-idea"},
		"t-copilot.agentsession": {models.ToolCopilotCLI, sidCopilot, "jetbrains-idea"},
		"t-unknown.agentsession": {"", "", ""},
		"t-broken.agentsession":  {"", "", ""},
	}
	for name, w := range want {
		c, ok := byPath[name]
		if !ok {
			t.Errorf("%s: missing", name)
			continue
		}
		if c.Tool != w.tool || c.Surface.SessionID != w.sid || c.Surface.SurfaceHost != w.host {
			t.Errorf("%s: got tool=%q sid=%q host=%q want %+v", name, c.Tool, c.Surface.SessionID, c.Surface.SurfaceHost, w)
		}
		if w.tool != "" && (c.Surface.Surface != models.SurfaceIDE || !c.Surface.Hosted) {
			t.Errorf("%s: surface %+v must be ide + Hosted", name, c.Surface)
		}
		// Unresolvable candidates carry a reason (logged once by the
		// enricher); resolvable ones carry none.
		if (w.tool == "") != (c.Unresolvable != "") {
			t.Errorf("%s: Unresolvable = %q with tool %q", name, c.Unresolvable, c.Tool)
		}
		if c.ModTime.IsZero() {
			t.Errorf("%s: mtime not carried", name)
		}
		if filepath.Dir(c.Path) != hist {
			t.Errorf("%s: path %q not under %q", name, c.Path, hist)
		}
	}
}

func TestEnricherResolvesAgainstTheStore(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	f, home, _ := linuxFixture(now)
	st := &fakeStore{sessions: map[string]models.SessionSurface{
		// claude-code self-reported sdk/ts (the ACP runtime is the SDK) → replaced.
		sidClaude: {SessionID: sidClaude, Surface: models.SurfaceSDK, SurfaceHost: "ts"},
		// codex self-stamped the right value already (its originator carries JetBrains) → landed, no write.
		sidCodex: {SessionID: sidCodex, Surface: models.SurfaceIDE, SurfaceHost: "jetbrains-idea"},
		// copilot-cli row exists with no surface → filled.
		sidCopilot: {SessionID: sidCopilot},
		// junie: NOT ingested yet → pending.
	}}
	clock := now
	e := New(Options{
		Load: st.load, Stamp: st.stamp,
		Homes:   func() []crossmount.HomeRoot { return []crossmount.HomeRoot{home} },
		FS:      f.FS(),
		Now:     func() time.Time { return clock },
		Window:  time.Hour,
		Logger:  nil,
		Sources: []Source{jetbrainsSource},
	})

	r := e.Tick(context.Background())
	if r.Candidates != 6 || r.Stamped != 2 || r.Landed != 1 || r.Pending != 1 || r.Skipped != 2 || r.Expired != 0 {
		t.Fatalf("tick 1 = %+v", r)
	}
	if got := st.sessions[sidClaude]; got.Surface != models.SurfaceIDE || got.SurfaceHost != "jetbrains-idea" {
		t.Errorf("claude session not overridden: %+v", got)
	}
	if got := st.sessions[sidCopilot]; got.Surface != models.SurfaceIDE || got.SurfaceHost != "jetbrains-idea" {
		t.Errorf("copilot session not filled: %+v", got)
	}
	for _, s := range st.stamps {
		if !s.Hosted {
			t.Errorf("stamp %+v must be Hosted", s)
		}
	}

	// Tick 2: the three landed + the two unresolvable are skipped; junie
	// still pending (retried, no stamp).
	r = e.Tick(context.Background())
	if r.Stamped != 0 || r.Landed != 0 || r.Pending != 1 || r.Skipped != 5 {
		t.Fatalf("tick 2 = %+v", r)
	}
	if len(st.stamps) != 2 {
		t.Fatalf("re-tick must not re-stamp landed sessions: %d stamps", len(st.stamps))
	}

	// Junie's transcript lands → the next tick stamps it.
	st.mu.Lock()
	st.sessions[sidJunie] = models.SessionSurface{SessionID: sidJunie}
	st.mu.Unlock()
	r = e.Tick(context.Background())
	if r.Stamped != 1 || r.Pending != 0 {
		t.Fatalf("tick 3 = %+v", r)
	}
	if got := st.sessions[sidJunie]; got.SurfaceHost != "jetbrains-idea" {
		t.Errorf("junie not stamped: %+v", got)
	}
	// Steady state: nothing but skips.
	r = e.Tick(context.Background())
	if r.Skipped != 6 || r.Stamped != 0 || r.Pending != 0 {
		t.Fatalf("steady tick = %+v", r)
	}
}

func TestEnricherPendingExpiresAfterWindowButIsCheckedOnce(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	f, home, hist := linuxFixture(now)
	// Age every pointer file well past the window.
	for p := range f.mtimes {
		f.mtimes[p] = now.Add(-48 * time.Hour)
	}
	st := &fakeStore{sessions: map[string]models.SessionSurface{
		sidClaude: {SessionID: sidClaude, Surface: models.SurfaceSDK, SurfaceHost: "ts"},
	}}
	e := New(Options{
		Load: st.load, Stamp: st.stamp,
		Homes:  func() []crossmount.HomeRoot { return []crossmount.HomeRoot{home} },
		FS:     f.FS(),
		Now:    func() time.Time { return now },
		Window: 2 * time.Hour,
	})
	// First sight: old files are still resolved ONCE (daemon restart
	// case) — claude is stamped, the three missing sessions are pending.
	r := e.Tick(context.Background())
	if r.Stamped != 1 || r.Pending != 3 || r.Skipped != 2 {
		t.Fatalf("tick 1 = %+v", r)
	}
	// Second tick: the still-missing old ones are expired, not retried.
	r = e.Tick(context.Background())
	if r.Expired != 3 || r.Pending != 0 || r.Skipped != 3 {
		t.Fatalf("tick 2 = %+v", r)
	}
	// A fresh pointer file (young mtime) for a missing session keeps
	// retrying.
	fresh := filepath.Join(hist, "t-fresh.agentsession")
	f.dirs[hist] = append(f.dirs[hist], "t-fresh.agentsession")
	f.files[fresh] = []byte("acp.registry.junie:session-260101-130000-zz99")
	f.mtimes[fresh] = now.Add(-time.Minute)
	for i := 0; i < 3; i++ {
		r = e.Tick(context.Background())
		if r.Pending != 1 {
			t.Fatalf("fresh tick %d = %+v", i, r)
		}
	}
}

func TestEnricherErrorsAreRetriedNotFatal(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	f, home, _ := linuxFixture(now)
	st := &fakeStore{sessions: map[string]models.SessionSurface{
		sidClaude: {SessionID: sidClaude, Surface: models.SurfaceSDK, SurfaceHost: "ts"},
	}, loadErr: errors.New("db locked")}
	e := New(Options{
		Load: st.load, Stamp: st.stamp,
		Homes: func() []crossmount.HomeRoot { return []crossmount.HomeRoot{home} },
		FS:    f.FS(), Now: func() time.Time { return now },
	})
	if r := e.Tick(context.Background()); r.Pending != 4 || r.Stamped != 0 {
		t.Fatalf("load error tick = %+v", r)
	}
	st.mu.Lock()
	st.loadErr = nil
	st.stampErr = errors.New("write failed")
	st.mu.Unlock()
	if r := e.Tick(context.Background()); r.Pending != 4 || r.Stamped != 0 {
		t.Fatalf("stamp error tick = %+v", r)
	}
	st.mu.Lock()
	st.stampErr = nil
	st.mu.Unlock()
	if r := e.Tick(context.Background()); r.Stamped != 1 || r.Pending != 3 {
		t.Fatalf("recovered tick = %+v", r)
	}
}

func TestEnricherNilSeamsAreNoOps(t *testing.T) {
	t.Parallel()
	e := New(Options{})
	if r := e.Tick(context.Background()); r != (TickResult{}) {
		t.Errorf("no seams: %+v", r)
	}
	var nilE *Enricher
	if r := nilE.Tick(context.Background()); r != (TickResult{}) {
		t.Errorf("nil enricher: %+v", r)
	}
	nilE.Run(context.Background()) // must not panic
}

func TestEnricherRunStopsWithContext(t *testing.T) {
	t.Parallel()
	st := &fakeStore{sessions: map[string]models.SessionSurface{}}
	e := New(Options{
		Load: st.load, Stamp: st.stamp,
		Homes:    func() []crossmount.HomeRoot { return nil },
		Interval: 5 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop with ctx")
	}
}

// TestJetBrainsSourceOnCheckedInFixture runs the real OSFS over the
// anonymized fixture (testdata/jetbrains/): the four grounded agents'
// pointer files resolve to their owning tools with the identity session
// id mapping, and the .events/.usage/.lastid siblings are never read.
func TestJetBrainsSourceOnCheckedInFixture(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "jetbrains"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	// The fixture root plays the role of <vendor root>: it holds one
	// product dir with the aia-task-history inside, so we point a fake
	// home at it by resolving through the real FS but with the vendor
	// listing taken from the fixture directory.
	osfs := OSFS()
	readDir := func(p string) ([]string, error) {
		if filepath.Clean(p) == filepath.Join("/fixture-home", ".config", "JetBrains") {
			return osfs.ReadDir(root)
		}
		if rel, ok := underFixtureVendor(p); ok {
			return osfs.ReadDir(filepath.Join(root, rel))
		}
		return osfs.ReadDir(p)
	}
	readFile := func(p string) ([]byte, error) {
		if rel, ok := underFixtureVendor(p); ok {
			return osfs.ReadFile(filepath.Join(root, rel))
		}
		return osfs.ReadFile(p)
	}
	modTime := func(p string) (time.Time, error) {
		if rel, ok := underFixtureVendor(p); ok {
			return osfs.ModTime(filepath.Join(root, rel))
		}
		return osfs.ModTime(p)
	}
	home := crossmount.HomeRoot{Path: "/fixture-home", OS: crossmount.OSLinux, Origin: "native"}
	cands := jetbrainsSource(home, FS{ReadDir: readDir, ReadFile: readFile, ModTime: modTime})
	got := map[string]string{}
	for _, c := range cands {
		got[c.Tool] = c.Surface.SessionID
		if c.Surface.Surface != models.SurfaceIDE || c.Surface.SurfaceHost != "jetbrains-idea" || !c.Surface.Hosted {
			t.Errorf("%s: surface %+v", c.Path, c.Surface)
		}
	}
	want := map[string]string{
		models.ToolJunie:      "session-260101-120000-ab12",
		models.ToolClaudeCode: "11111111-2222-4333-8444-555555555555",
		models.ToolCodex:      "01900000-0000-7000-8000-000000000001",
		models.ToolCopilotCLI: "22222222-3333-4444-8555-666666666666",
	}
	for tool, sid := range want {
		if got[tool] != sid {
			t.Errorf("%s: session %q want %q (candidates %+v)", tool, got[tool], sid, cands)
		}
	}
	if len(cands) != 4 {
		t.Errorf("fixture yields %d candidates, want 4", len(cands))
	}
}

// underFixtureVendor maps a path under the fake home's vendor root to a
// path relative to the fixture directory.
func underFixtureVendor(p string) (string, bool) {
	vendor := filepath.Join("/fixture-home", ".config", "JetBrains")
	rel, err := filepath.Rel(vendor, filepath.Clean(p))
	if err != nil || rel == "." || len(rel) >= 2 && rel[:2] == ".." {
		return "", false
	}
	return rel, true
}
