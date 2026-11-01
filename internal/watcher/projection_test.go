package watcher

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestProjectionRootParsesATranscriptWrittenInTheBox is lane SBX-P3C's G27
// case: a transcript a box wrote into its projected tool state (a host
// directory outside every adapter's own roots) is parsed by the tool's own
// adapter once the run registers the projection, as if it lay at the path
// the tool wrote it at in the box; a symlink planted there that leaves the
// projection is never read; and the root goes when the run ends.
func TestProjectionRootParsesATranscriptWrittenInTheBox(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "w.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s := store.New(database)

	home := t.TempDir()
	boxProjects := filepath.Join(home, ".claude", "projects") // the box path; not on this host
	reg := adapter.NewRegistry()
	reg.Register(claudecode.NewWithOptions(nil, boxProjects))
	w := New(s, reg, Options{
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		NativePredicate: map[string]func(string) bool{"claude-code": claudecode.IsNativeTool},
		Debounce:        20 * time.Millisecond,
	})
	if _, err := w.AddProjectionRoot(ctx, "claude-code", "/x", "/y", ProjectionBinding{}); err == nil {
		t.Fatal("a root was added before the watcher runs")
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Watch(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, 5*time.Second, func() bool {
		w.liveMu.Lock()
		defer w.liveMu.Unlock()
		return w.fsw != nil
	}, "Watch never became live")

	hostProjects := filepath.Join(t.TempDir(), "run1.state", "0", "projects")
	if err := os.MkdirAll(filepath.Join(hostProjects, "-ws"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][3]string{
		{"no-such-tool", hostProjects, boxProjects},
		{"claude-code", "relative", boxProjects},
		{"claude-code", hostProjects, "relative"},
	} {
		if _, err := w.AddProjectionRoot(ctx, bad[0], bad[1], bad[2], ProjectionBinding{}); err == nil {
			t.Fatalf("AddProjectionRoot%v accepted", bad)
		}
	}
	remove, err := w.AddProjectionRoot(ctx, "claude-code", hostProjects, boxProjects, ProjectionBinding{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddProjectionRoot(ctx, "claude-code", hostProjects, boxProjects, ProjectionBinding{}); err == nil {
		t.Fatal("the same root was added twice")
	}
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(hostProjects, "-ws", "planted.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostProjects, "-ws", "session.jsonl"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, func() bool {
		n, _ := s.CountActions(ctx)
		return n == 4
	}, "the transcript in the projection was not parsed")
	time.Sleep(200 * time.Millisecond)
	if n, _ := s.CountActions(ctx); n != 4 {
		t.Fatalf("actions %d, want 4 (the planted symlink to a file outside the projection must not be read)", n)
	}
	remove()
	w.liveMu.Lock()
	_, still := w.byRoot[hostProjects]
	w.liveMu.Unlock()
	if still {
		t.Fatal("the projection root is still watched after the run")
	}
}

func TestProjectionAdapterMapsOntoTheBoxPath(t *testing.T) {
	t.Parallel()
	pa := &projectionAdapter{Adapter: claudecode.NewWithOptions(nil, "/home/dev/.claude/projects"), hostRoot: "/m/r.state/0/projects", boxRoot: "/home/dev/.claude/projects"}
	cases := map[string]bool{
		"/m/r.state/0/projects/-ws/s.jsonl":  true,
		"/m/r.state/0/projects/-ws/s.txt":    false,
		"/m/r.state/0/other/s.jsonl":         false,
		"/m/r.state/0/projects":              false,
		"/home/dev/.claude/projects/x.jsonl": false,
		"/m/r.state/0/projects/../x/s.jsonl": false,
		"/m/r.state/0/projectsx/-ws/s.jsonl": false,
	}
	for p, want := range cases {
		if got := pa.IsSessionFile(p); got != want {
			t.Errorf("IsSessionFile(%q) = %v, want %v", p, got, want)
		}
	}
	if got := pa.WatchPaths(); len(got) != 1 || got[0] != "/m/r.state/0/projects" {
		t.Fatalf("WatchPaths %v", got)
	}
}

// TestProjectionTranscriptIsBoundToTheRun is lane SBX-P3C audit finding 3:
// a box-written transcript that claims another project's cwd and an
// existing session id lands on the run's workspace project under a
// run-namespaced session id, keeps the claimed cwd only in the action's
// metadata, and does not touch the existing session.
func TestProjectionTranscriptIsBoundToTheRun(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "w.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s := store.New(database)
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}

	// The developer's own session sess-001 of /tmp/superbased-fixture-simple,
	// ingested from its own transcript (a source outside any projection).
	ownDir := filepath.Join(t.TempDir(), "projects")
	if err := os.MkdirAll(filepath.Join(ownDir, "-p"), 0o700); err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(ownDir, "-p", "sess-001.jsonl")
	if err := os.WriteFile(own, body, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := claudecode.NewWithOptions(nil, ownDir).ParseSessionFile(ctx, own, 0)
	if err != nil || len(res.ToolEvents) == 0 {
		t.Fatalf("parse the developer's transcript: %v", err)
	}
	if _, err := s.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	count := func(session string) int {
		var n int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions WHERE session_id = ?`, session).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count("sess-001")
	ownRoot, _ := s.ProjectRootForSession(ctx, "sess-001")
	if before == 0 || ownRoot != "/tmp/superbased-fixture-simple" {
		t.Fatalf("setup: %d actions, root %q", before, ownRoot)
	}

	home := t.TempDir()
	boxProjects := filepath.Join(home, ".claude", "projects")
	reg := adapter.NewRegistry()
	reg.Register(claudecode.NewWithOptions(nil, boxProjects))
	w := New(s, reg, Options{
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
		NativePredicate: map[string]func(string) bool{"claude-code": claudecode.IsNativeTool},
		Debounce:        20 * time.Millisecond,
	})
	done := make(chan struct{})
	go func() { defer close(done); _ = w.Watch(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, 5*time.Second, func() bool {
		w.liveMu.Lock()
		defer w.liveMu.Unlock()
		return w.fsw != nil
	}, "Watch never became live")

	ws := filepath.Join(t.TempDir(), "workspaces", "run1", "repo")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	hostProjects := filepath.Join(t.TempDir(), "run1.state", "0", "projects")
	if err := os.MkdirAll(filepath.Join(hostProjects, "-ws"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := w.AddProjectionRoot(ctx, "claude-code", hostProjects, boxProjects, ProjectionBinding{RunID: "run 1", Workspace: ws}); err == nil {
		t.Fatal("a binding with an unclean run id was accepted")
	}
	remove, err := w.AddProjectionRoot(ctx, "claude-code", hostProjects, boxProjects, ProjectionBinding{RunID: "run1", Workspace: ws})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	// The poll pass resolves a projection file too (audit finding 7).
	if a, ok := w.adapterFor(filepath.Join(hostProjects, "-ws", "session.jsonl")).(*projectionAdapter); !ok || a.hostRoot != hostProjects {
		t.Fatal("the poll pass does not see the projection root")
	}
	if err := os.WriteFile(filepath.Join(hostProjects, "-ws", "session.jsonl"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, func() bool { return count("sandbox-run1-sess-001") == before }, "the box's transcript was not ingested under the run")
	if got := count("sess-001"); got != before {
		t.Fatalf("the existing session changed: %d actions, was %d", got, before)
	}
	if root, _ := s.ProjectRootForSession(ctx, "sess-001"); root != ownRoot {
		t.Fatalf("the existing session moved to %q", root)
	}
	if root, _ := s.ProjectRootForSession(ctx, "sandbox-run1-sess-001"); root != ws {
		t.Fatalf("the run's session landed on %q, want the run's workspace %q", root, ws)
	}
	var stamped int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM actions WHERE session_id = ? AND metadata LIKE ?`,
		"sandbox-run1-sess-001", `%"sandbox_claimed_cwd":"/tmp/superbased-fixture-simple"%`).Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	if stamped == 0 {
		t.Fatal("the box's claimed cwd was not kept as a stamped field")
	}
}

// TestProjectionBindToRunTable: the per-field decisions of bindToRun over a
// parse result: a cwd inside the workspace is kept, one outside is rebound
// and stamped, a session the store holds elsewhere is namespaced (once,
// consistently), a new one is kept, and box pids never seed a bridge.
func TestProjectionBindToRunTable(t *testing.T) {
	t.Parallel()
	owners := map[string]store.SessionOwnerFacts{
		"taken":   {Exists: true, ProjectRoot: "/elsewhere"},
		"foreign": {Exists: true, ProjectRoot: "/ws/run", ForeignSource: true},
		"mine":    {Exists: true, ProjectRoot: "/ws/run"},
	}
	asked := map[string]int{}
	pa := &projectionAdapter{bind: ProjectionBinding{RunID: "r1", Workspace: "/ws/run"}, owner: func(_ context.Context, id string) (store.SessionOwnerFacts, error) {
		asked[id]++
		return owners[id], nil
	}}
	res := adapter.ParseResult{
		ToolEvents: []models.ToolEvent{
			{SessionID: "taken", ProjectRoot: "/ws/run/sub", GitBranch: "main"},
			{SessionID: "taken", ProjectRoot: "/home/dev/secret-project", GitBranch: "main", GitRemote: "git@x:y"},
			{SessionID: "fresh", ProjectRoot: "/ws/run"},
			{SessionID: "foreign", ProjectRoot: "/ws/run"},
			{SessionID: "mine", ProjectRoot: "/ws/run"},
		},
		TokenEvents:         []models.TokenEvent{{SessionID: "taken", ProjectRoot: "/other"}},
		SessionProcessSeeds: []models.SessionProcessSeed{{PID: 1, SessionID: "fresh"}},
		SessionSurfaces:     []models.SessionSurface{{SessionID: "taken"}},
	}
	pa.bindToRun(context.Background(), &res)
	te := res.ToolEvents
	if te[0].SessionID != "sandbox-r1-taken" || te[1].SessionID != "sandbox-r1-taken" || te[2].SessionID != "fresh" ||
		te[3].SessionID != "sandbox-r1-foreign" || te[4].SessionID != "mine" {
		t.Fatalf("sessions %q %q %q %q %q", te[0].SessionID, te[1].SessionID, te[2].SessionID, te[3].SessionID, te[4].SessionID)
	}
	if asked["taken"] != 1 {
		t.Fatalf("the owner was asked %d times for one id", asked["taken"])
	}
	if te[0].ProjectRoot != "/ws/run/sub" || te[0].GitBranch != "main" || te[0].Metadata != nil {
		t.Fatalf("an in-workspace cwd was changed: %+v", te[0])
	}
	if te[1].ProjectRoot != "/ws/run" || te[1].GitBranch != "" || te[1].GitRemote != "" || te[1].Metadata == nil || te[1].Metadata.SandboxClaimedCwd != "/home/dev/secret-project" {
		t.Fatalf("an outside cwd was not rebound and stamped: %+v %+v", te[1], te[1].Metadata)
	}
	if res.TokenEvents[0].ProjectRoot != "/ws/run" || res.TokenEvents[0].SessionID != "sandbox-r1-taken" || res.SessionSurfaces[0].SessionID != "sandbox-r1-taken" {
		t.Fatalf("tokens/surfaces: %+v %+v", res.TokenEvents[0], res.SessionSurfaces[0])
	}
	if res.SessionProcessSeeds != nil {
		t.Fatal("a box pid seeded a host pid bridge")
	}
}
