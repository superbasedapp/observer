package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fakeAdapterBasic is a minimal in-file adapter.Adapter that does NOT
// implement adapter.CursorSemantics, exercising the byte-offset default path
// (the historical behaviour every pre-CursorSemantics adapter still gets).
type fakeAdapterBasic struct {
	roots  []string
	suffix string // IsSessionFile match; "" matches every non-directory entry
	parse  func(path string) (adapter.ParseResult, error)
}

func (f *fakeAdapterBasic) Name() string         { return "fake-tool" }
func (f *fakeAdapterBasic) WatchPaths() []string { return f.roots }

func (f *fakeAdapterBasic) IsSessionFile(path string) bool {
	if f.suffix == "" {
		return true
	}
	return strings.HasSuffix(path, f.suffix)
}

func (f *fakeAdapterBasic) ParseSessionFile(_ context.Context, path string, _ int64) (adapter.ParseResult, error) {
	if f.parse != nil {
		return f.parse(path)
	}
	return adapter.ParseResult{}, nil
}

// fakeAdapterCursor wraps fakeAdapterBasic and additionally implements
// adapter.CursorSemantics, so tests can exercise the CursorWatermark /
// CursorEncrypted shape-exclusion gate in resolveGenericCandidate.
type fakeAdapterCursor struct {
	*fakeAdapterBasic
	kinds map[string]adapter.CursorKind // path -> declared kind; unlisted paths default to CursorByteOffset
}

func (f *fakeAdapterCursor) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if k, ok := f.kinds[path]; ok {
		return adapter.FileCursorSemantics{Kind: k}
	}
	return adapter.FileCursorSemantics{}
}

var (
	_ adapter.Adapter         = (*fakeAdapterBasic)(nil)
	_ adapter.Adapter         = (*fakeAdapterCursor)(nil)
	_ adapter.CursorSemantics = (*fakeAdapterCursor)(nil)
)

// newFakeSessionAdapter builds a fakeAdapterBasic whose ParseSessionFile
// derives a session id from the file's basename (stripping the ".log"
// IsSessionFile suffix) and looks up its project root in rootsByID — letting
// tests control candidate identity purely through which files they write,
// the same way codex_discover_test.go's writeRollout embeds id + cwd in the
// fixture content.
func newFakeSessionAdapter(dir string, rootsByID map[string]string) *fakeAdapterBasic {
	return &fakeAdapterBasic{
		roots:  []string{dir},
		suffix: ".log",
		parse: func(path string) (adapter.ParseResult, error) {
			id := strings.TrimSuffix(filepath.Base(path), ".log")
			return adapter.ParseResult{
				ToolEvents: []models.ToolEvent{{SessionID: id, ProjectRoot: rootsByID[id]}},
			}, nil
		},
	}
}

func writeGenericSessionFile(t *testing.T, dir, id string) string {
	t.Helper()
	path := filepath.Join(dir, id+".log")
	if err := os.WriteFile(path, []byte("session data\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestSnapshotGenericSessionFiles(t *testing.T) {
	dir := t.TempDir()
	a := &fakeAdapterBasic{roots: []string{dir}, suffix: ".log"}

	p1 := writeGenericSessionFile(t, dir, "a")
	p2 := writeGenericSessionFile(t, dir, "b")
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	snap := snapshotGenericSessionFiles(a)
	if _, ok := snap[p1]; !ok {
		t.Fatalf("snapshot missing %s", p1)
	}
	if _, ok := snap[p2]; !ok {
		t.Fatalf("snapshot missing %s", p2)
	}
	if len(snap) != 2 {
		t.Fatalf("snapshot size = %d, want 2 (session files only): %+v", len(snap), snap)
	}
}

func TestScanNewGenericSessionFiles(t *testing.T) {
	dir := t.TempDir()
	a := &fakeAdapterBasic{roots: []string{dir}, suffix: ".log"}
	start := time.Now()

	pre := writeGenericSessionFile(t, dir, "pre")
	preexisting := map[string]struct{}{pre: {}}

	newP := writeGenericSessionFile(t, dir, "new")

	got := scanNewGenericSessionFiles(a, preexisting, start)
	if len(got) != 1 || got[0] != newP {
		t.Fatalf("scanNewGenericSessionFiles = %+v, want [%s]", got, newP)
	}

	// ModTime skew guard: a file predating start (beyond the skew) is excluded
	// even though its path was never in the pre-start snapshot.
	stale := writeGenericSessionFile(t, dir, "stale")
	old := start.Add(-1 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	got2 := scanNewGenericSessionFiles(a, preexisting, start)
	for _, p := range got2 {
		if p == stale {
			t.Fatalf("file with ModTime before start must be excluded, got %+v", got2)
		}
	}

	// A file IsSessionFile does not claim is never a candidate, new or not.
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got3 := scanNewGenericSessionFiles(a, preexisting, start)
	for _, p := range got3 {
		if strings.HasSuffix(p, ".txt") {
			t.Fatalf("non-session file must be excluded, got %+v", got3)
		}
	}
}

func TestUniqueSessionIdentity(t *testing.T) {
	cases := []struct {
		name           string
		res            adapter.ParseResult
		wantID, wantRt string
	}{
		{"empty result", adapter.ParseResult{}, "", ""},
		{
			"different tool and token session identities abstain",
			adapter.ParseResult{
				ToolEvents:  []models.ToolEvent{{SessionID: "t1", ProjectRoot: "/t"}},
				TokenEvents: []models.TokenEvent{{SessionID: "k1", ProjectRoot: "/k"}},
			},
			"", "",
		},
		{
			"falls back to token event when no tool event carries an id",
			adapter.ParseResult{
				ToolEvents:  []models.ToolEvent{{SessionID: ""}},
				TokenEvents: []models.TokenEvent{{SessionID: "k1", ProjectRoot: "/k"}},
			},
			"k1", "/k",
		},
		{
			"first non-empty tool event among several",
			adapter.ParseResult{
				ToolEvents: []models.ToolEvent{{SessionID: ""}, {SessionID: "t2", ProjectRoot: "/t2"}},
			},
			"t2", "/t2",
		},
		{
			"two sessions in the same project abstain",
			adapter.ParseResult{ToolEvents: []models.ToolEvent{{SessionID: "one", ProjectRoot: "/project"}, {SessionID: "two", ProjectRoot: "/project"}}},
			"", "",
		},
		{
			"consistent events fill missing root",
			adapter.ParseResult{
				ToolEvents:  []models.ToolEvent{{SessionID: "one"}, {SessionID: "one", ProjectRoot: "/project/"}},
				TokenEvents: []models.TokenEvent{{SessionID: "one", ProjectRoot: "/project"}},
			},
			"one", "/project",
		},
		{
			"conflicting project roots abstain",
			adapter.ParseResult{ToolEvents: []models.ToolEvent{{SessionID: "one", ProjectRoot: "/a"}, {SessionID: "one", ProjectRoot: "/b"}}},
			"", "",
		},
		{
			"sidechain-only file abstains",
			adapter.ParseResult{ToolEvents: []models.ToolEvent{{SessionID: "parent", IsSidechain: true}}},
			"", "",
		},
		{
			"subagent lineage abstains despite unflagged event",
			adapter.ParseResult{
				ToolEvents:      []models.ToolEvent{{SessionID: "child"}},
				SessionLineages: []models.SessionLineage{{SessionID: "child", ParentThreadID: "parent", ThreadSource: "subagent"}},
			},
			"", "",
		},
		{
			"user fork remains a primary session",
			adapter.ParseResult{
				TokenEvents:     []models.TokenEvent{{SessionID: "fork"}},
				SessionLineages: []models.SessionLineage{{SessionID: "fork", ForkedFromID: "previous", ThreadSource: "user"}},
			},
			"fork", "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, root := uniqueSessionIdentity(tc.res)
			if id != tc.wantID || root != tc.wantRt {
				t.Fatalf("uniqueSessionIdentity = (%q,%q), want (%q,%q)", id, root, tc.wantID, tc.wantRt)
			}
		})
	}
}

func TestResolveGenericCandidate(t *testing.T) {
	dir := t.TempDir()
	watermarkPath := filepath.Join(dir, "store.watermark")
	encryptedPath := filepath.Join(dir, "store.enc")
	okPath := writeGenericSessionFile(t, dir, "sess")
	emptyIDPath := filepath.Join(dir, "empty.log")
	errPath := filepath.Join(dir, "broken.log")

	results := map[string]adapter.ParseResult{
		okPath:      {ToolEvents: []models.ToolEvent{{SessionID: "sess-1", ProjectRoot: "/proj"}}},
		emptyIDPath: {ToolEvents: []models.ToolEvent{{SessionID: ""}}},
	}
	a := &fakeAdapterCursor{
		fakeAdapterBasic: &fakeAdapterBasic{
			roots: []string{dir},
			parse: func(path string) (adapter.ParseResult, error) {
				if path == errPath {
					return adapter.ParseResult{}, errors.New("boom")
				}
				return results[path], nil
			},
		},
		kinds: map[string]adapter.CursorKind{
			watermarkPath: adapter.CursorWatermark,
			encryptedPath: adapter.CursorEncrypted,
		},
	}

	cases := []struct {
		name     string
		path     string
		wantOK   bool
		wantID   string
		wantRoot string
	}{
		{"watermark-shaped file excluded", watermarkPath, false, "", ""},
		{"encrypted-shaped file excluded", encryptedPath, false, "", ""},
		{"parse error excluded", errPath, false, "", ""},
		{"empty session id excluded", emptyIDPath, false, "", ""},
		{"byte-offset default resolves", okPath, true, "sess-1", "/proj"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveGenericCandidate(context.Background(), a, tc.path)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && (got.sessionID != tc.wantID || got.projectRoot != tc.wantRoot) {
				t.Fatalf("candidate = %+v, want id=%q root=%q", got, tc.wantID, tc.wantRoot)
			}
		})
	}
}

func TestResolveGenericCandidateDefaultsWithoutCursorSemantics(t *testing.T) {
	// An adapter that does not implement CursorSemantics at all must keep the
	// byte-offset (eligible) default for every path.
	dir := t.TempDir()
	okPath := writeGenericSessionFile(t, dir, "sess")
	a := &fakeAdapterBasic{
		roots: []string{dir},
		parse: func(string) (adapter.ParseResult, error) {
			return adapter.ParseResult{TokenEvents: []models.TokenEvent{{SessionID: "sess-tok", ProjectRoot: "/proj"}}}, nil
		},
	}
	got, ok := resolveGenericCandidate(context.Background(), a, okPath)
	if !ok || got.sessionID != "sess-tok" || got.projectRoot != "/proj" {
		t.Fatalf("resolveGenericCandidate = (%+v,%v), want (sess-tok,/proj)/true", got, ok)
	}
}

func TestCwdUnderProjectRoot(t *testing.T) {
	cases := []struct {
		name      string
		cwd, root string
		want      bool
	}{
		{"empty cwd is unknown, kept", "", "/proj", true},
		{"empty root is unknown, kept", "/proj/sub", "", true},
		{"exact match", "/proj", "/proj", true},
		{"subdirectory", "/proj/sub/dir", "/proj", true},
		{"unrelated path", "/other", "/proj", false},
		{"prefix collision is not a subdirectory", "/projector", "/proj", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cwdUnderProjectRoot(tc.cwd, tc.root)
			if got != tc.want {
				t.Fatalf("cwdUnderProjectRoot(%q,%q) = %v, want %v", tc.cwd, tc.root, got, tc.want)
			}
		})
	}
}

func TestSelectDiscoveredGenericSession(t *testing.T) {
	cwd := "/work/proj"
	cases := []struct {
		name      string
		cands     []genericDiscoverCandidate
		targetCwd string
		wantID    string
		wantCount int
	}{
		{"zero candidates", nil, cwd, "", 0},
		{"duplicate artifacts for one session", []genericDiscoverCandidate{{path: "a", sessionID: "same"}, {path: "b", sessionID: "same"}}, cwd, "same", 1},
		{"single, no cwd filter", []genericDiscoverCandidate{{sessionID: "a", projectRoot: cwd}}, "", "a", 1},
		{"single, cwd match", []genericDiscoverCandidate{{sessionID: "a", projectRoot: cwd}}, cwd, "a", 1},
		{
			"two candidates -> abstain",
			[]genericDiscoverCandidate{{sessionID: "a", projectRoot: cwd}, {sessionID: "b", projectRoot: cwd}},
			cwd, "", 2,
		},
		{
			"two candidates, one root mismatch -> single survives",
			[]genericDiscoverCandidate{{sessionID: "a", projectRoot: cwd}, {sessionID: "b", projectRoot: "/other"}},
			cwd, "a", 1,
		},
		{
			"candidate with unknown root is kept (counts toward ambiguity)",
			[]genericDiscoverCandidate{{sessionID: "a", projectRoot: cwd}, {sessionID: "b", projectRoot: ""}},
			cwd, "", 2,
		},
		{
			"empty session id skipped",
			[]genericDiscoverCandidate{{sessionID: "", projectRoot: cwd}, {sessionID: "a", projectRoot: cwd}},
			cwd, "a", 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, count := selectDiscoveredGenericSession(tc.cands, tc.targetCwd)
			if id != tc.wantID || count != tc.wantCount {
				t.Fatalf("selectDiscoveredGenericSession = (%q,%d), want (%q,%d)", id, count, tc.wantID, tc.wantCount)
			}
		})
	}
}

func TestRunGenericDiscovery(t *testing.T) {
	// A short window keeps the test fast while still exercising the
	// observe-the-whole-window-then-decide behaviour mirrored from
	// runCodexDiscovery's R2-1 fix.
	cfg := genericDiscoverConfig{window: 120 * time.Millisecond, poll: 5 * time.Millisecond}
	cwd := "/work/proj"

	t.Run("single new session file announces at window END (not mid-window)", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Now().Add(-time.Second)
		writeGenericSessionFile(t, dir, "disco-1")
		a := newFakeSessionAdapter(dir, map[string]string{"disco-1": cwd})

		var got string
		var calls int
		begin := time.Now()
		runGenericDiscovery(context.Background(), a, map[string]struct{}{}, start, cwd, cfg,
			func(id string) { got = id; calls++ })
		elapsed := time.Since(begin)
		if calls != 1 || got != "disco-1" {
			t.Fatalf("announce calls=%d id=%q, want 1 / disco-1", calls, got)
		}
		if elapsed < cfg.window/2 {
			t.Fatalf("announced after %v — must observe the whole window before announcing (>= %v)", elapsed, cfg.window/2)
		}
	})

	t.Run("two new session files -> no announcement (never guess)", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Now().Add(-time.Second)
		writeGenericSessionFile(t, dir, "amb-1")
		writeGenericSessionFile(t, dir, "amb-2")
		a := newFakeSessionAdapter(dir, map[string]string{"amb-1": cwd, "amb-2": cwd})

		var calls int
		runGenericDiscovery(context.Background(), a, map[string]struct{}{}, start, cwd, cfg, func(string) { calls++ })
		if calls != 0 {
			t.Fatalf("ambiguous window must not announce, got %d calls", calls)
		}
	})

	t.Run("late second candidate before close -> abstain", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Now().Add(-time.Second)
		writeGenericSessionFile(t, dir, "first-1")
		a := newFakeSessionAdapter(dir, map[string]string{"first-1": cwd, "second-1": cwd})
		go func() {
			time.Sleep(cfg.window / 3)
			writeGenericSessionFile(t, dir, "second-1")
		}()

		var got string
		var calls int
		runGenericDiscovery(context.Background(), a, map[string]struct{}{}, start, cwd, cfg,
			func(id string) { got = id; calls++ })
		if calls != 0 {
			t.Fatalf("a second candidate appearing before window close must force abstention, got %d calls (id=%q)", calls, got)
		}
	})

	t.Run("cwd mismatch disambiguates to the matching session", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Now().Add(-time.Second)
		writeGenericSessionFile(t, dir, "mine-1")
		writeGenericSessionFile(t, dir, "theirs-1")
		a := newFakeSessionAdapter(dir, map[string]string{"mine-1": cwd, "theirs-1": "/some/other/dir"})

		var got string
		var calls int
		runGenericDiscovery(context.Background(), a, map[string]struct{}{}, start, cwd, cfg,
			func(id string) { got = id; calls++ })
		if calls != 1 || got != "mine-1" {
			t.Fatalf("announce calls=%d id=%q, want 1 / mine-1", calls, got)
		}
	})

	t.Run("no session file in window -> no announcement", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Now().Add(-time.Second)
		a := newFakeSessionAdapter(dir, nil)

		var calls int
		runGenericDiscovery(context.Background(), a, map[string]struct{}{}, start, cwd, cfg, func(string) { calls++ })
		if calls != 0 {
			t.Fatalf("empty window must not announce, got %d calls", calls)
		}
	})

	t.Run("cancelled ctx stops without announcing", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Now().Add(-time.Second)
		writeGenericSessionFile(t, dir, "disco-1")
		a := newFakeSessionAdapter(dir, map[string]string{"disco-1": cwd})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		var calls int
		runGenericDiscovery(ctx, a, map[string]struct{}{}, start, cwd, cfg, func(string) { calls++ })
		if calls != 0 {
			t.Fatalf("cancelled discovery must not announce, got %d calls", calls)
		}
	})

	t.Run("watermark-shaped candidate excluded even though it's the only new file", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Now().Add(-time.Second)
		p := writeGenericSessionFile(t, dir, "store-1")
		base := newFakeSessionAdapter(dir, map[string]string{"store-1": cwd})
		a := &fakeAdapterCursor{
			fakeAdapterBasic: base,
			kinds:            map[string]adapter.CursorKind{p: adapter.CursorWatermark},
		}

		var calls int
		runGenericDiscovery(context.Background(), a, map[string]struct{}{}, start, cwd, cfg, func(string) { calls++ })
		if calls != 0 {
			t.Fatalf("a watermark-shaped file must never resolve to a session id, got %d calls", calls)
		}
	})
}

func TestResolveDiscoverableAdapter(t *testing.T) {
	if a := resolveDiscoverableAdapter(""); a != nil {
		t.Fatalf("empty tool must resolve nil, got %v", a.Name())
	}
	if a := resolveDiscoverableAdapter("not-a-real-tool"); a != nil {
		t.Fatalf("unknown tool must resolve nil, got %v", a.Name())
	}
	if a := resolveDiscoverableAdapter(models.ToolClaudeCode); a == nil {
		t.Fatal("claude-code must resolve to a discoverable adapter (it declares session-file WatchPaths)")
	}
	// The browser-capture rail has no WatchPaths — capture arrives over the
	// native-messaging bridge, not a session file on disk — so the SHAPE gate
	// must exclude it even though it IS a registered adapter.
	if a := resolveDiscoverableAdapter(models.ToolClaudeWeb); a != nil {
		t.Fatalf("a hook-only adapter with no WatchPaths must resolve nil, got %v", a.Name())
	}
}

func TestPrepareGenericDiscoveryNoOOBChannel(t *testing.T) {
	// In a `go test` process nothing has authenticated the trusted OOB
	// channel (that only happens when the daemon spawns an `observer <tool>`
	// launcher and sets the OBSERVER_OOB_* env), so oobChannelActive() is
	// false here — prepareGenericDiscovery must be a pure no-op regardless
	// of tool, matching every other best-effort OOB announce in this package.
	if plan := prepareGenericDiscovery(context.Background(), models.ToolClaudeCode, ""); plan != nil {
		t.Fatal("must return nil when the OOB channel is not active")
	}
	if plan := prepareGenericDiscovery(context.Background(), "", ""); plan != nil {
		t.Fatal("must return nil for an empty tool")
	}
}

func TestGenericDiscoverySnapshotPrecedesImmediateWrite(t *testing.T) {
	dir := t.TempDir()
	a := newFakeSessionAdapter(dir, nil)
	writeGenericSessionFile(t, dir, "old")
	plan := prepareAdapterDiscovery(context.Background(), a, dir)
	// The child creates a transcript immediately during Start.
	writeGenericSessionFile(t, dir, "immediate")
	var got string
	runGenericDiscovery(plan.ctx, plan.a, plan.preexisting, plan.startedAt, plan.cwd,
		genericDiscoverConfig{window: time.Millisecond, poll: time.Millisecond}, func(id string) { got = id })
	if got != "immediate" {
		t.Fatalf("immediate write lost: %q", got)
	}
}

func TestGenericDiscoveryRevalidatesBeforeAnnouncement(t *testing.T) {
	for _, mutation := range []string{"session changed", "inode replaced", "deleted", "multi session"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			path := writeGenericSessionFile(t, dir, "main")
			calls := 0
			a := &fakeAdapterBasic{roots: []string{dir}, suffix: ".log", parse: func(string) (adapter.ParseResult, error) {
				calls++
				res := adapter.ParseResult{ToolEvents: []models.ToolEvent{{SessionID: "main"}}}
				if calls > 1 {
					switch mutation {
					case "session changed":
						res.ToolEvents[0].SessionID = "other"
					case "multi session":
						res.ToolEvents = append(res.ToolEvents, models.ToolEvent{SessionID: "other"})
					case "deleted":
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
					case "inode replaced":
						replacement := filepath.Join(dir, "replacement")
						if err := os.WriteFile(replacement, []byte("new"), 0o600); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(replacement, path); err != nil {
							t.Fatal(err)
						}
					}
				}
				return res, nil
			}}
			announced := false
			runGenericDiscovery(context.Background(), a, nil, time.Now(), dir,
				genericDiscoverConfig{window: time.Millisecond, poll: time.Millisecond}, func(string) { announced = true })
			if announced {
				t.Fatal("announced a replaced identity")
			}
		})
	}
}

func TestGenericDiscoveryExcludesTokenOnlyArtifact(t *testing.T) {
	dir := t.TempDir()
	path := writeGenericSessionFile(t, dir, "global-usage")
	a := &fakeAdapterCursor{fakeAdapterBasic: newFakeSessionAdapter(dir, nil), kinds: map[string]adapter.CursorKind{path: adapter.CursorNoActions}}
	if _, ok := resolveGenericCandidate(context.Background(), a, path); ok {
		t.Fatal("usage-only file identified a terminal")
	}
}
