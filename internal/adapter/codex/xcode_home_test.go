package codex

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestXcodeHomeFixtureIngestsTheRolloutOnce (FU-150): in a fixture Xcode
// Codex home holding the files the MAC-1 read listed, exactly one file is a
// session file (the rollout under sessions/), it sits under exactly one
// watch root, and it parses to ide/xcode with the project taken from the
// rollout's own cwd: the same project the rollout gives outside the home.
func TestXcodeHomeFixtureIngestsTheRolloutOnce(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "codex", "rollout-surface-attribution.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "codex")
	root := filepath.Join(home, "sessions")
	name := "rollout-2026-10-28T17-57-00-00000000-0000-4000-8000-000000000001.jsonl"
	rollout := filepath.Join(root, "2026", "10", "28", name)
	files := map[string][]byte{
		filepath.Join(home, "installation_id"):         []byte("id"),
		filepath.Join(home, "logs_2.sqlite"):           []byte(""),
		filepath.Join(home, "memories_1.sqlite"):       []byte(""),
		filepath.Join(home, "models_cache.json"):       []byte(`{}`),
		filepath.Join(home, "rules", "xcode.rules"):    []byte("rule"),
		filepath.Join(home, "plugins", "p.json"):       []byte(`{}`),
		filepath.Join(home, "shell_snapshots", "s.sh"): []byte(""),
		filepath.Join(home, ".personality_migration"):  []byte(""),
		filepath.Join(home, "cache", "c"):              []byte(""),
		rollout:                                        body,
	}
	for p, b := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := New()
	a.xcodeRootFn = func() string { return root }

	var sessions []string
	if err := filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if a.IsSessionFile(p) {
			sessions = append(sessions, p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0] != rollout {
		t.Fatalf("session files in the Xcode home = %v, want only %s", sessions, rollout)
	}
	n := 0
	for _, r := range a.WatchPaths() {
		if adapter.UnderAnyWatchRoot(rollout, []string{r}) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the rollout is under %d watch roots (%v), want 1", n, a.WatchPaths())
	}

	res, err := a.ParseSessionFile(context.Background(), rollout, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceIDE || res.SessionSurfaces[0].SurfaceHost != "xcode" {
		t.Errorf("surfaces = %+v, want one ide/xcode", res.SessionSurfaces)
	}

	outside := t.TempDir()
	elsewhere := filepath.Join(outside, "2026", "10", "28", name)
	if err := os.MkdirAll(filepath.Dir(elsewhere), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(elsewhere, body, 0o600); err != nil {
		t.Fatal(err)
	}
	b := NewWithOptions(nil, outside)
	b.xcodeRootFn = func() string { return root }
	ref, err := b.ParseSessionFile(context.Background(), elsewhere, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, want := codexProjectRoots(res.ToolEvents), codexProjectRoots(ref.ToolEvents)
	if len(got) == 0 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("project roots in the Xcode home = %v, want the cwd's %v", got, want)
	}
	for _, p := range got {
		if strings.Contains(p, "CodingAssistant") || strings.HasPrefix(p, home) {
			t.Errorf("project root %q comes from the Xcode home, not the cwd", p)
		}
	}
}

// codexProjectRoots lists the distinct project roots of evs in first-seen
// order.
func codexProjectRoots(evs []models.ToolEvent) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range evs {
		if e.ProjectRoot != "" && !seen[e.ProjectRoot] {
			seen[e.ProjectRoot] = true
			out = append(out, e.ProjectRoot)
		}
	}
	return out
}
