package claudecode

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

// TestXcodeHomeFixtureIngestsTheTranscriptOnce (FU-150): in a fixture Xcode
// Claude Agent home holding the files the MAC-1 read listed, exactly one
// file is a session file (the transcript under projects/), it sits under
// exactly one watch root, and it parses to ide/xcode with the project taken
// from the transcript's own cwd: the same project the transcript gives when
// it lives outside the Xcode home.
func TestXcodeHomeFixtureIngestsTheTranscriptOnce(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "ClaudeAgentConfig")
	root := filepath.Join(home, "projects")
	transcript := filepath.Join(root, "-Users-u-App", "9820487a-0000-4000-8000-000000000001.jsonl")
	files := map[string][]byte{
		filepath.Join(home, ".claude.json"):                       []byte(`{"numStartups":1}`),
		filepath.Join(home, "policy-limits.json"):                 []byte(`{}`),
		filepath.Join(home, "remote-settings.json"):               []byte(`{}`),
		filepath.Join(home, "sessions", "1.json"):                 []byte(`{}`),
		filepath.Join(home, "session-env", "env"):                 []byte(""),
		filepath.Join(home, "shell-snapshots", "snapshot-zsh.sh"): []byte(""),
		filepath.Join(home, "backups", ".claude.json.backup"):     []byte(`{}`),
		filepath.Join(home, "debug", "latest"):                    []byte(""),
		transcript:                                                body,
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
	if len(sessions) != 1 || sessions[0] != transcript {
		t.Fatalf("session files in the Xcode home = %v, want only %s", sessions, transcript)
	}
	n := 0
	for _, r := range a.WatchPaths() {
		if adapter.UnderAnyWatchRoot(transcript, []string{r}) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the transcript is under %d watch roots (%v), want 1", n, a.WatchPaths())
	}

	res, err := a.ParseSessionFile(context.Background(), transcript, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceIDE || res.SessionSurfaces[0].SurfaceHost != "xcode" {
		t.Errorf("surfaces = %+v, want one ide/xcode", res.SessionSurfaces)
	}

	outside := filepath.Join(t.TempDir(), "projects")
	elsewhere := filepath.Join(outside, "-Users-u-App", filepath.Base(transcript))
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
	got, want := projectRoots(res.ToolEvents), projectRoots(ref.ToolEvents)
	if len(got) == 0 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("project roots in the Xcode home = %v, want the cwd's %v", got, want)
	}
	for _, p := range got {
		if strings.Contains(p, "ClaudeAgentConfig") {
			t.Errorf("project root %q comes from the Xcode home, not the cwd", p)
		}
	}
}

// projectRoots lists the distinct project roots of evs in first-seen order.
func projectRoots(evs []models.ToolEvent) []string {
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
