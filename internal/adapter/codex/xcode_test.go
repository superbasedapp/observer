package codex

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestXcodeSessionsRootIsDarwinOnly: the Xcode Codex home resolves from the
// catalogue on macOS only, and the Open Interpreter variant has none
// (FU-150).
func TestXcodeSessionsRootIsDarwinOnly(t *testing.T) {
	home := "/Users/u"
	want := filepath.ToSlash(filepath.Join(home, "Library", "Developer", "Xcode", "CodingAssistant", "codex", "sessions"))
	if got := filepath.ToSlash(hostSessionsRoot(xcodeHomeArtifact, "darwin", home)); got != want {
		t.Errorf("darwin root = %q, want %q", got, want)
	}
	for _, goos := range []string{"linux", "windows"} {
		if got := hostSessionsRoot(xcodeHomeArtifact, goos, home); got != "" {
			t.Errorf("%s root = %q, want none", goos, got)
		}
	}
	if NewOpenInterpreter().hostHomeArtifact != "" {
		t.Error("the Open Interpreter variant watches the Xcode Codex home")
	}
}

// TestXcodeRolloutsAreWatchedAndStampedByPlace: a rollout under the Xcode
// Codex home is watched (CODEX_HOME set or not) and stamped ide/xcode
// whatever its originator says; one elsewhere keeps its originator stamp.
func TestXcodeRolloutsAreWatchedAndStampedByPlace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "codex", "sessions")
	a := New()
	a.xcodeRootFn = func() string { return root }
	a.getenv = func(k string) string {
		if k == "CODEX_HOME" {
			return filepath.Join(t.TempDir(), "elsewhere")
		}
		return ""
	}
	if !slices.Contains(a.WatchPaths(), root) {
		t.Fatalf("WatchPaths = %v, want the Xcode root", a.WatchPaths())
	}
	path := filepath.Join(root, "2026", "10", "28", "rollout-x.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(sessionMetaLine("sx", "codex_cli_rs", "cli")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !a.IsSessionFile(path) {
		t.Fatal("the Xcode rollout is not a session file")
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceIDE || res.SessionSurfaces[0].SurfaceHost != "xcode" {
		t.Errorf("surfaces = %+v, want one ide/xcode", res.SessionSurfaces)
	}
	otherDir := t.TempDir()
	other := filepath.Join(otherDir, "rollout-y.jsonl")
	if err := os.WriteFile(other, []byte(sessionMetaLine("sy", "codex_cli_rs", "cli")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := NewWithOptions(nil, otherDir)
	b.xcodeRootFn = func() string { return root }
	res, err = b.ParseSessionFile(context.Background(), other, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].SurfaceHost != "codex-cli" {
		t.Errorf("a rollout outside the Xcode home = %+v, want its codex-cli stamp", res.SessionSurfaces)
	}
}

// TestXcodeAutosaveCwdStillStampsXcode: with no project open Xcode runs its
// Codex with cwd ~/Library/Autosave Information (Mac round 5b); such a
// rollout parses and is stamped ide/xcode like any other in the home.
func TestXcodeAutosaveCwdStillStampsXcode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "codex", "sessions")
	a := New()
	a.xcodeRootFn = func() string { return root }
	path := filepath.Join(root, "2026", "10", "28", "rollout-auto.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	line := strings.Replace(sessionMetaLine("sa", "codex_cli_rs", "cli"), `"cwd":"/w"`, `"cwd":"/Users/u/Library/Autosave Information"`, 1)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceIDE || res.SessionSurfaces[0].SurfaceHost != "xcode" {
		t.Errorf("surfaces = %+v, want one ide/xcode", res.SessionSurfaces)
	}
}
