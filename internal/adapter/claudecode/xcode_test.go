package claudecode

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestXcodeProjectsRootIsDarwinOnly: the Xcode Claude Agent home resolves
// from the catalogue on macOS only (FU-150).
func TestXcodeProjectsRootIsDarwinOnly(t *testing.T) {
	home := "/Users/u"
	want := filepath.ToSlash(filepath.Join(home, "Library", "Developer", "Xcode", "CodingAssistant", "ClaudeAgentConfig", "projects"))
	if got := filepath.ToSlash(xcodeProjectsRoot("darwin", home)); got != want {
		t.Errorf("darwin root = %q, want %q", got, want)
	}
	for _, goos := range []string{"linux", "windows"} {
		if got := xcodeProjectsRoot(goos, home); got != "" {
			t.Errorf("%s root = %q, want none", goos, got)
		}
	}
}

// TestXcodeTranscriptsAreWatchedAndStampedByPlace: a transcript under the
// Xcode home is watched and stamped ide/xcode whatever its entrypoint says
// (or when it says nothing); one under ~/.claude keeps its entrypoint
// stamp.
func TestXcodeTranscriptsAreWatchedAndStampedByPlace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ClaudeAgentConfig", "projects")
	a := New()
	a.xcodeRootFn = func() string { return root }
	if !slices.Contains(a.WatchPaths(), root) {
		t.Fatalf("WatchPaths = %v, want the Xcode root", a.WatchPaths())
	}
	for _, tc := range []struct {
		name, entrypoint string
	}{{"cli entrypoint", "cli"}, {"no entrypoint", ""}, {"unknown entrypoint", "xcode-something"}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, "-Users-u-App", "s1.jsonl")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(userLine("s1", "m1", tc.entrypoint)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !a.IsSessionFile(path) {
				t.Fatal("the Xcode transcript is not a session file")
			}
			res, err := a.ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceIDE || res.SessionSurfaces[0].SurfaceHost != "xcode" {
				t.Errorf("surfaces = %+v, want one ide/xcode", res.SessionSurfaces)
			}
		})
	}
	other := filepath.Join(t.TempDir(), "s2.jsonl")
	if err := os.WriteFile(other, []byte(userLine("s2", "m1", "cli")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := a.ParseSessionFile(context.Background(), other, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceCLI {
		t.Errorf("a transcript outside the Xcode home = %+v, want its cli stamp", res.SessionSurfaces)
	}
}

// TestXcodeAutosaveCwdStillStampsXcode: with no project open Xcode runs its
// Claude Agent with cwd ~/Library/Autosave Information, so the transcript
// lands under the -Users-<user>-Library-Autosave-Information slug (Mac
// round 5b); it parses and is stamped ide/xcode like any other.
func TestXcodeAutosaveCwdStillStampsXcode(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ClaudeAgentConfig", "projects")
	a := New()
	a.xcodeRootFn = func() string { return root }
	path := filepath.Join(root, "-Users-u-Library-Autosave-Information", "s3.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	line := strings.Replace(userLine("s3", "m1", "cli"), `"cwd":"/tmp/w"`, `"cwd":"/Users/u/Library/Autosave Information"`, 1)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !a.IsSessionFile(path) {
		t.Fatal("the Autosave transcript is not a session file")
	}
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceIDE || res.SessionSurfaces[0].SurfaceHost != "xcode" {
		t.Errorf("surfaces = %+v, want one ide/xcode", res.SessionSurfaces)
	}
}
