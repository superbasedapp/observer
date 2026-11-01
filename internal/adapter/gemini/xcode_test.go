package gemini

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestXcodeChatsRootIsDarwinOnly: the Xcode Gemini home resolves from the
// catalogue on macOS only (FU-160).
func TestXcodeChatsRootIsDarwinOnly(t *testing.T) {
	home := "/Users/u"
	want := filepath.ToSlash(filepath.Join(home, "Library", "Developer", "Xcode", "CodingAssistant", "gemini", ".gemini", "tmp"))
	if got := filepath.ToSlash(xcodeChatsRoot("darwin", home)); got != want {
		t.Errorf("darwin root = %q, want %q", got, want)
	}
	for _, goos := range []string{"linux", "windows"} {
		if got := xcodeChatsRoot(goos, home); got != "" {
			t.Errorf("%s root = %q, want none", goos, got)
		}
	}
}

// writeTree writes files (path -> body) under their directories.
func writeTree(t *testing.T, files map[string][]byte) {
	t.Helper()
	for p, b := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestXcodeHomeFixtureIngestsTheChatOnce (FU-160): in a fixture Xcode Gemini
// home holding the files Mac round 5b listed, exactly one file is a session
// file (the chat under tmp/<project>/chats), it sits under exactly one watch
// root, it is stamped ide/xcode, and its project is the one the CLI recorded
// in that home (the tmp/<project>/.project_root sidecar it writes for the
// cwd), not one a ~/.gemini beside it records for the same project key. The
// same chat outside the Xcode home keeps no stamp.
func TestXcodeHomeFixtureIngestsTheChatOnce(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "gemini", "session-live-toolcalls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	const key = "superbasedtest"
	base := t.TempDir()
	home := filepath.Join(base, "CodingAssistant", "gemini", ".gemini")
	root := filepath.Join(home, "tmp")
	project := filepath.Join(base, "superbasedtest")
	decoy := filepath.Join(base, "decoy")
	native := filepath.Join(base, "user", ".gemini")
	chat := filepath.Join(root, key, "chats", "session-2026-10-28T17-50-00000001.jsonl")
	writeTree(t, map[string][]byte{
		filepath.Join(home, "settings.json"):                 []byte(`{}`),
		filepath.Join(home, "GEMINI.md"):                     []byte("# notes"),
		filepath.Join(home, "projects.json"):                 []byte(`{"projects":{"` + project + `":"` + key + `"}}`),
		filepath.Join(home, "history", key, ".project_root"): []byte(project),
		filepath.Join(root, key, ".project_root"):            []byte(project + "\n"),
		filepath.Join(root, key, "logs.json"):                []byte(`[]`),
		filepath.Join(root, key, "checkpoints", "cp-1.json"): []byte(`{}`),
		filepath.Join(project, "README"):                     []byte(""),
		filepath.Join(decoy, "README"):                       []byte(""),
		filepath.Join(native, "tmp", key, ".project_root"):   []byte(decoy + "\n"),
		filepath.Join(native, "projects.json"):               []byte(`{"projects":{"` + decoy + `":"` + key + `"}}`),
		chat:                                                 body,
	})
	a := NewWithOptions(nil, filepath.Join(native, "tmp"))
	a.xcodeRootFn = func() string { return root }
	if !slices.Contains(a.WatchPaths(), root) {
		t.Fatalf("WatchPaths = %v, want the Xcode root", a.WatchPaths())
	}

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
	if len(sessions) != 1 || sessions[0] != chat {
		t.Fatalf("session files in the Xcode home = %v, want only %s", sessions, chat)
	}
	n := 0
	for _, r := range a.WatchPaths() {
		if adapter.UnderAnyWatchRoot(chat, []string{r}) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the chat is under %d watch roots (%v), want 1", n, a.WatchPaths())
	}

	res, err := a.ParseSessionFile(context.Background(), chat, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ToolEvents) == 0 {
		t.Fatal("the chat parsed to no events")
	}
	if len(res.SessionSurfaces) != 1 || res.SessionSurfaces[0].Surface != models.SurfaceIDE || res.SessionSurfaces[0].SurfaceHost != "xcode" ||
		res.SessionSurfaces[0].SessionID != res.ToolEvents[0].SessionID {
		t.Errorf("surfaces = %+v, want one ide/xcode for session %q", res.SessionSurfaces, res.ToolEvents[0].SessionID)
	}
	for _, e := range res.ToolEvents {
		if e.ProjectRoot != project {
			t.Errorf("event %s project = %q, want the recorded cwd %q", e.SourceEventID, e.ProjectRoot, project)
			break
		}
	}

	// The same chat in a plain ~/.gemini: no Xcode stamp.
	other := filepath.Join(native, "tmp", key, "chats", filepath.Base(chat))
	writeTree(t, map[string][]byte{other: body})
	ref, err := a.ParseSessionFile(context.Background(), other, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ref.SessionSurfaces) != 0 {
		t.Errorf("a chat outside the Xcode home = %+v, want no stamp", ref.SessionSurfaces)
	}
}

// TestXcodeStampNeedsAnEvent: a chunk that carries no event (a resumed
// parse with nothing new) stamps nothing.
func TestXcodeStampNeedsAnEvent(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".gemini", "tmp")
	a := NewWithOptions(nil, t.TempDir())
	a.xcodeRootFn = func() string { return root }
	var res adapter.ParseResult
	a.stampHostedSurface(filepath.Join(root, "k", "chats", "session-1.jsonl"), &res)
	if len(res.SessionSurfaces) != 0 {
		t.Errorf("surfaces = %+v, want none", res.SessionSurfaces)
	}
}
