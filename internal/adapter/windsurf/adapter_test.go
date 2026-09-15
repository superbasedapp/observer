package windsurf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// withFakeHomes swaps the crossmount seam for the duration of a test so root
// composition is asserted against fabricated homes, never the host's real
// $HOME (which on a developer box may or may not have a Windsurf install).
func withFakeHomes(t *testing.T, homes ...crossmount.HomeRoot) {
	t.Helper()
	prev := allHomesFunc
	allHomesFunc = func() []crossmount.HomeRoot { return homes }
	t.Cleanup(func() { allHomesFunc = prev })
}

func TestName(t *testing.T) {
	if got := New().Name(); got != "windsurf" {
		t.Errorf("Name() = %q, want %q", got, "windsurf")
	}
	if ToolName != "windsurf" {
		t.Errorf("ToolName = %q, want %q", ToolName, "windsurf")
	}
}

// TestDefaultRootsComposition pins the two declared shapes per home: the
// three `.codeium/<channel>/cascade` directory roots and the single Windsurf
// `state.vscdb` FILE root — and pins that no OTHER vscodehost product
// contributes a root.
func TestDefaultRootsComposition(t *testing.T) {
	linuxHome := filepath.Join("/fake", "linuxhome")
	winHome := filepath.Join("/fake", "mnt", "c", "Users", "u")

	withFakeHomes(t,
		crossmount.HomeRoot{Path: linuxHome, OS: crossmount.OSLinux, Origin: "native"},
		crossmount.HomeRoot{Path: winHome, OS: crossmount.OSWindows, Origin: "wsl-mnt:u"},
	)

	got := defaultRoots()
	index := map[string]bool{}
	for _, r := range got {
		index[filepath.Clean(r)] = true
	}

	want := []string{
		filepath.Join(linuxHome, ".codeium", "windsurf", "cascade"),
		filepath.Join(linuxHome, ".codeium", "windsurf-insiders", "cascade"),
		filepath.Join(linuxHome, ".codeium", "windsurf-next", "cascade"),
		filepath.Join(linuxHome, ".config", "Windsurf", "User", "globalStorage", "state.vscdb"),
		filepath.Join(winHome, ".codeium", "windsurf", "cascade"),
		filepath.Join(winHome, ".codeium", "windsurf-insiders", "cascade"),
		filepath.Join(winHome, ".codeium", "windsurf-next", "cascade"),
		filepath.Join(winHome, "AppData", "Roaming", "Windsurf", "User", "globalStorage", "state.vscdb"),
	}
	for _, w := range want {
		if !index[filepath.Clean(w)] {
			t.Errorf("defaultRoots() missing %q\ngot: %v", w, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("defaultRoots() returned %d roots, want exactly %d: %v", len(got), len(want), got)
	}

	// No sibling VS Code-family product may contribute a root: this adapter
	// claims Windsurf's state database only.
	for _, r := range got {
		norm := strings.ToLower(filepath.ToSlash(r))
		for _, foreign := range []string{"/cursor/", "/code/", "/code - insiders/", "/vscodium/", "/kiro/", "/qoder/", "/trae/"} {
			if strings.Contains(norm, foreign) {
				t.Errorf("root %q belongs to a foreign product (%s); only Windsurf may be claimed", r, foreign)
			}
		}
	}
}

// TestDefaultRootsDedupAndEmptyHome pins that a repeated home contributes
// its roots once and an empty home path contributes none.
func TestDefaultRootsDedupAndEmptyHome(t *testing.T) {
	home := filepath.Join("/fake", "dup")
	withFakeHomes(t,
		crossmount.HomeRoot{Path: home, OS: crossmount.OSLinux, Origin: "native"},
		crossmount.HomeRoot{Path: home, OS: crossmount.OSLinux, Origin: "native"},
		crossmount.HomeRoot{Path: "", OS: crossmount.OSLinux, Origin: "native"},
	)
	if got := defaultRoots(); len(got) != 4 {
		t.Errorf("defaultRoots() = %v; want 4 deduplicated roots", got)
	}
}

// TestIsSessionFile is the shape matrix. Roots are injected (not discovered)
// so the table reads the same on every OS.
func TestIsSessionFile(t *testing.T) {
	base := t.TempDir()
	cascadeRoot := filepath.Join(base, ".codeium", "windsurf", "cascade")
	memoriesDir := filepath.Join(base, ".codeium", "windsurf", "memories")
	nestedDir := filepath.Join(cascadeRoot, "nested")
	windsurfStateDB := filepath.Join(base, "AppData", "Roaming", "Windsurf", "User", "globalStorage", "state.vscdb")
	cursorStateDB := filepath.Join(base, "AppData", "Roaming", "Cursor", "User", "globalStorage", "state.vscdb")

	for _, dir := range []string{cascadeRoot, memoriesDir, nestedDir, filepath.Dir(windsurfStateDB), filepath.Dir(cursorStateDB)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	// A real directory sitting directly under the cascade root must not be
	// claimed as a session file, which is why these paths are materialised.
	childDir := filepath.Join(cascadeRoot, "childdir")
	if err := os.MkdirAll(childDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", childDir, err)
	}
	files := []string{
		filepath.Join(cascadeRoot, "abc123"),
		filepath.Join(cascadeRoot, "abc123.json"),
		filepath.Join(cascadeRoot, "trajectory.pb"),
		filepath.Join(nestedDir, "deep.json"),
		filepath.Join(memoriesDir, "mem1.md"),
		windsurfStateDB,
		windsurfStateDB + "-wal",
		windsurfStateDB + "-shm",
		cursorStateDB,
		filepath.Join(base, "elsewhere.json"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	a := NewWithOptions(nil, cascadeRoot, windsurfStateDB)

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"cascade file, no extension", filepath.Join(cascadeRoot, "abc123"), true},
		{"cascade file, .json", filepath.Join(cascadeRoot, "abc123.json"), true},
		{"cascade file, .pb", filepath.Join(cascadeRoot, "trajectory.pb"), true},
		{"cascade root itself", cascadeRoot, false},
		{"directory directly under cascade root", childDir, false},
		{"file nested below cascade root", filepath.Join(nestedDir, "deep.json"), false},
		{"memories sibling dir", filepath.Join(memoriesDir, "mem1.md"), false},
		{"windsurf state.vscdb", windsurfStateDB, true},
		{"windsurf state.vscdb-wal sidecar", windsurfStateDB + "-wal", false},
		{"windsurf state.vscdb-shm sidecar", windsurfStateDB + "-shm", false},
		{"cursor state.vscdb", cursorStateDB, false},
		{"outside every root", filepath.Join(base, "elsewhere.json"), false},
		{"empty path", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.IsSessionFile(tc.path); got != tc.want {
				t.Errorf("IsSessionFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestParseSessionFileEmptyContract pins the skeleton contract: no error, no
// rows of any kind, exactly one Warning naming the fixture README, and a
// cursor at EOF so the watcher does not re-poll the same bytes forever.
func TestParseSessionFileEmptyContract(t *testing.T) {
	base := t.TempDir()
	cascadeRoot := filepath.Join(base, ".codeium", "windsurf", "cascade")
	if err := os.MkdirAll(cascadeRoot, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := []byte("some ungrounded cascade bytes\n")
	path := filepath.Join(cascadeRoot, "session-1")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	a := NewWithOptions(nil, cascadeRoot)
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 {
		t.Errorf("skeleton emitted rows: %d tool events, %d token events", len(res.ToolEvents), len(res.TokenEvents))
	}
	if len(res.CacheObservations) != 0 || len(res.SessionSurfaces) != 0 || len(res.SessionLineages) != 0 {
		t.Errorf("skeleton emitted side-channel rows: %+v", res)
	}
	if res.RetrySuggested {
		t.Error("skeleton must not ask the watcher to retry")
	}
	if want := int64(len(body)); res.NewOffset != want {
		t.Errorf("NewOffset = %d, want file size %d", res.NewOffset, want)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("Warnings = %v, want exactly one", res.Warnings)
	}
	if res.Warnings[0] != ungroundedWarning {
		t.Errorf("Warnings[0] = %q, want %q", res.Warnings[0], ungroundedWarning)
	}
	if !strings.Contains(res.Warnings[0], "testdata/windsurf/README.md") {
		t.Errorf("warning must name the fixture README, got %q", res.Warnings[0])
	}

	// A cursor already at EOF never moves backwards.
	res2, err := a.ParseSessionFile(context.Background(), path, int64(len(body)))
	if err != nil {
		t.Fatalf("ParseSessionFile (resume): %v", err)
	}
	if res2.NewOffset != int64(len(body)) {
		t.Errorf("resume NewOffset = %d, want %d", res2.NewOffset, len(body))
	}

	// A cursor beyond EOF (truncated / replaced file) is held, not rewound.
	res3, err := a.ParseSessionFile(context.Background(), path, 9999)
	if err != nil {
		t.Fatalf("ParseSessionFile (truncated): %v", err)
	}
	if res3.NewOffset != 9999 {
		t.Errorf("truncated NewOffset = %d, want the cursor held at 9999", res3.NewOffset)
	}
}

// TestParseSessionFileMissingFile pins the error-wrapping contract.
func TestParseSessionFileMissingFile(t *testing.T) {
	a := NewWithOptions(nil, t.TempDir())
	_, err := a.ParseSessionFile(context.Background(), filepath.Join(t.TempDir(), "absent"), 0)
	if err == nil {
		t.Fatal("ParseSessionFile on a missing file: want error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "windsurf.ParseSessionFile: ") {
		t.Errorf("error not wrapped with the package/function prefix: %v", err)
	}
}

// TestParseSessionFileCancelledContext pins that the context parameter is
// honoured rather than decorative.
func TestParseSessionFileCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := NewWithOptions(nil, t.TempDir())
	res, err := a.ParseSessionFile(ctx, filepath.Join(t.TempDir(), "whatever"), 7)
	if err == nil {
		t.Fatal("want a context error, got nil")
	}
	if res.NewOffset != 7 {
		t.Errorf("NewOffset = %d, want the incoming cursor 7 held", res.NewOffset)
	}
}
