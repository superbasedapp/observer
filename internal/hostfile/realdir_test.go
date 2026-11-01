package hostfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
)

// TestApplyRefusesALinkAtAMiddleComponent (FU-198): a link anywhere below
// the trusted anchor is refused, not only one at the file's own directory:
// root/link -> outside, edit root/link/sub/settings.json. The link target
// is untouched, and a missing middle component is still ErrNoHostDir.
func TestApplyRefusesALinkAtAMiddleComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "sub", "settings.json"), "{}\n")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "link", "sub", "settings.json")
	if _, err := Apply(Edit{Path: path, Format: cfgfmt.FormatJSONC, Member: []string{"a"}, Value: "b"}); !errors.Is(err, ErrLink) {
		t.Errorf("middle link: Apply err = %v, want ErrLink", err)
	}
	if _, _, err := Value(path, cfgfmt.FormatJSONC, []string{"a"}); !errors.Is(err, ErrLink) {
		t.Errorf("middle link: Value err = %v, want ErrLink", err)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "sub", "settings.json")); string(b) != "{}\n" {
		t.Errorf("link target changed: %q", b)
	}
	missing := filepath.Join(root, "absent", "sub", "settings.json")
	if _, err := Apply(Edit{Path: missing, Format: cfgfmt.FormatJSONC, Member: []string{"a"}, Value: "b"}); !errors.Is(err, ErrNoHostDir) {
		t.Errorf("missing middle dir: err = %v, want ErrNoHostDir", err)
	}
	real := filepath.Join(root, "real", "sub")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(Edit{Path: filepath.Join(real, "settings.json"), Format: cfgfmt.FormatJSONC, Member: []string{"a"}, Value: "b"}); err != nil {
		t.Errorf("a real chain: err = %v", err)
	}
}

// TestRealDirTrustsOnlyItsAnchor: a link ABOVE the anchor (the system
// layout, macOS /var -> /private/var) is not judged; one at or below it is.
func TestRealDirTrustsOnlyItsAnchor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	realHome := filepath.Join(base, "real-home")
	if err := os.MkdirAll(filepath.Join(realHome, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	linkedHome := filepath.Join(base, "home")
	if err := os.Symlink(realHome, linkedHome); err != nil {
		t.Fatal(err)
	}
	prev := anchorRoots
	t.Cleanup(func() { anchorRoots = prev })

	anchorRoots = func() []string { return []string{linkedHome} }
	if err := realDir(filepath.Join(linkedHome, "app")); err != nil {
		t.Errorf("below a linked anchor: %v, want trusted", err)
	}
	anchorRoots = func() []string { return []string{base} }
	if err := realDir(filepath.Join(linkedHome, "app")); !errors.Is(err, ErrLink) {
		t.Errorf("a link below the anchor: %v, want ErrLink", err)
	}
}

func TestDirChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	for _, tc := range []struct {
		dir, anchor string
		want        []string
	}{
		{"/h/u/a/b", "/h/u", []string{"/h/u/a", "/h/u/a/b"}},
		{"/a/b", "", []string{"/a", "/a/b"}},
	} {
		got := dirChain(tc.dir, tc.anchor)
		if len(got) != len(tc.want) {
			t.Fatalf("dirChain(%q, %q) = %q", tc.dir, tc.anchor, got)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("dirChain(%q, %q) = %q, want %q", tc.dir, tc.anchor, got, tc.want)
			}
		}
	}
}
