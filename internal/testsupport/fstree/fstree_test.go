package fstree

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteCreatesNestedFiles(t *testing.T) {
	root := Write(t, map[string]string{"a.txt": "one", "dir/sub/b.txt": "two"})
	for rel, want := range map[string]string{"a.txt": "one", "dir/sub/b.txt": "two"} {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
}

func TestWriteInKeepsExistingFiles(t *testing.T) {
	root := t.TempDir()
	WriteIn(t, root, map[string]string{"x": "1"})
	WriteIn(t, root, map[string]string{"y/z": "2"})
	for _, rel := range []string{"x", "y/z"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Errorf("%s: %v", rel, err)
		}
	}
}

func TestModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	cases := []struct {
		name          string
		write         func(testing.TB, map[string]string) string
		dirMode, file os.FileMode
	}{
		{"Write", Write, 0o755, 0o644},
		{"WritePrivate", WritePrivate, 0o700, 0o600},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := c.write(t, map[string]string{"d/f": "body"})
			d, err := os.Stat(filepath.Join(root, "d"))
			if err != nil {
				t.Fatal(err)
			}
			f, err := os.Stat(filepath.Join(root, "d", "f"))
			if err != nil {
				t.Fatal(err)
			}
			// The umask can only clear bits, so compare against the
			// requested mode with the umask's possible clears allowed.
			if got := d.Mode().Perm(); got&^c.dirMode != 0 {
				t.Errorf("dir mode %o has bits outside %o", got, c.dirMode)
			}
			if got := f.Mode().Perm(); got&^c.file != 0 {
				t.Errorf("file mode %o has bits outside %o", got, c.file)
			}
		})
	}
}
