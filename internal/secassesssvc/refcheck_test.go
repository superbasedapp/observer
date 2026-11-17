package secassesssvc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

func writeProjectFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newChecker(t *testing.T, root string, deadline time.Time, now func() time.Time) *RefChecker {
	t.Helper()
	c, err := NewRefChecker(root, deadline, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// TestSplitLines: one row per shape of file the checker is handed.
func TestSplitLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"one line with a newline", "a\n", []string{"a"}},
		{"one line without", "a", []string{"a"}},
		{"two lines", "a\nb\n", []string{"a", "b"}},
		{"CRLF", "a\r\nb\r\n", []string{"a", "b"}},
		{"a blank line is a line", "a\n\nb", []string{"a", "", "b"}},
		{"only a newline is one empty line", "\n", []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitLines([]byte(tc.in))
			if strings.Join(got, "|") != strings.Join(tc.want, "|") || len(got) != len(tc.want) {
				t.Fatalf("lines = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRefCheckerLines(t *testing.T) {
	root := t.TempDir()
	writeProjectFile(t, root, "cmd/api/main.go", "one\ntwo\nthree\nfour\n")
	writeProjectFile(t, root, "empty.txt", "")
	if err := os.MkdirAll(filepath.Join(root, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := newChecker(t, root, time.Time{}, nil)
	t.Run("a range inside the file", func(t *testing.T) {
		ls, total, st := c.Lines("cmd/api/main.go", 2, 3)
		if st != secassess.LookupOK || total != 4 || strings.Join(ls, ",") != "two,three" {
			t.Fatalf("%q %d %v", ls, total, st)
		}
	})
	t.Run("a range past the end is clipped", func(t *testing.T) {
		ls, total, st := c.Lines("cmd/api/main.go", 3, 99)
		if st != secassess.LookupOK || total != 4 || strings.Join(ls, ",") != "three,four" {
			t.Fatalf("%q %d %v", ls, total, st)
		}
	})
	t.Run("a start past the end gives no lines and the total", func(t *testing.T) {
		ls, total, st := c.Lines("cmd/api/main.go", 9, 12)
		if st != secassess.LookupOK || total != 4 || len(ls) != 0 {
			t.Fatalf("%q %d %v", ls, total, st)
		}
	})
	t.Run("an empty file has no lines", func(t *testing.T) {
		if _, total, st := c.Lines("empty.txt", 1, 1); st != secassess.LookupOK || total != 0 {
			t.Fatalf("total %d %v", total, st)
		}
	})
	for _, rel := range []string{"nope.go", "adir", "../outside.go", "cmd/../../x"} {
		if _, _, st := c.Lines(rel, 1, 1); st != secassess.LookupMissing {
			t.Errorf("%q: status %v, want missing", rel, st)
		}
	}
}

// TestRefCheckerSymlinks: a link in the project never reads: the final component
// is refused, and a link that leaves the project cannot be followed.
func TestRefCheckerSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeProjectFile(t, root, "real.go", "secret-free\n")
	writeProjectFile(t, outside, "host.txt", "a file outside the project\n")
	if err := os.Symlink(filepath.Join(root, "real.go"), filepath.Join(root, "link.go")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	c := newChecker(t, root, time.Time{}, nil)
	if _, _, st := c.Lines("real.go", 1, 1); st != secassess.LookupOK {
		t.Fatalf("the real file: %v", st)
	}
	if _, _, st := c.Lines("link.go", 1, 1); st != secassess.LookupMissing {
		t.Errorf("a link to a file in the project: %v", st)
	}
	if _, _, st := c.Lines("escape/host.txt", 1, 1); st != secassess.LookupMissing {
		t.Errorf("a path through a link that leaves the project: %v", st)
	}
}

func TestRefCheckerBudget(t *testing.T) {
	t.Run("the file past the default budget (500 distinct files) is unchecked and the first 500 are read", func(t *testing.T) {
		if maxRefFiles != 500 || maxRefTotalBytes != 128<<20 || RefDeadline != 10*time.Second {
			t.Fatalf("the defaults are %d files, %d bytes, %v", maxRefFiles, int64(maxRefTotalBytes), RefDeadline)
		}
		root := t.TempDir()
		for i := 0; i < maxRefFiles+5; i++ {
			writeProjectFile(t, root, fmt.Sprintf("f/%03d.txt", i), "x\n")
		}
		c := newChecker(t, root, time.Time{}, nil)
		for i := 0; i < maxRefFiles+5; i++ {
			_, _, st := c.Lines(fmt.Sprintf("f/%03d.txt", i), 1, 1)
			want := secassess.LookupOK
			if i >= maxRefFiles {
				want = secassess.LookupBudget
			}
			if st != want {
				t.Fatalf("file %d: %v, want %v", i, st, want)
			}
		}
		// A file already read stays readable after the budget is gone.
		if _, _, st := c.Lines("f/000.txt", 1, 1); st != secassess.LookupOK {
			t.Errorf("a file read earlier: %v", st)
		}
		if n := len(c.Files()); n != maxRefFiles {
			t.Errorf("%d stamps, want %d", n, maxRefFiles)
		}
	})
	t.Run("a file over its own cap is unchecked, never missing or found", func(t *testing.T) {
		root := t.TempDir()
		writeProjectFile(t, root, "big.txt", strings.Repeat("x", maxRefFileBytes+1))
		c := newChecker(t, root, time.Time{}, nil)
		if _, _, st := c.Lines("big.txt", 1, 1); st != secassess.LookupBudget {
			t.Fatalf("status %v", st)
		}
	})
	t.Run("the deadline ends the walk", func(t *testing.T) {
		root := t.TempDir()
		writeProjectFile(t, root, "a.txt", "x\n")
		writeProjectFile(t, root, "b.txt", "x\n")
		now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
		clock := now
		c := newChecker(t, root, now.Add(time.Second), func() time.Time { return clock })
		if _, _, st := c.Lines("a.txt", 1, 1); st != secassess.LookupOK {
			t.Fatalf("before the deadline: %v", st)
		}
		clock = now.Add(2 * time.Second)
		if _, _, st := c.Lines("b.txt", 1, 1); st != secassess.LookupBudget {
			t.Fatalf("after the deadline: %v", st)
		}
	})
}

func TestRefCheckerStampsAndDrift(t *testing.T) {
	root := t.TempDir()
	writeProjectFile(t, root, "a.go", "alpha\nbeta\n")
	writeProjectFile(t, root, "b.go", "gamma\n")
	c := newChecker(t, root, time.Time{}, nil)
	c.Lines("a.go", 1, 1)
	c.Lines("b.go", 1, 1)
	c.Lines("gone.go", 1, 1)
	stamps := c.Files()
	if len(stamps) != 2 || stamps[0].Path != "a.go" || stamps[0].Lines != 2 || stamps[1].Path != "b.go" || len(stamps[0].SHA) != 16 {
		t.Fatalf("stamps = %+v", stamps)
	}
	if d, err := StampsDrift(root, stamps); err != nil || len(d) != 0 {
		t.Fatalf("unchanged: %v %v", d, err)
	}
	writeProjectFile(t, root, "a.go", "alpha\nbeta changed\n")
	if err := os.Remove(filepath.Join(root, "b.go")); err != nil {
		t.Fatal(err)
	}
	d, err := StampsDrift(root, stamps)
	if err != nil || strings.Join(d, ",") != "a.go,b.go" {
		t.Fatalf("changed and gone: %v %v", d, err)
	}
	// A project that is gone drifts everything; no stamps drift nothing.
	if d, err := StampsDrift(filepath.Join(root, "missing"), stamps); err != nil || len(d) != 2 {
		t.Fatalf("a missing project: %v %v", d, err)
	}
	if d, err := StampsDrift(root, nil); err != nil || d != nil {
		t.Fatalf("no stamps: %v %v", d, err)
	}
}
