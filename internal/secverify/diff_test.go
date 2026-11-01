package secverify

import (
	"errors"
	"strings"
	"testing"
)

func ns(pairs ...string) []byte {
	return []byte(strings.Join(pairs, "\x00") + "\x00")
}

func TestParseDiff(t *testing.T) {
	patch := strings.Join([]string{
		"diff --git a/app/main.go b/app/main.go",
		"index 1111111..2222222 100644",
		"--- a/app/main.go",
		"+++ b/app/main.go",
		"@@ -3,0 +4,2 @@ func main() {",
		"+	a := 1",
		"+	b := 2",
		"@@ -10 +12 @@",
		"-old",
		"+new",
		`\ No newline at end of file`,
		"diff --git a/new file.txt b/new file.txt",
		"new file mode 100644",
		"--- /dev/null",
		"+++ b/new file.txt",
		"@@ -0,0 +1 @@",
		"+hello",
		"diff --git a/img.png b/img.png",
		"new file mode 100644",
		"Binary files /dev/null and b/img.png differ",
		`diff --git "a/caf\303\251.txt" "b/caf\303\251.txt"`,
		"--- a/x",
		"+++ b/x",
		"@@ -1 +1 @@",
		"+accent",
		"diff --git a/gone.txt b/gone.txt",
		"deleted file mode 100644",
		"--- a/gone.txt",
		"+++ /dev/null",
		"@@ -1 +0,0 @@",
		"-bye",
	}, "\n") + "\n"
	files, err := ParseDiff(ns("M", "app/main.go", "A", "new file.txt", "A", "img.png", "M", "café.txt", "D", "gone.txt"), []byte(patch), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ChangedFile{}
	for _, f := range files {
		got[f.Path] = f
	}
	main := got["app/main.go"]
	if len(main.Added) != 3 || main.Added[0].N != 4 || main.Added[1].N != 5 || main.Added[2].N != 12 || main.Added[2].Text != "new" {
		t.Errorf("app/main.go added = %+v", main.Added)
	}
	if nf := got["new file.txt"]; nf.Status != StatusAdded || len(nf.Added) != 1 || nf.Added[0].Text != "hello" {
		t.Errorf("new file.txt = %+v", nf)
	}
	if !got["img.png"].Binary {
		t.Error("img.png not binary")
	}
	if c := got["café.txt"]; len(c.Added) != 1 || c.Added[0].Text != "accent" {
		t.Errorf("quoted path = %+v", c)
	}
	if g := got["gone.txt"]; g.Status != StatusDeleted || len(g.Added) != 0 {
		t.Errorf("gone.txt = %+v", g)
	}
	if files[0].Path != "app/main.go" {
		t.Errorf("not sorted: %v", files[0].Path)
	}
}

func TestParseDiffCaps(t *testing.T) {
	patch := "diff --git a/f b/f\n@@ -0,0 +1,3 @@\n+" + strings.Repeat("x", 20) + "\n+yy\n+zz\n"
	files, err := ParseDiff(ns("A", "f"), []byte(patch), Limits{MaxFiles: 10, MaxFileAddedBytes: 11, MaxLineBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	f := files[0]
	if !f.Partial || len(f.Added) != 1 || f.Added[0].Text != strings.Repeat("x", 10) {
		t.Errorf("cap: %+v", f)
	}
	if _, err := ParseDiff(ns("A", "a", "A", "b"), nil, Limits{MaxFiles: 1}); err == nil {
		t.Error("file cap not enforced")
	}
}

func TestParseDiffRefusals(t *testing.T) {
	cases := []struct {
		name       string
		nameStatus []byte
		patch      string
	}{
		{"odd fields", []byte("A\x00a\x00M\x00"), ""},
		{"rename status", ns("R100", "a"), ""},
		{"unknown status", ns("X", "a"), ""},
		{"duplicate", ns("A", "a", "M", "a"), ""},
		{"absolute path", ns("A", "/etc/passwd"), ""},
		{"dotdot", ns("A", "a/../b"), ""},
		{"control char", ns("A", "a\nb"), ""},
		{"patch file not listed", ns("A", "a"), "diff --git a/b b/b\n"},
		{"header sides differ", ns("A", "a"), "diff --git a/a b/c\n"},
		{"bad hunk", ns("A", "a"), "diff --git a/a b/a\n@@ nonsense\n"},
		{"unterminated quote", ns("A", "a"), "diff --git \"a/a\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseDiff(c.nameStatus, []byte(c.patch), DefaultLimits()); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := ParseDiff(ns("A", "a"), []byte("diff --git a/b b/b\n"), DefaultLimits()); !errors.Is(err, ErrInconsistentDiff) {
		t.Errorf("err = %v, want ErrInconsistentDiff", err)
	}
}

func TestAddedBlocks(t *testing.T) {
	got := addedBlocks([]AddedLine{{1, "a"}, {2, "b"}, {5, "c"}})
	if len(got) != 2 || got[0].first != 1 || got[0].text != "a\nb" || got[1].first != 5 || got[1].text != "c" {
		t.Errorf("blocks = %+v", got)
	}
	if addedBlocks(nil) != nil {
		t.Error("nil input gave blocks")
	}
}

// TestRemovedLinesHaveTheirOwnCap (lane SEC-GATEFIX milestone 2j): a large
// deletion before the additions does not crowd the added lines out of
// their cap; past its own cap the removed text marks the file Partial.
func TestRemovedLinesHaveTheirOwnCap(t *testing.T) {
	patch := "diff --git a/f b/f\n@@ -1,2 +1,1 @@\n-" + strings.Repeat("r", 10) + "\n-" + strings.Repeat("s", 10) + "\n+added\n"
	files, err := ParseDiff(ns("M", "f"), []byte(patch), Limits{MaxFiles: 10, MaxFileAddedBytes: 10, MaxLineBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	f := files[0]
	if len(f.Added) != 1 || f.Added[0].Text != "added" {
		t.Fatalf("the removed text crowded out the added line: %+v", f)
	}
	if len(f.Removed) != 1 || !f.Partial {
		t.Fatalf("the removed cap: %+v", f)
	}
	files, _ = ParseDiff(ns("M", "f"), []byte(patch), Limits{MaxFiles: 10, MaxFileAddedBytes: 10, MaxFileRemovedBytes: 64, MaxLineBytes: 100})
	if f := files[0]; len(f.Removed) != 2 || f.Partial {
		t.Fatalf("a wider removed cap: %+v", f)
	}
}
