package artifactfind

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// Synthetic headers (no real binary, no environment): the first bytes a
// header sniff reads, padded to the minimum file size.
var (
	elfFile   = &fstest.MapFile{Data: []byte("\x7fELF\x02\x01\x01\x00rest")}
	peFile    = &fstest.MapFile{Data: []byte("MZ\x90\x00\x03\x00\x00\x00rest")}
	machoFile = &fstest.MapFile{Data: []byte("\xcf\xfa\xed\xfe\x07\x00\x00\x01rest")}
	wasmFile  = &fstest.MapFile{Data: []byte("\x00asm\x01\x00\x00\x00rest")}
	zipFile   = &fstest.MapFile{Data: []byte("PK\x03\x04\x14\x00\x00\x00rest")}
	textFile  = &fstest.MapFile{Data: []byte("#!/bin/sh\necho hello\n")}
)

func find(t *testing.T, fsys fs.FS) map[string]Folder {
	t.Helper()
	got, err := Discover(fsys)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Folder{}
	for _, f := range got {
		out[f.Dir] = f
	}
	return out
}

// TestCandidateRules: one case per row of candidateRules (and the paths no
// row matches).
func TestCandidateRules(t *testing.T) {
	for _, tc := range []struct {
		rel  string
		rule string
	}{
		{"bin", "default list"},
		{"dist", "default list"},
		{"target/release", "default list"},
		{"target/debug", "cargo profile"},
		{"build", "build output name"},
		{"out", "build output name"},
		{"release", "build output name"},
		{"app/dist", "build output name"},
		{"services/bin", "build output name"},
		{"src", ""},
		{"target", ""},
		{"docs/build-notes", ""},
		{"binary", ""},
	} {
		got, ok := isCandidate(tc.rel)
		if got != tc.rule || ok != (tc.rule != "") {
			t.Errorf("%s: rule %q (%v), want %q", tc.rel, got, ok, tc.rule)
		}
	}
}

func TestDiscoverCountsByHeaderNotName(t *testing.T) {
	fsys := fstest.MapFS{
		"bin/app":                  elfFile,
		"bin/app.exe":              peFile,
		"bin/tool":                 machoFile,
		"bin/module":               wasmFile,
		"bin/notes.txt":            textFile,
		"bin/script.sh":            textFile,
		"bin/looks-like.exe":       textFile,
		"bin/lib/server.jar":       zipFile,
		"bin/lib/not-a-jar.jar":    textFile,
		"bin/wheel-1.0-py3.whl":    zipFile,
		"bin/archive.zip":          zipFile,
		"bin/tiny":                 &fstest.MapFile{Data: []byte("MZ")},
		"src/main.go":              textFile,
		"unrelated/app":            elfFile,
		"build/libs/app-1.0.jar":   zipFile,
		"node_modules/x/dist/a.js": textFile,
	}
	got := find(t, fsys)
	bin := got["bin"]
	want := map[string]int{KindELF: 1, KindPE: 1, KindMachO: 1, KindWasm: 1, KindJAR: 1, KindWheel: 1}
	for k, n := range want {
		if bin.Counts[k] != n {
			t.Errorf("bin %s: %d, want %d (%v)", k, bin.Counts[k], n, bin.Counts)
		}
	}
	if !bin.Default || bin.Total() != 6 {
		t.Errorf("bin = %+v", bin)
	}
	if b := got["build"]; b.Dir != "build" || b.Counts[KindJAR] != 1 || b.Default {
		t.Errorf("build = %+v", b)
	}
	if _, ok := got["unrelated"]; ok {
		t.Error("a folder no rule names is not a candidate")
	}
	if _, ok := got["node_modules/x/dist"]; ok {
		t.Error("a dependency tree is never looked into")
	}
	if s := bin.Summary(); !strings.Contains(s, "1 ELF executable") || !strings.Contains(s, "1 JAR") || !strings.Contains(s, "1 wheel or egg") {
		t.Errorf("summary %q", s)
	}
}

func TestDiscoverDefaultsAreShownEvenWhenEmpty(t *testing.T) {
	fsys := fstest.MapFS{
		"dist/readme.txt":    textFile,
		"out/readme.txt":     textFile,
		"app/build/note.txt": textFile,
	}
	got := find(t, fsys)
	d, ok := got["dist"]
	if !ok || !d.Default || d.Total() != 0 || d.Summary() != "no executables, JARs or wheels" {
		t.Errorf("an existing default folder with no artifacts is still offered: %+v %v", d, ok)
	}
	if _, ok := got["out"]; ok {
		t.Error("a non-default candidate with no artifact is not offered")
	}
	if _, ok := got["app/build"]; ok {
		t.Error("a non-default candidate with no artifact (one level down) is not offered")
	}
	if _, ok := got["bin"]; ok {
		t.Error("a default folder that does not exist is not offered")
	}
}

func TestDiscoverDepth(t *testing.T) {
	fsys := fstest.MapFS{
		"services/api/bin/app":    elfFile, // three levels down: not looked for
		"services/bin/app":        elfFile, // two levels down: found
		"target/release/app":      elfFile,
		"target/debug/app":        elfFile,
		"bin/deep/a/b/c/d/e/app":  elfFile, // too deep inside a candidate
		"bin/deep/ok/app":         elfFile,
		"vendor/bin/app":          elfFile,
		".git/hooks/dist/app":     elfFile,
		"node_modules/dist/a.exe": peFile,
	}
	got := find(t, fsys)
	for _, dir := range []string{"services/bin", "target/release", "target/debug", "bin"} {
		if _, ok := got[dir]; !ok {
			t.Errorf("%s not found: %v", dir, got)
		}
	}
	for _, dir := range []string{"services/api/bin", "vendor/bin", ".git/hooks/dist", "node_modules/dist"} {
		if _, ok := got[dir]; ok {
			t.Errorf("%s must not be offered", dir)
		}
	}
	if n := got["bin"].Counts[KindELF]; n != 1 {
		t.Errorf("bin sees only the file within MaxFolderDepth: %d", n)
	}
}

func TestDiscoverRefusesSymlinks(t *testing.T) {
	fsys := fstest.MapFS{
		"bin/real":     elfFile,
		"bin/link":     &fstest.MapFile{Data: []byte("../etc/passwd"), Mode: fs.ModeSymlink},
		"dist":         &fstest.MapFile{Data: []byte("/elsewhere"), Mode: fs.ModeSymlink},
		"build/a.jar":  zipFile,
		"out/real.jar": zipFile,
	}
	got := find(t, fsys)
	if b := got["bin"]; b.Counts[KindELF] != 1 || b.Skipped != 1 {
		t.Errorf("the link is skipped and counted: %+v", b)
	}
	if _, ok := got["dist"]; ok {
		t.Error("a symbolic link named dist is not a folder")
	}
	if o := got["out"]; o.Counts[KindJAR] != 1 {
		t.Errorf("out = %+v", o)
	}
}

func TestDiscoverBounds(t *testing.T) {
	fsys := fstest.MapFS{}
	for i := 0; i < MaxFilesPerFolder+50; i++ {
		fsys[fmt.Sprintf("bin/f%05d", i)] = elfFile
	}
	f := find(t, fsys)["bin"]
	if !f.Truncated || f.Total() > MaxFilesPerFolder || !strings.HasSuffix(f.Summary(), "or more") {
		t.Errorf("a bound ends the look and says so: total %d truncated %v summary %q", f.Total(), f.Truncated, f.Summary())
	}
}
