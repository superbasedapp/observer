package secimage

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// symlinkOrSkip makes a symlink, skipping the test on a host that refuses
// (Windows without developer mode).
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
}

func readRoot(t *testing.T, src string) (Result, string, error) {
	t.Helper()
	run := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(run, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := NewDirSink(run)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := os.OpenRoot(src)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	res, err := ReadRoot(r.FS(), s, DefaultLimits())
	return res, run, err
}

func TestReadRootAllowListOnly(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"usr/lib/os-release":                debianOSRelease,
		"var/lib/dpkg/status":               dpkgStatus,
		"var/lib/dpkg/status.d/tzdata":      "Package: tzdata\n",
		"var/lib/dpkg/status.d/x.md5sums":   "x",
		"etc/passwd":                        "root:x:0:0",
		"home/dev/.ssh/id_ed25519":          "secret",
		"var/lib/dpkg/info/libc6.list":      "/lib",
		"usr/lib/sysimage/rpm/rpmdb.sqlite": "db",
	})
	res, run, err := readRoot(t, src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"etc/os-release", "usr/lib/os-release", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/dpkg/status", "var/lib/dpkg/status.d/tzdata"}
	if !slices.Equal(filesIn(t, run), want) {
		t.Fatalf("run directory %v, want %v", filesIn(t, run), want)
	}
	if !slices.Equal(res.Files, want) || !res.OSReleaseCopied || res.OSRelease["ID"] != "debian" || res.Format != "dir" {
		t.Fatalf("result %+v", res)
	}
}

func TestReadRootNeverFollowsLinks(t *testing.T) {
	src := t.TempDir()
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"rpmdb.sqlite": "host db", "status": dpkgStatus})
	writeTree(t, src, map[string]string{"usr/lib/os-release": debianOSRelease})
	symlinkOrSkip(t, filepath.Join(outside, "rpmdb.sqlite"), filepath.Join(src, "var", "lib", "rpm", "rpmdb.sqlite"))
	symlinkOrSkip(t, "../usr/lib/os-release", filepath.Join(src, "etc", "os-release"))
	// A symlinked parent directory: never read through.
	symlinkOrSkip(t, outside, filepath.Join(src, "var", "lib", "dpkg"))
	res, run, err := readRoot(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.RefusedWanted, []string{"var/lib/rpm/rpmdb.sqlite"}) {
		t.Errorf("RefusedWanted %v: a package database that is a link must be named", res.RefusedWanted)
	}
	for _, p := range filesIn(t, run) {
		if strings.HasPrefix(p, "var/") {
			t.Errorf("%s was read through a link", p)
		}
	}
	if !res.OSReleaseCopied || res.OSRelease["ID"] != "debian" {
		t.Errorf("a symlinked etc/os-release is replaced by usr/lib/os-release: %+v", res)
	}
}

func TestReadRootRefusesAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, _ := NewDirSink(t.TempDir())
	defer s.Close()
	if _, err := ReadRoot(os.DirFS(f), s, DefaultLimits()); ReasonOf(err) != ReasonNotADirectory {
		t.Fatalf("a file input: %v", err)
	}
}

func TestDirDigest(t *testing.T) {
	a, b := DirDigest("/a"), DirDigest("/b")
	if a == b || !strings.HasPrefix(a, "dir:") || len(a) != len("dir:")+64 {
		t.Fatalf("%q %q", a, b)
	}
}
