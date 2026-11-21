package secimage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// smallLimits keeps the bomb tests cheap: a 1 MiB ratio floor.
func smallLimits() Limits {
	l := DefaultLimits()
	l.RatioFloor = 1 << 20
	l.MaxRatio = 20
	return l
}

func TestFlattenAdversarial(t *testing.T) {
	debianLayer := tarOf(t,
		dirent("./"), dirent("etc/"),
		sym("etc/os-release", "../usr/lib/os-release"),
		reg("usr/lib/os-release", debianOSRelease),
		reg("var/lib/dpkg/status", dpkgStatus),
		reg("usr/bin/bash", "not read"),
		reg("etc/passwd", "root:x:0:0"),
	)
	manyLayers := func(n int) [][]byte {
		var ls [][]byte
		for i := range n {
			ls = append(ls, tarOf(t, reg(fmt.Sprintf("var/lib/dpkg/status.d/p%d", i), "Package: p\n")))
		}
		return ls
	}
	truncated := gz(t, debianLayer)
	truncated = truncated[:len(truncated)/2]

	cases := []struct {
		name      string
		img       []byte
		lim       Limits
		reason    string // "" = success
		files     []string
		refusedW  []string
		refused   int
		copiedOS  bool
		osID      string
		removedWh int
	}{
		{
			name:     "debian, symlinked os-release, gzip layer",
			img:      dockerSave(t, [][]byte{gz(t, debianLayer)}),
			files:    []string{"etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status"},
			copiedOS: true, osID: "debian",
		},
		{
			name:  "alpine, regular os-release, uncompressed",
			img:   dockerSave(t, [][]byte{tarOf(t, reg("etc/os-release", alpineOSRelease), reg("lib/apk/db/installed", "P:musl\nV:1.2.5-r0\n\n"))}),
			files: []string{"etc/os-release", "lib/apk/db/installed"}, osID: "alpine",
		},
		{
			name:  "zstd layer",
			img:   dockerSave(t, [][]byte{zst(t, debianLayer)}),
			files: []string{"etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status"}, copiedOS: true, osID: "debian",
		},
		{
			name: "whiteout removes a lower status.d file",
			img: dockerSave(t, [][]byte{
				tarOf(t, reg("var/lib/dpkg/status.d/a", "Package: a\n"), reg("var/lib/dpkg/status.d/b", "Package: b\n"), reg("var/lib/dpkg/status.d/b.md5sums", "x")),
				gz(t, tarOf(t, reg("var/lib/dpkg/status.d/.wh.a", ""))),
			}),
			files: []string{"var/lib/dpkg/status.d/b"}, removedWh: 1,
		},
		{
			name: "opaque directory keeps only its own layer",
			img: dockerSave(t, [][]byte{
				tarOf(t, reg("var/lib/dpkg/status.d/a", "Package: a\n")),
				tarOf(t, reg("var/lib/dpkg/status.d/.wh..wh..opq", ""), reg("var/lib/dpkg/status.d/c", "Package: c\n")),
			}),
			files: []string{"var/lib/dpkg/status.d/c"}, removedWh: 1,
		},
		{
			name: "package database deleted in a later layer",
			img: dockerSave(t, [][]byte{
				tarOf(t, reg("var/lib/dpkg/status", dpkgStatus)),
				tarOf(t, reg("var/lib/dpkg/.wh.status", "")),
			}),
			files: nil, removedWh: 1,
		},
		{
			name: "a directory replaced by a file hides what was beneath",
			img: dockerSave(t, [][]byte{
				tarOf(t, reg("var/lib/rpm/rpmdb.sqlite", "db")),
				tarOf(t, reg("var/lib/rpm", "now a file")),
			}),
			files: nil,
		},
		{
			name: "a later regular file replaces a refused link",
			img: dockerSave(t, [][]byte{
				tarOf(t, sym("var/lib/rpm/rpmdb.sqlite", "/elsewhere")),
				tarOf(t, reg("var/lib/rpm/rpmdb.sqlite", "db")),
			}),
			files: []string{"var/lib/rpm/rpmdb.sqlite"},
		},
		{
			name: "traversal and absolute paths are refused",
			img: dockerSave(t, [][]byte{tarOf(t,
				reg("../../var/lib/dpkg/status", "escape"),
				reg("/var/lib/dpkg/status", "absolute"),
				reg("var/lib/../../../var/lib/dpkg/status", "dotdot"),
				reg("var/lib/dpkg/status", dpkgStatus),
			)}),
			files: []string{"var/lib/dpkg/status"}, refused: 3,
		},
		{
			name: "links that escape, and a package database that is a link",
			img: dockerSave(t, [][]byte{tarOf(t,
				hard("var/lib/dpkg/status", "../../../etc/shadow"),
				sym("var/lib/rpm/rpmdb.sqlite", "../../../../host/rpmdb.sqlite"),
				sym("usr/lib/sysimage/rpm/Packages", "/var/lib/rpm/Packages"),
			)}),
			refusedW: []string{"usr/lib/sysimage/rpm/Packages", "var/lib/dpkg/status", "var/lib/rpm/rpmdb.sqlite"},
			refused:  2,
		},
		{
			name: "a hard link to an extracted file is copied, one to an unread file is refused",
			img: dockerSave(t, [][]byte{tarOf(t,
				reg("var/lib/rpm/Packages", "berkeley"),
				hard("usr/lib/sysimage/rpm/Packages", "var/lib/rpm/Packages"),
				reg("opt/real.db", "x"),
				hard("usr/share/rpm/rpmdb.sqlite", "opt/real.db"),
			)}),
			files:    []string{"usr/lib/sysimage/rpm/Packages", "var/lib/rpm/Packages"},
			refusedW: []string{"usr/share/rpm/rpmdb.sqlite"},
		},
		{
			name:   "gzip bomb",
			img:    dockerSave(t, [][]byte{gz(t, tarOf(t, zeros("usr/share/big", 16<<20)))}),
			lim:    smallLimits(),
			reason: ReasonCapExceeded,
		},
		{
			name:   "zstd bomb",
			img:    dockerSave(t, [][]byte{zst(t, tarOf(t, zeros("usr/share/big", 16<<20)))}),
			lim:    smallLimits(),
			reason: ReasonCapExceeded,
		},
		{
			name: "many layers under the cap",
			img:  dockerSave(t, manyLayers(200)),
			files: func() []string {
				var f []string
				for i := range 200 {
					f = append(f, fmt.Sprintf("var/lib/dpkg/status.d/p%d", i))
				}
				slices.Sort(f)
				return f
			}(),
		},
		{
			name:   "layers over the cap",
			img:    dockerSave(t, manyLayers(300)),
			reason: ReasonCapExceeded,
		},
		{
			name:   "truncated layer",
			img:    dockerSave(t, [][]byte{truncated}),
			reason: ReasonCorrupt,
		},
		{
			name:   "manifest names a missing layer",
			img:    manifestTar(t, `[{"Config":"c.json","Layers":["0/layer.tar","1/layer.tar"]}]`, reg("0/layer.tar", string(debianLayer))),
			reason: ReasonLayerMissing,
		},
		{
			name:   "manifest names a path outside the archive",
			img:    manifestTar(t, `[{"Layers":["../evil.tar"]}]`),
			reason: ReasonUnsafe,
		},
		{
			name:   "two images",
			img:    manifestTar(t, `[{"Layers":[]},{"Layers":[]}]`),
			reason: ReasonMultipleImages,
		},
		{
			name:   "not an image",
			img:    tarOf(t, reg("README", "hello")),
			reason: ReasonNotAnImage,
		},
		{
			name: "legacy save links a repeated layer to its first copy",
			img: manifestTar(t, `[{"Layers":["a/layer.tar","b/layer.tar"]}]`,
				reg("a/layer.tar", string(tarOf(t, reg("var/lib/dpkg/status", dpkgStatus)))),
				sym("b/layer.tar", "../a/layer.tar")),
			files: []string{"var/lib/dpkg/status"},
		},
		{
			name: "per-entry size cap on a package database",
			img:  dockerSave(t, [][]byte{tarOf(t, reg("var/lib/dpkg/status", dpkgStatus))}),
			lim: func() Limits {
				l := DefaultLimits()
				l.MaxEntryBytes = 10
				return l
			}(),
			reason: ReasonCapExceeded,
		},
		{
			name: "entry cap",
			img:  dockerSave(t, [][]byte{tarOf(t, reg("a", "1"), reg("b", "2"), reg("c", "3"))}),
			lim: func() Limits {
				l := DefaultLimits()
				l.MaxEntries = 2
				return l
			}(),
			reason: ReasonCapExceeded,
		},
		{
			name: "path length cap refuses the entry",
			img:  dockerSave(t, [][]byte{tarOf(t, reg("var/lib/dpkg/status", dpkgStatus))}),
			lim: func() Limits {
				l := DefaultLimits()
				l.MaxPathLen = 15
				return l
			}(),
			refused: 1,
		},
		{
			name:  "a symlinked os-release with no target leaves etc empty",
			img:   dockerSave(t, [][]byte{tarOf(t, sym("etc/os-release", "../usr/lib/os-release"), reg("var/lib/dpkg/status", dpkgStatus))}),
			files: []string{"var/lib/dpkg/status"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lim := c.lim
			if lim == (Limits{}) {
				lim = DefaultLimits()
			}
			res, run, err := flatten(t, c.img, lim)
			if c.reason != "" {
				if got := ReasonOf(err); got != c.reason {
					t.Fatalf("reason %q (err %v), want %q", got, err, c.reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("Flatten: %v", err)
			}
			if !slices.Equal(res.Files, c.files) {
				t.Errorf("Files %v, want %v", res.Files, c.files)
			}
			if got := filesIn(t, run); !slices.Equal(got, c.files) {
				t.Errorf("run directory holds %v, want %v", got, c.files)
			}
			if !slices.Equal(res.RefusedWanted, c.refusedW) {
				t.Errorf("RefusedWanted %v, want %v", res.RefusedWanted, c.refusedW)
			}
			if res.Refused != c.refused {
				t.Errorf("Refused %d, want %d", res.Refused, c.refused)
			}
			if res.OSReleaseCopied != c.copiedOS {
				t.Errorf("OSReleaseCopied %v, want %v", res.OSReleaseCopied, c.copiedOS)
			}
			if got := res.OSRelease["ID"]; got != c.osID {
				t.Errorf("os-release ID %q, want %q", got, c.osID)
			}
			if res.RemovedByWhiteout != c.removedWh {
				t.Errorf("RemovedByWhiteout %d, want %d", res.RemovedByWhiteout, c.removedWh)
			}
			if fi, err := os.Stat(filepath.Join(run, "etc")); err != nil || !fi.IsDir() {
				t.Errorf("etc/ must always exist (osrelease refuses a root without it): %v", err)
			}
			if res.Digest == "" || res.Format != "docker-save" {
				t.Errorf("digest %q format %q", res.Digest, res.Format)
			}
			// Nothing escaped the run directory.
			if _, err := os.Stat(filepath.Join(filepath.Dir(run), "var")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a file was written beside the run directory: %v", err)
			}
		})
	}
}

func TestFlattenOCILayout(t *testing.T) {
	layer := gz(t, tarOf(t, reg("etc/os-release", alpineOSRelease), reg("lib/apk/db/installed", "P:musl\n\n")))
	img, md := ociLayout(t, [][]byte{layer})
	res, _, err := flatten(t, img, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "oci-layout" || res.Digest != md {
		t.Fatalf("format %q digest %q, want oci-layout %q (the manifest's own digest)", res.Format, res.Digest, md)
	}
	if !slices.Equal(res.Files, []string{"etc/os-release", "lib/apk/db/installed"}) {
		t.Fatalf("files %v", res.Files)
	}
	// A manifest blob whose bytes do not match its digest is refused.
	bad := bytes.Replace(img, []byte(`"schemaVersion":2}`), []byte(`"schemaVersion":3}`), 1)
	if _, _, err := flatten(t, bad, DefaultLimits()); ReasonOf(err) != ReasonCorrupt {
		t.Fatalf("tampered manifest blob: %v", err)
	}
}

func TestFlattenDigestIsStable(t *testing.T) {
	img := dockerSave(t, [][]byte{tarOf(t, reg("var/lib/dpkg/status", dpkgStatus))})
	a, _, err := flatten(t, img, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := flatten(t, img, DefaultLimits())
	if a.Digest != b.Digest || len(a.Digest) != len("sha256:")+64 {
		t.Fatalf("digest %q / %q", a.Digest, b.Digest)
	}
}

func TestFlattenInputCap(t *testing.T) {
	img := dockerSave(t, [][]byte{tarOf(t, reg("var/lib/dpkg/status", dpkgStatus))})
	l := DefaultLimits()
	l.MaxInputBytes = 100
	if _, _, err := flatten(t, img, l); ReasonOf(err) != ReasonCapExceeded {
		t.Fatalf("input cap: %v", err)
	}
}

func TestWanted(t *testing.T) {
	for _, c := range []struct {
		p    string
		want bool
	}{
		{"etc/os-release", true},
		{"usr/lib/os-release", true},
		{"var/lib/dpkg/status", true},
		{"var/lib/dpkg/status.d/libc6", true},
		{"var/lib/dpkg/status.d/libc6.md5sums", false},
		{"var/lib/dpkg/status.d/sub/x", false},
		{"lib/apk/db/installed", true},
		{"var/lib/rpm/rpmdb.sqlite", true},
		{"var/lib/rpm/Packages", true},
		{"usr/lib/sysimage/rpm/rpmdb.sqlite", true},
		{"usr/share/rpm/Packages.db", true},
		{"var/lib/rpm/.rpm.lock", false},
		{"etc/passwd", false},
		{"var/lib/dpkg/info/libc6.list", false},
	} {
		if got := Wanted(c.p); got != c.want {
			t.Errorf("Wanted(%q) = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	m := ParseOSRelease(bytes.NewBufferString("# comment\nID=ubuntu\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nVERSION_ID='24.04'\nbad line\nCPE_NAME=\"cpe:/o:redhat:enterprise_linux:9::baseos\"\nX=\"a\\\"b\"\nlower=x\n"))
	want := map[string]string{"ID": "ubuntu", "VERSION": "24.04.1 LTS (Noble Numbat)", "VERSION_ID": "24.04", "CPE_NAME": "cpe:/o:redhat:enterprise_linux:9::baseos", "X": `a"b`}
	if len(m) != len(want) {
		t.Fatalf("got %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
}

// FuzzFlatten feeds arbitrary bytes to the manifest and tar readers: they
// must refuse or read, never panic or write outside the run directory.
func FuzzFlatten(f *testing.F) {
	f.Add(dockerSave(f, [][]byte{tarOf(f, reg("var/lib/dpkg/status", dpkgStatus))}))
	oci, _ := ociLayout(f, [][]byte{gz(f, tarOf(f, reg("etc/os-release", alpineOSRelease)))})
	f.Add(oci)
	f.Add(manifestTar(f, `[{"Layers":["x"]}]`, reg("x", "garbage")))
	f.Fuzz(func(t *testing.T, img []byte) {
		lim := DefaultLimits()
		lim.RatioFloor, lim.MaxRatio = 1<<20, 10
		_, run, _ := flatten(t, img, lim)
		for _, p := range filesIn(t, run) {
			if !Wanted(p) {
				t.Fatalf("wrote %s, which is not on the allow-list", p)
			}
		}
	})
}
