//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// artifacts_test.go holds the canaries of the four artifact extractors
// (artifacts.go, plan 14.6): each extractor reads a real artifact made at
// test time (no binary in testdata, no environment in a fixture), so a
// SCALIBR bump that breaks one fails here rather than reading clean:
//
//   - Go build info: the test binary itself (it carries this module's build
//     info) and, where the toolchain is on PATH, a program built by the
//     test as a Linux ELF with no extension and no exec bit, so the header
//     rule is what finds it on every host;
//   - a JAR with a pom.properties, written with archive/zip;
//   - a wheel's METADATA under a site-packages tree;
//   - a minimal ELF with a cargo auditable .dep-v0 section.

// writeArtifact writes body to root/rel.
func writeArtifact(t *testing.T, root, rel string, body []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// placeTestBinary links (or copies) the running test binary to root/rel.
func placeTestBinary(t *testing.T, root, rel string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no test executable: %v", err)
	}
	dst := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Link(exe, dst) == nil {
		return
	}
	in, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// testJAR is a Java archive with one pom.properties.
func testJAR(t *testing.T, group, artifact, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("Manifest-Version: 1.0\r\n\r\n"))
	w, err = zw.Create("META-INF/maven/" + group + "/" + artifact + "/pom.properties")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// cargoAuditableELF is a minimal ELF64 executable whose only content is a
// cargo auditable .dep-v0 section (zlib-compressed JSON), as cargo
// auditable writes it into a Rust binary.
func cargoAuditableELF(t *testing.T, depJSON string) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write([]byte(depJSON)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := z.Bytes()
	strtab := []byte("\x00.dep-v0\x00.shstrtab\x00")
	const ehsize, shentsize = 64, 64
	dataOff := uint64(ehsize)
	strOff := dataOff + uint64(len(data))
	shOff := (strOff + uint64(len(strtab)) + 7) &^ 7
	var b bytes.Buffer
	hdr := elf.Header64{
		Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Shoff: shOff, Ehsize: ehsize, Phentsize: 56, Shentsize: shentsize, Shnum: 3, Shstrndx: 2,
	}
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	_ = binary.Write(&b, binary.LittleEndian, hdr)
	b.Write(data)
	b.Write(strtab)
	for uint64(b.Len()) < shOff {
		b.WriteByte(0)
	}
	sections := []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_PROGBITS), Off: dataOff, Size: uint64(len(data)), Addralign: 1},
		{Name: 9, Type: uint32(elf.SHT_STRTAB), Off: strOff, Size: uint64(len(strtab)), Addralign: 1},
	}
	for _, s := range sections {
		_ = binary.Write(&b, binary.LittleEndian, s)
	}
	return b.Bytes()
}

const cargoDeps = `{"packages":[` +
	`{"name":"canary-app","version":"0.1.0","source":"local","kind":"runtime","dependencies":[1],"root":true},` +
	`{"name":"time","version":"0.1.42","source":"crates.io","kind":"runtime","dependencies":[]},` +
	`{"name":"cc","version":"1.0.0","source":"crates.io","kind":"build","dependencies":[]}]}`

// pkgAt finds a package by ecosystem, name and path.
func pkgAt(inv *Inventory, eco, name, path string) (Package, bool) {
	for _, p := range inv.Packages {
		if p.Ecosystem == eco && p.Name == name && p.Path == path {
			return p, true
		}
	}
	return Package{}, false
}

// moduleVersion is the version this test binary was built with for a
// module path, without the leading v.
func moduleVersion(t *testing.T, path string) string {
	t.Helper()
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info in the test binary")
	}
	for _, d := range bi.Deps {
		if d.Path == path {
			if d.Replace != nil && d.Replace.Version != "" {
				return strings.TrimPrefix(d.Replace.Version, "v")
			}
			return strings.TrimPrefix(d.Version, "v")
		}
	}
	t.Skipf("the test binary does not list %s", path)
	return ""
}

func TestArtifactCanaries(t *testing.T) {
	root := t.TempDir()
	placeTestBinary(t, root, "bin/canary-go")
	writeArtifact(t, root, "lib/log4j-core-2.14.1.jar", testJAR(t, "org.apache.logging.log4j", "log4j-core", "2.14.1"))
	writeArtifact(t, root, ".venv/lib/python3.12/site-packages/requests-2.19.0.dist-info/METADATA",
		[]byte("Metadata-Version: 2.1\nName: requests\nVersion: 2.19.0\nSummary: canary\n"))
	writeArtifact(t, root, "target/release/canary-rust", cargoAuditableELF(t, cargoDeps))

	// Artifact folders are opt-in: the two executables are read because
	// their folders are turned on (ruling 2026-11-05).
	inv, err := Extract(context.Background(), root, ExtractOptions{ArtifactDirs: []string{"bin", "target/release"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, eco, pkg, version, path, extractor string
	}{
		{"go build info: a module", "Go", "github.com/google/osv-scalibr", moduleVersion(t, "github.com/google/osv-scalibr"), "bin/canary-go", "go/binary"},
		{"go build info: the toolchain as stdlib", "Go", "stdlib", depscan.NormalizeGoVersion(runtime.Version()), "bin/canary-go", "go/binary"},
		{"java archive", "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "lib/log4j-core-2.14.1.jar", "java/archive"},
		{"wheel metadata", "PyPI", "requests", "2.19.0", ".venv/lib/python3.12/site-packages/requests-2.19.0.dist-info/METADATA", "python/wheelegg"},
		{"cargo auditable", "crates.io", "time", "0.1.42", "target/release/canary-rust", "rust/cargoauditable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := pkgAt(inv, tc.eco, tc.pkg, tc.path)
			if !ok {
				t.Fatalf("%s %s at %s not extracted; packages: %+v", tc.eco, tc.pkg, tc.path, inv.Packages)
			}
			if p.Version != tc.version || !p.Artifact || p.Extractor != tc.extractor {
				t.Fatalf("got %+v, want version %s, Artifact, extractor %s", p, tc.version, tc.extractor)
			}
		})
	}
	// cargo auditable build-only dependencies stay out (SCALIBR's default).
	if _, ok := pkgAt(inv, "crates.io", "cc", "target/release/canary-rust"); ok {
		t.Error("a build-only crate was reported")
	}
	// The lockfile rows are not artifacts.
	for _, p := range inv.Packages {
		if p.Artifact != artifactExtractorNames[p.Extractor] {
			t.Errorf("%s from %s: Artifact %v", p.Name, p.Extractor, p.Artifact)
		}
	}
	for _, s := range inv.Statuses {
		if !s.OK {
			t.Errorf("extractor %s failed: %s %v", s.Extractor, s.Detail, s.Files)
		}
	}
	if len(inv.TooLarge) != 0 {
		t.Errorf("nothing is over the cap: %+v", inv.TooLarge)
	}
}

// TestArtifactExecutablesOnlyUnderArtifactDirs: an executable outside the
// artifact directories is never read (the old default list, bin/, dist/ and
// target/release/, included: nothing is implied); a named directory adds
// one; a file over the cap is reported, not read.
func TestArtifactExecutablesOnlyUnderArtifactDirs(t *testing.T) {
	root := t.TempDir()
	placeTestBinary(t, root, "tools/canary-go")
	writeArtifact(t, root, "out/canary-rust", cargoAuditableELF(t, cargoDeps))
	writeArtifact(t, root, "bin/not-an-executable", []byte("#!/bin/sh\necho hello\n"))
	placeTestBinary(t, root, "bin/default-listed")
	ctx := context.Background()

	inv, err := Extract(ctx, root, ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range inv.Packages {
		if p.Artifact {
			t.Fatalf("an executable outside the artifact directories was read: %+v", p)
		}
	}

	inv, err = Extract(ctx, root, ExtractOptions{ArtifactDirs: []string{"tools", "out"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pkgAt(inv, "Go", "stdlib", "tools/canary-go"); !ok {
		t.Error("a named directory's Go binary was not read")
	}
	if _, ok := pkgAt(inv, "crates.io", "time", "out/canary-rust"); !ok {
		t.Error("a named directory's Rust binary was not read")
	}

	inv, err = Extract(ctx, root, ExtractOptions{ArtifactDirs: []string{"tools", "out"}, MaxArtifactBytes: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pkgAt(inv, "Go", "stdlib", "tools/canary-go"); ok {
		t.Error("a binary over the cap was read")
	}
	found := false
	for _, s := range inv.TooLarge {
		if s.Path == "tools/canary-go" && s.Ecosystem == "" {
			found = true
		}
	}
	if !found {
		t.Errorf("the binary over the cap is not reported: %+v", inv.TooLarge)
	}
	if _, ok := pkgAt(inv, "crates.io", "time", "out/canary-rust"); !ok {
		t.Error("a small binary under the cap was not read")
	}
}

// TestArtifactGoBinaryBuiltByTheToolchain: a program built by the test for
// linux (an ELF with no extension and, on Windows, no exec bit) is found by
// its header alone.
func TestArtifactGoBinaryBuiltByTheToolchain(t *testing.T) {
	if testing.Short() || os.Getenv("SBO_SKIP_TOOLCHAIN_TESTS") != "" {
		t.Skip("execs the Go toolchain")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no Go toolchain on PATH")
	}
	src := t.TempDir()
	writeArtifact(t, src, "go.mod", []byte("module example.com/observer-artifact-canary\n\ngo 1.21\n"))
	writeArtifact(t, src, "main.go", []byte("package main\n\nfunc main() {}\n"))
	root := t.TempDir()
	out := filepath.Join(root, "dist", "canary")
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=-mod=mod", "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inv, err := Extract(context.Background(), root, ExtractOptions{ArtifactDirs: []string{"dist"}})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := pkgAt(inv, "Go", "stdlib", "dist/canary")
	if !ok || !p.Artifact || p.Version == "" {
		t.Fatalf("the toolchain row of a built binary: %+v (packages %+v)", p, inv.Packages)
	}
	if m, ok := pkgAt(inv, "Go", "example.com/observer-artifact-canary", "dist/canary"); !ok || m.Version != "(devel)" {
		t.Fatalf("the main module row: %+v %v", m, ok)
	}
}

// TestArtifactPackagesMatch: what the artifact extractors read reaches the
// same matcher as a lockfile's packages: log4j-core from a JAR, the time
// crate from cargo auditable, and a Go binary's standard library under the
// "stdlib" name the Go advisories use.
func TestArtifactPackagesMatch(t *testing.T) {
	root := t.TempDir()
	placeTestBinary(t, root, "bin/canary-go")
	writeArtifact(t, root, "lib/log4j-core-2.14.1.jar", testJAR(t, "org.apache.logging.log4j", "log4j-core", "2.14.1"))
	writeArtifact(t, root, "target/release/canary-rust", cargoAuditableELF(t, cargoDeps))
	inv, err := Extract(context.Background(), root, ExtractOptions{ArtifactDirs: []string{"bin", "target/release"}})
	if err != nil {
		t.Fatal(err)
	}
	db := t.TempDir()
	writeDB(t, db, "Maven", map[string]string{"GHSA-jfh8-c2jp-5v3q.json": `{"id":"GHSA-jfh8-c2jp-5v3q","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-44228"],
"affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.15.0"}]}]}]}`})
	writeDB(t, db, "crates.io", map[string]string{"RUSTSEC-2020-0071.json": `{"id":"RUSTSEC-2020-0071","modified":"2024-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"crates.io","name":"time"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.2.23"}]}]}]}`})
	writeDB(t, db, "Go", map[string]string{"GO-9999-0001.json": `{"id":"GO-9999-0001","modified":"2024-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"Go","name":"stdlib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"999.0.0"}]}]}]}`})
	for _, tc := range []struct{ eco, pkg, id string }{
		{"Maven", "org.apache.logging.log4j:log4j-core", "GHSA-jfh8-c2jp-5v3q"},
		{"crates.io", "time", "RUSTSEC-2020-0071"},
		{"Go", "stdlib", "GO-9999-0001"},
	} {
		t.Run(tc.eco, func(t *testing.T) {
			res, err := Match(context.Background(), inv, MatchRequest{Ecosystem: tc.eco, Indices: indices(inv, tc.eco)}, MatchOptions{DBDir: db})
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range res.Vulns {
				if p := inv.Packages[v.Index]; p.Name == tc.pkg && v.ID == tc.id && p.Artifact {
					return
				}
			}
			t.Fatalf("%s %s not matched to %s: %+v", tc.eco, tc.pkg, tc.id, res.Vulns)
		})
	}
}

// TestArtifactOffFoldersAreLeftAlone: a discovered candidate folder that is
// not turned on is not read, not even a Java archive found by name
// (ruling 2026-11-05: nothing under an artifact folder is scanned until
// its folder is on); turning it on reads it; an archive outside every
// candidate folder is read as before.
func TestArtifactOffFoldersAreLeftAlone(t *testing.T) {
	root := t.TempDir()
	writeArtifact(t, root, "build/libs/app.jar", testJAR(t, "org.example", "in-build", "1.0.0"))
	writeArtifact(t, root, "lib/dep.jar", testJAR(t, "org.example", "in-lib", "2.0.0"))
	ctx := context.Background()
	has := func(inv *Inventory, name string) bool {
		for _, p := range inv.Packages {
			if p.Name == name {
				return true
			}
		}
		return false
	}
	inv, err := Extract(ctx, root, ExtractOptions{ArtifactOff: []string{"build"}})
	if err != nil {
		t.Fatal(err)
	}
	if has(inv, "org.example:in-build") {
		t.Error("an archive under a folder that is off was read")
	}
	if !has(inv, "org.example:in-lib") {
		t.Error("an archive outside every candidate folder was not read")
	}
	inv, err = Extract(ctx, root, ExtractOptions{ArtifactOff: []string{"build"}, ArtifactDirs: []string{"build"}})
	if err != nil {
		t.Fatal(err)
	}
	if !has(inv, "org.example:in-build") {
		t.Error("an archive under a folder that is turned on was not read")
	}
}

// TestRepairArtifactPackagesGoStdlib: the toolchain row of a Go binary
// becomes package stdlib at the normalized release; a development build or
// an unparseable string is emptied and reported, never kept as a version;
// only a gobinary row is touched.
func TestRepairArtifactPackagesGoStdlib(t *testing.T) {
	mk := func(plugin, name, version string) *extractor.Package {
		return &extractor.Package{Name: name, Version: version, Plugins: []string{plugin}}
	}
	for _, tc := range []struct {
		name        string
		in          *extractor.Package
		wantName    string
		wantVersion string
		wantUnknown bool
	}{
		{"release", mk(gobinary.Name, "go", "1.22.3"), "stdlib", "1.22.3", false},
		{"two components", mk(gobinary.Name, "go", "1.22"), "stdlib", "1.22.0", false},
		{"release candidate", mk(gobinary.Name, "go", "1.22rc1"), "stdlib", "1.22.0-rc.1", false},
		{"already stdlib stays one", mk(gobinary.Name, "stdlib", "1.21.9"), "stdlib", "1.21.9", false},
		{"development build", mk(gobinary.Name, "go", "devel"), "stdlib", "", true},
		{"garbage", mk(gobinary.Name, "go", "banana"), "stdlib", "", true},
		{"another extractor's go row", mk("other/extractor", "go", "1.22.3"), "go", "1.22.3", false},
		{"a module row", mk(gobinary.Name, "golang.org/x/net", "0.17.0"), "golang.org/x/net", "0.17.0", false},
		{"a toolchain module is never made one", mk(gobinary.Name, "toolchain", "1.22.3"), "toolchain", "1.22.3", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unknown := repairArtifactPackages([]*extractor.Package{tc.in})
			if tc.in.Name != tc.wantName || tc.in.Version != tc.wantVersion || unknown[tc.in] != tc.wantUnknown {
				t.Fatalf("got %q %q unknown=%v, want %q %q unknown=%v", tc.in.Name, tc.in.Version, unknown[tc.in], tc.wantName, tc.wantVersion, tc.wantUnknown)
			}
		})
	}
}
