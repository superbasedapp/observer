//go:build !sbo_omit_org_update

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_bundle_test.go: the update path installs the Windows sandbox
// driver's mxc\ set beside the binary (lane SBX-P3B, the P-067 follow-up),
// each file checked against the archive's own manifest first, and a failure
// part way leaves the old set whole.

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// mxcManifestJSON is the mxc-manifest.json scripts/mxc-files.sh writes, for
// the given file bodies.
func mxcManifestJSON(t *testing.T, ffi, exe string) string {
	t.Helper()
	type file struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	}
	b, err := json.Marshal(map[string]any{
		"kind": "observer.mxc-files.v1", "version": "1.0.1",
		"files": []file{
			{Name: "mxc_ffi.dll", SHA256: sha256Hex([]byte(ffi)), Size: len(ffi)},
			{Name: "wxc-exec.exe", SHA256: sha256Hex([]byte(exe)), Size: len(exe)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeWin32Zip writes a win32 archive with files and returns its artifact
// row (member observer.exe, the declared companions as the release declares
// them).
func writeWin32Zip(t *testing.T, path string, files map[string]string) update.Artifact {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var aliases []string
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if name != "observer.exe" {
			aliases = append(aliases, name)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return update.Artifact{ArchiveType: update.ArchiveZip, Member: "observer.exe", AliasMembers: aliases}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// TestUpdateInstallsTheMXCSet: extraction stages and checks the set; the
// rename-aside swap installs it beside the executable with the old files
// aside; restoreBinary (a failed handshake) puts the old set back.
func TestUpdateInstallsTheMXCSet(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "observer.exe")
	prev := filepath.Join(dir, "rollback-observer.exe")
	for p, body := range map[string]string{exe: "OLD", prev: "OLD", filepath.Join(dir, "mxc", "mxc_ffi.dll"): "old dll", filepath.Join(dir, "mxc", "wxc-exec.exe"): "old exe"} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "observer.zip")
	a := writeWin32Zip(t, archive, map[string]string{
		"observer.exe": "NEW", "superbased.exe": "NEW",
		"mxc/mxc_ffi.dll": "new dll", "mxc/wxc-exec.exe": "new exe!",
		"mxc/mxc-manifest.json": mxcManifestJSON(t, "new dll", "new exe!"),
	})
	staged := filepath.Join(dir, ".observer-staged-v2.exe")
	if _, err := extractMember(archive, staged, a); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := readFile(t, filepath.Join(stagedBundleRoot(staged), "mxc", "wxc-exec.exe")); got != "new exe!" {
		t.Fatalf("staged %q", got)
	}
	if _, err := swapBinary(osSwapFS{}, "windows", staged, exe, prev, "v1"); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if readFile(t, exe) != "NEW" || readFile(t, filepath.Join(dir, "mxc", "wxc-exec.exe")) != "new exe!" ||
		readFile(t, filepath.Join(dir, "mxc", "mxc_ffi.dll")) != "new dll" {
		t.Fatal("the new binary and set are not in place")
	}
	if _, err := os.Stat(filepath.Join(dir, "mxc", "mxc-manifest.json")); err != nil {
		t.Fatal("the manifest was not installed")
	}
	if _, err := os.Stat(stagedBundleRoot(staged)); !os.IsNotExist(err) {
		t.Fatal("the staging directory was left behind")
	}
	if err := restoreBinary(osSwapFS{}, "windows", prev, exe, "v1"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if readFile(t, exe) != "OLD" || readFile(t, filepath.Join(dir, "mxc", "wxc-exec.exe")) != "old exe" ||
		readFile(t, filepath.Join(dir, "mxc", "mxc_ffi.dll")) != "old dll" {
		t.Fatal("the rollback did not restore the old binary and set")
	}
	if _, err := os.Stat(filepath.Join(dir, "mxc", "mxc-manifest.json")); !os.IsNotExist(err) {
		t.Fatal("the manifest the update added survived the rollback")
	}
}

// TestUpdateRefusesATamperedMXCFile: a file that does not match its
// manifest (or a missing manifest) fails extraction; the staged binary is
// removed and nothing beside the executable changes.
func TestUpdateRefusesATamperedMXCFile(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"tampered":    {"observer.exe": "NEW", "mxc/mxc_ffi.dll": "new dlX", "mxc/wxc-exec.exe": "new exe!", "mxc/mxc-manifest.json": mxcManifestJSON(t, "new dll", "new exe!")},
		"no manifest": {"observer.exe": "NEW", "mxc/mxc_ffi.dll": "new dll", "mxc/wxc-exec.exe": "new exe!"},
		"short list":  {"observer.exe": "NEW", "mxc/mxc_ffi.dll": "new dll", "mxc/mxc-manifest.json": `{"kind":"observer.mxc-files.v1","files":[{"name":"mxc_ffi.dll","sha256":"` + sha256Hex([]byte("new dll")) + `","size":7}]}`},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			archive := filepath.Join(t.TempDir(), "observer.zip")
			a := writeWin32Zip(t, archive, files)
			staged := filepath.Join(dir, ".observer-staged-v2.exe")
			if _, err := extractMember(archive, staged, a); err == nil {
				t.Fatal("a set that does not match its manifest was accepted")
			}
			if _, err := os.Stat(staged); !os.IsNotExist(err) {
				t.Fatal("the staged binary was kept")
			}
			if _, err := os.Stat(stagedBundleRoot(staged)); !os.IsNotExist(err) {
				t.Fatal("the staged set was kept")
			}
		})
	}
}

// partialFailFS fails the rename that installs the named target from the
// staging directory (the undo's rename back is allowed).
type partialFailFS struct {
	osSwapFS
	failTarget string
}

func (f partialFailFS) Rename(o, n string) error {
	if n == f.failTarget && strings.Contains(o, ".bundle") {
		return errors.New("simulated failure")
	}
	return f.osSwapFS.Rename(o, n)
}

// TestUpdateMXCPartialCopyKeepsTheOldSet: a failure installing the second
// file undoes the first, so the previous set is whole, and the binary never
// moved.
func TestUpdateMXCPartialCopyKeepsTheOldSet(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "observer.exe")
	prev := filepath.Join(dir, "rollback-observer.exe")
	staged := filepath.Join(dir, ".observer-staged-v2.exe")
	write := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(exe, "OLD")
	write(prev, "OLD")
	write(staged, "NEW")
	write(filepath.Join(dir, "mxc", "mxc_ffi.dll"), "old dll")
	write(filepath.Join(dir, "mxc", "wxc-exec.exe"), "old exe")
	root := stagedBundleRoot(staged)
	write(filepath.Join(root, "mxc", "mxc_ffi.dll"), "new dll")
	write(filepath.Join(root, "mxc", "wxc-exec.exe"), "new exe!")
	write(filepath.Join(root, "mxc", "mxc-manifest.json"), mxcManifestJSON(t, "new dll", "new exe!"))
	fs := partialFailFS{failTarget: filepath.Join(dir, "mxc", "wxc-exec.exe")}
	if _, err := swapBinary(fs, "windows", staged, exe, prev, "v1"); err == nil {
		t.Fatal("the swap reported success")
	}
	if readFile(t, exe) != "OLD" || readFile(t, filepath.Join(dir, "mxc", "mxc_ffi.dll")) != "old dll" || readFile(t, filepath.Join(dir, "mxc", "wxc-exec.exe")) != "old exe" {
		t.Fatal("the old binary and set are not whole after a partial failure")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "mxc", "*.old-*")); len(left) != 0 {
		t.Fatalf("asides left behind: %v", left)
	}
}

// TestUpdateWithoutMXCLeavesTheSetAlone: an archive that carries no mxc\
// leaves an installed set untouched.
func TestUpdateWithoutMXCLeavesTheSetAlone(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "observer.exe")
	prev := filepath.Join(dir, "rollback-observer.exe")
	for p, body := range map[string]string{exe: "OLD", prev: "OLD", filepath.Join(dir, "mxc", "wxc-exec.exe"): "old exe"} {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "observer.zip")
	a := writeWin32Zip(t, archive, map[string]string{"observer.exe": "NEW", "superbased.exe": "NEW"})
	staged := filepath.Join(dir, ".observer-staged-v2.exe")
	if _, err := extractMember(archive, staged, a); err != nil {
		t.Fatal(err)
	}
	if _, err := swapBinary(osSwapFS{}, "windows", staged, exe, prev, "v1"); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(dir, "mxc", "wxc-exec.exe")) != "old exe" {
		t.Fatal("an archive without mxc changed the installed set")
	}
}

// TestUpdateBundlesMatchTheMXCFiles: the update path's and the Windows
// installer's names equal the driver's own and the release script's.
func TestUpdateBundlesMatchTheMXCFiles(t *testing.T) {
	var mxc *updateBundle
	for i := range updateBundles {
		if updateBundles[i].Dir == sandboxmxc.BundleDir {
			mxc = &updateBundles[i]
		}
	}
	if mxc == nil {
		t.Fatalf("no %s bundle", sandboxmxc.BundleDir)
	}
	want := []string{sandboxmxc.FileFFI, sandboxmxc.FileExec}
	if strings.Join(mxc.Files, ",") != strings.Join(want, ",") {
		t.Fatalf("bundle files %v, want %v", mxc.Files, want)
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "mxc-files.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), mxc.Kind) || !strings.Contains(string(script), mxc.Manifest) {
		t.Fatalf("scripts/mxc-files.sh does not write %s as %s", mxc.Manifest, mxc.Kind)
	}
	ps, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`$MxcDir = "` + mxc.Dir + `"`, `"` + sandboxmxc.FileFFI + `"`, `"` + sandboxmxc.FileExec + `"`, `$MxcManifest = "` + mxc.Manifest + `"`, `$MxcManifestKind = "` + mxc.Kind + `"`} {
		if !strings.Contains(string(ps), s) {
			t.Errorf("scripts/install.ps1 lacks %s", s)
		}
	}
}

// TestVerifyStagedBundleRefusesADuplicatedEntry (audit SBX-P3B F5): a
// manifest that lists one file twice and leaves the other out has the right
// count and only known names, yet must be refused, or the file it leaves out
// would be installed unchecked.
func TestVerifyStagedBundleRefusesADuplicatedEntry(t *testing.T) {
	b := updateBundles[0]
	stage := func(t *testing.T, manifest string) string {
		t.Helper()
		dir := t.TempDir()
		for name, body := range map[string]string{"mxc_ffi.dll": "new dll", "wxc-exec.exe": "tampered exe", b.Manifest: manifest} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	ffi := `{"name":"mxc_ffi.dll","sha256":"` + sha256Hex([]byte("new dll")) + `","size":7}`
	dup := `{"kind":"observer.mxc-files.v1","files":[` + ffi + `,` + ffi + `]}`
	err := verifyStagedBundle(stage(t, dup), b)
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a duplicated entry: %v", err)
	}
	exe := `{"name":"wxc-exec.exe","sha256":"` + sha256Hex([]byte("tampered exe")) + `","size":12}`
	if err := verifyStagedBundle(stage(t, `{"kind":"observer.mxc-files.v1","files":[`+ffi+`,`+exe+`]}`), b); err != nil {
		t.Fatalf("the exact set was refused: %v", err)
	}
}
