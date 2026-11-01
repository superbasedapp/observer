//go:build !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// terminal_sandbox_vm_imageset_test.go covers the guest image set's import
// and load (lane SBX-P4 milestone 3) with a TEST key generated here: no
// production signature anywhere.

// vmTestSet writes a signed set (stand-in bulk files) in the vendorsign
// layout under a fresh dir and returns it.
type vmTestSet struct {
	dir     string
	root    sandboximage.VMDescriptor
	version string
}

func writeVMTestSet(t *testing.T, priv ed25519.PrivateKey, manifestVersion int64, setVersion, guestVersion string, revoked ...content.Revocation) vmTestSet {
	t.Helper()
	return writeVMTestSetWith(t, priv, manifestVersion, setVersion, guestVersion, nil, revoked...)
}

// writeVMTestSetWith is writeVMTestSet with a descriptor edit (nil: none).
func writeVMTestSetWith(t *testing.T, priv ed25519.PrivateKey, manifestVersion int64, setVersion, guestVersion string, edit func(*sandboximage.VMDescriptor), revoked ...content.Revocation) vmTestSet {
	t.Helper()
	dir := t.TempDir()
	d := sandboximage.VMDescriptor{
		Schema: sandboximage.VMDescriptorSchema, Version: setVersion, MinVersion: "1.0.0", Arch: runtime.GOARCH,
		VerityRootHash: strings.Repeat("9", 64), Recipe: "deploy/sandbox-vm-image/recipe.env", RecipeSHA256: strings.Repeat("e", 64),
		SourceCommit: strings.Repeat("ab", 20), GuestUserns: true,
		Kernel: sandboximage.KernelPackage{Package: "linux-image-6.8.0-87-generic", Version: "6.8.0-87.88", SHA256: strings.Repeat("d", 64)},
		SBOM:   sandboximage.VMSBOMName,
	}
	if edit != nil {
		edit(&d)
	}
	db, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := sandboximage.VMSPDX(sandboximage.VMSBOMInput{Descriptor: d, Created: time.Now(), Packages: []sandboximage.Package{{Name: "busybox", Version: "1", Arch: runtime.GOARCH}}})
	if err != nil {
		t.Fatal(err)
	}
	rdir := filepath.Join(dir, string(content.SandboxRootfs))
	gdir := filepath.Join(dir, string(content.SandboxGuest))
	for _, p := range []string{rdir, gdir} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string, b []byte) {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(rdir, sandboximage.VMDescriptorName), db)
	write(filepath.Join(rdir, sandboximage.VMSBOMName), sb)
	facts := map[string]sandboximage.FileFacts{}
	for _, n := range sandboximage.BulkEntries() {
		b := []byte("stand-in " + n + " " + setVersion)
		write(filepath.Join(rdir, n), b)
		facts[n] = sandboximage.FileFacts{SizeBytes: int64(len(b)), SHA256: content.HashBytes(b)}
	}
	now := time.Now().UTC()
	m, err := sandboximage.BuildRootfsManifest(sandboximage.RootfsManifestInput{Descriptor: db, SBOM: sb, Files: facts, ManifestVersion: manifestVersion, Epoch: 1, Issued: now.Add(-time.Hour), Valid: 30 * 24 * time.Hour, Revoked: revoked})
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(rdir, contentchan.ManifestFile), vmSign(t, m, priv))
	gb := []byte("stand-in guest observer " + guestVersion)
	write(filepath.Join(gdir, sandboximage.GuestBinaryName), gb)
	gm, err := sandboximage.BuildGuestManifest(sandboximage.GuestManifestInput{Version: guestVersion, Commit: strings.Repeat("ab", 20), Binaries: map[string]sandboximage.FileFacts{runtime.GOARCH: {SizeBytes: int64(len(gb)), SHA256: content.HashBytes(gb)}}, ManifestVersion: manifestVersion, Epoch: 1, Issued: now.Add(-time.Hour), Valid: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(gdir, contentchan.ManifestFile), vmSign(t, gm, priv))
	return vmTestSet{dir: dir, root: d, version: setVersion}
}

func vmSign(t *testing.T, m content.Manifest, priv ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := content.EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vmTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestSandboxContentImportInstallsTheVMSet: an import verifies both kinds,
// installs them, leaves the source untouched, and the driver's load
// resolves the set with its userns flag.
func TestSandboxContentImportInstallsTheVMSet(t *testing.T) {
	pub, priv := vmTestKey(t)
	set := writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0")
	store := vmContentStore(t.TempDir())
	got, err := sandboxContentImport(store, []ed25519.PublicKey{pub}, set.dir)
	if err != nil || len(got) != 2 {
		t.Fatalf("import %v %+v", err, got)
	}
	if _, err := os.Stat(filepath.Join(set.dir, string(content.SandboxRootfs), sandboximage.VMRootfsName)); err != nil {
		t.Fatalf("the source dir was consumed: %v", err)
	}
	s := loadVMImageSet(store, contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}, "", "v1.40.0")
	if !s.res.OK || !s.facts().GuestUserns || s.facts().Version != "1.0.0" || s.guest == "" || len(s.paths) != 4 {
		t.Fatalf("load %+v facts %+v", s.res, s.facts())
	}
	// Wrong agent version: the host binary is never substituted.
	if s := loadVMImageSet(store, contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}, "", "1.41.0"); s.res.OK || s.res.Reason != sandboximage.ReasonWrongGuestVersion {
		t.Fatalf("another agent version: %+v", s.res)
	}
	// Tampered after install: refused on the next load (re-hashed).
	if err := os.WriteFile(s.paths[sandboximage.VMKernelName], []byte("evil kernel bytes..."), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := loadVMImageSet(store, contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}, "", "1.40.0"); s.res.OK || s.res.Reason != sandboximage.ReasonTampered {
		t.Fatalf("tampered: %+v", s.res)
	}
}

// TestSandboxContentImportRefusals: a wrong key, a replayed manifest, a
// tampered file and a symlinked entry are refused and nothing is
// installed.
func TestSandboxContentImportRefusals(t *testing.T) {
	pub, priv := vmTestKey(t)
	keys := []ed25519.PublicKey{pub}
	t.Run("no key", func(t *testing.T) {
		if _, err := sandboxContentImport(vmContentStore(t.TempDir()), nil, writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0").dir); err == nil || !strings.Contains(err.Error(), "artifact_unverified") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("another key", func(t *testing.T) {
		_, other := vmTestKey(t)
		store := vmContentStore(t.TempDir())
		if _, err := sandboxContentImport(store, keys, writeVMTestSet(t, other, 1, "1.0.0", "1.40.0").dir); err == nil {
			t.Fatal("accepted")
		}
		vmAssertNothingInstalled(t, store)
	})
	t.Run("tampered file", func(t *testing.T) {
		set := writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0")
		if err := os.WriteFile(filepath.Join(set.dir, string(content.SandboxGuest), sandboximage.GuestBinaryName), []byte("stand-in guest observer 1.40.X"), 0o600); err != nil {
			t.Fatal(err)
		}
		store := vmContentStore(t.TempDir())
		if _, err := sandboxContentImport(store, keys, set.dir); err == nil {
			t.Fatal("accepted")
		}
		vmAssertNothingInstalled(t, store)
	})
	t.Run("symlinked entry", func(t *testing.T) {
		set := writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0")
		p := filepath.Join(set.dir, string(content.SandboxRootfs), sandboximage.VMRootfsName)
		real := p + ".real"
		if err := os.Rename(p, real); err != nil {
			t.Fatal(err)
		}
		if err := testSymlink(t, real, p); err != nil {
			t.Skip("no symlinks here")
		}
		store := vmContentStore(t.TempDir())
		if _, err := sandboxContentImport(store, keys, set.dir); err == nil {
			t.Fatal("a symlinked entry was imported")
		}
		vmAssertNothingInstalled(t, store)
	})
	t.Run("replayed", func(t *testing.T) {
		store := vmContentStore(t.TempDir())
		if _, err := sandboxContentImport(store, keys, writeVMTestSet(t, priv, 2, "1.1.0", "1.40.0").dir); err != nil {
			t.Fatal(err)
		}
		if _, err := sandboxContentImport(store, keys, writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0").dir); err == nil {
			t.Fatal("a replayed older set was imported")
		}
		if s := loadVMImageSet(store, contentchan.Trust{VendorKeys: keys}, "", "1.40.0"); !s.res.OK || s.res.Descriptor.Version != "1.1.0" {
			t.Fatalf("the last-known-good changed: %+v", s.res)
		}
	})
	t.Run("empty dir", func(t *testing.T) {
		if _, err := sandboxContentImport(vmContentStore(t.TempDir()), keys, t.TempDir()); err == nil {
			t.Fatal("an empty dir imported")
		}
	})
}

func vmAssertNothingInstalled(t *testing.T, store contentchan.Store) {
	t.Helper()
	for _, k := range []content.Kind{content.SandboxRootfs, content.SandboxGuest} {
		if st, err := store.State(k); err == nil && st.Accepted != nil {
			t.Fatalf("%s was installed", k)
		}
	}
}

// TestVMImageSetFactsForTheProbe: the probe row reads image_missing with
// nothing installed and artifact_unverified for a refused set.
func TestVMImageSetFactsForTheProbe(t *testing.T) {
	store := vmContentStore(t.TempDir())
	f := loadVMImageSet(store, contentchan.Trust{}, "", "1.40.0").facts()
	if f.Present {
		t.Fatalf("nothing installed: %+v", f)
	}
	pub, priv := vmTestKey(t)
	if _, err := sandboxContentImport(store, []ed25519.PublicKey{pub}, writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0").dir); err != nil {
		t.Fatal(err)
	}
	f = loadVMImageSet(store, contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}, "9.9.9", "1.40.0").facts()
	if !f.Present || f.Verdict.Code != "artifact_unverified" || !strings.Contains(f.Verdict.Reason, "image_set") {
		t.Fatalf("a pinned set that is not installed: %+v", f)
	}
}

// TestSandboxContentImportIsAllOrNothing (audit finding 5): the guest
// binary installs first and the rootfs is then refused (a file of the right
// size but the wrong digest, caught only at install); the guest binary is
// put back, on a fresh store and over an installed older set.
func TestSandboxContentImportIsAllOrNothing(t *testing.T) {
	pub, priv := vmTestKey(t)
	keys := []ed25519.PublicKey{pub}
	tamperRootfs := func(set vmTestSet) {
		p := filepath.Join(set.dir, string(content.SandboxRootfs), sandboximage.VMKernelName)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)-1] ^= 1
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("fresh store", func(t *testing.T) {
		set := writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0")
		tamperRootfs(set)
		store := vmContentStore(t.TempDir())
		_, err := sandboxContentImport(store, keys, set.dir)
		if err == nil || !strings.Contains(err.Error(), "nothing was installed") {
			t.Fatalf("%v", err)
		}
		vmAssertNothingInstalled(t, store)
		if dir, _ := store.KindDir(content.SandboxGuest); dir != "" {
			if _, err := os.Stat(filepath.Join(dir, sandboximage.GuestBinaryName)); !os.IsNotExist(err) {
				t.Fatalf("the guest binary was left installed: %v", err)
			}
		}
	})
	t.Run("over an installed set", func(t *testing.T) {
		store := vmContentStore(t.TempDir())
		if _, err := sandboxContentImport(store, keys, writeVMTestSet(t, priv, 1, "1.0.0", "1.40.0").dir); err != nil {
			t.Fatal(err)
		}
		set := writeVMTestSet(t, priv, 2, "1.1.0", "1.41.0")
		tamperRootfs(set)
		if _, err := sandboxContentImport(store, keys, set.dir); err == nil {
			t.Fatal("a set with a tampered rootfs was imported")
		}
		s := loadVMImageSet(store, contentchan.Trust{VendorKeys: keys}, "", "1.40.0")
		if !s.res.OK || s.res.Descriptor.Version != "1.0.0" {
			t.Fatalf("the last-known-good set (rootfs 1.0.0 with guest 1.40.0) did not survive: %+v", s.res)
		}
	})
}
