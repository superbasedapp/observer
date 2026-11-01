package sandboximage

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// vmset_test.go covers the guest image set (lane SBX-P4 milestone 3): the
// descriptor table, both manifests, and acceptance case A12 through the
// real content channel with TEST keys generated here.

func testVMDescriptor(version, minVersion string) VMDescriptor {
	return VMDescriptor{
		Schema: VMDescriptorSchema, Version: version, MinVersion: minVersion, Arch: "amd64",
		VerityRootHash: hex64('9'), Recipe: "deploy/sandbox-vm-image/recipe.env", RecipeSHA256: hex64('e'),
		SourceCommit: strings.Repeat("ab", 20),
		Kernel:       KernelPackage{Package: "linux-image-6.8.0-87-generic", Version: "6.8.0-87.88", SHA256: hex64('d')},
		SBOM:         VMSBOMName,
		FetchBase:    "https://github.com/marmutapp/superbased-observer/releases/download/v1.40.0",
	}
}

type vmFiles map[string][]byte

// vmPublish signs a rootfs manifest and a guest manifest over small stand-in
// bulk files and returns the two envelopes and their files on disk.
func vmPublish(t *testing.T, priv ed25519.PrivateKey, version int64, issued time.Time, d VMDescriptor, guestVersion string, revoked ...content.Revocation) (rootEnv, guestEnv []byte, root, guest vmFiles) {
	t.Helper()
	db, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := VMSPDX(VMSBOMInput{Descriptor: d, Created: t0, Packages: []Package{{Name: "busybox", Version: "1:1.36.1-6ubuntu3", Arch: "amd64"}, {Name: "cryptsetup-bin", Version: "2:2.7.0-1ubuntu4", Arch: "amd64"}}})
	if err != nil {
		t.Fatal(err)
	}
	root = vmFiles{VMDescriptorName: db, VMSBOMName: sb}
	facts := map[string]FileFacts{}
	for _, n := range BulkEntries() {
		b := []byte("stand-in " + n + " " + d.Version)
		root[n] = b
		facts[n] = FileFacts{SizeBytes: int64(len(b)), SHA256: content.HashBytes(b)}
	}
	m, err := BuildRootfsManifest(RootfsManifestInput{Descriptor: db, SBOM: sb, Files: facts, ManifestVersion: version, Epoch: 1, Issued: issued, Valid: 30 * 24 * time.Hour, Revoked: revoked})
	if err != nil {
		t.Fatal(err)
	}
	rootEnv = sign(t, m, priv)
	gb := []byte("stand-in guest observer " + guestVersion)
	gm, err := BuildGuestManifest(GuestManifestInput{Version: guestVersion, Commit: strings.Repeat("ab", 20), Binaries: map[string]FileFacts{"amd64": {SizeBytes: int64(len(gb)), SHA256: content.HashBytes(gb)}}, ManifestVersion: version, Epoch: 1, Issued: issued, Valid: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return rootEnv, sign(t, gm, priv), root, vmFiles{GuestBinaryName: gb}
}

func sign(t *testing.T, m content.Manifest, priv ed25519.PrivateKey) []byte {
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

// install writes the files to a scratch dir and installs them through
// InstallFiles (the import path's install).
func install(t *testing.T, s contentchan.Store, kind content.Kind, env []byte, files vmFiles, tr contentchan.Trust) error {
	t.Helper()
	dir := t.TempDir()
	paths := map[string]string{}
	for n, b := range files {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		paths[n] = p
	}
	_, err := s.InstallFiles(kind, env, paths, tr)
	return err
}

// vmResolveFrom is the driver's glue: load both kinds, read the small
// entries, re-hash the bulk ones from disk, resolve.
func vmResolveFrom(s contentchan.Store, tr contentchan.Trust, agentVersion, want string) VMSetResult {
	in := VMSetInput{Arch: "amd64", AgentVersion: agentVersion, Want: want, BulkErr: map[string]error{}}
	rl, err := s.Load(content.SandboxRootfs, tr, 0)
	in.Rootfs = KindLoad{NotInstalled: errors.Is(err, contentchan.ErrNotInstalled), LoadErr: err}
	if errors.Is(err, contentchan.ErrNotInstalled) {
		in.Rootfs.LoadErr = nil
	}
	gl, gerr := s.Load(content.SandboxGuest, tr, 0)
	in.Guest = KindLoad{NotInstalled: errors.Is(gerr, contentchan.ErrNotInstalled), LoadErr: gerr}
	if errors.Is(gerr, contentchan.ErrNotInstalled) {
		in.Guest.LoadErr = nil
	}
	if err == nil {
		in.Rootfs.Manifest, in.Rootfs.Freshness = rl.Manifest, rl.Freshness
		in.Descriptor, in.DescriptorErr = rl.ReadArtifact(VMDescriptorName)
		in.SBOM, in.SBOMErr = rl.ReadArtifact(VMSBOMName)
		for _, n := range BulkEntries() {
			_, in.BulkErr[n] = rl.ReadArtifact(n)
		}
	}
	if gerr == nil {
		in.Guest.Manifest, in.Guest.Freshness = gl.Manifest, gl.Freshness
		in.GuestEntry, in.GuestErr = content.EntryFor(gl.Manifest, GuestBinaryName, "linux", "amd64")
		if in.GuestErr == nil {
			_, in.GuestErr = gl.ReadArtifact(GuestBinaryName)
		}
	}
	return ResolveVMSet(in)
}

func TestVMSetAcceptsASignedSet(t *testing.T) {
	pub, priv := testKey(9)
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	clock := t0
	s := newStore(t, &clock)
	re, ge, rf, gf := vmPublish(t, priv, 1, t0.Add(-time.Hour), testVMDescriptor("1.0.0", "1.0.0"), "1.40.0")
	if err := install(t, s, content.SandboxRootfs, re, rf, tr); err != nil {
		t.Fatal(err)
	}
	if err := install(t, s, content.SandboxGuest, ge, gf, tr); err != nil {
		t.Fatal(err)
	}
	r := vmResolveFrom(s, tr, "v1.40.0", "")
	if !r.OK || r.Descriptor.VerityRootHash != hex64('9') || r.Stale {
		t.Fatalf("%+v", r)
	}
	if r := vmResolveFrom(s, tr, "1.40.0", "1.0.0"); !r.OK {
		t.Fatalf("pinned: %+v", r)
	}
	if r := vmResolveFrom(s, tr, "1.40.0", "2.0.0"); r.OK || r.Reason != ReasonImageSetPinned {
		t.Fatalf("another pinned set: %+v", r)
	}
}

// TestVMSetA12 is acceptance case A12 for the VM family: a replayed older
// manifest, a below-minimum set, a revoked entry, a tampered entry, an
// expired manifest (last-known-good, reported), a wrong guest version and a
// set with no guest binary are each refused, or reported, before boot.
func TestVMSetA12(t *testing.T) {
	pub, priv := testKey(9)
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}

	t.Run("replayed older manifest", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		re2, _, rf2, _ := vmPublish(t, priv, 2, t0.Add(-time.Hour), testVMDescriptor("1.1.0", "1.0.0"), "1.40.0")
		if err := install(t, s, content.SandboxRootfs, re2, rf2, tr); err != nil {
			t.Fatal(err)
		}
		re1, _, rf1, _ := vmPublish(t, priv, 1, t0.Add(-2*time.Hour), testVMDescriptor("1.0.0", "1.0.0"), "1.40.0")
		err := install(t, s, content.SandboxRootfs, re1, rf1, tr)
		if err == nil || content.ReasonOf(err) == "" {
			t.Fatalf("a replayed older manifest installed: %v", err)
		}
		l, _ := s.Load(content.SandboxRootfs, tr, 0)
		if l.Manifest.ManifestVersion != 2 {
			t.Fatalf("the last-known-good was replaced: %d", l.Manifest.ManifestVersion)
		}
	})
	t.Run("below minimum", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		re, ge, rf, gf := vmPublish(t, priv, 1, t0.Add(-time.Hour), testVMDescriptor("1.0.0", "1.2.0"), "1.40.0")
		_ = install(t, s, content.SandboxRootfs, re, rf, tr)
		_ = install(t, s, content.SandboxGuest, ge, gf, tr)
		if r := vmResolveFrom(s, tr, "1.40.0", ""); r.OK || r.Reason != ReasonBelowMinimum {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		d := testVMDescriptor("1.0.0", "1.0.0")
		re, ge, rf, gf := vmPublish(t, priv, 1, t0.Add(-time.Hour), d, "1.40.0")
		_ = install(t, s, content.SandboxRootfs, re, rf, tr)
		_ = install(t, s, content.SandboxGuest, ge, gf, tr)
		if r := vmResolveFrom(s, tr, "1.40.0", ""); !r.OK {
			t.Fatalf("before the revocation: %+v", r)
		}
		// The publisher withdraws the set by its verity root hash with no
		// replacement: the same set re-issued at a higher version.
		re2, _, rf2, _ := vmPublish(t, priv, 2, t0.Add(-time.Hour), d, "1.40.0", content.Revocation{SHA256: d.VerityRootHash, Name: "image set 1.0.0", Reason: "test"})
		if err := install(t, s, content.SandboxRootfs, re2, rf2, tr); err != nil {
			t.Fatal(err)
		}
		if r := vmResolveFrom(s, tr, "1.40.0", ""); r.OK || r.Reason != ReasonRevoked {
			t.Fatalf("a revoked set: %+v", r)
		}
		// And the guest binary by its digest.
		re3, _, rf3, _ := vmPublish(t, priv, 3, t0.Add(-time.Hour), d, "1.40.0", content.Revocation{SHA256: content.HashBytes(gf[GuestBinaryName]), Name: GuestBinaryName, Reason: "test"})
		if err := install(t, s, content.SandboxRootfs, re3, rf3, tr); err != nil {
			t.Fatal(err)
		}
		if r := vmResolveFrom(s, tr, "1.40.0", ""); r.OK || r.Reason != ReasonRevoked || !strings.Contains(r.Detail, "guest observer") {
			t.Fatalf("a revoked guest binary: %+v", r)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		re, ge, rf, gf := vmPublish(t, priv, 1, t0.Add(-time.Hour), testVMDescriptor("1.0.0", "1.0.0"), "1.40.0")
		_ = install(t, s, content.SandboxRootfs, re, rf, tr)
		_ = install(t, s, content.SandboxGuest, ge, gf, tr)
		dir, _ := s.KindDir(content.SandboxRootfs)
		b := rf[VMRootfsName]
		b[0] ^= 1
		if err := os.WriteFile(filepath.Join(dir, VMRootfsName), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if r := vmResolveFrom(s, tr, "1.40.0", ""); r.OK || r.Reason != ReasonTampered {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("expired is last-known-good, reported", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		re, ge, rf, gf := vmPublish(t, priv, 1, t0.Add(-time.Hour), testVMDescriptor("1.0.0", "1.0.0"), "1.40.0")
		_ = install(t, s, content.SandboxRootfs, re, rf, tr)
		_ = install(t, s, content.SandboxGuest, ge, gf, tr)
		clock = t0.Add(40 * 24 * time.Hour)
		if r := vmResolveFrom(s, tr, "1.40.0", ""); !r.OK || !r.Stale {
			t.Fatalf("expired within the age floor: %+v", r)
		}
		clock = t0.Add(500 * 24 * time.Hour)
		if r := vmResolveFrom(s, tr, "1.40.0", ""); r.OK || r.Reason != ReasonUnknownAge {
			t.Fatalf("past the age floor: %+v", r)
		}
	})
	t.Run("wrong guest version", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		re, ge, rf, gf := vmPublish(t, priv, 1, t0.Add(-time.Hour), testVMDescriptor("1.0.0", "1.0.0"), "1.39.0")
		_ = install(t, s, content.SandboxRootfs, re, rf, tr)
		_ = install(t, s, content.SandboxGuest, ge, gf, tr)
		if r := vmResolveFrom(s, tr, "1.40.0", ""); r.OK || r.Reason != ReasonWrongGuestVersion {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("no guest binary", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		re, _, rf, _ := vmPublish(t, priv, 1, t0.Add(-time.Hour), testVMDescriptor("1.0.0", "1.0.0"), "1.40.0")
		_ = install(t, s, content.SandboxRootfs, re, rf, tr)
		if r := vmResolveFrom(s, tr, "1.40.0", ""); r.OK || r.Reason != ReasonGuestMissing {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("another key", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		_, other := testKey(3)
		re, _, rf, _ := vmPublish(t, other, 1, t0.Add(-time.Hour), testVMDescriptor("1.0.0", "1.0.0"), "1.40.0")
		if err := install(t, s, content.SandboxRootfs, re, rf, tr); err == nil {
			t.Fatal("a set signed by another key installed")
		}
	})
	t.Run("a half set is never installed", func(t *testing.T) {
		clock := t0
		s := newStore(t, &clock)
		re, _, rf, _ := vmPublish(t, priv, 1, t0.Add(-time.Hour), testVMDescriptor("1.0.0", "1.0.0"), "1.40.0")
		delete(rf, VMVerityName)
		if err := install(t, s, content.SandboxRootfs, re, rf, tr); content.ReasonOf(err) != content.ContentReasonNotCovered {
			t.Fatalf("a set without its verity tree: %v", err)
		}
		if st, _ := s.State(content.SandboxRootfs); st.Accepted != nil {
			t.Fatal("a half set was accepted")
		}
	})
}

// TestVMDescriptorRules is one case per descriptor row.
func TestVMDescriptorRules(t *testing.T) {
	cases := map[string]func(*VMDescriptor){
		"schema":           func(d *VMDescriptor) { d.Schema = "x" },
		"version":          func(d *VMDescriptor) { d.Version = "1.0" },
		"min_version":      func(d *VMDescriptor) { d.MinVersion = "v1.0.0" },
		"arch":             func(d *VMDescriptor) { d.Arch = "riscv64" },
		"verity_root_hash": func(d *VMDescriptor) { d.VerityRootHash = "ABC" },
		"recipe":           func(d *VMDescriptor) { d.Recipe = "/abs" },
		"source_commit":    func(d *VMDescriptor) { d.SourceCommit = "main" },
		"kernel":           func(d *VMDescriptor) { d.Kernel.SHA256 = "" },
		"sbom":             func(d *VMDescriptor) { d.SBOM = "x.json" },
		"agent_cli":        func(d *VMDescriptor) { d.AgentCLI = true },
		"fetch_base http":  func(d *VMDescriptor) { d.FetchBase = "http://github.com/x" },
		"fetch_base host":  func(d *VMDescriptor) { d.FetchBase = "https://evil.example/x" },
	}
	for name, mut := range cases {
		d := testVMDescriptor("1.0.0", "1.0.0")
		mut(&d)
		b, _ := d.Encode()
		if _, err := ParseVMDescriptor(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good, _ := testVMDescriptor("1.0.0", "1.0.0").Encode()
	if _, err := ParseVMDescriptor(good); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseVMDescriptor([]byte(strings.Replace(string(good), `"schema"`, `"extra": 1, "schema"`, 1))); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}

// TestVMManifestCaps: an entry over its cap or a missing bulk entry never
// builds, and the SBOM refuses an agent CLI package.
func TestVMManifestCaps(t *testing.T) {
	d := testVMDescriptor("1.0.0", "1.0.0")
	db, _ := d.Encode()
	sb, _ := VMSPDX(VMSBOMInput{Descriptor: d, Created: t0, Packages: []Package{{Name: "busybox", Version: "1", Arch: "amd64"}}})
	facts := map[string]FileFacts{}
	for _, n := range BulkEntries() {
		facts[n] = FileFacts{SizeBytes: 10, SHA256: hex64('1')}
	}
	in := RootfsManifestInput{Descriptor: db, SBOM: sb, Files: facts, ManifestVersion: 1, Epoch: 1, Issued: t0, Valid: 24 * time.Hour}
	if _, err := BuildRootfsManifest(in); err != nil {
		t.Fatal(err)
	}
	big := in
	big.Files = map[string]FileFacts{}
	for k, v := range facts {
		big.Files[k] = v
	}
	big.Files[VMKernelName] = FileFacts{SizeBytes: 65 << 20, SHA256: hex64('1')}
	if _, err := BuildRootfsManifest(big); err == nil {
		t.Fatal("an oversized kernel built")
	}
	delete(big.Files, VMKernelName)
	if _, err := BuildRootfsManifest(big); err == nil {
		t.Fatal("a set with no kernel built")
	}
	if _, err := VMSPDX(VMSBOMInput{Descriptor: d, Created: t0, Packages: []Package{{Name: "claude-code", Version: "1", Arch: "amd64"}}}); err == nil {
		t.Fatal("an agent CLI package was listed")
	}
	if _, err := BuildGuestManifest(GuestManifestInput{Version: "1.40.0", Commit: strings.Repeat("ab", 20), Binaries: map[string]FileFacts{"riscv64": {SizeBytes: 1, SHA256: hex64('1')}}, ManifestVersion: 1, Epoch: 1, Issued: t0, Valid: time.Hour}); err == nil {
		t.Fatal("a guest for an unknown arch built")
	}
}
