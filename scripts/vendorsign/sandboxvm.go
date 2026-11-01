package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandboxvm.go holds the `vendorsign sandboxrootfs` and `vendorsign
// sandboxguest` verbs (sandbox plan v2 sections 12.3 and 13 P4, lane
// SBX-P4, ledger SBX-BE-4; hosting and signing per operator ruling P-126):
//
//   - sandboxrootfs turns deploy/sandbox-vm-image/build.sh's build/ output
//     into the guest image set's descriptor and SBOM, copies the kernel,
//     the initramfs, the rootfs and its verity tree beside them, and, only
//     when given a key, writes the signed sandbox.rootfs manifest over all
//     six;
//   - sandboxguest writes the sandbox.guest_binary set: one guest observer
//     per architecture, its version the agent release's.
//
// Without -key each verb writes the unsigned files and stops at the named
// seam sandbox_vm_signing_key_missing (an error, so a release job cannot
// mistake it for a signed set). Output, the layout `observer sandbox
// content import <dir>` takes:
//
//	<out>/sandbox.rootfs/{sandbox-vm.json,sandbox-vm.spdx.json,vmlinuz,initrd.img,rootfs.img,rootfs.verity,manifest.json}
//	<out>/sandbox.guest_binary/{observer-guest,manifest.json}
//
// A guest binary set with more than one architecture cannot share one entry
// file name in one directory: only the first is copied beside the manifest,
// the others are named <name>.<arch> for the release step to publish.

// errSandboxVMSigningKeyMissing is the signing seam.
var errSandboxVMSigningKeyMissing = errors.New("sandbox_vm_signing_key_missing: the files are written unsigned; no node accepts them until the release step signs them with -key")

// sandboxVMSign is the common -key handling.
type sandboxVMSign struct {
	keyPath                string
	allowUnpinned          bool
	manifestVersion, epoch int64
	validDays              int
	revoke                 revokeFlags
	// debug signs a debug image set (R-016) with a throwaway debug key:
	// never a key this tree's agents accept.
	debug bool
}

func (s *sandboxVMSign) flags(fsx *flag.FlagSet) {
	fsx.StringVar(&s.keyPath, "key", "", "vendor signing key file (release step only)")
	fsx.BoolVar(&s.allowUnpinned, "allow-unpinned-key", false, "sign with a key this tree's agents do not accept (rotation step only)")
	fsx.Int64Var(&s.manifestVersion, "manifest-version", 0, "monotonic manifest version (with -key)")
	fsx.Int64Var(&s.epoch, "epoch", 1, "data epoch")
	fsx.IntVar(&s.validDays, "valid-days", 90, "manifest validity in days, at most 180")
	fsx.Var(&s.revoke, "revoke", "sha256 digest (or a set's verity root hash) to withdraw (repeatable)")
	fsx.BoolVar(&s.debug, "debug", false, "sign a debug image set (build.sh --debug) with a throwaway debug key, never the vendor key; writes debug-key.pub")
}

func (s *sandboxVMSign) key() (ed25519.PrivateKey, error) {
	if s.keyPath == "" {
		if s.debug {
			return nil, errors.New("vendorsign: -debug needs -key, a throwaway debug key (a debug set is never left unsigned for the vendor step)")
		}
		return nil, nil
	}
	if s.manifestVersion <= 0 {
		return nil, errors.New("vendorsign: -key needs a positive -manifest-version")
	}
	priv, err := loadPrivateKey(s.keyPath)
	if err != nil {
		return nil, err
	}
	if s.debug {
		if err := refuseVendorKeyForDebug(priv); err != nil {
			return nil, err
		}
		return priv, nil
	}
	warn, err := checkKeyIsPinned(priv, s.allowUnpinned)
	if err != nil {
		return nil, err
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}
	return priv, nil
}

func (s *sandboxVMSign) revocations() []content.Revocation {
	var out []content.Revocation
	for _, r := range s.revoke {
		out = append(out, content.Revocation{SHA256: r, Reason: "withdrawn by the publisher"})
	}
	return out
}

// vmHashFile streams a file's sha256 and size.
func vmHashFile(p string) (sandboximage.FileFacts, error) {
	f, err := os.Open(p) //nolint:gosec // G304: a build output the operator named
	if err != nil {
		return sandboximage.FileFacts{}, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return sandboximage.FileFacts{}, err
	}
	return sandboximage.FileFacts{SizeBytes: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// vmCopyFile copies src to dst (0644).
func vmCopyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // G304: a build output the operator named
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // G302,G304: a published artifact under -out
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// recipeDigest is the sha256 of the recipe directory's files (recipe.env,
// build.sh, init), each as "<sha256>  <name>\n", sorted by name.
// refuseVendorKeyForDebug refuses a debug set signed with a key this tree's
// agents accept as a vendor key (R-016): a debug set is never shipped.
func refuseVendorKeyForDebug(priv ed25519.PrivateKey) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("vendorsign: signing key is not Ed25519")
	}
	for _, k := range acceptedVendorKeys() {
		if pub.Equal(k) {
			return fmt.Errorf("vendorsign: refusing to sign a debug image set with key id %s, a vendor key this tree's agents accept; a debug set is signed only with a throwaway debug key", keyID(pub))
		}
	}
	return nil
}

// vmDebugRecipeFiles are the debug variant's files (R-016), digested with the
// release recipe's into a debug set's descriptor.
var vmDebugRecipeFiles = []string{"debug/recipe-debug.env", "debug/init-wrapper", "debug/debugd", "debug/remount-root", "debug/selfcheck-debug.sh"}

// vmDebugMarker is the file build.sh --debug writes into build/: its
// presence makes a build a debug build.
const vmDebugMarker = "debug"

// vmDebugInitMarker is what a debug build's /init names: PID 1 handed to
// the debug wrapper (build.sh --debug's sed). The marker file above can be
// deleted; this cannot be lost without rebuilding the initramfs, which then
// no longer starts the debug hooks (LEFT2 audit S6).
const vmDebugInitMarker = "/usr/libexec/observer-debug/init-wrapper"

// vmBuildIsDebug reports whether build is a debug build: its marker file,
// or its initramfs's /init handing PID 1 to the debug wrapper.
func vmBuildIsDebug(build string) bool {
	if _, err := os.Lstat(filepath.Join(build, vmDebugMarker)); err == nil {
		return true
	}
	body, ok := vmInitrdInit(filepath.Join(build, "initrd.img"))
	return ok && bytes.Contains(body, []byte(vmDebugInitMarker))
}

// vmInitrdInit reads /init out of a gzip newc cpio initramfs (what
// build.sh packs). ok is false when the file is not one, or has no /init.
// Bounded: at most 100,000 entries, /init at most 1 MiB, nothing else
// read into memory.
func vmInitrdInit(path string) (body []byte, ok bool) {
	f, err := os.Open(path) //nolint:gosec // G304: the build the operator named
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, false
	}
	r := bufio.NewReader(zr)
	var off int64
	pad := func(n int64) error {
		if rem := (off + n) % 4; rem != 0 {
			n += 4 - rem
		}
		_, err := io.CopyN(io.Discard, r, n)
		off += n
		return err
	}
	for i := 0; i < 100_000; i++ {
		var hdr [110]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, false
		}
		off += 110
		if m := string(hdr[:6]); m != "070701" && m != "070702" {
			return nil, false
		}
		field := func(i int) (int64, bool) {
			v, err := strconv.ParseInt(string(hdr[6+8*i:14+8*i]), 16, 64)
			return v, err == nil && v >= 0
		}
		size, ok1 := field(6)
		nameSize, ok2 := field(11)
		if !ok1 || !ok2 || nameSize < 1 || nameSize > 4096 {
			return nil, false
		}
		name := make([]byte, nameSize)
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, false
		}
		off += nameSize
		if err := pad(0); err != nil {
			return nil, false
		}
		n := strings.TrimRight(string(name), "\x00")
		switch {
		case n == "TRAILER!!!":
			return nil, false
		case n == "init" || n == "./init":
			if size > 1<<20 {
				return nil, false
			}
			body = make([]byte, size)
			if _, err := io.ReadFull(r, body); err != nil {
				return nil, false
			}
			return body, true
		}
		if err := pad(size); err != nil {
			return nil, false
		}
	}
	return nil, false
}

// writeDebugPublicKey writes debug-key.pub (64 hex) beside the kinds, the
// file `observer sandbox content import --debug-key` reads.
func writeDebugPublicKey(outDir string, priv ed25519.PrivateKey) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("vendorsign: signing key is not Ed25519")
	}
	return os.WriteFile(filepath.Join(outDir, "debug-key.pub"), []byte(hex.EncodeToString(pub)+"\n"), 0o644) //nolint:gosec // G306: a public key
}

func recipeDigest(dir string) (string, error) { return recipeDigestFor(dir, false) }

// recipeDigestFor digests the recipe's files; a debug set's digest also
// covers the debug variant's.
func recipeDigestFor(dir string, debug bool) (string, error) {
	names := []string{"recipe.env", "build.sh", "init"}
	if debug {
		names = append(names, vmDebugRecipeFiles...)
	}
	var lines []string
	for _, name := range names {
		f, err := vmHashFile(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}
		lines = append(lines, f.SHA256+"  "+name+"\n")
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(sum[:]), nil
}

// readRecipeValue reads KEY=value from recipe.env.
func readRecipeValue(dir, key string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "recipe.env")) //nolint:gosec // G304: the recipe the operator named
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), key+"="); ok {
			return strings.Trim(v, `"`), nil
		}
	}
	return "", fmt.Errorf("recipe.env has no %s", key)
}

// vmWriteEnvelope signs m with priv and writes it as manifest.json in dir.
func vmWriteEnvelope(dir string, m content.Manifest, priv ed25519.PrivateKey) error {
	env, err := content.Sign(m, priv)
	if err != nil {
		return err
	}
	b, err := content.EncodeEnvelope(env)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o644) //nolint:gosec // G306: a published manifest
}

func runSandboxRootfs(args []string, out *os.File) error {
	fsx := flag.NewFlagSet("sandboxrootfs", flag.ContinueOnError)
	build := fsx.String("build", "", "build.sh's build/ directory")
	recipeDir := fsx.String("recipe-dir", "deploy/sandbox-vm-image", "the recipe directory")
	recipePath := fsx.String("recipe-path", "deploy/sandbox-vm-image/recipe.env", "the recipe's path in the source tree, as recorded")
	version := fsx.String("version", "", "image set version MAJOR.MINOR.PATCH")
	minVersion := fsx.String("min-version", "", "lowest version still allowed")
	commit := fsx.String("commit", "", "full source commit id")
	fetchBase := fsx.String("fetch-base", "", "https URL on the public Observer release the entries are published under (optional)")
	outDir := fsx.String("out", "", "output directory")
	epochSecs := fsx.Int64("source-date-epoch", 0, "SOURCE_DATE_EPOCH of the build (the SBOM's created time)")
	var sign sandboxVMSign
	sign.flags(fsx)
	if err := fsx.Parse(args); err != nil {
		return err
	}
	if *build == "" || *outDir == "" || *version == "" || *minVersion == "" || *commit == "" || *epochSecs <= 0 {
		return errors.New("vendorsign sandboxrootfs: -build, -out, -version, -min-version, -commit and a positive -source-date-epoch are required")
	}
	priv, err := sign.key()
	if err != nil {
		return err
	}
	rootHash, err := os.ReadFile(filepath.Join(*build, "root-hash")) //nolint:gosec // G304: the build the operator named
	if err != nil {
		return err
	}
	ktsv, err := os.ReadFile(filepath.Join(*build, "kernel.tsv")) //nolint:gosec // G304: the build the operator named
	if err != nil {
		return err
	}
	kf := strings.Split(strings.TrimSpace(string(ktsv)), "\t")
	if len(kf) != 3 {
		return errors.New("vendorsign sandboxrootfs: kernel.tsv is not package, version, sha256")
	}
	arch, err := readRecipeValue(*recipeDir, "ARCH")
	if err != nil {
		return err
	}
	userns, _ := readRecipeValue(*recipeDir, "GUEST_USERNS")
	switch built := vmBuildIsDebug(*build); {
	case built && !sign.debug:
		return errors.New("vendorsign sandboxrootfs: the build is a debug build (build.sh --debug: its marker, or its initramfs /init handing PID 1 to the debug wrapper); it is never signed as a release set (sign it with -debug and a throwaway debug key)")
	case !built && sign.debug:
		return errors.New("vendorsign sandboxrootfs: -debug signs only a debug build (build.sh --debug), and this build has no debug marker")
	}
	rd, err := recipeDigestFor(*recipeDir, sign.debug)
	if err != nil {
		return err
	}
	d := sandboximage.VMDescriptor{
		Schema: sandboximage.VMDescriptorSchema, Version: *version, MinVersion: *minVersion, Arch: arch,
		VerityRootHash: strings.TrimSpace(string(rootHash)), Recipe: *recipePath, RecipeSHA256: rd,
		SourceCommit: *commit, Kernel: sandboximage.KernelPackage{Package: kf[0], Version: kf[1], SHA256: kf[2]},
		GuestUserns: userns == "true", SBOM: sandboximage.VMSBOMName, FetchBase: *fetchBase, Debug: sign.debug,
	}
	if err := d.Validate(); err != nil {
		return err
	}
	ptsv, err := os.ReadFile(filepath.Join(*build, "packages.tsv")) //nolint:gosec // G304: the build the operator named
	if err != nil {
		return err
	}
	pkgs, err := sandboximage.ParsePackagesTSV(ptsv)
	if err != nil {
		return err
	}
	sb, err := sandboximage.VMSPDX(sandboximage.VMSBOMInput{Descriptor: d, Created: time.Unix(*epochSecs, 0).UTC(), Packages: pkgs})
	if err != nil {
		return err
	}
	db, err := d.Encode()
	if err != nil {
		return err
	}
	dir := filepath.Join(*outDir, string(content.SandboxRootfs))
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: a publish directory
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, sandboximage.VMDescriptorName), db, 0o644); err != nil { //nolint:gosec // G306: published
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, sandboximage.VMSBOMName), sb, 0o644); err != nil { //nolint:gosec // G306: published
		return err
	}
	facts := map[string]sandboximage.FileFacts{}
	for _, name := range sandboximage.BulkEntries() {
		f, err := vmHashFile(filepath.Join(*build, name))
		if err != nil {
			return err
		}
		if err := vmCopyFile(filepath.Join(*build, name), filepath.Join(dir, name)); err != nil {
			return err
		}
		facts[name] = f
	}
	fmt.Fprintf(out, "sandbox.rootfs: set %s, verity root %s, written to %s\n", d.Version, d.VerityRootHash, dir)
	if priv == nil {
		return errSandboxVMSigningKeyMissing
	}
	m, err := sandboximage.BuildRootfsManifest(sandboximage.RootfsManifestInput{
		Descriptor: db, SBOM: sb, Files: facts, ManifestVersion: sign.manifestVersion, Epoch: sign.epoch,
		Issued: time.Now().UTC(), Valid: time.Duration(sign.validDays) * 24 * time.Hour, Revoked: sign.revocations(),
	})
	if err != nil {
		return err
	}
	if sign.debug {
		if err := writeDebugPublicKey(*outDir, priv); err != nil {
			return err
		}
	}
	return vmWriteEnvelope(dir, m, priv)
}

// binaryFlags is the repeatable -binary arch=FILE flag.
type binaryFlags map[string]string

func (b binaryFlags) String() string { return fmt.Sprint(map[string]string(b)) }

func (b binaryFlags) Set(v string) error {
	arch, file, ok := strings.Cut(v, "=")
	if !ok || file == "" {
		return fmt.Errorf("want arch=FILE, got %q", v)
	}
	b[arch] = file
	return nil
}

func runSandboxGuest(args []string, out *os.File) error {
	fsx := flag.NewFlagSet("sandboxguest", flag.ContinueOnError)
	bins := binaryFlags{}
	fsx.Var(bins, "binary", "arch=FILE, a linux guest observer of this release (repeatable)")
	version := fsx.String("version", "", "the agent release's version MAJOR.MINOR.PATCH")
	commit := fsx.String("commit", "", "full source commit id")
	outDir := fsx.String("out", "", "output directory")
	var sign sandboxVMSign
	sign.flags(fsx)
	if err := fsx.Parse(args); err != nil {
		return err
	}
	if len(bins) == 0 || *version == "" || *commit == "" || *outDir == "" {
		return errors.New("vendorsign sandboxguest: -binary, -version, -commit and -out are required")
	}
	priv, err := sign.key()
	if err != nil {
		return err
	}
	dir := filepath.Join(*outDir, string(content.SandboxGuest))
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: a publish directory
		return err
	}
	arches := make([]string, 0, len(bins))
	for a := range bins {
		arches = append(arches, a)
	}
	sort.Strings(arches)
	facts := map[string]sandboximage.FileFacts{}
	for i, a := range arches {
		f, err := vmHashFile(bins[a])
		if err != nil {
			return err
		}
		facts[a] = f
		name := sandboximage.GuestBinaryName
		if i > 0 {
			name += "." + a
		}
		if err := vmCopyFile(bins[a], filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	m, err := sandboximage.BuildGuestManifest(sandboximage.GuestManifestInput{
		Version: strings.TrimPrefix(*version, "v"), Commit: *commit, Binaries: facts,
		ManifestVersion: max(sign.manifestVersion, 1), Epoch: sign.epoch, Issued: time.Now().UTC(),
		Valid: time.Duration(sign.validDays) * 24 * time.Hour, Revoked: sign.revocations(),
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "sandbox.guest_binary: %s for %v, written to %s\n", m.Entries[0].Version, arches, dir)
	if priv == nil {
		return errSandboxVMSigningKeyMissing
	}
	return vmWriteEnvelope(dir, m, priv)
}
