//go:build !sbo_omit_org_update

package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_bundle.go installs the files an update archive carries BESIDE the
// binary that the binary needs at run time (lane SBX-P3B, the P-067
// follow-up): today the Windows sandbox driver's mxc\ set (mxc_ffi.dll,
// wxc-exec.exe and their mxc-manifest.json, bundled by scripts/mxc-files.sh
// only in the win32 archives of the distros that compile the driver). Before
// this file an update replaced only the binary, so a node that updated kept
// the old set and its sandbox row reported artifact_unverified after a pin
// change.
//
// The rules, in order:
//   - only a declared companion entry (update.Artifact.AliasMembers, signed
//     in the manifest and checked by update.SelectMember) under a bundle
//     directory of updateBundles is extracted; anything else stays skipped;
//   - each payload file is checked against the bundle's own manifest (name,
//     size, sha256), which rides inside the archive whose sha256 and vendor
//     signature the apply has already verified, before anything replaces the
//     old set;
//   - the set is swapped one file at a time beside the executable: the old
//     file is renamed aside (a running wxc-exec.exe can be renamed, never
//     overwritten), the new one renamed in; a failure part way undoes every
//     step, so the previous set stays whole; a failed handshake restores the
//     asides with the binary (restoreBinary);
//   - an archive that carries no bundle leaves an installed set untouched.

// updateBundle is one directory of companion files.
type updateBundle struct {
	// Dir is the directory beside the executable.
	Dir string
	// Files are the payload files, each listed in the manifest.
	Files []string
	// Manifest is the manifest file name and Kind its "kind" value.
	Manifest string
	Kind     string
}

// updateBundles is the table of companion directories an update installs.
// The mxc row's names equal internal/sandboxmxc's BundleDir, FileFFI and
// FileExec and the manifest scripts/mxc-files.sh writes
// (TestUpdateBundlesMatchTheMXCFiles).
var updateBundles = []updateBundle{
	{Dir: "mxc", Files: []string{"mxc_ffi.dll", "wxc-exec.exe"}, Manifest: "mxc-manifest.json", Kind: "observer.mxc-files.v1"},
}

// maxBundleFileBytes caps one extracted companion file (the MXC files are
// about 6 and 12 MB).
const maxBundleFileBytes int64 = 64 << 20

// stagedBundleRoot is where an apply stages the companion directories, beside
// the staged binary (so the swap's renames never cross a filesystem).
func stagedBundleRoot(staged string) string { return staged + ".bundle" }

// bundleFor returns the bundle and file name a cleaned archive entry name
// belongs to.
func bundleFor(name string) (updateBundle, string, bool) {
	dir, file := path.Split(name)
	dir = strings.TrimSuffix(dir, "/")
	for _, b := range updateBundles {
		if dir == b.Dir && (file == b.Manifest || slices.Contains(b.Files, file)) {
			return b, file, true
		}
	}
	return updateBundle{}, "", false
}

// bundleManifest is the part of a bundle manifest the check reads.
type bundleManifest struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
	Files   []struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"files"`
}

// extractZipBundles writes the declared companion entries of the selection
// (sel.Aliases) that belong to a bundle into stagedBundleRoot(dest), then
// checks every staged bundle against its manifest. Nothing is staged when the
// archive carries no bundle.
func extractZipBundles(zr *zip.Reader, sel update.Selection, dest string) error {
	root := stagedBundleRoot(dest)
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("observer update: clearing %s: %w", root, err)
	}
	byName := map[string]*zip.File{}
	for _, f := range zr.File {
		byName[cleanArchiveEntryName(f.Name)] = f
	}
	staged := map[string]updateBundle{}
	for _, e := range sel.Aliases {
		b, file, ok := bundleFor(e.Name)
		if !ok || e.Kind != update.EntryFile {
			continue
		}
		zf, ok := byName[e.Name]
		if !ok {
			return fmt.Errorf("observer update: companion %q vanished between passes", e.Name)
		}
		if err := writeBundleFile(filepath.Join(root, b.Dir, file), zf); err != nil {
			return err
		}
		staged[b.Dir] = b
	}
	for _, b := range updateBundles {
		if _, ok := staged[b.Dir]; ok {
			if err := verifyStagedBundle(filepath.Join(root, b.Dir), b); err != nil {
				_ = os.RemoveAll(root)
				return err
			}
		}
	}
	return nil
}

// writeBundleFile streams one companion file to dest under the size cap.
func writeBundleFile(dest string, zf *zip.File) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("observer update: staging %s: %w", filepath.Dir(dest), err)
	}
	rc, err := zf.Open()
	if err != nil {
		return fmt.Errorf("observer update: companion %s: %w", zf.Name, err)
	}
	defer func() { _ = rc.Close() }()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) //nolint:gosec // a library and an executable, deliberately 0755
	if err != nil {
		return fmt.Errorf("observer update: create %s: %w", dest, err)
	}
	n, err := io.Copy(out, io.LimitReader(rc, maxBundleFileBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxBundleFileBytes {
		err = fmt.Errorf("exceeds %d bytes", maxBundleFileBytes)
	}
	if err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("observer update: companion %s: %w", zf.Name, err)
	}
	return nil
}

// verifyStagedBundle checks a staged bundle directory against its manifest:
// the manifest of the right kind lists exactly the bundle's files (the listed
// names equal the known set: none unknown, none twice, none missing), and
// each staged file is a regular file whose size and sha256 equal the
// manifest's. This checks the archive's own manifest, as install.ps1 does;
// the compiled pins (sandboxmxc.ManifestX64) are re-checked by the runtime
// helper before each use.
func verifyStagedBundle(dir string, b updateBundle) error {
	raw, err := os.ReadFile(filepath.Join(dir, b.Manifest)) //nolint:gosec // a path this process staged
	if err != nil {
		return fmt.Errorf("observer update: the archive's %s/ carries no %s, so its files cannot be checked: %w", b.Dir, b.Manifest, err)
	}
	var m bundleManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("observer update: %s/%s: %w", b.Dir, b.Manifest, err)
	}
	if m.Kind != b.Kind {
		return fmt.Errorf("observer update: %s/%s is not a %s manifest", b.Dir, b.Manifest, b.Kind)
	}
	if len(m.Files) != len(b.Files) {
		return fmt.Errorf("observer update: %s/%s lists %d files, not the %d known ones", b.Dir, b.Manifest, len(m.Files), len(b.Files))
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		if !slices.Contains(b.Files, f.Name) {
			return fmt.Errorf("observer update: %s/%s lists an unknown file %q", b.Dir, b.Manifest, f.Name)
		}
		if listed[f.Name] {
			return fmt.Errorf("observer update: %s/%s lists %q twice", b.Dir, b.Manifest, f.Name)
		}
		listed[f.Name] = true
	}
	for _, name := range b.Files {
		if !listed[name] {
			return fmt.Errorf("observer update: %s/%s does not list %q", b.Dir, b.Manifest, name)
		}
	}
	for _, f := range m.Files {
		p := filepath.Join(dir, f.Name)
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			return fmt.Errorf("observer update: %s/%s is missing from the archive or not a regular file", b.Dir, f.Name)
		}
		if st.Size() != f.Size {
			return fmt.Errorf("observer update: %s/%s is %d bytes, its manifest says %d", b.Dir, f.Name, st.Size(), f.Size)
		}
		sum, err := sha256File(p)
		if err != nil {
			return err
		}
		if !strings.EqualFold(sum, f.SHA256) {
			return fmt.Errorf("observer update: %s/%s sha256 %s does not match its manifest", b.Dir, f.Name, sum)
		}
	}
	return nil
}

// bundleStep is one file a bundle swap moved: the target beside the
// executable and, when an old file was there, where it went.
type bundleStep struct {
	target string
	aside  string
	// added marks a target that had no old file (the update added it).
	added string
}

// bundleAddedMarker is the empty file that records that the update added
// target (there was no old file to put back), so a restore removes it.
func bundleAddedMarker(target, oldVersion string) string {
	return asidePath(target, oldVersion) + ".added"
}

// swapBundles moves every staged bundle into place beside exePath, one file
// at a time, and returns the steps taken. On any failure it undoes the steps
// it took, so the previous set is whole, and returns the error. With nothing
// staged it does nothing.
func swapBundles(fs swapFS, staged, exePath, oldVersion string) ([]bundleStep, error) {
	root := stagedBundleRoot(staged)
	var steps []bundleStep
	for _, b := range updateBundles {
		src := filepath.Join(root, b.Dir)
		if _, err := fs.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(filepath.Dir(exePath), b.Dir)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			undoBundleSteps(fs, steps)
			return nil, fmt.Errorf("observer update: creating %s: %w", dst, err)
		}
		for _, name := range append(slices.Clone(b.Files), b.Manifest) {
			step, err := swapBundleFile(fs, filepath.Join(src, name), filepath.Join(dst, name), oldVersion)
			if err != nil {
				undoBundleSteps(fs, steps)
				return nil, err
			}
			steps = append(steps, step)
		}
	}
	_ = os.RemoveAll(root)
	return steps, nil
}

// swapBundleFile moves one staged file to target, the old one aside.
func swapBundleFile(fs swapFS, src, target, oldVersion string) (bundleStep, error) {
	step := bundleStep{target: target}
	aside := asidePath(target, oldVersion)
	marker := bundleAddedMarker(target, oldVersion)
	// The asides an earlier, completed apply left behind are no longer any
	// rollback's: removed best effort (one a process still runs stays until
	// the next apply).
	if old, _ := filepath.Glob(target + ".old-*"); len(old) > 0 {
		for _, o := range old {
			if o != aside && o != marker {
				_ = fs.Remove(o)
			}
		}
	}
	for _, leftover := range []string{aside, marker} {
		if err := fs.Remove(leftover); err != nil && !os.IsNotExist(err) {
			return step, fmt.Errorf("observer update: clearing %s: %w", leftover, err)
		}
	}
	if _, err := fs.Stat(target); err == nil {
		if err := fs.Rename(target, aside); err != nil {
			return step, fmt.Errorf("observer update: moving %s aside: %w", target, err)
		}
		step.aside = aside
	} else {
		if err := os.WriteFile(marker, nil, 0o600); err != nil {
			return step, fmt.Errorf("observer update: recording %s: %w", marker, err)
		}
		step.added = marker
	}
	if err := fs.Rename(src, target); err != nil {
		undoBundleSteps(fs, []bundleStep{step})
		return bundleStep{}, fmt.Errorf("observer update: installing %s: %w", target, err)
	}
	return step, nil
}

// undoBundleSteps reverses steps, newest first: the new file is removed and
// the old one renamed back.
func undoBundleSteps(fs swapFS, steps []bundleStep) {
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		switch {
		case s.aside != "":
			_ = fs.Remove(s.target)
			_ = fs.Rename(s.aside, s.target)
		case s.added != "":
			_ = fs.Remove(s.target)
			_ = fs.Remove(s.added)
		}
	}
}

// restoreBundles puts back the companion files an earlier swap moved aside
// (the failed-handshake rollback, beside restoreBinary): for every known
// file, an aside replaces the current file, and a file the update added is
// removed. It reports the first failure and keeps going.
func restoreBundles(fs swapFS, exePath, oldVersion string) error {
	var first error
	for _, b := range updateBundles {
		dst := filepath.Join(filepath.Dir(exePath), b.Dir)
		for _, name := range append(slices.Clone(b.Files), b.Manifest) {
			target := filepath.Join(dst, name)
			aside := asidePath(target, oldVersion)
			marker := bundleAddedMarker(target, oldVersion)
			if _, err := fs.Stat(aside); err == nil {
				if err := fs.Remove(target); err != nil && !os.IsNotExist(err) && first == nil {
					first = fmt.Errorf("observer update: restoring %s: %w", target, err)
				}
				if err := fs.Rename(aside, target); err != nil && first == nil {
					first = fmt.Errorf("observer update: restoring %s: %w", target, err)
				}
				continue
			}
			if _, err := fs.Stat(marker); err == nil {
				if err := fs.Remove(target); err != nil && !os.IsNotExist(err) && first == nil {
					first = fmt.Errorf("observer update: removing %s: %w", target, err)
				}
				_ = fs.Remove(marker)
			}
		}
	}
	return first
}

// recoverInterruptedBundles is the boot-time half of the bundle swap: a file
// whose aside exists while the file itself does not was interrupted between
// its two renames, and the aside goes back.
func recoverInterruptedBundles(fs swapFS, exePath, oldVersion string) error {
	var errs []error
	for _, b := range updateBundles {
		dst := filepath.Join(filepath.Dir(exePath), b.Dir)
		for _, name := range append(slices.Clone(b.Files), b.Manifest) {
			target := filepath.Join(dst, name)
			aside := asidePath(target, oldVersion)
			if _, err := fs.Stat(aside); err != nil {
				continue
			}
			if _, err := fs.Stat(target); err == nil {
				continue
			}
			if err := fs.Rename(aside, target); err != nil {
				errs = append(errs, fmt.Errorf("observer update: recovering %s: %w", target, err))
			}
		}
	}
	return errors.Join(errs...)
}
