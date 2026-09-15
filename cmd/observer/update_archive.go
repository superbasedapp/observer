package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_archive.go extracts the ONE named binary out of a downloaded
// artifact (§3.7 step 4 of
// docs/plans/enterprise-update-management-plan-2026-09-07.md).
//
// The SAFETY RULES ARE NOT IMPLEMENTED HERE. update.SelectMember owns them —
// take the manifest's `member`, skip its declared `alias_members`, and refuse
// an unlisted member, an absolute path, a `..` traversal, an escaping or
// wrong-target symlink, a duplicate name or an exotic entry kind. This file
// owns only the two readers that turn a real tar.gz / zip into the abstract
// entry list that pure function judges, which is precisely why that package
// models entries abstractly: the org server's importer
// (internal/orgserver/updateartifact/member.go) does the same conversion for
// its own purpose, and a rule fixed in update.SelectMember is fixed for both
// with no chance of them disagreeing about what a safe archive is.
//
// Two passes over the archive, not one. "An entry the manifest does not name"
// is a WHOLE-ARCHIVE property and cannot be decided while still reading:
// deciding it early would let a malicious extra member land on disk before
// the rule that rejects it had run.

// maxExtractedMemberBytes caps the DECOMPRESSED member. The manifest's
// size_bytes already bounds the compressed download; this bounds the
// expansion, which is the separate hazard — a zip bomb is small on disk.
const maxExtractedMemberBytes int64 = 1 << 30

// extractMember writes the artifact's named member to dest and returns its
// hex sha256. dest is created with mode 0o755 (the binary must be
// executable) and is replaced if it already exists, so a retried apply does
// not inherit a partial file from the previous attempt.
func extractMember(archivePath, dest string, a update.Artifact) (string, error) {
	switch a.ArchiveType {
	case update.ArchiveTarGz:
		return extractTarMember(archivePath, dest, a)
	case update.ArchiveZip:
		return extractZipMember(archivePath, dest, a)
	default:
		return "", fmt.Errorf("observer update: unknown archive_type %q", a.ArchiveType)
	}
}

// extractTarMember handles the POSIX tarball the release pipeline emits for
// linux/darwin — the one carrying a relative `superbased -> observer`
// symlink, which is why alias handling is a rule and not an afterthought.
func extractTarMember(archivePath, dest string, a update.Artifact) (string, error) {
	entries, err := tarArchiveEntries(archivePath)
	if err != nil {
		return "", err
	}
	sel, err := update.SelectMember(a, entries)
	if err != nil {
		return "", fmt.Errorf("observer update: %w", err)
	}
	f, err := os.Open(archivePath) //nolint:gosec // a path this process composed under state_dir
	if err != nil {
		return "", fmt.Errorf("observer update: open archive: %w", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("observer update: gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("observer update: tar: %w", err)
		}
		if cleanArchiveEntryName(h.Name) != sel.Member.Name {
			continue
		}
		return writeMember(dest, tr)
	}
	return "", fmt.Errorf("observer update: member %q vanished between passes over %s", sel.Member.Name, filepath.Base(archivePath))
}

// extractZipMember handles the win32 zip, which carries a COPIED
// superbased.exe beside observer.exe because zip symlink support is
// unreliable across extractors.
func extractZipMember(archivePath, dest string, a update.Artifact) (string, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("observer update: zip: %w", err)
	}
	defer func() { _ = zr.Close() }()
	entries := make([]update.Entry, 0, len(zr.File))
	for _, f := range zr.File {
		e := update.Entry{Name: cleanArchiveEntryName(f.Name)}
		switch {
		case f.FileInfo().IsDir():
			e.Kind = update.EntryDir
		case f.Mode()&os.ModeSymlink != 0:
			// A symlink inside a zip is refused by the rules; carry the
			// kind faithfully so the REFUSAL comes from the rule table and
			// not from this loop quietly dropping it.
			e.Kind = update.EntrySymlink
		default:
			e.Kind = update.EntryFile
		}
		entries = append(entries, e)
	}
	sel, err := update.SelectMember(a, entries)
	if err != nil {
		return "", fmt.Errorf("observer update: %w", err)
	}
	for _, f := range zr.File {
		if cleanArchiveEntryName(f.Name) != sel.Member.Name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("observer update: zip member: %w", err)
		}
		sum, err := writeMember(dest, rc)
		_ = rc.Close()
		return sum, err
	}
	return "", fmt.Errorf("observer update: member %q vanished between passes over %s", sel.Member.Name, filepath.Base(archivePath))
}

// tarArchiveEntries builds the abstract entry list for the selection rules.
func tarArchiveEntries(path string) ([]update.Entry, error) {
	f, err := os.Open(path) //nolint:gosec // a path this process composed under state_dir
	if err != nil {
		return nil, fmt.Errorf("observer update: open archive: %w", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("observer update: gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var entries []update.Entry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("observer update: tar: %w", err)
		}
		e := update.Entry{Name: cleanArchiveEntryName(h.Name), LinkTarget: h.Linkname}
		switch h.Typeflag {
		case tar.TypeDir:
			e.Kind = update.EntryDir
		case tar.TypeReg:
			e.Kind = update.EntryFile
		case tar.TypeSymlink, tar.TypeLink:
			e.Kind = update.EntrySymlink
		default:
			e.Kind = update.EntryOther
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// writeMember streams one member to dest with the decompression ceiling
// applied, then hashes what it wrote.
//
// It hashes the BYTES ON DISK rather than the bytes in flight, because the
// value being checked is the file the node is about to execute — a hash of a
// stream that was then truncated by a full disk would be a hash of something
// that no longer exists.
func writeMember(dest string, r io.Reader) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", fmt.Errorf("observer update: staging dir: %w", err)
	}
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("observer update: clearing %s: %w", dest, err)
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) //nolint:gosec // an executable, deliberately 0755
	if err != nil {
		return "", fmt.Errorf("observer update: create %s: %w", dest, err)
	}
	limited := io.LimitReader(r, maxExtractedMemberBytes+1)
	n, err := io.Copy(out, limited)
	closeErr := out.Close()
	if err != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("observer update: extract: %w", err)
	}
	if closeErr != nil {
		_ = os.Remove(dest)
		return "", fmt.Errorf("observer update: extract: %w", closeErr)
	}
	if n > maxExtractedMemberBytes {
		_ = os.Remove(dest)
		return "", fmt.Errorf("observer update: extracted member exceeds %d bytes", maxExtractedMemberBytes)
	}
	return sha256File(dest)
}

// sha256File hashes a file on disk.
func sha256File(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // a path this process composed under state_dir
	if err != nil {
		return "", fmt.Errorf("observer update: hash %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("observer update: hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cleanArchiveEntryName normalises separators so a zip written on Windows and
// a tar written on Linux present the same names to the selection rules.
func cleanArchiveEntryName(name string) string {
	return strings.TrimSuffix(strings.ReplaceAll(name, `\`, "/"), "/")
}
