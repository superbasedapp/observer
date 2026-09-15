package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// maxMemberBytes caps how many bytes are hashed out of one archive
// member. The observer binary is ~60 MB; 512 MB is far above any
// plausible growth and far below "a decompression bomb makes the
// release job OOM".
const maxMemberBytes = 512 << 20

// archiveEntries builds the abstract entry list update.SelectMember
// reasons over, for either archive shape.
//
// Entry names are normalized exactly as the NODE normalizes them
// (cmd/observer/update_archive.go: separators to "/", a trailing "/"
// dropped), and no further: a producer that were more forgiving than
// the verifier would happily emit a manifest the fleet cannot apply.
func archiveEntries(path, archiveType string) ([]update.Entry, error) {
	switch archiveType {
	case "tar.gz":
		return tarEntries(path)
	case "zip":
		return zipEntries(path)
	default:
		return nil, fmt.Errorf("vendorsign: unknown archive_type %q for %s", archiveType, path)
	}
}

// tarEntries walks a .tar.gz header by header.
func tarEntries(path string) ([]update.Entry, error) {
	f, err := os.Open(path) //nolint:gosec // a release-asset path this tool was pointed at
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("vendorsign: %s: %w", path, err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	var out []update.Entry
	for {
		h, rerr := tr.Next()
		if errors.Is(rerr, io.EOF) {
			return out, nil
		}
		if rerr != nil {
			return nil, fmt.Errorf("vendorsign: %s: %w", path, rerr)
		}
		out = append(out, update.Entry{
			Name:       cleanArchiveName(h.Name),
			Kind:       tarEntryKind(h),
			LinkTarget: h.Linkname,
			Size:       h.Size,
		})
	}
}

// tarEntryKind maps a tar header onto the abstract kind vocabulary.
// Everything exotic collapses onto EntryOther, which SelectMember
// refuses — the safe direction for a kind this producer has never seen.
func tarEntryKind(h *tar.Header) update.EntryKind {
	switch h.Typeflag {
	case tar.TypeReg:
		return update.EntryFile
	case tar.TypeDir:
		return update.EntryDir
	case tar.TypeSymlink, tar.TypeLink:
		return update.EntrySymlink
	default:
		return update.EntryOther
	}
}

// zipEntries reads a zip's central directory.
func zipEntries(path string) ([]update.Entry, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("vendorsign: %s: %w", path, err)
	}
	defer func() { _ = zr.Close() }()
	out := make([]update.Entry, 0, len(zr.File))
	for _, f := range zr.File {
		out = append(out, update.Entry{
			Name: cleanArchiveName(f.Name),
			Kind: zipEntryKind(f),
			Size: int64(f.UncompressedSize64), //nolint:gosec // bounded by maxMemberBytes when read
		})
	}
	return out, nil
}

// zipEntryKind maps a zip entry onto the abstract kind vocabulary. A
// zip symlink is reported AS a symlink so SelectMember can refuse it
// (ErrSymlinkInZip) rather than this producer quietly accepting a shape
// the node rejects.
func zipEntryKind(f *zip.File) update.EntryKind {
	mode := f.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		return update.EntrySymlink
	case f.FileInfo().IsDir():
		return update.EntryDir
	case mode.IsRegular():
		return update.EntryFile
	default:
		return update.EntryOther
	}
}

// hashMember returns the hex sha256 of the binary INSIDE an archive,
// after the archive has passed the SAME pure selection rules the node's
// apply path uses (update.SelectMember).
//
// Reading the member out of the finished archive is the point. The CI
// job has the loose binary right there and could hash that instead, but
// then member_sha256 would attest to a file the release does not ship;
// hashing through the archive proves the shipped bytes are the bytes
// the manifest names, and it makes the producer refuse an archive the
// fleet would refuse (an unlisted member, a traversal, a symlink in a
// zip) at BUILD time rather than at a customer's first ring.
func hashMember(path string, a update.Artifact, entries []update.Entry) (string, error) {
	sel, err := update.SelectMember(a, entries)
	if err != nil {
		return "", fmt.Errorf("vendorsign: %s: %w", a.Filename, err)
	}
	switch a.ArchiveType {
	case "tar.gz":
		return hashTarMember(path, a, sel.Member.Name)
	case "zip":
		return hashZipMember(path, a, sel.Member.Name)
	default:
		return "", fmt.Errorf("vendorsign: unknown archive_type %q for %s", a.ArchiveType, a.Filename)
	}
}

// hashTarMember re-reads the tar and hashes the chosen member. It is a
// SECOND pass because the selection rules are whole-archive rules — "an
// entry the manifest does not name" cannot be decided while still
// reading — and a tar has no directory to seek by.
func hashTarMember(path string, a update.Artifact, member string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // a release-asset path this tool was pointed at
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("vendorsign: %s: %w", a.Filename, err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		h, rerr := tr.Next()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return "", fmt.Errorf("vendorsign: %s: %w", a.Filename, rerr)
		}
		if cleanArchiveName(h.Name) != member {
			continue
		}
		return hashReader(tr)
	}
	return "", fmt.Errorf("vendorsign: %s: member %q vanished between passes", a.Filename, member)
}

// hashZipMember is the zip half.
func hashZipMember(path string, a update.Artifact, member string) (string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("vendorsign: %s: %w", a.Filename, err)
	}
	defer func() { _ = zr.Close() }()
	for _, f := range zr.File {
		if cleanArchiveName(f.Name) != member {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			return "", fmt.Errorf("vendorsign: %s: %w", a.Filename, oerr)
		}
		sum, herr := hashReader(rc)
		_ = rc.Close()
		return sum, herr
	}
	return "", fmt.Errorf("vendorsign: %s: member %q not found", a.Filename, member)
}

// hashReader hashes at most maxMemberBytes from r, refusing a stream
// that still has bytes at the ceiling rather than silently hashing a
// truncation.
func hashReader(r io.Reader) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, maxMemberBytes+1))
	if err != nil {
		return "", fmt.Errorf("vendorsign: hash member: %w", err)
	}
	if n > maxMemberBytes {
		return "", fmt.Errorf("vendorsign: archive member exceeds %d bytes", int64(maxMemberBytes))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// cleanArchiveName normalizes an entry name the way the node does:
// backslashes to slashes, trailing "/" dropped. It deliberately does
// NOT strip a "./" prefix, because the node does not either — see
// deriveCompanions for why the release pipeline stopped producing one.
func cleanArchiveName(name string) string {
	return strings.TrimSuffix(strings.ReplaceAll(name, `\`, "/"), "/")
}

// hashFile returns the hex sha256 and byte size of a file on disk.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path) //nolint:gosec // a release-asset path this tool was pointed at
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("vendorsign: hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
