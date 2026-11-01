package hostfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// MaxBytes caps the read of a host config file.
const MaxBytes int64 = 4 << 20

// BackupKeep is how many displaced copies of a file the backup ring keeps.
const BackupKeep = 5

// ErrNoHostDir is the refusal of an edit whose directory does not exist:
// the host app has not created it, so there is nothing to wire.
var ErrNoHostDir = errors.New("the host's config directory does not exist")

// ErrLink is the refusal of an edit whose directory or file is a symbolic
// link.
var ErrLink = errors.New("a symbolic link is not followed")

// Edit is one member edit of one file.
type Edit struct {
	// Path is the file.
	Path string
	// Format is the file's syntax (JSON or JSONC).
	Format cfgfmt.Format
	// Member is the object-key path of the member.
	Member []string
	// Value is the member's new value (ignored when Remove is set).
	Value any
	// Remove deletes the member instead.
	Remove bool
	// DryRun computes the result without writing.
	DryRun bool
	// NoBackup skips the displaced-copy backup. Set it for a file that may
	// hold a credential: the credential-file rule is no backup copy beside
	// the file (internal/hook credentialfile.go, mcpregister's
	// writeCredentialMCPFile), so a plaintext key is never duplicated.
	NoBackup bool
}

// Result says what an edit did.
type Result struct {
	// Changed reports whether the file's bytes changed (or would, on a dry
	// run).
	Changed bool
	// Created reports that the file did not exist before.
	Created bool
	// Backup is the displaced copy of the prior bytes ("" when none was
	// taken: a new file, an unchanged one, or a dry run).
	Backup string
}

// Apply runs e. A removal from a file that does not exist is a no-op.
func Apply(e Edit) (Result, error) {
	var res Result
	if len(e.Member) == 0 {
		return res, credfile.SafeErrorf("hostfile: %s: no member named", e.Path)
	}
	dir := filepath.Dir(e.Path)
	if err := realDir(dir); err != nil {
		return res, err
	}
	orig, mode, exists, err := readFile(e.Path)
	if err != nil {
		return res, err
	}
	if !exists {
		if e.Remove {
			return res, nil
		}
		res.Created = true
	}
	base := orig
	if len(bytes.TrimSpace(base)) == 0 {
		base = []byte("{}\n")
	}
	out, err := credfile.SetMember(e.Format, base, e.Member, e.Value, !e.Remove)
	if err != nil {
		return res, credfile.Withhold("hostfile edit", e.Path, err)
	}
	if exists && bytes.Equal(out, orig) {
		return res, nil
	}
	res.Changed = true
	if e.DryRun {
		return res, nil
	}
	if err := testwriteguard.Check("write", e.Path); err != nil {
		return res, err
	}
	if exists && !e.NoBackup {
		aside, err := fsatomic.KeepDisplacedCopy(e.Path, orig, time.Now(), BackupKeep)
		if err != nil {
			return res, fmt.Errorf("hostfile: back up %s: %w", e.Path, err)
		}
		res.Backup = aside
	}
	if err := fsatomic.WriteFile(e.Path, out, fsatomic.Options{Fsync: true, FilePerm: mode, TempPattern: ".observer-*.tmp"}); err != nil {
		return res, fmt.Errorf("hostfile: write %s: %w", e.Path, err)
	}
	return res, nil
}

// Value reads the member at member in path: found is false when the file
// or the member is absent. The value is returned to the caller, never put in
// an error.
func Value(path string, f cfgfmt.Format, member []string) (value any, found bool, err error) {
	if err := realDir(filepath.Dir(path)); err != nil {
		return nil, false, err
	}
	orig, _, exists, err := readFile(path)
	if err != nil || !exists || len(bytes.TrimSpace(orig)) == 0 {
		return nil, false, err
	}
	v, ok, err := credfile.MemberValue(f, orig, member)
	if err != nil {
		return nil, false, credfile.SafeErrorf("hostfile: %s does not parse as %s", path, f)
	}
	return v, ok, nil
}

// realDir refuses a directory that is absent, not a directory, or reached
// through a symbolic link anywhere below its trusted anchor (FU-198): every
// component from the anchor down to dir is Lstat'ed without following it, so
// a link at a middle component (~/Library/Application Support -> elsewhere)
// is refused as ErrLink, not only one at dir itself. A missing component is
// still ErrNoHostDir (the host app has not created it). The anchor is the
// user's home or the OS temp directory, whichever contains dir (the longer
// one), else the volume root: the layout above a home (macOS /var ->
// /private/var, a /home -> /usr/home mount) is the system's, not an
// attacker's, and is not judged.
func realDir(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("hostfile: %s: %w", dir, err)
	}
	for _, p := range dirChain(abs, trustedAnchor(abs)) {
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("hostfile: %s: %w", dir, ErrNoHostDir)
		case err != nil:
			return fmt.Errorf("hostfile: %s: %w", dir, err)
		case fi.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("hostfile: %s: %s: %w", dir, p, ErrLink)
		case !fi.IsDir():
			return fmt.Errorf("hostfile: %s: %w", dir, ErrNoHostDir)
		}
	}
	return nil
}

// anchorRoots are the directories whose own path realDir trusts (a seam for
// tests).
var anchorRoots = func() []string {
	var out []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out, home)
	}
	return append(out, os.TempDir())
}

// trustedAnchor returns the longest anchor root that is a proper ancestor of
// dir, "" when none is.
func trustedAnchor(dir string) string {
	best := ""
	for _, root := range anchorRoots() {
		root = filepath.Clean(root)
		if !filepath.IsAbs(root) || root == dir || len(root) <= len(best) {
			continue
		}
		if rel, err := filepath.Rel(root, dir); err == nil && rel != "." && !filepath.IsAbs(rel) &&
			rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			best = root
		}
	}
	return best
}

// dirChain lists every directory from the child of anchor (or of the volume
// root when anchor is "") down to dir, dir last. dir is absolute and clean.
func dirChain(dir, anchor string) []string {
	var chain []string
	for p := dir; ; {
		if p == anchor {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		chain = append(chain, p)
		p = parent
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// readFile reads path through the bounded no-follow regular-file read: the
// bytes, the permission bits to keep (0600 for a new file) and whether it
// exists. One descriptor opened without following a link judges the file
// (regularfile.ReadNoFollow), and the bits are that descriptor's, so a link
// or a FIFO swapped in after a path stat is refused, never read through. A
// file that is absent (or removed before the open) is a new file; a link at
// the path is refused as ErrLink.
func readFile(path string) ([]byte, os.FileMode, bool, error) {
	b, fi, err := regularfile.ReadNoFollow(path, MaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0o600, false, nil
	}
	if err != nil {
		if lfi, lerr := os.Lstat(path); lerr == nil && lfi.Mode()&os.ModeSymlink != 0 {
			return nil, 0, false, fmt.Errorf("hostfile: %s: %w", path, ErrLink)
		}
		return nil, 0, false, fmt.Errorf("hostfile: read %s: %w", path, err)
	}
	return b, fi.Mode().Perm(), true, nil
}
