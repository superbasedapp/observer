package sandboxrelayd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
)

// confine.go is the confined reader of the daemon path (sandbox plan
// section 5.2, the confused-deputy rule; ledger SBX-BE-2 and SBX-BE-10): a
// payload-named path is read only under the run's own roots, never
// through a symlink at any component, only as a regular file, and size
// capped. Any other path is refused with hookctx.ErrRefused, so a guest
// cannot make the host read ~/.ssh into the database (and from there onto
// the org wire under full_content).

// MaxConfinedFile caps one confined read (the largest transcript tail a
// hook reads is far below it).
const MaxConfinedFile = 16 << 20

// ConfinedFiles returns the hookctx.Files of a run over roots. An empty
// roots list refuses every path.
func ConfinedFiles(roots []string) hookctx.Files {
	c := confined{roots: cleanRoots(roots)}
	return hookctx.Files{ReadFile: c.readFile, Open: c.open, Stat: c.stat}
}

type confined struct{ roots []string }

func cleanRoots(roots []string) []string {
	var out []string
	for _, r := range roots {
		if r == "" || !filepath.IsAbs(r) {
			continue
		}
		out = append(out, filepath.Clean(r))
	}
	return out
}

// locate returns the root holding path and path relative to it, or a
// refusal.
func (c confined) locate(path string) (string, string, error) {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return "", "", refusal(path)
	}
	p := filepath.Clean(path)
	for _, r := range c.roots {
		rel, err := filepath.Rel(r, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return r, rel, nil
	}
	return "", "", refusal(path)
}

// noLinks walks rel under root with Lstat and refuses any symlink or a
// final component that is not a regular file.
func noLinks(root *os.Root, rel string) (fs.FileInfo, error) {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	cur := ""
	var fi fs.FileInfo
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		var err error
		if fi, err = root.Lstat(cur); err != nil {
			return nil, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("a symlink at %s", cur)
		}
	}
	if fi == nil || !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return fi, nil
}

func (c confined) open(path string) (hookctx.File, error) { return c.openCapped(path, MaxConfinedFile) }

// OpenConfinedTail opens path under roots by the confined reader's rules
// (no symlink at any component, a regular file, the inode checked) with no
// size cap: the transcript comparison (gatedrift.go) reads a growing
// transcript in bounded chunks from an offset, never whole.
func OpenConfinedTail(roots []string, path string) (hookctx.File, error) {
	return confined{roots: cleanRoots(roots)}.openCapped(path, 0)
}

// openCapped is open with a size cap (0: none).
func (c confined) openCapped(path string, limit int64) (hookctx.File, error) {
	r, rel, err := c.locate(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(r)
	if err != nil {
		return nil, refusal(path)
	}
	defer func() { _ = root.Close() }()
	fi, err := noLinks(root, rel)
	if err != nil || (limit > 0 && fi.Size() > limit) {
		return nil, refusal(path)
	}
	if confineBeforeOpen != nil {
		confineBeforeOpen(r, rel)
	}
	// The path is guest-writable, so what is opened may not be what Lstat
	// saw: opened without blocking, a FIFO (or a device) swapped in after
	// the check can never hold the daemon in open(2), and the descriptor
	// itself is checked below.
	f, err := root.OpenFile(rel, os.O_RDONLY|oNoFollow|oNonblock, 0)
	if err != nil {
		return nil, refusal(path)
	}
	// The file opened is the one checked: same device and inode, and a
	// regular file by the opened descriptor's own fstat.
	if got, err := f.Stat(); err != nil || !os.SameFile(got, fi) || !got.Mode().IsRegular() {
		_ = f.Close()
		return nil, refusal(path)
	}
	// A regular file reads the same either way; the flag is cleared so no
	// read ever sees EAGAIN.
	clearNonblock(f)
	return f, nil
}

// confineBeforeOpen, when set (tests only), runs between the Lstat walk and
// the open, where a hostile box would swap the file.
var confineBeforeOpen func(root, rel string)

func (c confined) readFile(path string) ([]byte, error) {
	f, err := c.open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxConfinedFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxConfinedFile {
		return nil, refusal(path)
	}
	return b, nil
}

func (c confined) stat(path string) (fs.FileInfo, error) {
	r, rel, err := c.locate(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(r)
	if err != nil {
		return nil, refusal(path)
	}
	defer func() { _ = root.Close() }()
	fi, err := noLinks(root, rel)
	if err != nil {
		return nil, refusal(path)
	}
	return fi, nil
}

func refusal(path string) error {
	return &fs.PathError{Op: "read", Path: path, Err: hookctx.ErrRefused}
}
