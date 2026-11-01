package secpostwrite

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Read refusals. Each is a reason the file is not scanned, recorded as
// such, never as clean.
var (
	ErrOutsideRoot = errors.New("secpostwrite: path outside the project root")
	ErrSymlink     = errors.New("secpostwrite: path is a symlink")
	ErrNotRegular  = errors.New("secpostwrite: not a regular file")
	ErrTooLarge    = errors.New("secpostwrite: file over the post-write cap")
	ErrReplaced    = errors.New("secpostwrite: file replaced while it was opened")
)

// ReadFile reads root/rel for a scan under the rules of the package doc.
// rel is slash-separated and project-relative. maxBytes is the cap.
func ReadFile(root, rel string, maxBytes int) ([]byte, error) {
	b, err := readOnce(root, rel, maxBytes)
	if errors.Is(err, ErrReplaced) {
		b, err = readOnce(root, rel, maxBytes)
	}
	return b, err
}

func readOnce(root, rel string, maxBytes int) ([]byte, error) {
	full, err := within(root, rel)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(full)
	if err != nil {
		return nil, fmt.Errorf("secpostwrite.ReadFile: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, ErrSymlink
	}
	if !st.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	if maxBytes > 0 && st.Size() > int64(maxBytes) {
		return nil, ErrTooLarge
	}
	f, err := openNoFollow(full)
	if err != nil {
		return nil, fmt.Errorf("secpostwrite.ReadFile: %w", err)
	}
	defer f.Close()
	fst, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("secpostwrite.ReadFile: %w", err)
	}
	if !os.SameFile(st, fst) {
		return nil, ErrReplaced
	}
	limit := int64(maxBytes)
	if limit <= 0 {
		limit = fst.Size()
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("secpostwrite.ReadFile: %w", err)
	}
	if maxBytes > 0 && len(b) > maxBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}

// within returns the absolute path of rel under root after checking that
// neither rel nor a symlinked directory on the way leaves the root.
func within(root, rel string) (string, error) {
	if root == "" || rel == "" || filepath.IsAbs(rel) || strings.HasPrefix(filepath.ToSlash(rel), "/") {
		return "", ErrOutsideRoot
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", ErrOutsideRoot
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("secpostwrite: root: %w", err)
	}
	full := filepath.Join(root, clean)
	dir, err := filepath.EvalSymlinks(filepath.Dir(full))
	if err != nil {
		return "", fmt.Errorf("secpostwrite: dir: %w", err)
	}
	r, err := filepath.Rel(realRoot, dir)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", ErrOutsideRoot
	}
	return filepath.Join(dir, filepath.Base(full)), nil
}
