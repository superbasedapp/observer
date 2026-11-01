package sectrust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// OSFS returns the production FS over the repository rooted at root (an
// absolute path). It is the only file in the package that imports os
// (imports_test.go).
func OSFS(root string) FS {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		resolved = root
	}
	return osFS{root: filepath.Clean(root), resolved: filepath.Clean(resolved)}
}

type osFS struct {
	root     string
	resolved string
}

func (o osFS) abs(rel string) string {
	if rel == "" {
		return o.root
	}
	return filepath.Join(o.root, filepath.FromSlash(rel))
}

func (o osFS) Lstat(rel string) (fs.FileInfo, error) { return os.Lstat(o.abs(rel)) }

func (o osFS) Stat(rel string) (fs.FileInfo, error) { return os.Stat(o.abs(rel)) }

func (o osFS) ReadFile(rel string, max int64) ([]byte, error) {
	f, err := os.Open(o.abs(rel))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("sectrust.ReadFile: %w", err)
	}
	if int64(len(b)) > max {
		return nil, errTooLarge
	}
	return b, nil
}

func (o osFS) HashFile(rel string, max int64) (string, int64, error) {
	f, err := os.Open(o.abs(rel))
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, max+1))
	if err != nil {
		return "", 0, fmt.Errorf("sectrust.HashFile: %w", err)
	}
	if n > max {
		return "", n, errTooLarge
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Readlink reads the target text of the symlink at rel (linkReader).
func (o osFS) Readlink(rel string) (string, error) { return os.Readlink(o.abs(rel)) }

func (o osFS) ReadDir(rel string) ([]fs.DirEntry, error) { return os.ReadDir(o.abs(rel)) }

func (o osFS) Escapes(rel string) bool {
	target, err := filepath.EvalSymlinks(o.abs(rel))
	if err != nil {
		return true
	}
	r, err := filepath.Rel(o.resolved, target)
	if err != nil {
		return true
	}
	return r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r)
}
