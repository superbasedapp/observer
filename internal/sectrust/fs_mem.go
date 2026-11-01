package sectrust

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// MemFS returns an FS over an in-memory tree: files maps slash paths
// relative to the repository root to their bytes; every directory on a
// file's path exists. It holds no symlinks, so nothing escapes. The CI
// verify detector runs the check over the files a change adds through it
// (internal/secverify, detector repo_trust).
func MemFS(files map[string][]byte) FS {
	m := memFS{files: map[string][]byte{}, dirs: map[string]map[string]bool{"": {}}}
	for p, b := range files {
		p = strings.Trim(path.Clean("/"+strings.ReplaceAll(p, `\`, "/")), "/")
		if p == "" {
			continue
		}
		m.files[p] = b
		child := p
		for {
			dir := path.Dir(child)
			if dir == "." {
				dir = ""
			}
			if m.dirs[dir] == nil {
				m.dirs[dir] = map[string]bool{}
			}
			m.dirs[dir][path.Base(child)] = true
			if dir == "" {
				break
			}
			child = dir
		}
	}
	return m
}

type memFS struct {
	files map[string][]byte
	dirs  map[string]map[string]bool
}

// memInfo is a file or directory of a memFS.
type memInfo struct {
	name string
	size int64
	dir  bool
}

func (i memInfo) Name() string { return i.name }
func (i memInfo) Size() int64  { return i.size }
func (i memInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (i memInfo) ModTime() time.Time         { return time.Time{} }
func (i memInfo) IsDir() bool                { return i.dir }
func (i memInfo) Sys() any                   { return nil }
func (i memInfo) Type() fs.FileMode          { return i.Mode().Type() }
func (i memInfo) Info() (fs.FileInfo, error) { return i, nil }

func (m memFS) Lstat(rel string) (fs.FileInfo, error) {
	if b, ok := m.files[rel]; ok {
		return memInfo{name: path.Base(rel), size: int64(len(b))}, nil
	}
	if _, ok := m.dirs[rel]; ok {
		return memInfo{name: path.Base(rel), dir: true}, nil
	}
	return nil, fs.ErrNotExist
}

func (m memFS) Stat(rel string) (fs.FileInfo, error) { return m.Lstat(rel) }

func (m memFS) ReadFile(rel string, max int64) ([]byte, error) {
	b, ok := m.files[rel]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if int64(len(b)) > max {
		return nil, errTooLarge
	}
	return b, nil
}

func (m memFS) HashFile(rel string, max int64) (string, int64, error) {
	b, ok := m.files[rel]
	if !ok {
		return "", 0, fs.ErrNotExist
	}
	if int64(len(b)) > max {
		return "", int64(len(b)), errTooLarge
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), int64(len(b)), nil
}

func (m memFS) ReadDir(rel string) ([]fs.DirEntry, error) {
	kids, ok := m.dirs[rel]
	if !ok {
		return nil, fs.ErrNotExist
	}
	names := make([]string, 0, len(kids))
	for n := range kids {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		child := joinRel(rel, n)
		_, isDir := m.dirs[child]
		out = append(out, memInfo{name: n, size: int64(len(m.files[child])), dir: isDir})
	}
	return out, nil
}

func (m memFS) Escapes(string) bool { return false }
