package guidance

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

// memFS is the in-memory [FS] the scanner tests run against: a set of
// fstest.MapFS trees mounted at virtual absolute roots. Using a real FS
// implementation (rather than stubbing Scan's internals) means the tests
// exercise the same walker, depth cap and skip table production does.
type memFS struct {
	mounts map[string]fstest.MapFS
}

func newMemFS() *memFS { return &memFS{mounts: map[string]fstest.MapFS{}} }

// mount loads a directory from testdata into the tree at the virtual
// absolute path root. The fixtures are real files on disk (see
// testdata/guidance/) so the front matter under test is the front matter
// a reviewer can read.
func (m *memFS) mount(t *testing.T, root, dir string) {
	t.Helper()
	mapfs := fstest.MapFS{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		mapfs[filepath.ToSlash(rel)] = &fstest.MapFile{Data: b, Mode: 0o644}
		return nil
	})
	if err != nil {
		t.Fatalf("mount %s: %v", dir, err)
	}
	m.mounts[normalizeRoot(root)] = mapfs
}

// resolve maps an absolute path back to (mount, key). key is "." for the
// mount root itself, matching io/fs conventions.
func (m *memFS) resolve(p string) (fstest.MapFS, string, bool) {
	p = normalizeRoot(p)
	for root, mapfs := range m.mounts {
		switch {
		case p == root:
			return mapfs, ".", true
		case strings.HasPrefix(p, root+"/"):
			return mapfs, strings.TrimPrefix(p, root+"/"), true
		}
	}
	return nil, "", false
}

func (m *memFS) notExist(op, p string) error {
	return &fs.PathError{Op: op, Path: p, Err: fs.ErrNotExist}
}

func (m *memFS) Glob(pattern string) ([]string, error) {
	var out []string
	for root, mapfs := range m.mounts {
		for key := range mapfs {
			abs := root + "/" + key
			ok, err := filepath.Match(filepath.FromSlash(pattern), filepath.FromSlash(abs))
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, abs)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memFS) ReadDir(p string) ([]fs.DirEntry, error) {
	mapfs, key, ok := m.resolve(p)
	if !ok {
		return nil, m.notExist("readdir", p)
	}
	return mapfs.ReadDir(key)
}

func (m *memFS) Stat(p string) (fs.FileInfo, error) {
	mapfs, key, ok := m.resolve(p)
	if !ok {
		return nil, m.notExist("stat", p)
	}
	return mapfs.Stat(key)
}

func (m *memFS) ReadFile(p string) ([]byte, error) {
	mapfs, key, ok := m.resolve(p)
	if !ok {
		return nil, m.notExist("open", p)
	}
	return mapfs.ReadFile(key)
}
