package secreachsvc

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secreach"
)

// Caps on the installed Python metadata read (a project's .venv or venv).
const (
	// maxSitePackagesEntries caps the entries read from one site-packages
	// directory.
	maxSitePackagesEntries = 20000
	// maxLibEntries caps the entries read from a venv's lib directory.
	maxLibEntries = 64
	// maxRecordBytes caps one RECORD file.
	maxRecordBytes = 8 << 20
	// maxTopLevelBytes caps one top_level.txt.
	maxTopLevelBytes = 64 << 10
	// maxMetaTotalBytes caps the metadata bytes read per directory.
	maxMetaTotalBytes = 64 << 20
)

// venvNames are the virtual environment directories read under a project
// directory, in order.
var venvNames = []string{".venv", "venv"}

// PythonMeta is the installed metadata of one directory's virtual
// environments: PEP 503 normalised distribution -> the module paths it
// installs.
type PythonMeta struct {
	Provides map[string][]string
	// Dists, Bytes count what was read; Stopped names a cap that cut the
	// read short ("" when none).
	Dists   int
	Bytes   int64
	Stopped string
}

// ReadPythonMeta reads the installed metadata of dir's virtual
// environments (dir/.venv and dir/venv; site-packages under
// lib/python*/ or Lib/): each *.dist-info or *.egg-info directory's RECORD
// (else its top_level.txt), capped per file, per directory and in total,
// refusing every symbolic link on the way (a link may leave the project).
// A missing environment reads as no metadata.
func ReadPythonMeta(ctx context.Context, dir string) *PythonMeta {
	m := &PythonMeta{Provides: map[string][]string{}}
	for _, name := range venvNames {
		venv := filepath.Join(dir, name)
		if !realDir(venv) {
			continue
		}
		for _, sp := range sitePackagesDirs(venv) {
			if m.readSitePackages(ctx, sp); m.Stopped != "" {
				return m
			}
		}
	}
	return m
}

// sitePackagesDirs returns the real (not linked) site-packages
// directories of a venv: lib/python*/site-packages (POSIX) and
// Lib/site-packages (Windows).
func sitePackagesDirs(venv string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] && realDir(p) {
			seen[p] = true
			out = append(out, p)
		}
	}
	lib := filepath.Join(venv, "lib")
	if realDir(lib) {
		if entries, err := readDirCapped(lib, maxLibEntries); err == nil {
			for _, e := range entries {
				if e.IsDir() && strings.HasPrefix(e.Name(), "python") {
					add(filepath.Join(lib, e.Name(), "site-packages"))
				}
			}
		}
	}
	add(filepath.Join(venv, "Lib", "site-packages"))
	return out
}

// readSitePackages reads every metadata directory of one site-packages.
func (m *PythonMeta) readSitePackages(ctx context.Context, sp string) {
	entries, err := readDirCapped(sp, maxSitePackagesEntries+1)
	if err != nil {
		return
	}
	if len(entries) > maxSitePackagesEntries {
		m.Stopped = "max_entries"
		entries = entries[:maxSitePackagesEntries]
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if ctx.Err() != nil {
			m.Stopped = StoppedCanceled
			return
		}
		if !e.IsDir() {
			continue
		}
		dist, ok := secreach.PythonDistOfMetadataDir(e.Name())
		if !ok {
			continue
		}
		mods := m.readDist(filepath.Join(sp, e.Name()))
		if m.Stopped != "" {
			return
		}
		if len(mods) == 0 {
			continue
		}
		m.Dists++
		m.Provides[dist] = mergeSorted(m.Provides[dist], mods)
	}
}

// readDist reads one metadata directory's modules: RECORD first, else
// top_level.txt.
func (m *PythonMeta) readDist(metaDir string) []string {
	for _, f := range []struct {
		name  string
		limit int64
		parse func([]byte) []string
	}{
		{"RECORD", maxRecordBytes, secreach.PythonModulesFromRecord},
		{"top_level.txt", maxTopLevelBytes, secreach.PythonModulesFromTopLevel},
	} {
		if m.Bytes >= maxMetaTotalBytes {
			m.Stopped = "max_bytes"
			return nil
		}
		b, err := readRegularCapped(filepath.Join(metaDir, f.name), f.limit)
		if err != nil {
			continue
		}
		m.Bytes += int64(len(b))
		if mods := f.parse(b); len(mods) > 0 {
			return mods
		}
	}
	return nil
}

func mergeSorted(a, b []string) []string {
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		seen[s] = true
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > secreach.MaxDistModules {
		out = out[:secreach.MaxDistModules]
	}
	return out
}

// realDir reports a directory that is not a symbolic link.
func realDir(p string) bool {
	st, err := os.Lstat(p)
	return err == nil && st.IsDir()
}

// readDirCapped reads at most n entries of a directory (unsorted).
func readDirCapped(dir string, n int) ([]os.DirEntry, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(n)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return entries, nil
}

// readRegularCapped reads a regular file (never a symbolic link, checked
// before and after the open) of at most limit bytes.
func readRegularCapped(name string, limit int64) ([]byte, error) {
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if before.Size() > limit {
		return nil, errors.New("file over its cap")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file over its cap")
	}
	return b, nil
}
