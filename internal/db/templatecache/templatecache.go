package templatecache

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

// formatVersion is mixed into every key. Bump it when the way a template is
// built changes in a way the other key inputs cannot see, so every machine
// rebuilds instead of reusing a file made the old way.
const formatVersion = "sbo-dbtemplate-v2"

// DirName is the directory under the OS temp directory that holds the shared
// templates.
const DirName = "sbo-dbtemplates"

// sqliteDriverModule is the module of the only SQL driver the templates are
// built with (modernc.org/sqlite, registered as "sqlite").
const sqliteDriverModule = "modernc.org/sqlite"

// pruneAge is how long a template of the same lineage may go unused before a
// new build removes it.
const pruneAge = 3 * 24 * time.Hour

// lockWait bounds the wait for another binary's build. A build takes about a
// minute under -race on a loaded runner; a holder stuck for longer is treated
// as gone and this binary builds privately instead.
const lockWait = 10 * time.Minute

// sqliteHeader is the first 16 bytes of every SQLite database file.
var sqliteHeader = []byte("SQLite format 3\x00")

// baseTempDir is resolved at package init, before any test can rewrite the
// variables os.TempDir consults: tests t.Setenv TMPDIR to a t.TempDir(), and a
// template placed there would vanish at that test's end.
var baseTempDir = os.TempDir()

// Spec names one template: a lineage's migration set under one driver and
// dialect, built by one version of the migration runner.
type Spec struct {
	Lineage    string // "agent" or "org"; part of the file name
	Driver     string // the SQL driver module the template is built with
	Dialect    string // the SQL dialect of the migration set
	Migrations fs.FS  // the embedded migration directory
	// RunnerDirs are the module-relative directories whose non-test .go
	// files build the template (the lineage's runner, internal/migplan and
	// the fixture's build function), read from Source. A template built by
	// other runner code is a different key (TESTDB audit M2).
	RunnerDirs []string
	// Source is the module source tree (nil: not found, so the template is
	// built privately and never shared).
	Source fs.FS
}

// runnerDirs is the runner source of each lineage, by lineage name.
var runnerDirs = map[string][]string{
	"agent": {"internal/db", "internal/db/dbtemplate", "internal/migplan", "internal/migplan/sqliteledger"},
	"org":   {"internal/orgserver/db", "internal/orgserver/db/dbtest", "internal/migplan", "internal/migplan/sqliteledger"},
}

// SQLite returns the Spec of a lineage built with the modernc SQLite driver,
// with that lineage's runner source read from the module tree.
func SQLite(lineage string, migrations fs.FS) Spec {
	return Spec{
		Lineage: lineage, Driver: sqliteDriverModule, Dialect: "sqlite", Migrations: migrations,
		RunnerDirs: runnerDirs[lineage], Source: moduleSource(),
	}
}

// modulePath is the module whose source tree holds the runner.
const modulePath = "github.com/marmutapp/superbased-observer"

// moduleSource returns the module source tree found by walking up from the
// working directory (a test binary runs in its package directory), or nil
// when no go.mod of this module is above it.
func moduleSource() fs.FS {
	dir, err := os.Getwd()
	if err != nil {
		return nil
	}
	for {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			first, _, _ := strings.Cut(string(b), "\n")
			if strings.TrimSpace(first) == "module "+modulePath {
				return os.DirFS(dir)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// errNoRunnerSource: the runner source the key needs cannot be read, so the
// template must not be shared.
var errNoRunnerSource = errors.New("templatecache: migration runner source not found")

// Key returns the hex key of spec: a SHA-256 over the format version, the
// lineage, the driver and its module version, the dialect, the name and
// bytes of every file in spec.Migrations, in name order, and the path and
// bytes of every non-test .go file in spec.RunnerDirs, in path order.
func Key(spec Spec) (string, error) {
	if spec.Lineage == "" || strings.ContainsAny(spec.Lineage, `/\.`) {
		return "", fmt.Errorf("templatecache: invalid lineage %q", spec.Lineage)
	}
	if spec.Migrations == nil {
		return "", errors.New("templatecache: no migration set")
	}
	entries, err := fs.ReadDir(spec.Migrations, ".")
	if err != nil {
		return "", fmt.Errorf("templatecache: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", errors.New("templatecache: empty migration set")
	}
	sort.Strings(names)
	h := sha256.New()
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	for _, s := range []string{formatVersion, spec.Lineage, spec.Driver, moduleVersion(spec.Driver), spec.Dialect} {
		field(s)
	}
	for _, name := range names {
		body, err := fs.ReadFile(spec.Migrations, name)
		if err != nil {
			return "", fmt.Errorf("templatecache: read %s: %w", name, err)
		}
		field(name)
		field(string(body))
	}
	if len(spec.RunnerDirs) > 0 {
		if spec.Source == nil {
			return "", errNoRunnerSource
		}
		dirs := append([]string(nil), spec.RunnerDirs...)
		sort.Strings(dirs)
		for _, d := range dirs {
			ents, err := fs.ReadDir(spec.Source, d)
			if err != nil {
				return "", fmt.Errorf("%w: %w", errNoRunnerSource, err)
			}
			n := 0
			for _, e := range ents {
				name := e.Name()
				if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
					continue
				}
				body, err := fs.ReadFile(spec.Source, d+"/"+name)
				if err != nil {
					return "", fmt.Errorf("%w: %w", errNoRunnerSource, err)
				}
				field(d + "/" + name)
				field(string(body))
				n++
			}
			if n == 0 {
				return "", fmt.Errorf("%w: no Go file in %s", errNoRunnerSource, d)
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:32], nil
}

// moduleVersion is the version of module in this binary's build info, or
// "unknown" when the binary carries none.
func moduleVersion(module string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == module {
			if dep.Replace != nil {
				return dep.Replace.Path + "@" + dep.Replace.Version
			}
			return dep.Version
		}
	}
	return "unknown"
}

// BuildFunc creates a fully migrated database at path and closes it, leaving
// a single self-contained file (the write-ahead log folded back in).
type BuildFunc func(path string) error

// Image returns the template bytes for spec. It reads the shared file when one
// exists for spec's key, and otherwise builds it once with build under the
// key's lock. When the shared directory cannot be used it builds in a
// process-private directory instead; the only error returned is a failed
// build.
func Image(spec Spec, build BuildFunc) ([]byte, error) {
	key, err := Key(spec)
	if errors.Is(err, errNoRunnerSource) {
		return private(build)
	}
	if err != nil {
		return nil, err
	}
	if image, err := shared(spec.Lineage, key, build); err == nil {
		return image, nil
	} else if errors.Is(err, errBuild) {
		return nil, err
	}
	return private(build)
}

// errBuild marks a failure of the build itself, which a private build would
// only repeat.
var errBuild = errors.New("templatecache: build failed")

// Dir is the shared template directory.
func Dir() string { return filepath.Join(baseTempDir, DirName) }

// shared serves the template from the shared directory, building it there
// when needed.
func shared(lineage, key string, build BuildFunc) ([]byte, error) {
	dir := Dir()
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	base := filepath.Join(dir, lineage+"-"+key)
	final := base + ".db"
	unlock, err := lockPath(base+".lock", lockWait)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if image, err := readValid(final); err == nil {
		now := time.Now()
		_ = os.Chtimes(final, now, now) // keeps an active template out of the prune
		return image, nil
	}
	_ = os.Remove(final)

	tmp := base + ".tmp-" + strconv.Itoa(os.Getpid())
	removeDB(tmp)
	if err := build(tmp); err != nil {
		removeDB(tmp)
		return nil, fmt.Errorf("%w: %w", errBuild, err)
	}
	if err := checkBuilt(tmp); err != nil {
		removeDB(tmp)
		return nil, fmt.Errorf("%w: %w", errBuild, err)
	}
	// The bytes reach the disk before the name does, so a host that stops
	// right after the rename never leaves a short file at the key (TESTDB
	// audit M1); readValid still rejects one by its header size.
	if err := syncFile(tmp); err != nil {
		removeDB(tmp)
		return nil, err
	}
	renameErr := os.Rename(tmp, final)
	removeDB(tmp)
	if renameErr != nil {
		return nil, fmt.Errorf("templatecache: rename: %w", renameErr)
	}
	syncDir(dir)
	image, err := readValid(final)
	if err != nil {
		return nil, err
	}
	prune(dir, lineage, key)
	return image, nil
}

// private builds the template in a process-private directory and returns its
// bytes; the directory is removed before returning.
func private(build BuildFunc) ([]byte, error) {
	dir, err := os.MkdirTemp(baseTempDir, "observer-db-template-")
	if err != nil {
		return nil, fmt.Errorf("templatecache: mkdtemp: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "template.db")
	if err := build(path); err != nil {
		return nil, fmt.Errorf("%w: %w", errBuild, err)
	}
	if err := checkBuilt(path); err != nil {
		return nil, fmt.Errorf("%w: %w", errBuild, err)
	}
	return readValid(path)
}

// checkBuilt confirms a build left one self-contained file: a non-empty
// write-ahead log would hold migrations the main file lacks.
func checkBuilt(path string) error {
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() > 0 {
		return errors.New("template database left a non-empty -wal after close")
	}
	return nil
}

// readValid reads path and checks it is a whole SQLite database file: the
// header string, and a length equal to the page size (header bytes 16-17,
// 1 meaning 65536) times the page count (bytes 28-31) the header records. A
// file cut short after a host freeze keeps its header but not its length,
// and is rebuilt instead of being served (TESTDB audit M1).
func readValid(path string) ([]byte, error) {
	image, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(image) < 512 || !bytes.HasPrefix(image, sqliteHeader) {
		return nil, fmt.Errorf("templatecache: %s is not a SQLite database", filepath.Base(path))
	}
	pageSize := int64(binary.BigEndian.Uint16(image[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("templatecache: %s: invalid page size %d", filepath.Base(path), pageSize)
	}
	pages := int64(binary.BigEndian.Uint32(image[28:32]))
	if want := pageSize * pages; pages == 0 || int64(len(image)) != want {
		return nil, fmt.Errorf("templatecache: %s is %d bytes, its header says %d pages of %d (%d bytes)", filepath.Base(path), len(image), pages, pageSize, want)
	}
	return image, nil
}

// syncFile flushes path's bytes to the disk.
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("templatecache: sync: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("templatecache: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("templatecache: sync: %w", err)
	}
	return nil
}

// syncDir flushes the directory entry of a rename where the OS supports it
// (not Windows, where opening a directory for sync fails); best effort, as
// readValid rejects a short file either way.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// removeDB removes path and its SQLite sidecars.
func removeDB(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		_ = os.Remove(p)
	}
}

// prune removes the lineage's other templates, locks and leftover temporary
// files that have not been used for pruneAge. A removed lock can at worst let
// two binaries build the same key at once, which the atomic rename makes safe.
func prune(dir, lineage, keep string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-pruneAge)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, lineage+"-") || strings.HasPrefix(name, lineage+"-"+keep+".") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}
