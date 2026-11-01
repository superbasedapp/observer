package templatecache

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

func lineage(files map[string]string) fs.FS {
	m := fstest.MapFS{}
	for name, body := range files {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

// withDir points the package at a private temp directory for one test.
func withDir(t *testing.T) string {
	t.Helper()
	old := baseTempDir
	baseTempDir = t.TempDir()
	t.Cleanup(func() { baseTempDir = old })
	return Dir()
}

// fakeImage is a minimal file with a SQLite header whose page size (512)
// and page count (3) match its length, filled with marker.
func fakeImage(marker byte) []byte {
	image := bytes.Repeat([]byte{marker}, 3*512)
	copy(image, sqliteHeader)
	binary.BigEndian.PutUint16(image[16:18], 512)
	binary.BigEndian.PutUint32(image[28:32], 3)
	return image
}

// fakeDB is a build function that writes fakeImage and counts its calls.
func fakeDB(calls *atomic.Int32, marker byte) BuildFunc {
	return func(path string) error {
		calls.Add(1)
		return os.WriteFile(path, fakeImage(marker), 0o600)
	}
}

// TestKeyChangesWithEveryInput pins that a template is never shared across
// migration sets, drivers, dialects or lineages, and is shared otherwise.
//
// It uses the agent lineage, whose runner source ships on both trees; the
// org lineage's runner (internal/orgserver/db) is private-only.
func TestKeyChangesWithEveryInput(t *testing.T) {
	base := SQLite("agent", lineage(map[string]string{"001_a.sql": "CREATE TABLE a (x);", "002_b.sql": "CREATE TABLE b (x);"}))
	baseKey, err := Key(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		spec Spec
		same bool
	}{
		{name: "identical", spec: SQLite("agent", lineage(map[string]string{"002_b.sql": "CREATE TABLE b (x);", "001_a.sql": "CREATE TABLE a (x);"})), same: true},
		{name: "changed body", spec: SQLite("agent", lineage(map[string]string{"001_a.sql": "CREATE TABLE a (y);", "002_b.sql": "CREATE TABLE b (x);"}))},
		{name: "added migration", spec: SQLite("agent", lineage(map[string]string{"001_a.sql": "CREATE TABLE a (x);", "002_b.sql": "CREATE TABLE b (x);", "003_c.sql": ""}))},
		{name: "renamed migration", spec: SQLite("agent", lineage(map[string]string{"001_a.sql": "CREATE TABLE a (x);", "003_b.sql": "CREATE TABLE b (x);"}))},
		// Same runner and migrations, another lineage name: the name alone
		// keeps two lineages' templates apart.
		{name: "other lineage", spec: Spec{Lineage: "other", Driver: base.Driver, Dialect: base.Dialect, Migrations: base.Migrations, RunnerDirs: base.RunnerDirs, Source: base.Source}},
		{name: "other driver", spec: Spec{Lineage: "agent", Driver: "github.com/jackc/pgx/v5", Dialect: "sqlite", Migrations: base.Migrations}},
		{name: "other dialect", spec: Spec{Lineage: "agent", Driver: base.Driver, Dialect: "postgres", Migrations: base.Migrations}},
		{name: "name and body boundary", spec: SQLite("agent", lineage(map[string]string{"001_a.sqlCREATE TABLE a (x);": "", "002_b.sql": "CREATE TABLE b (x);"}))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := Key(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if (key == baseKey) != tc.same {
				t.Fatalf("key equal to base = %v, want %v", key == baseKey, tc.same)
			}
		})
	}
	for _, bad := range []Spec{SQLite("", base.Migrations), SQLite("../x", base.Migrations), SQLite("agent", nil), SQLite("agent", lineage(nil))} {
		if _, err := Key(bad); err == nil {
			t.Errorf("Key(%q) accepted an invalid spec", bad.Lineage)
		}
	}
}

// TestImageBuildsOnceAndIsReused is the point of the package: the second
// caller (a later test binary) reads the file the first one built.
func TestImageBuildsOnceAndIsReused(t *testing.T) {
	dir := withDir(t)
	// The agent lineage: its runner source ships on both trees.
	spec := SQLite("agent", lineage(map[string]string{"001_a.sql": "x"}))
	var calls atomic.Int32
	first, err := Image(spec, fakeDB(&calls, 'a'))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Image(spec, fakeDB(&calls, 'b'))
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !bytes.Equal(first, second) {
		t.Fatalf("builds = %d, images equal = %v; want one build reused", calls.Load(), bytes.Equal(first, second))
	}
	key, _ := Key(spec)
	if _, err := os.Stat(filepath.Join(dir, "agent-"+key+".db")); err != nil {
		t.Fatalf("shared template not at its keyed path: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*"))
	if len(matches) != 0 {
		t.Fatalf("temporary build files left behind: %v", matches)
	}

	// A different migration set never reads that file.
	other := SQLite("agent", lineage(map[string]string{"001_a.sql": "x", "002_b.sql": "y"}))
	third, err := Image(other, fakeDB(&calls, 'c'))
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || bytes.Equal(third, first) {
		t.Fatal("a different migration set reused another set's template")
	}
}

// TestImageConcurrentCallersShareOneBuild stands in for parallel test
// binaries: flock and LockFileEx are per open file, so goroutines that each
// open the lock file contend exactly as processes do.
func TestImageConcurrentCallersShareOneBuild(t *testing.T) {
	withDir(t)
	spec := SQLite("agent", lineage(map[string]string{"001_a.sql": "x"}))
	var calls atomic.Int32
	slow := func(path string) error {
		time.Sleep(50 * time.Millisecond)
		return fakeDB(&calls, 'a')(path)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Image(spec, slow); err != nil {
				t.Errorf("Image: %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("builds = %d, want 1", calls.Load())
	}
}

// TestImageRebuildsAnInvalidFile: a file at the key that is not a database is
// replaced, never handed out.
func TestImageRebuildsAnInvalidFile(t *testing.T) {
	dir := withDir(t)
	spec := SQLite("org", lineage(map[string]string{"001_a.sql": "x"}))
	key, _ := Key(spec)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "org-"+key+".db"), []byte("truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	image, err := Image(spec, fakeDB(&calls, 'a'))
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !bytes.HasPrefix(image, sqliteHeader) {
		t.Fatalf("builds = %d; an invalid template was not rebuilt", calls.Load())
	}
}

// TestImageRebuildsATruncatedFile: a template cut short after its header
// (a host freeze right after a build) is removed and rebuilt, never served
// (TESTDB audit M1: it used to fail every later run with "database disk
// image is malformed").
func TestImageRebuildsATruncatedFile(t *testing.T) {
	dir := withDir(t)
	spec := SQLite("agent", lineage(map[string]string{"001_a.sql": "x"}))
	key, _ := Key(spec)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "agent-"+key+".db")
	if err := os.WriteFile(final, fakeImage('o')[:2*512], 0o600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	image, err := Image(spec, fakeDB(&calls, 'a'))
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || !bytes.Equal(image, fakeImage('a')) {
		t.Fatalf("builds = %d, image %d bytes; a truncated template was served instead of rebuilt", calls.Load(), len(image))
	}
	if b, err := os.ReadFile(final); err != nil || !bytes.Equal(b, fakeImage('a')) {
		t.Fatalf("the rebuilt template is not on disk at the key (%d bytes, %v)", len(b), err)
	}
}

// TestReadValid pins the whole-file rule, one row per shape.
func TestReadValid(t *testing.T) {
	big := fakeImage('a')
	binary.BigEndian.PutUint16(big[16:18], 1) // 1 means 65536
	binary.BigEndian.PutUint32(big[28:32], 1)
	big = append(big, bytes.Repeat([]byte{'a'}, 65536-len(big))...)
	setPageSize := func(n uint16) []byte {
		b := fakeImage('a')
		binary.BigEndian.PutUint16(b[16:18], n)
		return b
	}
	setPages := func(n uint32) []byte {
		b := fakeImage('a')
		binary.BigEndian.PutUint32(b[28:32], n)
		return b
	}
	cases := []struct {
		name  string
		image []byte
		ok    bool
	}{
		{"whole file", fakeImage('a'), true},
		{"page size 1 means 65536", big, true},
		{"truncated with the header kept", fakeImage('a')[:1024], false},
		{"trailing bytes", append(fakeImage('a'), 0), false},
		{"page count zero", setPages(0), false},
		{"page size not a power of two", setPageSize(1000), false},
		{"page size below 512", setPageSize(256), false},
		{"no SQLite header", bytes.Repeat([]byte{'a'}, 1536), false},
	}
	dir := t.TempDir()
	for i, c := range cases {
		path := filepath.Join(dir, fmt.Sprintf("%d.db", i))
		if err := os.WriteFile(path, c.image, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := readValid(path)
		if (err == nil) != c.ok {
			t.Errorf("%s: readValid err = %v, want ok = %v", c.name, err, c.ok)
		}
	}
}

// TestKeyCoversTheRunner: a template built by other migration-runner code
// is a different key, while a test file or a file outside the runner
// directories is not part of it (TESTDB audit M2: a Go-created table added
// to db.go with the migrations unchanged reused the stale template).
func TestKeyCoversTheRunner(t *testing.T) {
	migs := lineage(map[string]string{"001_a.sql": "x"})
	spec := func(src fstest.MapFS) Spec {
		s := SQLite("org", migs)
		s.RunnerDirs = []string{"run", "plan"}
		s.Source = src
		return s
	}
	tree := func(dbGo string, extra map[string]string) fstest.MapFS {
		m := fstest.MapFS{
			"run/db.go":     {Data: []byte(dbGo)},
			"plan/a.go":     {Data: []byte("package plan")},
			"run/x_test.go": {Data: []byte("package run // test")},
		}
		for k, v := range extra {
			m[k] = &fstest.MapFile{Data: []byte(v)}
		}
		return m
	}
	key := func(src fstest.MapFS) string {
		t.Helper()
		k, err := Key(spec(src))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	base := key(tree("package run", nil))
	for _, tc := range []struct {
		name string
		src  fstest.MapFS
		same bool
	}{
		{"identical", tree("package run", nil), true},
		{"changed runner file", tree("package run // CREATE TABLE made in Go", nil), false},
		{"added runner file", tree("package run", map[string]string{"run/late.go": "package run"}), false},
		{"changed test file", tree("package run", map[string]string{"run/x_test.go": "package run // other"}), true},
		{"file outside the runner", tree("package run", map[string]string{"other/b.go": "package other"}), true},
		{"non-Go file in a runner dir", tree("package run", map[string]string{"run/README.md": "notes"}), true},
	} {
		if got := key(tc.src) == base; got != tc.same {
			t.Errorf("%s: key equal to base = %v, want %v", tc.name, got, tc.same)
		}
	}
	if _, err := Key(spec(nil)); !errors.Is(err, errNoRunnerSource) {
		t.Errorf("no source: err = %v, want errNoRunnerSource", err)
	}
	if _, err := Key(spec(fstest.MapFS{"run/db.go": {Data: []byte("package run")}})); !errors.Is(err, errNoRunnerSource) {
		t.Errorf("missing runner dir: err = %v, want errNoRunnerSource", err)
	}
}

// TestSQLiteSpecReadsTheRealRunner: the lineage specs the fixtures use find
// the module tree from a test's working directory and hash every runner
// directory, so the real key is never the migrations-only one.
func TestSQLiteSpecReadsTheRealRunner(t *testing.T) {
	public := publictree.In(publictree.RepoRoot(t))
	for lin, dirs := range runnerDirs {
		if public && lin == "org" {
			// The org runner (internal/orgserver/db) is private-only.
			continue
		}
		s := SQLite(lin, lineage(map[string]string{"001_a.sql": "x"}))
		if s.Source == nil {
			t.Fatalf("%s: module source not found from the test's working directory", lin)
		}
		if len(s.RunnerDirs) != len(dirs) {
			t.Fatalf("%s: runner dirs %v, want %v", lin, s.RunnerDirs, dirs)
		}
		if _, err := Key(s); err != nil {
			t.Errorf("%s: %v", lin, err)
		}
	}
}

// TestImageBuildsPrivatelyWithoutTheRunnerSource: a template whose runner
// cannot be read is never written to the shared directory.
func TestImageBuildsPrivatelyWithoutTheRunnerSource(t *testing.T) {
	dir := withDir(t)
	spec := SQLite("org", lineage(map[string]string{"001_a.sql": "x"}))
	spec.Source = nil
	var calls atomic.Int32
	for i := 0; i < 2; i++ {
		if _, err := Image(spec, fakeDB(&calls, 'a')); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("builds = %d, want 2 private builds", calls.Load())
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.db")); len(m) != 0 {
		t.Fatalf("a template with no runner source was shared: %v", m)
	}
}

// TestImageBuildFailureIsReturned: a failing build is reported, not retried
// privately (the retry would fail the same way and double the cost), and
// leaves nothing at the key.
func TestImageBuildFailureIsReturned(t *testing.T) {
	dir := withDir(t)
	spec := SQLite("org", lineage(map[string]string{"001_a.sql": "x"}))
	var calls atomic.Int32
	boom := errors.New("migration 001 failed")
	_, err := Image(spec, func(path string) error {
		calls.Add(1)
		_ = os.WriteFile(path, []byte("half"), 0o600)
		return boom
	})
	if !errors.Is(err, boom) || calls.Load() != 1 {
		t.Fatalf("err = %v, builds = %d; want the build error after one build", err, calls.Load())
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "org-*.db*")); len(matches) != 0 {
		t.Fatalf("a failed build left files: %v", matches)
	}
}

// TestImageLeftNonEmptyWALIsABuildFailure: the main file alone would miss
// whatever the log still holds.
func TestImageLeftNonEmptyWALIsABuildFailure(t *testing.T) {
	withDir(t)
	spec := SQLite("org", lineage(map[string]string{"001_a.sql": "x"}))
	var calls atomic.Int32
	_, err := Image(spec, func(path string) error {
		if err := fakeDB(&calls, 'a')(path); err != nil {
			return err
		}
		return os.WriteFile(path+"-wal", []byte("pending frames"), 0o600)
	})
	if !errors.Is(err, errBuild) {
		t.Fatalf("err = %v, want a build failure", err)
	}
}

// TestImageFallsBackWhenTheDirectoryIsUnusable: when the shared directory
// cannot be used every caller builds privately, as before this package.
func TestImageFallsBackWhenTheDirectoryIsUnusable(t *testing.T) {
	dir := withDir(t)
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := SQLite("org", lineage(map[string]string{"001_a.sql": "x"}))
	var calls atomic.Int32
	for i := 0; i < 2; i++ {
		if _, err := Image(spec, fakeDB(&calls, 'a')); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("builds = %d, want 2 private builds", calls.Load())
	}
}

// TestPruneRemovesOnlyStaleFilesOfTheLineage keeps the directory bounded
// without touching the live key, fresh files or other lineages.
func TestPruneRemovesOnlyStaleFilesOfTheLineage(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-2 * pruneAge)
	files := []struct {
		name string
		old  bool
		keep bool
	}{
		{name: "org-live.db", old: true, keep: true},
		{name: "org-live.lock", old: true, keep: true},
		{name: "org-stale.db", old: true},
		{name: "org-stale.lock", old: true},
		{name: "org-stale.tmp-123", old: true},
		{name: "org-recent.db", keep: true},
		{name: "agent-stale.db", old: true, keep: true},
		{name: "organisation-stale.db", old: true, keep: true},
	}
	for _, f := range files {
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if f.old {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	prune(dir, "org", "live")
	for _, f := range files {
		_, err := os.Stat(filepath.Join(dir, f.name))
		if (err == nil) != f.keep {
			t.Errorf("%s: present = %v, want %v", f.name, err == nil, f.keep)
		}
	}
}

// TestPackageIsTestSupportOnly keeps this package out of shipped binaries:
// the only non-test importers allowed are the two fixture packages, which are
// themselves reached only from tests (dbtemplate pins that for itself in
// TestPackageIsTestOnly).
func TestPackageIsTestSupportOnly(t *testing.T) {
	root := moduleRoot(t)
	const self = "internal/db/templatecache"
	allowed := map[string]bool{
		filepath.FromSlash("internal/db/dbtemplate/dbtemplate.go"):   true,
		filepath.FromSlash("internal/orgserver/db/dbtest/dbtest.go"): true,
	}
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata", "dist", "bin":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return nil
		}
		for _, imp := range file.Imports {
			if strings.HasSuffix(strings.Trim(imp.Path.Value, `"`), self) {
				rel, _ := filepath.Rel(root, path)
				if !allowed[rel] {
					offenders = append(offenders, rel)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("templatecache is test support but is imported from non-test files: %v", offenders)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}
