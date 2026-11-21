//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// coverage.go answers which dependency files this build reads, from the
// extractor table itself (never a second list), and walks a project for the
// known dependency files it does not read (depscan's dependency-file table),
// so a run that skipped a whole ecosystem's files is partial, never clean.
// A file stops being a gap by itself once a row for it lands in
// extractorTable.

// tableReaders are the table's lockfile and manifest extractors, built
// once. The artifact rows are left out: they read only under the artifact
// folders the developer turned on (artifacts.go), never a dependency file
// by its name.
var tableReaders = sync.OnceValue(func() []filesystem.Extractor {
	out := make([]filesystem.Extractor, 0, len(extractorTable))
	for _, row := range extractorTable {
		if row.artifact != notArtifact {
			continue
		}
		ex, err := row.new(&cpb.PluginConfig{})
		if err != nil {
			// Extract fails on the same row, so nothing reads through it.
			continue
		}
		out = append(out, ex)
	}
	return out
})

// Reads reports whether a linked lockfile or manifest extractor of the
// facade's table reads the file at rel (relative to the scanned root,
// forward slashes), asked through each extractor's own FileRequired with a
// small regular file.
func Reads(rel string) bool {
	return readsFile(probeFile{path: rel, info: smallFile(path.Base(rel))})
}

func readsFile(api filesystem.FileAPI) bool {
	for _, ex := range tableReaders() {
		if ex.FileRequired(api) {
			return true
		}
	}
	return false
}

// probeFile is the FileAPI the probe hands an extractor's FileRequired.
type probeFile struct {
	path string
	info fs.FileInfo
}

func (p probeFile) Path() string               { return p.path }
func (p probeFile) Stat() (fs.FileInfo, error) { return p.info, nil }

// smallFile is the FileInfo of a small regular file named name, for Reads.
type smallFile string

func (s smallFile) Name() string     { return string(s) }
func (smallFile) Size() int64        { return 1 }
func (smallFile) Mode() fs.FileMode  { return 0o644 }
func (smallFile) ModTime() time.Time { return time.Time{} }
func (smallFile) IsDir() bool        { return false }
func (smallFile) Sys() any           { return nil }

// probeSkipNames are the directory names the unread-file probe never
// enters: installed or vendored packages (their files are the packages'
// own, resolved by the project's lockfile) and version-control metadata.
// SkipDirs are skipped as the extraction walk skips them.
var probeSkipNames = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, ".hg": true, ".svn": true,
}

// maxProbeBytes bounds the body the probe reads for a content check; a
// larger file is taken to declare dependencies.
const maxProbeBytes = 1 << 20

// UnreadFiles walks root for the dependency files depscan's table knows
// (depscan.DepFileFor) and returns a gap for each one this build does not
// read and nothing else resolves (depscan.DecideUnread): "no extractor for
// this file", "no lockfile" for a manifest whose lockfile kind is read but
// missing, or "needs the online lookup". It reads only file names, plus a
// capped body where a row's content check needs one. The walk skips
// opts.SkipDirs, probeSkipNames and symlinks, and stops with an error past
// opts.MaxInodes. Paths are relative to root, forward slashes; gaps come
// back sorted by path.
func UnreadFiles(ctx context.Context, root string, opts ExtractOptions) ([]depscan.Gap, error) {
	gaps, err := unreadIn(ctx, os.DirFS(root), relSkips(root, opts.SkipDirs), opts.MaxInodes, readsFile)
	if err != nil {
		return gaps, fmt.Errorf("scalibrfacade.UnreadFiles: %w", err)
	}
	return gaps, nil
}

// relSkips turns the absolute skip directories into paths relative to
// root (forward slashes); one outside root is dropped.
func relSkips(root string, dirs []string) map[string]bool {
	out := map[string]bool{}
	for _, d := range dirs {
		rel, err := filepath.Rel(root, d)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		out[rel] = true
	}
	return out
}

// errInodeCap is the walk past its inode cap.
var errInodeCap = errors.New("inode cap exceeded")

// unreadIn is UnreadFiles over fsys, with the read check injected.
func unreadIn(ctx context.Context, fsys fs.FS, skip map[string]bool, maxInodes int, reads func(filesystem.FileAPI) bool) ([]depscan.Gap, error) {
	var gaps []depscan.Gap
	dirs := &dirIndex{fsys: fsys, names: map[string][]string{}}
	visited := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if p == "." {
				return werr
			}
			// An entry that cannot be read is skipped, as the extraction
			// walk skips it.
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		visited++
		if maxInodes > 0 && visited > maxInodes {
			return errInodeCap
		}
		if d.IsDir() {
			if p != "." && (probeSkipNames[d.Name()] || skip[p]) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		row, ok := depscan.DepFileFor(p)
		if !ok {
			return nil
		}
		if reason := decideFile(fsys, dirs, p, d, row, reads); reason != "" {
			gaps = append(gaps, depscan.Gap{Ecosystem: row.Ecosystem, Path: p, Reason: reason})
		}
		return nil
	})
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Path < gaps[j].Path })
	return gaps, err
}

// decideFile gathers one known dependency file's facts and asks depscan's
// table. A fact that needs the disk is looked up only when the cheaper ones
// leave the file a gap.
func decideFile(fsys fs.FS, dirs *dirIndex, rel string, d fs.DirEntry, row depscan.DepFile, reads func(filesystem.FileAPI) bool) string {
	info, err := d.Info()
	if err != nil {
		// Gone since the directory was read: judged by its name alone.
		info = smallFile(d.Name())
	}
	f := depscan.UnreadFacts{Online: row.Online, NoAdvisoryData: row.NoAdvisoryData, Read: reads(probeFile{path: rel, info: info})}
	if f.Read {
		return depscan.DecideUnread(f)
	}
	dir := path.Dir(rel)
	f.Locked = dirs.locked(dir, row.Lockfiles, row.LockPaths)
	if f.Locked {
		return depscan.DecideUnread(f)
	}
	if row.CheckContent {
		f.DeclaresNothing = !declares(fsys, rel)
	}
	if !row.Lockfile {
		f.LockfileRead = lockfileKindRead(dir, row.Lockfiles, reads)
	}
	return depscan.DecideUnread(f)
}

// lockfileKindRead reports whether a linked extractor reads one of a
// manifest's lockfile names in dir: the manifest then lacks a lockfile
// this build would read. A pattern is asked as one name it matches
// (x.opam.locked).
func lockfileKindRead(dir string, lockfiles []string, reads func(filesystem.FileAPI) bool) bool {
	for _, l := range lockfiles {
		name := strings.ReplaceAll(l, "*", "x")
		if reads(probeFile{path: path.Join(dir, name), info: smallFile(name)}) {
			return true
		}
	}
	return false
}

// declares reads a capped body and asks the row's content check. A body
// that cannot be read, or one over the cap, declares: unknown is never
// treated as nothing to check.
func declares(fsys fs.FS, rel string) bool {
	fh, err := fsys.Open(rel)
	if err != nil {
		return true
	}
	defer func() { _ = fh.Close() }()
	body, err := io.ReadAll(io.LimitReader(fh, maxProbeBytes+1))
	if err != nil || len(body) > maxProbeBytes {
		return true
	}
	return depscan.DepFileDeclares(rel, body)
}

// dirIndex caches each directory's file names, for the lockfile look.
type dirIndex struct {
	fsys  fs.FS
	names map[string][]string
}

func (x *dirIndex) files(dir string) []string {
	if n, ok := x.names[dir]; ok {
		return n
	}
	var out []string
	if entries, err := fs.ReadDir(x.fsys, dir); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() {
				out = append(out, e.Name())
			}
		}
	}
	x.names[dir] = out
	return out
}

// locked walks from dir up to the root (".") for a file whose name matches
// one of the lockfile patterns, or for one of the lock paths below a
// directory on the way.
func (x *dirIndex) locked(dir string, lockfiles, lockPaths []string) bool {
	if len(lockfiles) == 0 && len(lockPaths) == 0 {
		return false
	}
	for {
		if anyLockfile(x.files(dir), lockfiles) {
			return true
		}
		for _, lp := range lockPaths {
			if st, err := fs.Stat(x.fsys, path.Join(dir, lp)); err == nil && st.Mode().IsRegular() {
				return true
			}
		}
		if dir == "." || dir == "" || dir == "/" {
			return false
		}
		dir = path.Dir(dir)
	}
}

func anyLockfile(names, patterns []string) bool {
	for _, n := range names {
		if depscan.IsLockfile(n, patterns) {
			return true
		}
	}
	return false
}
