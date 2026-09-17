package guidance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// File is one discovered guidance file, as seen BY ONE TOOL. The same
// path matched by several tools' rules yields one File per tool — see
// the package doc.
type File struct {
	Tool  string
	Kind  Kind
	Scope Scope

	// RelPath is project-relative for ScopeProject and home-relative,
	// "~/"-prefixed, for ScopeUser (e.g. "~/.claude/skills/x/SKILL.md").
	// It is the stable identity half of the store's unique key, so it
	// always uses forward slashes regardless of host OS.
	RelPath string
	// AbsPath is the resolved path on this host.
	AbsPath string

	Name        string
	Description string

	SizeBytes int64
	ModTime   time.Time
	// ContentHash is the sha256 hex of the file's bytes. It is the only
	// thing derived from the body that is retained (plus a capped
	// description); the body itself is never kept.
	ContentHash string

	// Frontmatter holds the allow-listed, flattened front-matter keys.
	// nil when the file has none.
	Frontmatter map[string]string
	// ParseErr is a short human-readable reason the metadata could not be
	// read. A file with a ParseErr is still reported — it exists, and an
	// unparseable rule file is exactly what an operator wants to see.
	ParseErr string
}

// FS is the injected filesystem seam. Every path handed to it is
// ABSOLUTE and uses the host's separator convention as produced by the
// implementation's own joins. [OSFS] is the production implementation
// (the only file in this package that imports os); tests inject an
// in-memory tree.
type FS interface {
	// Glob expands a filepath.Glob-style pattern (no "**" support). Scan
	// itself does NOT use it — it runs its own depth-capped, "**"-aware
	// walker over ReadDir/Stat so every FS implementation, in-memory or
	// on disk, takes exactly the same code path. Glob is part of the seam
	// for callers that want raw expansion.
	Glob(pattern string) ([]string, error)
	// ReadDir lists one directory. It powers the walker.
	ReadDir(path string) ([]fs.DirEntry, error)
	// Stat resolves one path.
	Stat(path string) (fs.FileInfo, error)
	// ReadFile reads a whole file. The scanner only calls it after Stat
	// has cleared the size cap.
	ReadFile(path string) ([]byte, error)
}

// Options tunes a scan.
type Options struct {
	// MaxFileBytes skips (and counts) any file larger than this. A
	// guidance file is prose; a multi-megabyte match is a generated
	// artifact that happens to share a name.
	MaxFileBytes int64
	// MaxDepth caps how many directory levels a "**" segment may cross,
	// counted from wherever that segment is anchored. It is what keeps
	// "**/CLAUDE.md" from walking a monorepo. Literal and single-star
	// segments are author-written and finite, so they do not count
	// against it.
	MaxDepth int
	// IncludeUserScope enables the ScopeUser rows.
	IncludeUserScope bool
	// UserHome is the home directory ScopeUser rows anchor at. Empty
	// disables user scope regardless of IncludeUserScope — the package is
	// pure and never resolves a home directory itself.
	UserHome string
	// UserScopeOnly restricts the pass to the ScopeUser rules: the home
	// directory's own guidance, which is the SAME set of files for every
	// project on the machine. A caller with N project roots runs the
	// project-scope pass N times and this one ONCE, instead of re-walking
	// (and re-storing) the home tree N times. It requires
	// IncludeUserScope and UserHome; with either unset the result is
	// empty.
	UserScopeOnly bool
	// Known is an optional cache seam: given a file's absolute path it
	// returns what a PREVIOUS scan recorded for it. When the size and
	// mtime still match, the scanner reuses that row's hash and metadata
	// instead of reading and hashing the body again — a re-scan of an
	// unchanged project then costs one Stat per file. Nil (the zero
	// value) simply means "read everything", which is always correct.
	Known func(absPath string) (KnownFile, bool)
}

// KnownFile is everything a previous scan retained about one file. It is
// deliberately the WHOLE derived record and not just the hash: Name,
// Description and Frontmatter are derived from the body too, so a cache
// hit that carried only the hash would have to blank them (or re-read
// the body, which is the cost being avoided).
type KnownFile struct {
	SizeBytes   int64
	ModTime     time.Time
	ContentHash string
	Name        string
	Description string
	Frontmatter map[string]string
	ParseErr    string
}

// DefaultOptions is the shipped posture: 512 KiB per file, four levels
// of "**", user scope included.
func DefaultOptions() Options {
	return Options{
		MaxFileBytes:     512 * 1024,
		MaxDepth:         4,
		IncludeUserScope: true,
	}
}

// Result is a completed scan.
type Result struct {
	// Files is sorted by (tool, kind, rel path) so a scan is reproducible
	// and a diff between two scans is meaningful.
	Files []File
	// Skipped counts files that matched a rule but were over MaxFileBytes.
	// It means "too big to be guidance" and nothing else.
	Skipped int
	// Errors holds non-fatal per-path problems (an unreadable directory, a
	// bad glob, a path refused by the FS's containment — see
	// [ErrOutsideAnchors]). A scan does not fail because one path was
	// unreadable, and a refused path is reported HERE rather than being
	// silently absent from Files.
	Errors []string
	// Incomplete reports that the walk was cut short — the ctx deadline
	// fired (a per-root time budget) or the caller cancelled — so Files
	// is a PARTIAL inventory of the tree.
	//
	// A partial inventory must never be persisted: the store's upsert
	// tombstones every row a scan did not re-see, so publishing a
	// truncated walk would mark real, present guidance files as gone.
	// Callers treat Incomplete as "skip this root, try again next pass".
	Incomplete bool
}

// ErrOutsideAnchors is what an [FS] returns for a path that resolves
// outside the trees the scan is allowed to read — most importantly a
// symlink inside the project pointing somewhere else entirely. It is
// distinct from fs.ErrNotExist on purpose: "not there" is the ordinary
// case of a rule that does not apply, while "refused" is a fact the
// operator is shown.
var ErrOutsideAnchors = errors.New("path resolves outside the scan anchors")

// skipDirs are directory names the "**" walker never descends into.
// Matching a CLAUDE.md inside node_modules is noise, not guidance.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	".observer":    true,
	".next":        true,
	".cache":       true,
}

// skipDirNested are (parent base, name) pairs the walker never descends
// into — for names too ordinary to ban outright anywhere in a tree.
//
// ".claude/worktrees" is a Claude Code git-worktree checkout: ANOTHER
// revision of the same repo living inside it. Its CLAUDE.md is a stale
// copy of the one already inventoried at the root, so descending into it
// costs a second whole-repo walk and yields duplicate, wrong rows.
// Table-driven (CLAUDE.md rule #5) so the next contextual skip is a row,
// not a branch.
var skipDirNested = []struct{ parent, name string }{
	{parent: ".claude", name: "worktrees"},
}

// skipDir reports whether the walker must not descend into dir/name.
// parent is the directory being listed, so a rule can be scoped to
// where the name appears rather than banning it tree-wide.
func skipDir(parent, name string) bool {
	if skipDirs[name] {
		return true
	}
	base := path.Base(parent)
	for _, r := range skipDirNested {
		if r.name == name && r.parent == base {
			return true
		}
	}
	return false
}

// maxErrors caps Result.Errors so a pathological tree cannot turn a scan
// result into a log file.
const maxErrors = 64

// Scan walks the discovery table against one project root (and, when
// enabled, the operator's home) and returns every guidance file it
// found. fsys must be non-nil; projectRoot must be absolute for the
// results to be meaningful.
//
// Scan is the package's single entry point (CLAUDE.md rule #2): callers
// get a plain [Result] and none of the package's internals.
func Scan(ctx context.Context, projectRoot string, fsys FS, opts Options) (Result, error) {
	var res Result
	if fsys == nil {
		return res, errors.New("guidance.Scan: nil FS")
	}
	if strings.TrimSpace(projectRoot) == "" {
		return res, errors.New("guidance.Scan: empty project root")
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = DefaultOptions().MaxFileBytes
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = DefaultOptions().MaxDepth
	}
	projectRoot = normalizeRoot(projectRoot)
	userHome := normalizeRoot(opts.UserHome)

	// One directory listing is shared by every rule in this pass: several
	// rules anchor "**" at the same tree (claude-code alone has four), and
	// without the memo each one re-walks the project from scratch.
	fsys = newMemoFS(fsys)

	// seen dedupes within one (tool, abs path): "CLAUDE.md" and
	// "**/CLAUDE.md" both match the root file, and one tool must not
	// report it twice.
	seen := make(map[string]bool)

	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			res.Incomplete = true
			return res, err
		}
		root := projectRoot
		if rule.Scope == ScopeUser {
			if !opts.IncludeUserScope || userHome == "" {
				continue
			}
			root = userHome
		} else if opts.UserScopeOnly {
			continue
		}
		matches, errs, cut := expand(ctx, fsys, root, strings.TrimPrefix(rule.Glob, "~/"), opts.MaxDepth)
		res.appendErrors(errs)
		if cut {
			res.Incomplete = true
			return res, ctx.Err()
		}
		for _, abs := range matches {
			// Reading and hashing the matches is the other half of a
			// scan's cost; a budget that only bounded the walk would
			// still let one root run away on a directory full of
			// oversized files.
			if err := ctx.Err(); err != nil {
				res.Incomplete = true
				return res, err
			}
			key := rule.Tool + "\x00" + abs
			if seen[key] {
				continue
			}
			seen[key] = true
			f, skipped, err := collect(fsys, rule, root, abs, opts)
			if errors.Is(err, errSkipSilently) {
				continue
			}
			if err != nil {
				res.appendErrors([]string{err.Error()})
				continue
			}
			if skipped {
				res.Skipped++
				continue
			}
			res.Files = append(res.Files, f)
		}
	}
	sort.Slice(res.Files, func(i, j int) bool {
		a, b := res.Files[i], res.Files[j]
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.RelPath < b.RelPath
	})
	return res, nil
}

func (r *Result) appendErrors(errs []string) {
	for _, e := range errs {
		if len(r.Errors) >= maxErrors {
			return
		}
		r.Errors = append(r.Errors, e)
	}
}

// collect resolves one matched path into a File. skipped is true when the
// match is a directory (a rule like ".clinerules" matches both forms) or
// exceeds the size cap.
func collect(fsys FS, rule Rule, root, abs string, opts Options) (f File, skipped bool, err error) {
	info, err := fsys.Stat(abs)
	if err != nil {
		return File{}, false, fmt.Errorf("guidance: stat %s: %w", abs, err)
	}
	if info.IsDir() {
		// Not a skip in the size sense — the directory form of a rule is
		// covered by its own "**" row.
		return File{}, false, errSkipSilently
	}
	if info.Size() > opts.MaxFileBytes {
		return File{}, true, nil
	}
	rel := relative(root, abs)
	f = File{
		Tool:      rule.Tool,
		Kind:      rule.Kind,
		Scope:     rule.Scope,
		RelPath:   rel,
		AbsPath:   abs,
		SizeBytes: info.Size(),
		ModTime:   info.ModTime().UTC(),
	}
	if rule.Scope == ScopeUser {
		f.RelPath = "~/" + rel
	}

	// An unchanged file (same size, same mtime) keeps the previous scan's
	// hash and metadata: re-reading and re-hashing a CLAUDE.md that has
	// not moved is the bulk of a re-scan's cost and buys nothing.
	if opts.Known != nil {
		if k, ok := opts.Known(abs); ok && k.ContentHash != "" &&
			k.SizeBytes == info.Size() && k.ModTime.Equal(f.ModTime) {
			f.ContentHash = k.ContentHash
			f.Name = k.Name
			f.Description = k.Description
			f.ParseErr = k.ParseErr
			f.Frontmatter = copyFrontmatter(k.Frontmatter)
			return f, false, nil
		}
	}

	body, err := fsys.ReadFile(abs)
	if err != nil {
		f.ParseErr = fmt.Sprintf("read: %v", err)
		f.Name = fallbackName(rel)
		return f, false, nil
	}
	sum := sha256.Sum256(body)
	f.ContentHash = hex.EncodeToString(sum[:])

	var prose string
	switch rule.Frontmatter {
	case FrontmatterYAML, FrontmatterMDC:
		f.Frontmatter, prose, f.ParseErr = parseYAMLFrontmatter(body)
	case FrontmatterJSON:
		f.Frontmatter, f.ParseErr = parseJSONConfig(body, path.Base(rel) == "opencode.json")
	default:
		// Prose files may still carry front matter (many CLAUDE.md files
		// do not, some AGENTS.md files do); read it opportunistically but
		// never report a parse error for a file that never promised one.
		var perr string
		f.Frontmatter, prose, perr = parseYAMLFrontmatter(body)
		_ = perr
	}
	// The body is dropped here — only the hash, a capped description and
	// the allow-listed front-matter keys survive this function.
	f.Name = resolveName(f.Frontmatter, rel)
	f.Description = f.Frontmatter["description"]
	if f.Description == "" && rule.Frontmatter != FrontmatterJSON {
		f.Description = describeBody(prose)
	}
	return f, false, nil
}

// copyFrontmatter defensively copies a cached map so a Result never
// aliases the caller's own storage.
func copyFrontmatter(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// errSkipSilently marks a match that is neither a file nor a size skip
// (today: a directory matched by a single-token rule). collect's caller
// treats it as "nothing to report", not as an error worth surfacing.
var errSkipSilently = errors.New("guidance: not a regular file")

// resolveName picks the display name: the front matter's own name wins,
// then the "skills/<name>/SKILL.md" directory convention, then the file
// stem.
func resolveName(fm map[string]string, rel string) string {
	if n := strings.TrimSpace(fm["name"]); n != "" {
		return n
	}
	return fallbackName(rel)
}

func fallbackName(rel string) string {
	base := path.Base(rel)
	if strings.EqualFold(base, "SKILL.md") {
		if dir := path.Base(path.Dir(rel)); dir != "." && dir != "/" && dir != "" {
			return dir
		}
	}
	return strings.TrimSuffix(base, path.Ext(base))
}

// SkillKey is the wave-2 join primitive: a stable, case-folded identity
// for "this tool's guidance unit called <name>", so a skill observed in
// a scan can be joined to a skill named in a transcript without either
// side agreeing on a path.
func SkillKey(tool string, kind Kind, name string) string {
	norm := func(s string) string {
		s = strings.TrimSpace(strings.ToLower(s))
		s = strings.TrimSuffix(s, ".md")
		s = strings.TrimSuffix(s, ".mdc")
		return strings.TrimSpace(s)
	}
	name = norm(name)
	// A name that arrived as a path ("commands/deploy.md") joins on its
	// last element — that is the token a transcript prints.
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	return norm(tool) + "/" + norm(string(kind)) + "/" + name
}

// memoFS memoises ReadDir for the lifetime of ONE Scan. Scan is
// single-goroutine, so there is no locking and no lifetime beyond the
// call — a longer-lived cache would start serving a stale tree.
type memoFS struct {
	FS
	dirs map[string]memoDir
}

type memoDir struct {
	entries []fs.DirEntry
	err     error
}

func newMemoFS(f FS) *memoFS { return &memoFS{FS: f, dirs: map[string]memoDir{}} }

func (m *memoFS) ReadDir(p string) ([]fs.DirEntry, error) {
	if d, ok := m.dirs[p]; ok {
		return d.entries, d.err
	}
	entries, err := m.FS.ReadDir(p)
	m.dirs[p] = memoDir{entries: entries, err: err}
	return entries, err
}
