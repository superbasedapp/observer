package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
)

// worktreetarget.go: where a stored file target lives on disk once
// adapters store targets checkout-independently (git.CheckoutRelativePath,
// lane shr-worktree2, PT-39). A file touched in a linked worktree is stored
// as `pkg/a.go`, the path it has in the main checkout, so joining the
// target back onto the project root would name the main checkout's copy.
// The two readers that open the file (freshness hashing at ingest, and the
// post-write scan feed) recover the checkout from the absolute path the
// tool itself sent, found in the action's raw input. A project with no
// linked worktrees takes the old join unchanged.
//
// This runs for every file action on the watcher path, so it decodes only
// the raw input's path keys (never the write content) and reads each
// project's worktree layout from a short-lived per-root cache instead of
// walking the tree for every candidate (audit finding 5, lane
// shr-worktree2).

// maxTargetCandidateLen skips long strings: a path is never this long.
const maxTargetCandidateLen = 4096

// worktreeLayoutTTL is how long one project's worktree layout is reused
// before it is read again; a worktree added or removed is seen within it.
const worktreeLayoutTTL = 10 * time.Second

// maxLayoutRoots bounds the layout cache; past it the cache starts over.
const maxLayoutRoots = 256

// maxLayoutCheckouts caps the linked worktrees one layout lists.
const maxLayoutCheckouts = 200

// checkoutDiskPath returns the absolute path of target in the checkout the
// tool touched, when the project at root has linked worktrees and the raw
// tool input names an absolute path that maps to target the way
// git.CheckoutRelativePath maps it. It reports false otherwise (callers
// keep their old join).
func checkoutDiskPath(root, target, rawInput string) (string, bool) {
	return worktreeLayouts.diskPath(root, target, rawInput)
}

// diskPath is checkoutDiskPath over this cache's layouts.
func (c *worktreeLayoutCache) diskPath(root, target, rawInput string) (string, bool) {
	if root == "" || target == "" || rawInput == "" || filepath.IsAbs(target) ||
		strings.HasPrefix(target, "[external]/") {
		return "", false
	}
	layout := c.get(root)
	if !layout.has {
		return "", false
	}
	for _, cand := range rawPathCandidates(rawInput) {
		cand = filepath.Clean(cand)
		rel, ok := layout.relative(cand)
		if !ok {
			// A spelling outside every known checkout (a symlinked path,
			// say): the full seam resolves it.
			rel = git.CheckoutRelativePath(root, cand)
		}
		if rel == target {
			return cand, true
		}
	}
	return "", false
}

// rawPathFields are the raw-input keys the file-target adapters read a path
// from (claudecode, cowork: file_path; cline: path, file_path; codex: path,
// file_path, filename, target), in the order they are tried. Decoding into
// this struct skips every other key without allocating its value.
type rawPathFields struct {
	FilePath     string `json:"file_path"`
	FilePathCC   string `json:"filePath"`
	NotebookPath string `json:"notebook_path"`
	Path         string `json:"path"`
	Filename     string `json:"filename"`
	Target       string `json:"target"`
}

// rawPathCandidates returns the absolute paths the raw input's path keys
// name, in rawPathFields order. A key of another type is skipped; input
// that is not a JSON object yields nothing.
func rawPathCandidates(rawInput string) []string {
	var f rawPathFields
	if err := json.Unmarshal([]byte(rawInput), &f); err != nil {
		var typeErr *json.UnmarshalTypeError
		if !errors.As(err, &typeErr) {
			return nil
		}
	}
	var out []string
	for _, p := range []string{f.FilePath, f.FilePathCC, f.NotebookPath, f.Path, f.Filename, f.Target} {
		if p != "" && len(p) <= maxTargetCandidateLen && filepath.IsAbs(p) {
			out = append(out, p)
		}
	}
	return out
}

// worktreeLayout is one project's checkouts as last read: whether it has a
// linked-worktree admin directory, its linked worktree top levels (longest
// first, so an in-tree worktree wins over the main checkout around it) and
// the main checkout's spellings (as given and symlink-resolved).
type worktreeLayout struct {
	has       bool
	checkouts []string
	roots     []string
	at        time.Time
}

// relative maps an absolute, cleaned path to its checkout-relative form
// when it lies in one of the layout's checkouts.
func (l worktreeLayout) relative(p string) (string, bool) {
	for _, dir := range l.checkouts {
		if rel, ok := underDir(dir, p); ok {
			return rel, true
		}
	}
	for _, dir := range l.roots {
		if rel, ok := underDir(dir, p); ok {
			return rel, true
		}
	}
	return "", false
}

func underDir(dir, p string) (string, bool) {
	if dir == "" {
		return "", false
	}
	if p == dir {
		return ".", true
	}
	prefix := dir
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	return filepath.ToSlash(p[len(prefix):]), true
}

// worktreeLayoutCache is the one owner of the per-root layouts.
type worktreeLayoutCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	now    func() time.Time
	byRoot map[string]worktreeLayout
	// loads counts layout reads from disk; tests read it.
	loads int
}

var worktreeLayouts = &worktreeLayoutCache{ttl: worktreeLayoutTTL, now: time.Now, byRoot: map[string]worktreeLayout{}}

// get returns root's layout, reading it from disk at most once per ttl.
func (c *worktreeLayoutCache) get(root string) worktreeLayout {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if l, ok := c.byRoot[root]; ok && now.Sub(l.at) < c.ttl && !now.Before(l.at) {
		return l
	}
	l := worktreeLayout{at: now}
	if git.HasLinkedWorktrees(root) {
		l.has = true
		l.checkouts = git.LinkedWorktreeCheckouts(root, maxLayoutCheckouts)
		sort.SliceStable(l.checkouts, func(i, j int) bool { return len(l.checkouts[i]) > len(l.checkouts[j]) })
		clean := filepath.Clean(root)
		l.roots = []string{clean}
		if r, err := filepath.EvalSymlinks(clean); err == nil && r != clean {
			l.roots = append(l.roots, r)
		}
	}
	if len(c.byRoot) >= maxLayoutRoots {
		c.byRoot = map[string]worktreeLayout{}
	}
	c.byRoot[root] = l
	c.loads++
	return l
}

// loadCount reports how many layouts were read from disk (tests).
func (c *worktreeLayoutCache) loadCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loads
}
