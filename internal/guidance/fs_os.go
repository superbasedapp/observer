package guidance

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// OSFS returns the production [FS]: the real filesystem, confined to the
// two anchors a scan legitimately reads — the project root passed as
// root, and the operator's own home directory (the ScopeUser anchor).
// Everything else is refused with [ErrOutsideAnchors], so no rule glob,
// no "**" walk and no SYMLINK can be talked into reading outside those
// trees.
//
// Each anchor is registered twice when it needs to be: as the caller
// spelled it, and as it resolves once its own symlinks are followed (a
// home directory behind a link, macOS's /tmp → /private/tmp). Without
// that second spelling a perfectly legitimate file under a symlinked
// anchor would be refused by its own containment check.
//
// Pass root == "" to disable containment entirely; the caller is then
// responsible for every path it hands in.
//
// This is the ONLY file in the package that imports os. The boundary is
// pinned by TestNoForbiddenImports, so a future convenience os.ReadFile
// elsewhere in the package fails the test gate rather than quietly
// turning a pure package into an I/O package (CLAUDE.md rule #1).
func OSFS(root string) FS {
	var o osFS
	if r := normalizeRoot(root); r != "" {
		o.addAnchor(r)
		if home, err := os.UserHomeDir(); err == nil {
			o.addAnchor(normalizeRoot(home))
		}
	}
	return o
}

type osFS struct {
	// roots is the allow-list. Empty means containment is disabled.
	roots []string
}

// addAnchor registers one allowed tree, plus its fully-resolved spelling
// when the two differ.
func (o *osFS) addAnchor(p string) {
	o.appendAnchor(p)
	if p == "" {
		return
	}
	if real, err := filepath.EvalSymlinks(filepath.FromSlash(p)); err == nil {
		o.appendAnchor(normalizeRoot(filepath.ToSlash(real)))
	}
}

func (o *osFS) appendAnchor(p string) {
	if p == "" {
		return
	}
	for _, existing := range o.roots {
		if existing == p {
			return
		}
	}
	o.roots = append(o.roots, p)
}

// contained reports whether p sits under one of the configured anchors.
func (o osFS) contained(p string) bool {
	if len(o.roots) == 0 {
		return true
	}
	clean := normalizeRoot(filepath.ToSlash(filepath.Clean(filepath.FromSlash(p))))
	for _, r := range o.roots {
		if clean == r || strings.HasPrefix(clean, r+"/") {
			return true
		}
	}
	return false
}

func (o osFS) guard(op, p string) error {
	if o.contained(p) {
		return nil
	}
	return &fs.PathError{Op: op, Path: p, Err: ErrOutsideAnchors}
}

// resolve maps a requested path onto the real path a syscall may touch.
//
// Containment is checked TWICE: lexically, on what the caller asked for,
// and again on what the path actually IS once every symlink along it has
// been followed. The second check is the load-bearing one — `ln -s
// ~/.env CLAUDE.md` inside a cloned repo is lexically a project file and
// physically the operator's credentials, and Stat/ReadFile follow the
// link. A path that escapes is refused with [ErrOutsideAnchors], which
// the scanner surfaces in Result.Errors rather than swallowing.
//
// A dangling link (or a plain missing path) is fs.ErrNotExist — the
// ordinary "this rule does not apply here" case every caller handles.
func (o osFS) resolve(op, p string) (string, error) {
	if err := o.guard(op, p); err != nil {
		return "", err
	}
	host := filepath.FromSlash(p)
	if len(o.roots) == 0 {
		return host, nil
	}
	real, err := filepath.EvalSymlinks(host)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", &fs.PathError{Op: op, Path: p, Err: fs.ErrNotExist}
		}
		return "", err
	}
	if !o.contained(filepath.ToSlash(real)) {
		// The resolved target is deliberately NOT echoed: the refusal is
		// about the path the scan asked for, and naming the target would
		// print the very secret the escape was pointing at.
		return "", &fs.PathError{Op: op, Path: p, Err: ErrOutsideAnchors}
	}
	return real, nil
}

// Glob expands a filepath.Glob pattern and drops anything outside the
// anchors. Scan does not use it — it runs its own depth-capped, "**"
// aware walker (see expand) so every FS implementation behaves
// identically — but it is part of the seam for callers that want raw
// expansion.
func (o osFS) Glob(pattern string) ([]string, error) {
	hits, err := filepath.Glob(filepath.FromSlash(pattern))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		h = filepath.ToSlash(h)
		if _, err := o.resolve("glob", h); err != nil {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func (o osFS) ReadDir(p string) ([]fs.DirEntry, error) {
	real, err := o.resolve("readdir", p)
	if err != nil {
		return nil, err
	}
	return os.ReadDir(real)
}

func (o osFS) Stat(p string) (fs.FileInfo, error) {
	real, err := o.resolve("stat", p)
	if err != nil {
		return nil, err
	}
	return os.Stat(real)
}

func (o osFS) ReadFile(p string) ([]byte, error) {
	real, err := o.resolve("open", p)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(real)
}
