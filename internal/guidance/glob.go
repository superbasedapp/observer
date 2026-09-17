package guidance

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// expand resolves one rule glob against one root and returns the
// ABSOLUTE forward-slash paths that matched, plus any non-fatal
// per-directory problems.
//
// Matching is done here rather than through [FS.Glob] on purpose: "**"
// is not a filepath.Glob token, and doing the whole expansion over
// ReadDir/Stat means the in-memory FS used in tests and the real disk
// take byte-for-byte the same code path — including the depth cap and
// the skip-directory table, neither of which a stdlib Glob would honour.
//
// maxDepth caps how many directory levels a "**" segment may cross.
// Literal and single-star segments are author-specified and finite, so
// they are not counted against it.
//
// ctx is checked at EVERY directory step, not merely between rules: a
// "**" walk over a slow mount (a WSL DrvFs project root) is where a
// scan actually spends its minutes, so a deadline that only fires
// between rules would not bound it at all. incomplete reports that the
// walk stopped early; its caller must treat the match set as partial.
func expand(ctx context.Context, fsys FS, root, pattern string, maxDepth int) (matches []string, errs []string, incomplete bool) {
	segs := splitPattern(pattern)
	if len(segs) == 0 {
		return nil, nil, false
	}
	found := make(map[string]bool)
	var problems []string
	var cut bool

	var walk func(dir string, idx, depth int)
	walk = func(dir string, idx, depth int) {
		if idx >= len(segs) {
			return
		}
		if ctx.Err() != nil {
			cut = true
			return
		}
		seg := segs[idx]
		last := idx == len(segs)-1

		switch {
		case seg == "**":
			if last {
				// "dir/**" — every file at or below dir, depth-capped.
				if !collectTree(ctx, fsys, dir, depth, maxDepth, found, &problems) {
					cut = true
				}
				return
			}
			// "**" matches zero directories first, then one, then two…
			walk(dir, idx+1, depth)
			if depth >= maxDepth {
				return
			}
			for _, name := range subdirs(fsys, dir, &problems) {
				if cut {
					return
				}
				walk(dir+"/"+name, idx, depth+1)
			}

		case !hasMeta(seg):
			child := dir + "/" + seg
			if last {
				info, err := fsys.Stat(child)
				switch {
				case err == nil && !info.IsDir():
					found[child] = true
				case err != nil && !notExist(err):
					// A REFUSED path (a symlink escaping the anchors, an
					// unreadable file) must not look like a rule that simply
					// does not apply — say so.
					problems = append(problems, fmt.Sprintf("guidance: stat %s: %v", child, err))
				}
				return
			}
			walk(child, idx+1, depth)

		default:
			entries, err := fsys.ReadDir(dir)
			if err != nil {
				// A directory that does not exist is the common case for a
				// rule that simply does not apply — never an error.
				if !notExist(err) {
					problems = append(problems, fmt.Sprintf("guidance: read dir %s: %v", dir, err))
				}
				return
			}
			for _, e := range entries {
				if cut {
					return
				}
				ok, merr := path.Match(seg, e.Name())
				if merr != nil {
					problems = append(problems, fmt.Sprintf("guidance: bad pattern %q: %v", seg, merr))
					return
				}
				if !ok {
					continue
				}
				switch {
				case last && !e.IsDir():
					found[dir+"/"+e.Name()] = true
				case !last && e.IsDir() && !skipDir(dir, e.Name()):
					walk(dir+"/"+e.Name(), idx+1, depth)
				}
			}
		}
	}
	walk(root, 0, 0)

	matches = make([]string, 0, len(found))
	for p := range found {
		matches = append(matches, p)
	}
	sort.Strings(matches)
	return matches, problems, cut
}

// collectTree gathers every regular file at or below dir, honouring the
// depth cap and the skip-directory table. Only reached by a pattern that
// ENDS in "**"; the shipped table has none, but the walker must not
// silently drop such a rule if one is ever added.
//
// It returns false when ctx expired mid-walk, so the caller can mark the
// whole scan incomplete rather than publish a truncated inventory. A
// directory at or past the depth cap, or on the skip table, is never
// READ — the cap bounds the ReadDir count, not just the result set.
func collectTree(ctx context.Context, fsys FS, dir string, depth, maxDepth int, found map[string]bool, problems *[]string) bool {
	if ctx.Err() != nil {
		return false
	}
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		if !notExist(err) {
			*problems = append(*problems, fmt.Sprintf("guidance: read dir %s: %v", dir, err))
		}
		return true
	}
	for _, e := range entries {
		if !e.IsDir() {
			found[dir+"/"+e.Name()] = true
			continue
		}
		if depth >= maxDepth || skipDir(dir, e.Name()) {
			continue
		}
		if !collectTree(ctx, fsys, dir+"/"+e.Name(), depth+1, maxDepth, found, problems) {
			return false
		}
	}
	return true
}

// subdirs lists the descendable directories of dir, skip-table applied.
func subdirs(fsys FS, dir string, problems *[]string) []string {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		if !notExist(err) {
			*problems = append(*problems, fmt.Sprintf("guidance: read dir %s: %v", dir, err))
		}
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && !skipDir(dir, e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// notExist recognises a missing path without importing os: every FS
// implementation in the tree wraps fs.ErrNotExist, and the in-memory
// trees used in tests report the same sentinel.
func notExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "file does not exist") ||
		strings.Contains(msg, "no such file or directory")
}

func splitPattern(pattern string) []string {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	parts := strings.Split(pattern, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		out = append(out, p)
	}
	return out
}

func hasMeta(seg string) bool {
	return strings.ContainsAny(seg, "*?[")
}

// normalizeRoot folds a host path into the forward-slash form the
// scanner works in and drops any trailing separator.
func normalizeRoot(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// relative renders abs as a root-relative, forward-slash path. A path
// that is somehow not under root is returned as-is, which is honest: a
// surprising absolute path should be visible, not silently mangled.
func relative(root, abs string) string {
	if root != "" && strings.HasPrefix(abs, root+"/") {
		return strings.TrimPrefix(abs, root+"/")
	}
	return abs
}
