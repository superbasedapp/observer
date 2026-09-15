package git

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Info is the summary of a project's git metadata.
type Info struct {
	// Root is the absolute path to the git working tree root. For
	// non-git directories, Root equals the input directory (spec §20).
	Root string
	// IsGit is true when Root is an actual git working tree.
	IsGit bool
	// Branch is the currently checked-out branch, or "" if unknown or
	// detached HEAD.
	Branch string
	// Remote is the URL of the "origin" remote, or "" if unavailable.
	Remote string
}

// Resolve reports the git metadata for the project containing dir. A dir
// that is not inside any git working tree still returns a valid Info with
// IsGit = false and Root = dir (after symlink evaluation).
func Resolve(dir string) (Info, error) {
	abs, err := absResolveSymlinks(dir)
	if err != nil {
		return Info{}, fmt.Errorf("git.Resolve: %w", err)
	}
	root, ok := findGitRoot(abs)
	if !ok {
		return Info{Root: abs, IsGit: false}, nil
	}
	info := Info{Root: root, IsGit: true}
	info.Branch = readBranch(root)
	info.Remote = readOriginRemote(root)
	return info, nil
}

// FindRoot returns the absolute path of the git working tree containing dir.
// If dir is not inside any git working tree, it returns an empty string and
// false.
func FindRoot(dir string) (string, bool) {
	abs, err := absResolveSymlinks(dir)
	if err != nil {
		return "", false
	}
	return findGitRoot(abs)
}

// RelativePath returns p as a project-relative slash-separated path. If p
// lies outside root, it returns "[external]/<abs-path>" per spec §20.
func RelativePath(root, p string) string {
	if p == "" {
		return ""
	}
	abs, err := absResolveSymlinks(p)
	if err != nil {
		return p
	}
	rootAbs, err := absResolveSymlinks(root)
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "[external]/" + filepath.ToSlash(abs)
	}
	return filepath.ToSlash(rel)
}

func absResolveSymlinks(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	// EvalSymlinks requires the path to exist. If it doesn't, fall back to
	// Abs — callers may ask about non-existent paths (e.g. targets of a
	// pending write_file).
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs, nil
	}
	return resolved, nil
}

// findGitRoot walks up from dir looking for a `.git` directory or file
// (the latter indicates a git worktree). Returns the enclosing directory
// and true on success.
func findGitRoot(dir string) (string, bool) {
	root, ok, _ := findGitRootDetailed(dir)
	return root, ok
}

// findGitRootDetailed is findGitRoot plus the worktree bit (Project
// Identity Resolver v2, 2026-09-06, §3.1): isWorktree is true exactly
// when the `.git` entry found during the walk was a FILE (a linked
// worktree's pointer to its main repo's common dir), false when it was a
// directory or when dir isn't inside a git working tree at all.
func findGitRootDetailed(dir string) (root string, ok bool, isWorktree bool) {
	cur := dir
	for {
		gitPath := filepath.Join(cur, ".git")
		if fi, err := os.Stat(gitPath); err == nil {
			if fi.IsDir() {
				return cur, true, false
			}
			// .git file → worktree. Resolve to the main repo dir.
			if commonDir, ok2 := readWorktreeCommonDir(gitPath); ok2 {
				return filepath.Dir(commonDir), true, true
			}
			return cur, true, false
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false, false
		}
		cur = parent
	}
}

// readWorktreeCommonDir reads a `.git` file (found in linked worktrees) and
// returns the path stored in its "gitdir:" line, if any.
func readWorktreeCommonDir(path string) (string, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "gitdir:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
			// A real linked-worktree gitdir is an absolute path with no `..`
			// segments. Reject an empty value or one containing `..` so a
			// planted `.git` file can't redirect observer's HEAD/config reads
			// to an attacker-chosen directory via path traversal (absolute
			// worktree paths stay allowed).
			if val == "" || containsDotDot(val) {
				return "", false
			}
			return val, true
		}
	}
	return "", false
}

// containsDotDot reports whether any path segment of p is exactly "..".
func containsDotDot(p string) bool {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

func readBranch(root string) string {
	body, err := os.ReadFile(filepath.Join(root, ".git", "HEAD"))
	if err != nil {
		return ""
	}
	ref := strings.TrimSpace(string(body))
	if !strings.HasPrefix(ref, "ref: ") {
		// Detached HEAD — return empty rather than the commit sha.
		return ""
	}
	full := strings.TrimPrefix(ref, "ref: ")
	return strings.TrimPrefix(full, "refs/heads/")
}

// readOriginRemote parses .git/config for [remote "origin"] url = ...
// without shelling out to git.
func readOriginRemote(root string) string {
	f, err := os.Open(filepath.Join(root, ".git", "config"))
	if err != nil {
		return ""
	}
	defer f.Close()

	inOrigin := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if !inOrigin {
			continue
		}
		if strings.HasPrefix(line, "url") {
			if eq := strings.Index(line, "="); eq >= 0 {
				return strings.TrimSpace(line[eq+1:])
			}
		}
	}
	return ""
}

// remoteEntry is one `[remote "<name>"]` section's url, in the file
// order it appears in `.git/config`.
type remoteEntry struct {
	name string
	url  string
}

// readAllRemotes parses .git/config for every `[remote "<name>"] url =
// ...` entry, in file order (Project Identity Resolver v2, 2026-09-06,
// §3.1 — fork/upstream resolution needs every declared remote, not just
// origin). Deliberately does not share code with readOriginRemote: the
// latter is a heavily-depended-on pure function and a change here must
// not risk it.
func readAllRemotes(root string) []remoteEntry {
	f, err := os.Open(filepath.Join(root, ".git", "config"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []remoteEntry
	var curName string
	inRemote := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			if strings.HasPrefix(line, `[remote "`) && strings.HasSuffix(line, `"]`) {
				curName = line[len(`[remote "`) : len(line)-2]
				inRemote = true
			} else {
				inRemote = false
				curName = ""
			}
			continue
		}
		if !inRemote {
			continue
		}
		if strings.HasPrefix(line, "url") {
			if eq := strings.Index(line, "="); eq >= 0 {
				out = append(out, remoteEntry{name: curName, url: strings.TrimSpace(line[eq+1:])})
			}
		}
	}
	return out
}

// pickUpstreamRemote returns the url of the remote literally named
// "upstream"; failing that, the first non-"origin" remote in file order;
// failing that, "".
func pickUpstreamRemote(remotes []remoteEntry) string {
	for _, r := range remotes {
		if r.name == "upstream" {
			return r.url
		}
	}
	for _, r := range remotes {
		if r.name != "origin" {
			return r.url
		}
	}
	return ""
}
