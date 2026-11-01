package git

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
)

// Info is the summary of a project's git metadata.
type Info struct {
	// Root is the absolute path of the project root: the git working tree
	// root, or, inside a linked worktree, the main repository's top level
	// (F0-14), so every worktree of a repository attributes to one
	// project. For non-git directories, Root equals the input directory
	// (spec §20).
	Root string
	// IsGit is true when Root is an actual git working tree.
	IsGit bool
	// Branch is the currently checked-out branch, or "" if unknown or
	// detached HEAD.
	Branch string
	// Remote is the URL of the "origin" remote, or "" if unavailable.
	Remote string
	// CheckoutRoot is the top level of the checkout dir sits in: the
	// directory whose files, index and HEAD a caller reads. It equals Root
	// except inside a linked worktree, where Root is the main repository's
	// top level (the project) and CheckoutRoot the worktree's own top level
	// (F0-14; see the package doc). For a non-git directory it equals Root.
	CheckoutRoot string
}

// Resolve reports the git metadata for the project containing dir. A dir
// that is not inside any git working tree still returns a valid Info with
// IsGit = false and Root = dir (after symlink evaluation).
func Resolve(dir string) (Info, error) {
	abs, err := absResolveSymlinks(dir)
	if err != nil {
		return Info{}, fmt.Errorf("git.Resolve: %w", err)
	}
	loc := locateGit(abs)
	if !loc.ok {
		return Info{Root: abs, IsGit: false, CheckoutRoot: abs}, nil
	}
	info := Info{Root: loc.root, IsGit: true, CheckoutRoot: loc.checkout}
	info.Branch = readBranch(loc.gitDir)
	info.Remote = readOriginRemote(loc.commonDir)
	return info, nil
}

// FindRoot returns the absolute path of the project root containing dir:
// the git working tree's top level, or, inside a linked worktree, the main
// repository's top level (Info.Root). If dir is not inside any git working
// tree, it returns an empty string and false.
func FindRoot(dir string) (string, bool) {
	abs, err := absResolveSymlinks(dir)
	if err != nil {
		return "", false
	}
	loc := locateGit(abs)
	return loc.root, loc.ok
}

// FindCheckoutRoot returns the top level of the checkout containing dir
// (Info.CheckoutRoot): the same as FindRoot except inside a linked
// worktree, where it is the worktree's own top level. Callers that read
// the checkout's files, index or HEAD use it; callers that attribute or
// key by project use FindRoot. If dir is not inside any git working tree,
// it returns an empty string and false.
func FindCheckoutRoot(dir string) (string, bool) {
	abs, err := absResolveSymlinks(dir)
	if err != nil {
		return "", false
	}
	loc := locateGit(abs)
	return loc.checkout, loc.ok
}

// LinkedCommonDir returns the common git directory of the linked worktree
// containing dir (the main repository's `.git`, which holds its objects and
// refs), and false when dir is not inside a linked worktree in git's own
// layout. A caller that runs git in the worktree from a sandbox binds it
// read-only (lane SEC-G2: an isolated scan of a linked worktree).
func LinkedCommonDir(dir string) (string, bool) {
	abs, err := absResolveSymlinks(dir)
	if err != nil {
		return "", false
	}
	loc := locateGit(abs)
	if !loc.ok || !loc.worktree {
		return "", false
	}
	return loc.commonDir, true
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
	if foreignPOSIXAbs(abs) {
		// A path recorded on a POSIX host (FU-112): relate it to a root in
		// the same spelling with POSIX rules; under any other root it is
		// external, and it keeps its own spelling (never a drive).
		if foreignPOSIXAbs(rootAbs) {
			if rel, ok := posixRel(rootAbs, abs); ok {
				return rel
			}
		}
		return "[external]/" + abs
	}
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "[external]/" + filepath.ToSlash(abs)
	}
	return filepath.ToSlash(rel)
}

// CheckoutRelativePath is the one seam every adapter uses to store a file
// target (lane shr-worktree2, PT-39): RelativePath, except that a target
// inside a linked worktree of project root is made relative to that
// worktree's own top level (Info.CheckoutRoot), so a file has the same
// project-relative path whichever checkout of the project it was touched
// in (`pkg/a.go`, not `.worktrees/x/pkg/a.go` for an in-tree worktree or
// `[external]/...` for one outside the main checkout). The checkout is
// found from the target itself, so callers pass the project root they
// already hold. A relative target, a target in no linked worktree, and a
// target in a worktree of another project give exactly what RelativePath
// gives.
func CheckoutRelativePath(root, p string) string {
	if p == "" || root == "" || !filepath.IsAbs(p) {
		return RelativePath(root, p)
	}
	abs, err := absResolveSymlinks(p)
	if err != nil {
		return RelativePath(root, p)
	}
	loc := locateGit(abs)
	if !loc.ok || !loc.worktree || loc.checkout == loc.root {
		return RelativePath(root, p)
	}
	rootAbs, err := absResolveSymlinks(root)
	if err != nil || (loc.root != rootAbs && !sameFile(loc.root, rootAbs)) {
		return RelativePath(root, p)
	}
	return RelativePath(loc.checkout, abs)
}

// HasLinkedWorktrees reports whether the repository whose top level is
// root has a linked-worktree admin directory (`<root>/.git/worktrees`).
// It is a cheap pre-check for callers that only need CheckoutRelativePath's
// reverse when a project can have more than one checkout.
//
// A root that is not rooted on this host (HostRooted: FU-193's "Xcode
// (project unknown)", a placeholder) has no worktrees: it is never joined
// and stat'ed against the daemon's working directory (audit row 8).
func HasLinkedWorktrees(root string) bool {
	return HostRooted(root) && isDir(filepath.Join(root, ".git", "worktrees"))
}

// HostRooted reports whether p names a place on this host without the
// working directory: an absolute path, or on Windows one rooted on the
// current drive. A relative name (a stored project root that is not a path,
// such as FU-193's "Xcode (project unknown)") and, on a POSIX host, a
// Windows drive or UNC spelling are not. Callers that treat a stored
// project root as a directory skip a root that is not, so no git or file
// operation ever runs relative to the daemon's working directory.
func HostRooted(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(filepath.ToSlash(p), "/")
}

func absResolveSymlinks(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if foreignPOSIXAbs(p) {
		return cleanForeign(p), nil
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	// EvalSymlinks requires the path to exist. If it doesn't, fall back to
	// Abs — callers may ask about non-existent paths (e.g. targets of a
	// pending write_file). On Windows EvalSymlinks also upper-cases the
	// drive letter; the fallback does the same (WINNODE2 item 11), so a
	// cwd reported as `c:\x` and one reported as `C:\x` name one root.
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return pathnorm.CanonicalDriveLetter(abs), nil
	}
	return pathnorm.CanonicalDriveLetter(resolved), nil
}

// gitLocation is what the walk up from a directory found.
type gitLocation struct {
	// ok is false when the directory is not inside a git working tree.
	ok bool
	// root is the project root (Info.Root), checkout the checkout's top
	// level (Info.CheckoutRoot).
	root, checkout string
	// gitDir holds the checkout's HEAD; commonDir holds the shared config
	// (and so the remotes). Both are `<checkout>/.git` outside a linked
	// worktree.
	gitDir, commonDir string
	// worktree is true when the checkout is a linked worktree in git's own
	// layout (linkedWorktree).
	worktree bool
}

// locateGit walks up from dir (absolute, symlinks resolved) looking for a
// `.git` directory or file. A `.git` directory is a normal checkout. A
// `.git` file is followed only when it is a linked worktree in git's
// layout (linkedWorktree); any other `.git` file (a submodule, a
// `--separate-git-dir` clone, a planted file) resolves to the directory
// holding it, with no worktree bit, and its branch and remote reads find
// nothing, exactly as before F0-14.
func locateGit(dir string) gitLocation {
	if foreignPOSIXAbs(dir) {
		// Not addressable as written on this host (FU-112): stat'ing it
		// would walk the current drive instead.
		return gitLocation{}
	}
	cur := dir
	for {
		gitPath := filepath.Join(cur, ".git")
		//nolint:gosec // G703: stats `<dir>/.git` on the walk up from a caller's directory to find its repository; nothing is read or written.
		if fi, err := os.Stat(gitPath); err == nil {
			loc := gitLocation{ok: true, root: cur, checkout: cur, gitDir: gitPath, commonDir: gitPath}
			if fi.IsDir() {
				return loc
			}
			if wt, ok := linkedWorktree(gitPath); ok {
				loc.worktree = true
				loc.gitDir, loc.commonDir = wt.gitDir, wt.commonDir
				loc.root = mainTopLevel(wt.commonDir, cur)
			}
			return loc
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return gitLocation{}
		}
		cur = parent
	}
}

// worktreeDirs is a linked worktree's per-worktree and common git dirs.
type worktreeDirs struct {
	gitDir, commonDir string
}

// linkedWorktree reports whether the `.git` file at gitFile is a linked
// worktree in git's own layout, and its git dirs when it is. Every check
// must hold:
//
//   - the file's gitdir resolves (resolveGitPointer) to a directory: an
//     absolute path with no `..` segment, or, as git 2.48 writes it under
//     `worktree.useRelativePaths`, a path relative to the directory
//     holding the `.git` file (lane shr-worktree2, PT-39);
//   - `<gitdir>/commondir` names an existing directory (relative to the
//     gitdir, as git writes it, or absolute);
//   - the gitdir's parent is `<common>/worktrees`;
//   - `<gitdir>/gitdir`, git's pointer back to the worktree (absolute, or
//     relative to the gitdir), names this `.git` file, so a `.git` file
//     planted elsewhere that points at a real repository's worktree
//     directory is not followed.
//
// A relative pointer passes exactly the same checks as an absolute one
// once resolved; one that climbs above the filesystem root or names
// nothing is refused. Paths are compared as files (os.SameFile), so a
// drive-letter gitdir written with forward slashes on Windows, a case
// difference or a symlink in either spelling does not matter.
func linkedWorktree(gitFile string) (worktreeDirs, bool) {
	val, ok := readGitFileDir(gitFile)
	if !ok {
		return worktreeDirs{}, false
	}
	gitDir, ok := resolveGitPointer(filepath.Dir(gitFile), val)
	if !ok || !isDir(gitDir) {
		return worktreeDirs{}, false
	}
	body, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		return worktreeDirs{}, false
	}
	common := strings.TrimSpace(string(body))
	if common == "" {
		return worktreeDirs{}, false
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(gitDir, common)
	}
	common = filepath.Clean(common)
	if !isDir(common) || !sameFile(filepath.Dir(gitDir), filepath.Join(common, "worktrees")) {
		return worktreeDirs{}, false
	}
	back, err := os.ReadFile(filepath.Join(gitDir, "gitdir"))
	if err != nil {
		return worktreeDirs{}, false
	}
	backPath, ok := resolveGitPointer(gitDir, strings.TrimSpace(string(back)))
	if !ok || !sameFile(backPath, gitFile) {
		return worktreeDirs{}, false
	}
	return worktreeDirs{gitDir: gitDir, commonDir: common}, true
}

// mainTopLevel is the project root of a linked worktree whose common dir
// is common: the main repository's top level when common is that
// checkout's `.git` directory, else (a bare common dir, or a main
// checkout cloned with `--separate-git-dir`, which has no top level the
// common dir can name) the worktree's own checkout.
func mainTopLevel(common, checkout string) string {
	if !strings.EqualFold(filepath.Base(common), ".git") || configIsBare(common) {
		return checkout
	}
	parent := filepath.Dir(common)
	if !sameFile(filepath.Join(parent, ".git"), common) {
		return checkout
	}
	if resolved, err := filepath.EvalSymlinks(parent); err == nil {
		return resolved
	}
	return parent
}

// configIsBare reports whether `<gitDir>/config` sets core.bare true.
func configIsBare(gitDir string) bool {
	f, err := os.Open(filepath.Join(gitDir, "config"))
	if err != nil {
		return false
	}
	defer f.Close()
	inCore := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			inCore = strings.EqualFold(line, "[core]")
			continue
		}
		if !inCore {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "bare") {
			return strings.EqualFold(strings.TrimSpace(val), "true")
		}
	}
	return false
}

func isDir(p string) bool {
	//nolint:gosec // G703: stats a path named by the repository's own .git files to check git's layout; nothing is read or written.
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// sameFile reports whether a and b name the same existing file.
func sameFile(a, b string) bool {
	//nolint:gosec // G703: stats paths named by the repository's own .git files to compare them; nothing is read or written.
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	//nolint:gosec // G703: as above.
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// readGitFileDir reads a `.git` file and returns the path stored in its
// "gitdir:" line, if any. resolveGitPointer decides what the value may
// look like.
func readGitFileDir(path string) (string, bool) {
	//nolint:gosec // G703: reads the `.git` file locateGit found; its value only selects git metadata reads that must pass linkedWorktree's layout checks.
	body, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "gitdir:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
			if val == "" {
				return "", false
			}
			// Git for Windows writes the pointer in its own flavor
			// (`gitdir: D:/repo/.git/worktrees/wt`). Read from WSL, that
			// is a relative-looking string the main-repo root would be
			// derived from verbatim, so translate it to the host's flavor.
			return pathnorm.NormalizeForeign(val), true
		}
	}
	return "", false
}

// resolveGitPointer resolves a path git stored in a worktree pointer (the
// worktree's `.git` file, or the admin directory's `gitdir` back pointer)
// against base, the directory holding the pointer, and reports false for
// a value no git writes:
//
//   - an absolute path is taken as is, but never with a `..` segment, so a
//     planted `.git` file cannot redirect the HEAD and config reads by
//     path traversal (F0-14);
//   - a relative path (git 2.48 `worktree.useRelativePaths`) is joined to
//     base; its `..` segments are how it reaches the other checkout, but
//     it may not climb above the filesystem root;
//   - a drive-letter, UNC or rooted spelling that is not absolute on this
//     OS (`C:x` drive-relative, `\x` or `/x` on Windows, `C:/x` read on
//     another OS) is refused rather than read as a relative name, and so
//     is a relative path holding a backslash on an OS whose separator is
//     a slash (git writes forward slashes everywhere).
//
// Whatever it returns still has to pass linkedWorktree's layout checks.
func resolveGitPointer(base, val string) (string, bool) {
	if val == "" {
		return "", false
	}
	if filepath.IsAbs(val) {
		if containsDotDot(val) {
			return "", false
		}
		return filepath.Clean(val), true
	}
	if hasDriveOrRoot(val) || (filepath.Separator == '/' && strings.Contains(val, `\`)) {
		return "", false
	}
	depth := len(splitSegments(base))
	for _, seg := range splitSegments(val) {
		switch seg {
		case ".":
		case "..":
			depth--
			if depth < 0 {
				return "", false
			}
		default:
			depth++
		}
	}
	return filepath.Join(base, filepath.FromSlash(val)), true
}

// hasDriveOrRoot reports whether a path that is not absolute on this OS
// still carries a drive letter, a UNC prefix or a leading separator.
func hasDriveOrRoot(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return true
	}
	return len(p) >= 2 && p[1] == ':' && (p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z')
}

// splitSegments splits p on either separator, dropping empty segments and
// a Windows volume name.
func splitSegments(p string) []string {
	p = p[len(filepath.VolumeName(p)):]
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
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

// readBranch reads the branch checked out per gitDir/HEAD (the checkout's
// own git dir: `<root>/.git`, or a linked worktree's `<common>/worktrees/
// <name>`).
func readBranch(gitDir string) string {
	body, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
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

// readOriginRemote parses <commonDir>/config for [remote "origin"] url =
// ... without shelling out to git. commonDir is `<root>/.git`, or a linked
// worktree's common dir, which holds the remotes every worktree shares.
func readOriginRemote(commonDir string) string {
	f, err := os.Open(filepath.Join(commonDir, "config"))
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

// readAllRemotes parses <commonDir>/config for every `[remote "<name>"] url =
// ...` entry, in file order (Project Identity Resolver v2, 2026-09-06,
// §3.1 — fork/upstream resolution needs every declared remote, not just
// origin). Deliberately does not share code with readOriginRemote: the
// latter is a heavily-depended-on pure function and a change here must
// not risk it.
func readAllRemotes(commonDir string) []remoteEntry {
	f, err := os.Open(filepath.Join(commonDir, "config"))
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

// legacyWorktreeRootSuffix is the root a linked worktree resolved to before
// F0-14: its main repository's worktree admin directory.
const legacyWorktreeRootSuffix = "/.git/worktrees"

// IsLegacyWorktreeRoot reports whether root has the shape builds before
// F0-14 gave a linked worktree's sessions (`<main>/.git/worktrees`, with
// either path separator), whatever is on disk now.
func IsLegacyWorktreeRoot(root string) bool {
	slashed := strings.ReplaceAll(root, `\`, "/")
	return len(root) > len(legacyWorktreeRootSuffix) && strings.HasSuffix(slashed, legacyWorktreeRootSuffix)
}

// LegacyWorktreeRootTarget reports whether root is the project root builds
// before F0-14 gave a linked worktree's sessions (`<main>/.git/worktrees`,
// with either path separator) and, when it is, returns `<main>`, but only
// while `<main>` is a git repository on disk: `<main>/.git` is a directory
// and `<main>` is its own project root. Anything else, including a
// repository that has since been removed, reports false.
func LegacyWorktreeRootTarget(root string) (string, bool) {
	if !IsLegacyWorktreeRoot(root) {
		return "", false
	}
	mainTop := root[:len(root)-len(legacyWorktreeRootSuffix)]
	if !filepath.IsAbs(mainTop) || !isDir(filepath.Join(mainTop, ".git")) {
		return "", false
	}
	abs, err := absResolveSymlinks(mainTop)
	if err != nil {
		return "", false
	}
	if got, ok := FindRoot(abs); !ok || got != abs {
		return "", false
	}
	return abs, true
}

// CheckoutRootTarget reports whether root is the top level of a linked
// worktree checkout that resolves to another project root today and, when
// it is, returns that project root (Info.Root). Builds before lane
// shr-worktree2 gave a relative-path worktree (git 2.48
// `worktree.useRelativePaths`) a project of its own, rooted at its
// checkout; `observer backfill --worktree-roots` moves those rows onto the
// main project. A root that is not a linked worktree's top level on disk
// now (an ordinary repository, a subdirectory, a removed worktree, a
// worktree of a bare repository, whose project is its own checkout)
// reports false.
func CheckoutRootTarget(root string) (string, bool) {
	if root == "" || !filepath.IsAbs(root) {
		return "", false
	}
	abs, err := absResolveSymlinks(root)
	if err != nil {
		return "", false
	}
	loc := locateGit(abs)
	if !loc.ok || !loc.worktree || loc.checkout != abs || loc.root == loc.checkout {
		return "", false
	}
	return loc.root, true
}

// LinkedWorktreeCheckouts lists the top levels of the linked worktrees of
// the repository whose main top level is root, in admin-directory name
// order, at most max (0: none). It reads `<root>/.git/worktrees/*/gitdir`
// (git's back pointers, absolute or relative) and keeps a checkout only
// when it is on disk and resolves back to root as a linked worktree in
// git's layout (CheckoutRootTarget), so a stale admin directory or a
// pointer that names something else is skipped. File reads only, no git
// process (lane shr-worktree2: the guard's in-repo policy files and the
// trust baseline of a project's worktrees).
func LinkedWorktreeCheckouts(root string, max int) []string {
	return ListLinkedWorktrees(root, max).Checkouts
}

// WorktreeListing is one read of a repository's linked worktree admin
// entries (`<root>/.git/worktrees/*`).
type WorktreeListing struct {
	// Checkouts is LinkedWorktreeCheckouts' answer: the on-disk checkouts
	// that resolve back to root, symlinks resolved.
	Checkouts []string
	// Pointed is every on-disk checkout an admin entry points to, symlinks
	// resolved, whether or not it resolves back to root.
	Pointed []string
	// Complete is true only when every admin entry was read whole: the
	// admin directory read (or `<root>/.git` is a directory without one),
	// every gitdir file read and resolved, every pointed checkout on disk,
	// and no entry left unread at the cap of max checkouts. A partial listing proves nothing about
	// an entry it could not read (lane LEFT-SEC audit F1).
	Complete bool
}

// ListLinkedWorktrees reads root's linked worktree admin entries, at most
// max of them (LinkedWorktreeCheckouts is its Checkouts), and says whether
// the read was whole. File reads only, no git process.
func ListLinkedWorktrees(root string, max int) WorktreeListing {
	var l WorktreeListing
	if root == "" || max <= 0 {
		return l
	}
	adminRoot := filepath.Join(root, ".git", "worktrees")
	entries, err := os.ReadDir(adminRoot)
	if err != nil {
		// No admin directory under a real `.git` directory is a whole
		// answer: the repository has no linked worktree.
		l.Complete = errors.Is(err, fs.ErrNotExist) && isDir(filepath.Join(root, ".git"))
		return l
	}
	l.Complete = true
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if len(l.Checkouts) >= max {
			// More entries than the cap: the rest were never read.
			l.Complete = false
			break
		}
		admin := filepath.Join(adminRoot, e.Name())
		//nolint:gosec // G304: reads git's own back pointer under the repository's .git directory.
		body, err := os.ReadFile(filepath.Join(admin, "gitdir"))
		if err != nil {
			l.Complete = false
			continue
		}
		back, ok := resolveGitPointer(admin, strings.TrimSpace(string(body)))
		if !ok {
			l.Complete = false
			continue
		}
		checkout := filepath.Dir(back)
		resolved, err := filepath.EvalSymlinks(checkout)
		if err != nil {
			// Off disk (an unmounted drive, a moved folder, or a removed
			// worktree git has not pruned yet): unknown, never absent.
			l.Complete = false
			continue
		}
		l.Pointed = append(l.Pointed, resolved)
		got, ok := CheckoutRootTarget(checkout)
		if !ok || (got != root && !sameFile(got, root)) {
			continue
		}
		l.Checkouts = append(l.Checkouts, resolved)
	}
	return l
}
