package workspace

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// return.go plans the return step of a copy workspace (sandbox plan v2
// section 6, SBX-BE-10; lane SBX-P3A): when a box worked on a copy, the
// commits it made come back into the source repository as ONE new
// namespaced ref, refs/observer/sandbox/<run>, never into the working tree
// and never over an existing ref. Everything the box wrote is
// attacker-written, so the host:
//
//   - runs git only in the SOURCE repository (the user's own), fetching
//     from the copy with transfer.fsckObjects, no tags, no submodules, no
//     FETCH_HEAD and no hooks, by the single commit the copy's HEAD names
//     (on git older than 2.29, which has no --no-write-fetch-head, the cmd
//     layer puts the source's FETCH_HEAD back as it was; GitVersion);
//   - caps the copy's size before anything is fetched;
//   - checks every path of the returned tree (no absolute path, no "..",
//     no .git component, no control character, a length and count cap);
//   - calls ONE injected scan function (nil when the security module is
//     absent) after the objects are in and checked and BEFORE the ref is
//     written, so the box's commits get their commit-scope scan on return;
//   - writes the ref create-only (update-ref with an empty old value) and
//     reads it back.
//
// The copy itself is never deleted by this step: whether it holds
// uncommitted work cannot be told without running git in the agent-written
// repository (whose config can run filters), so it stays a managed
// workspace, listed by `observer workspaces` and swept by
// workspace_retention_days (copy-then-delete never deletes first).
//
// This file only builds argv; the cmd layer runs them (one runner, the
// workspace prep's).

// ReturnRefPrefix is the namespace every returned ref lives in.
const ReturnRefPrefix = "refs/observer/sandbox/"

// The return caps.
const (
	// MaxReturnBytes caps the copy's .git directory before a fetch.
	MaxReturnBytes = 2 << 30
	// MaxReturnPaths caps the paths of the returned tree.
	MaxReturnPaths = 200000
	// maxReturnPathLen caps one path.
	maxReturnPathLen = 4096
	// MaxReturnSymlinks caps the symlinks of the returned tree (each target
	// is read and checked).
	MaxReturnSymlinks = 10000
	// maxSymlinkTarget caps one symlink target.
	maxSymlinkTarget = 4096
)

// ReturnRequest names one return.
type ReturnRequest struct {
	// SourceRepo is the repository the copy was made from (absolute).
	SourceRepo string
	// CopyDir is the copy's working tree (absolute, under ManagedRoot).
	CopyDir string
	// ManagedRoot is the managed-workspaces root.
	ManagedRoot string
	// RunID names the run, and so the ref.
	RunID string
	// Bare is set for a clone-remote copy (lane SBX-P3C): there is no local
	// source repository to fetch into, so SourceRepo is a host-created bare
	// repository at exactly ReturnRepoPath(ManagedRoot, RunID), never the
	// agent-written copy and never pushed anywhere (return_bare.go).
	Bare bool `json:"bare,omitempty"`
	// BaseCommit is the commit a bare return's copy was cloned at, read by
	// the host before the box ran: a copy whose HEAD is still it returns
	// nothing.
	BaseCommit string `json:"base_commit,omitempty"`
}

// ReturnPlan builds the steps of one return.
type ReturnPlan struct {
	req ReturnRequest
	// gitVer is the host git's version (WithGitVersion); the zero value is
	// an unknown version, which takes the older-git path.
	gitVer GitVersion
	// Ref is the ref the return creates.
	Ref string
}

// GitVersion is the host git's version, read once per return (VersionStep,
// through the same hardened runner as every other step) so the fetch passes
// only flags that git knows: git older than 2.29 rejects
// --no-write-fetch-head and --no-auto-maintenance with exit 129. Known is
// false when the answer did not parse; the plan then takes the older-git
// path, which works on every git and is as safe.
type GitVersion struct {
	Major, Minor int
	Known        bool
}

// gitVersionRE reads "git version 2.25.1", "git version 2.39.2.windows.1"
// and "git version 2.37.1 (Apple Git-137.1)".
var gitVersionRE = regexp.MustCompile(`^git version (\d+)\.(\d+)(?:[.\s]|$)`)

// ParseGitVersion reads `git version`'s answer.
func ParseGitVersion(out []byte) GitVersion {
	m := gitVersionRE.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return GitVersion{}
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return GitVersion{}
	}
	return GitVersion{Major: major, Minor: minor, Known: true}
}

// AtLeast reports whether v is a known version at or above major.minor.
func (v GitVersion) AtLeast(major, minor int) bool {
	return v.Known && (v.Major > major || (v.Major == major && v.Minor >= minor))
}

// fetchSafetyFlags is the fetch's version-gated flags, walked top-down
// (CLAUDE.md module rule 5): each is passed only from the version given (the
// oldest git it is known, and on this project's hosts verified, to accept),
// and an older git reaches the same safety the way the row says. No row
// weakens a check: the objects are fsck-checked by safeGit's -c settings on
// every git, and no fetch names a destination ref, so no ref is written on
// any git.
var fetchSafetyFlags = []struct {
	flag         string
	major, minor int
}{
	// Older: safeGit's -c gc.auto=0.
	{"--no-auto-gc", 2, 25},
	// Older: the cmd layer puts FETCH_HEAD back (FetchWritesFetchHead).
	{"--no-write-fetch-head", 2, 29},
	// Older: safeGit's -c gc.auto=0 and -c maintenance.auto=false (git
	// before 2.29 has no maintenance to run).
	{"--no-auto-maintenance", 2, 29},
}

// WithGitVersion returns the plan for the host git v (VersionStep's answer,
// read by ParseGitVersion).
func (p ReturnPlan) WithGitVersion(v GitVersion) ReturnPlan {
	p.gitVer = v
	return p
}

// VersionStep asks the host git its version.
func (p ReturnPlan) VersionStep() Step { return p.git("version") }

// FetchWritesFetchHead reports whether Fetch, on the plan's git, writes the
// source's FETCH_HEAD (git before 2.29, or an unknown version): the cmd
// layer then reads FetchHeadPath before the fetch and puts the file back as
// it was (or removes it when there was none) after it.
func (p ReturnPlan) FetchWritesFetchHead() bool { return !p.gitVer.AtLeast(2, 29) }

// FetchHeadPath asks the source repository where its FETCH_HEAD lives (a
// linked worktree keeps its own), relative to the repository or absolute.
func (p ReturnPlan) FetchHeadPath() Step {
	return p.git("rev-parse", "--git-path", "FETCH_HEAD")
}

// runIDRE is the run id shape a ref component may carry.
var runIDRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$`)

// PlanReturn validates a return request.
func PlanReturn(req ReturnRequest) (ReturnPlan, error) {
	if err := validateAbsPath("SourceRepo", req.SourceRepo); err != nil {
		return ReturnPlan{}, fmt.Errorf("workspace.PlanReturn: %w", err)
	}
	if err := validateAbsPath("CopyDir", req.CopyDir); err != nil {
		return ReturnPlan{}, fmt.Errorf("workspace.PlanReturn: %w", err)
	}
	if err := ValidateManagedWorkspace(req.CopyDir, req.ManagedRoot); err != nil {
		return ReturnPlan{}, fmt.Errorf("workspace.PlanReturn: %w", err)
	}
	if !runIDRE.MatchString(req.RunID) {
		return ReturnPlan{}, fmt.Errorf("workspace.PlanReturn: run id %q is not a clean token", req.RunID)
	}
	if req.Bare {
		if err := checkBareReturn(req); err != nil {
			return ReturnPlan{}, fmt.Errorf("workspace.PlanReturn: %w", err)
		}
	} else if isWithinDir(req.SourceRepo, req.ManagedRoot) {
		return ReturnPlan{}, fmt.Errorf("workspace.PlanReturn: the source repository %s is itself a managed workspace", req.SourceRepo)
	}
	return ReturnPlan{req: req, Ref: ReturnRefPrefix + req.RunID}, nil
}

// isWithinDir reports whether p is root or inside it.
func isWithinDir(p, root string) bool {
	if root == "" {
		return false
	}
	p, root = path.Clean(p), path.Clean(root)
	return p == root || strings.HasPrefix(p, root+"/")
}

// safeGit are the -c settings every return step runs with: no hooks, no
// fsmonitor, objects checked on the way in, no automatic maintenance.
var safeGit = []string{
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.fsmonitor=false",
	"-c", "transfer.fsckObjects=true",
	"-c", "fetch.fsckObjects=true",
	"-c", "gc.auto=0",
	"-c", "maintenance.auto=false",
	"-c", "protocol.file.allow=always",
}

func (p ReturnPlan) git(args ...string) Step {
	argv := append([]string{"git", "-C", p.req.SourceRepo}, safeGit...)
	return Step{Argv: append(argv, args...)}
}

// HeadOfCopy asks the copy which commit its HEAD names (git upload-pack
// reads the copy; nothing in it runs).
func (p ReturnPlan) HeadOfCopy() Step { return p.git("ls-remote", p.req.CopyDir, "HEAD") }

// Exists asks whether the source already has commit sha (nothing new to
// return).
func (p ReturnPlan) Exists(sha string) Step { return p.git("cat-file", "-e", sha+"^{commit}") }

// Fetch brings the copy's commit and its history into the source's object
// store, checked, writing no ref (no destination is named) and, from git
// 2.29, no FETCH_HEAD (before it, FetchWritesFetchHead). The flags a git
// does not know are left out per fetchSafetyFlags.
func (p ReturnPlan) Fetch(sha string) Step {
	args := []string{"fetch", "--no-tags", "--no-recurse-submodules"}
	for _, f := range fetchSafetyFlags {
		if p.gitVer.AtLeast(f.major, f.minor) {
			args = append(args, f.flag)
		}
	}
	return p.git(append(args, p.req.CopyDir, sha)...)
}

// ListPaths lists the returned tree's paths, NUL separated.
func (p ReturnPlan) ListPaths(sha string) Step {
	return p.git("ls-tree", "-r", "-z", "--name-only", sha)
}

// ListTree lists the returned tree's entries with their modes and object
// names ("<mode> <type> <object>\t<path>", NUL separated), so the symlinks
// and gitlinks can be checked (SBX-P3A merge finding F10).
func (p ReturnPlan) ListTree(sha string) Step {
	return p.git("ls-tree", "-r", "-z", "--full-tree", sha)
}

// ReadBlob reads one blob of the source's object store (a symlink's
// target, already fetched and checked).
func (p ReturnPlan) ReadBlob(oid string) Step { return p.git("cat-file", "blob", oid) }

// CreateRef writes the ref only if it does not exist (empty old value).
func (p ReturnPlan) CreateRef(sha string) Step {
	return p.git("update-ref", "-m", "observer sandbox return "+p.req.RunID, p.Ref, sha, "")
}

// VerifyRef reads the ref back.
func (p ReturnPlan) VerifyRef() Step {
	return p.git("rev-parse", "--verify", "--quiet", p.Ref+"^{commit}")
}

// shaRE is a full SHA-1 or SHA-256 object name.
var shaRE = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// ParseHead reads ls-remote's answer for HEAD: the "<sha>\tHEAD" line
// (ls-remote's pattern also matches refs ending in /HEAD, such as
// refs/remotes/origin/HEAD, which are ignored).
func ParseHead(out []byte) (string, error) {
	found := ""
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		sha, name, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || name != "HEAD" {
			continue
		}
		if found != "" {
			return "", fmt.Errorf("workspace: the copy answered more than one HEAD line")
		}
		if !shaRE.MatchString(sha) {
			return "", fmt.Errorf("workspace: the copy's HEAD answer %q is not a commit name", line)
		}
		found = sha
	}
	if found == "" {
		return "", fmt.Errorf("workspace: the copy has no HEAD commit")
	}
	return found, nil
}

// ValidSHA reports whether s is a full object name.
func ValidSHA(s string) bool { return shaRE.MatchString(s) }

// CheckReturnedPaths checks every path of the returned tree.
func CheckReturnedPaths(nulList []byte) error {
	n := 0
	for _, raw := range bytes.Split(nulList, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		n++
		if n > MaxReturnPaths {
			return fmt.Errorf("workspace: the returned tree has more than %d paths", MaxReturnPaths)
		}
		if err := checkReturnedPath(string(raw)); err != nil {
			return err
		}
	}
	return nil
}

func checkReturnedPath(p string) error {
	switch {
	case len(p) > maxReturnPathLen:
		return fmt.Errorf("workspace: a returned path is longer than %d bytes", maxReturnPathLen)
	case strings.HasPrefix(p, "/"):
		return fmt.Errorf("workspace: returned path %q is absolute", p)
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return fmt.Errorf("workspace: returned path %q holds a control character", p)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		low := strings.ToLower(strings.TrimRight(seg, ". "))
		switch {
		case seg == "" || seg == "." || seg == "..":
			return fmt.Errorf("workspace: returned path %q leaves the repository", p)
		case low == ".git" || strings.HasPrefix(low, "git~"):
			return fmt.Errorf("workspace: returned path %q names a .git directory", p)
		}
	}
	return nil
}

// TreeEntry is one entry of the returned tree.
type TreeEntry struct {
	Mode   string
	Type   string
	Object string
	Path   string
}

// The entry modes the tree check acts on.
const (
	modeSymlink = "120000"
	modeGitlink = "160000"
)

// CheckReturnedTree checks every entry of the returned tree (ListTree's
// answer): each path as CheckReturnedPaths does, a gitlink (a submodule
// commit, which names another repository and is never part of the returned
// objects) refused, and the symlinks returned for their targets to be read
// and checked (CheckSymlinkTarget), at most MaxReturnSymlinks of them.
func CheckReturnedTree(nulList []byte) ([]TreeEntry, error) {
	n := 0
	var links []TreeEntry
	for _, raw := range bytes.Split(nulList, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		n++
		if n > MaxReturnPaths {
			return nil, fmt.Errorf("workspace: the returned tree has more than %d paths", MaxReturnPaths)
		}
		meta, name, ok := strings.Cut(string(raw), "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return nil, fmt.Errorf("workspace: a returned tree entry %q is not <mode> <type> <object>\\t<path>", string(raw))
		}
		e := TreeEntry{Mode: f[0], Type: f[1], Object: f[2], Path: name}
		if err := checkReturnedPath(e.Path); err != nil {
			return nil, err
		}
		switch {
		case e.Mode == modeGitlink || e.Type == "commit":
			return nil, fmt.Errorf("workspace: returned path %q is a gitlink (a submodule commit of another repository); a returned tree may not carry one", e.Path)
		case e.Mode == modeSymlink:
			if !shaRE.MatchString(e.Object) {
				return nil, fmt.Errorf("workspace: returned symlink %q names object %q", e.Path, e.Object)
			}
			if len(links) >= MaxReturnSymlinks {
				return nil, fmt.Errorf("workspace: the returned tree has more than %d symlinks", MaxReturnSymlinks)
			}
			links = append(links, e)
		}
	}
	return links, nil
}

// CheckSymlinkTarget checks one returned symlink's target: relative, no
// control character, and, resolved from the link's own directory, inside
// the returned tree and never into a .git directory. A link that points
// outside would let a later checkout of the returned ref read or write a
// host path through it.
func CheckSymlinkTarget(linkPath string, target []byte) error {
	t := string(target)
	switch {
	case len(t) == 0:
		return fmt.Errorf("workspace: returned symlink %q has an empty target", linkPath)
	case len(t) > maxSymlinkTarget:
		return fmt.Errorf("workspace: returned symlink %q has a target longer than %d bytes", linkPath, maxSymlinkTarget)
	case strings.HasPrefix(t, "/") || (len(t) >= 2 && t[1] == ':') || strings.HasPrefix(t, "\\"):
		return fmt.Errorf("workspace: returned symlink %q points at the absolute path %q, outside the returned tree", linkPath, t)
	}
	for _, r := range t {
		if unicode.IsControl(r) {
			return fmt.Errorf("workspace: returned symlink %q has a control character in its target", linkPath)
		}
	}
	resolved := path.Clean(path.Join(path.Dir(linkPath), strings.ReplaceAll(t, "\\", "/")))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("workspace: returned symlink %q points at %q, outside the returned tree", linkPath, t)
	}
	for _, seg := range strings.Split(resolved, "/") {
		low := strings.ToLower(strings.TrimRight(seg, ". "))
		if low == ".git" || strings.HasPrefix(low, "git~") {
			return fmt.Errorf("workspace: returned symlink %q points into a .git directory (%q)", linkPath, t)
		}
	}
	return nil
}

// maxSymlinkHops bounds how many returned symlinks one resolution may pass
// through, like the kernel's own limit (ELOOP).
const maxSymlinkHops = 40

// CheckSymlinkChains resolves every returned symlink the way the kernel
// would after a checkout, following the other returned symlinks it passes
// through (targets maps each link's path to its target), and refuses one
// that leaves the returned tree, enters a .git directory or loops.
// CheckSymlinkTarget alone judges each target lexically from its own
// directory, which a chain defeats: a link "d" deep in the tree that points
// back to the top cleans to "." on its own, and "esc -> <...>/d/../../x"
// then cleans to an inside path while the kernel resolves it above the
// tree (RB1 sweep finding S1). Run it after CheckSymlinkTarget passed for
// every link.
func CheckSymlinkChains(targets map[string]string) error {
	for link, target := range targets {
		dir := path.Dir(link)
		var stack []string
		if dir != "." {
			stack = strings.Split(dir, "/")
		}
		if _, err := resolveReturned(stack, target, targets); err != nil {
			return fmt.Errorf("workspace: returned symlink %q: %w", link, err)
		}
	}
	return nil
}

// resolveReturned walks target from the directory stack, substituting each
// returned symlink it reaches, and returns the resolved path components.
func resolveReturned(stack []string, target string, targets map[string]string) ([]string, error) {
	stack = append([]string(nil), stack...)
	rest := strings.Split(strings.ReplaceAll(target, "\\", "/"), "/")
	hops := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(stack) == 0 {
				return nil, fmt.Errorf("resolves outside the returned tree")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		low := strings.ToLower(strings.TrimRight(c, ". "))
		if low == ".git" || strings.HasPrefix(low, "git~") {
			return nil, fmt.Errorf("resolves into a .git directory")
		}
		stack = append(stack, c)
		next, isLink := targets[strings.Join(stack, "/")]
		if !isLink {
			continue
		}
		hops++
		if hops > maxSymlinkHops {
			return nil, fmt.Errorf("passes through more than %d symlinks (a loop)", maxSymlinkHops)
		}
		if strings.HasPrefix(next, "/") || strings.HasPrefix(next, "\\") || (len(next) >= 2 && next[1] == ':') {
			return nil, fmt.Errorf("passes through a symlink to an absolute path")
		}
		stack = stack[:len(stack)-1]
		rest = append(strings.Split(strings.ReplaceAll(next, "\\", "/"), "/"), rest...)
	}
	return stack, nil
}

// CheckReturnSize refuses a copy whose .git is over the cap.
func CheckReturnSize(bytes int64) error {
	if bytes > MaxReturnBytes {
		return fmt.Errorf("workspace: the copy's repository is over %d bytes; it is not returned", int64(MaxReturnBytes))
	}
	return nil
}
