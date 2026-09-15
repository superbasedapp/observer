package git

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Identity is the full project-identity bundle for a directory: a
// superset of Info produced by Resolve. See ResolveIdentity's doc
// comment for the semantics of each field, and the Project Identity
// Resolver v2 plan (docs/plans/project-identity-resolver-v2-plan-2026-09
// -06.md §3.1) for the design rationale.
type Identity struct {
	Info // Root / IsGit / Branch / Remote (Remote is NORMALIZED — see ResolveIdentity)

	// UpstreamRemote is the NormalizeRemote'd url of the remote literally
	// named "upstream", or (failing that) the first non-"origin" remote
	// declared in .git/config, in file order. "" when neither exists.
	UpstreamRemote string
	// RemoteOwner is the "host/owner" prefix (OwnerOf) of Remote. ""
	// when Remote has fewer than two path segments.
	RemoteOwner string
	// UpstreamOwner is OwnerOf(UpstreamRemote).
	UpstreamOwner string
	// RootCommitSHA is the repository's stable root commit (see
	// DefaultRootCommit), populated only when IdentityOptions.RootCommit
	// is non-nil. Empty on every hot-path adapter call (they pass nil):
	// the exec is expensive enough that internal/store runs it lazily,
	// once per project root, fenced to at most every
	// store.RootCommitRecheckInterval.
	RootCommitSHA string
	// ContentFingerprint is a sha256 hex digest over a canonical string
	// built from the project's manifest module names and top-level
	// directory names (see ResolveIdentity). "" when there was nothing
	// to fingerprint (an empty or unreadable directory).
	ContentFingerprint string
	// Workspace is the session cwd's position inside the repo: the
	// slash-separated path (relative to Root) of the nearest ancestor
	// directory (walking from dir up to, and including, Root) that
	// contains one of WorkspaceManifests. "" means the workspace IS the
	// repo root, dir lies outside Root, or no manifest was found.
	Workspace string
	// IsWorktree is true when dir resolved to its git root through a
	// linked worktree's `.git` FILE (as opposed to the main repo's
	// `.git` directory).
	IsWorktree bool
}

// IdentityOptions configures ResolveIdentity's optional, non-pure-file-
// read behavior. The zero value performs only file reads (as pure as
// Resolve) except for the content-fingerprint directory scan, which is
// still just os.ReadDir/os.Stat and can be turned off via
// SkipContentFingerprint.
type IdentityOptions struct {
	// RootCommit runs the root-commit exec (see DefaultRootCommit) for
	// repoRoot. nil (the zero value) skips it entirely — Identity.
	// RootCommitSHA comes back "" and no error is returned. Every W1
	// adapter call site passes nil: the watcher/hook hot path must not
	// fork a git process per event. internal/store instead runs
	// DefaultRootCommit directly, lazily, gated by
	// store.RootCommitNeedsCheck's 7-day retry fence.
	RootCommit func(ctx context.Context, repoRoot string) (string, error)
	// SkipContentFingerprint disables the manifest/top-level-directory
	// scan for callers that have no use for it.
	SkipContentFingerprint bool
}

// ResolveIdentity reports the full project identity for the project
// containing dir — a superset of Resolve. Two things distinguish it from
// Resolve:
//
//  1. Info.Remote (and the new UpstreamRemote) come back NORMALIZED via
//     NormalizeRemote, unlike Resolve's Info.Remote, which is the RAW
//     origin URL. Every existing git.Resolve call site normalizes the
//     remote itself before use — after switching to ResolveIdentity,
//     callers should use the already-normalized field directly and drop
//     their own NormalizeRemote call. NormalizeRemote is idempotent, so
//     leaving the extra call in is harmless, just redundant.
//  2. It reads EVERY declared remote (not just origin) and derives the
//     owner/root-commit/fingerprint/workspace/worktree signals described
//     on Identity.
//
// A dir that is not inside any git working tree still returns a valid
// Identity (IsGit=false, Root=dir after symlink evaluation) with an
// honestly empty Branch/Remote/UpstreamRemote/Workspace/RootCommitSHA;
// ContentFingerprint is still computed from dir itself (it is never
// git-gated — spec accepts ".git"-less directories as fingerprint
// candidates).
func ResolveIdentity(dir string, opts IdentityOptions) (Identity, error) {
	abs, err := absResolveSymlinks(dir)
	if err != nil {
		return Identity{}, fmt.Errorf("git.ResolveIdentity: %w", err)
	}

	root, isGit, isWorktree := findGitRootDetailed(abs)
	if !isGit {
		root = abs
	}

	id := Identity{
		Info: Info{Root: root, IsGit: isGit},
	}

	if isGit {
		id.IsWorktree = isWorktree
		id.Branch = readBranch(root)
		id.Remote = NormalizeRemote(readOriginRemote(root))
		remotes := readAllRemotes(root)
		id.UpstreamRemote = NormalizeRemote(pickUpstreamRemote(remotes))
		id.RemoteOwner = OwnerOf(id.Remote)
		id.UpstreamOwner = OwnerOf(id.UpstreamRemote)
		id.Workspace = resolveWorkspace(root, abs)

		if opts.RootCommit != nil {
			// ResolveIdentity has no ctx parameter (it mirrors Resolve's
			// signature); every production call passes opts.RootCommit
			// == nil and never reaches this branch. context.Background()
			// is only exercised by tests and any future direct caller
			// that opts in.
			if sha, rcErr := opts.RootCommit(context.Background(), root); rcErr == nil {
				id.RootCommitSHA = sha
			}
		}
	}

	if !opts.SkipContentFingerprint {
		id.ContentFingerprint = computeContentFingerprint(root)
	}

	return id, nil
}

// OwnerOf returns the "host/owner" prefix of a NormalizeRemote'd remote
// string — the first two slash-separated segments (e.g. "github.com/acme"
// from "github.com/acme/repo"; "gitlab.example.com:8443/acme" from
// "gitlab.example.com:8443/acme/repo" — a non-default port stays part of
// the host segment and is preserved as identity, per NormalizeRemote).
// Returns "" when the normalized remote has fewer than two non-empty
// segments — never a partial guess (Project Identity Resolver v2,
// 2026-09-06, §3.1/§3.4: an owner-hash equality is a full-segment match,
// so a partial value must never be produced).
func OwnerOf(normalizedRemote string) string {
	if normalizedRemote == "" {
		return ""
	}
	parts := strings.SplitN(normalizedRemote, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// WorkspaceManifests is the fixed, documented allow-list of files that
// mark a monorepo workspace boundary (Project Identity Resolver v2,
// 2026-09-06, §3.1). Walking UP from a session's cwd to the git root, the
// nearest ancestor directory containing one of these is that session's
// workspace. Deliberately excludes glob patterns (e.g. "*.csproj" — glob
// complexity, skipped by design) and folder-NAME heuristics: the plan's
// "never merge on folder-name similarity" ruling extends here too — only
// an explicit manifest file counts. Order is insignificant (every
// manifest in a directory is checked); the list itself is pinned exactly
// by TestWorkspaceManifestsAllowList so a change is a visible diff.
var WorkspaceManifests = []string{
	"package.json",
	"go.mod",
	"Cargo.toml",
	"pyproject.toml",
	"pom.xml",
	"build.gradle",
	"build.gradle.kts",
	"composer.json",
	"Gemfile",
	"pubspec.yaml",
	"BUILD.bazel",
	"project.json",
}

// resolveWorkspace walks from dir up to (and including) root, and
// returns the RelativePath(root, .) of the nearest directory containing
// a WorkspaceManifests entry. "" when dir lies outside root, dir IS root,
// or nothing was found. Both root and dir must already be absolute,
// symlink-resolved paths from the same absResolveSymlinks call family so
// string equality against root is reliable.
func resolveWorkspace(root, dir string) string {
	if root == "" || dir == "" {
		return ""
	}
	if rel := RelativePath(root, dir); strings.HasPrefix(rel, "[external]/") {
		return ""
	}

	cur := dir
	for {
		for _, m := range WorkspaceManifests {
			if _, err := os.Stat(filepath.Join(cur, m)); err == nil {
				if cur == root {
					return ""
				}
				return RelativePath(root, cur)
			}
		}
		if cur == root {
			return ""
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

// contentFingerprintPrefix domain-separates the fingerprint input so it
// can never collide with an unrelated hash computed over similar-looking
// input elsewhere in the codebase.
const contentFingerprintPrefix = "sbo-projfp-v1\n"

// contentFingerprintDirCap bounds the number of top-level directory
// names folded into a content fingerprint, so a directory with an
// enormous flat fan-out can't turn this into an expensive hash.
const contentFingerprintDirCap = 500

// contentFingerprintExcludedDirs are top-level directory names that are
// dependency/build output, not project identity signal.
var contentFingerprintExcludedDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"target":       true,
	"dist":         true,
	"build":        true,
}

// computeContentFingerprint returns a sha256 hex digest over the sorted
// set of manifest module names declared directly in root UNION the
// sorted set of root's top-level directory names (excluding dot-
// directories and contentFingerprintExcludedDirs). Returns "" when both
// sets are empty — an empty fingerprint is never hashed, so it can never
// collide with sha256("") elsewhere. Reads no file contents beyond the
// few named manifest key lines (readManifestModuleName) and never
// recurses.
func computeContentFingerprint(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}

	var dirNames []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || contentFingerprintExcludedDirs[name] {
			continue
		}
		dirNames = append(dirNames, name)
		if len(dirNames) >= contentFingerprintDirCap {
			break
		}
	}
	sort.Strings(dirNames)

	var moduleNames []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name := readManifestModuleName(root, e.Name()); name != "" {
			moduleNames = append(moduleNames, name)
		}
	}
	sort.Strings(moduleNames)

	if len(dirNames) == 0 && len(moduleNames) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(contentFingerprintPrefix)
	sb.WriteString(strings.Join(moduleNames, "\n"))
	sb.WriteString("\n--\n")
	sb.WriteString(strings.Join(dirNames, "\n"))

	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// readManifestModuleName extracts the declared module/package name from
// one of the content-fingerprint's supported manifest files. Returns ""
// for a manifest it can't cheaply parse or doesn't recognize — by
// design, only go.mod, package.json, Cargo.toml and pyproject.toml are
// supported (Project Identity Resolver v2, 2026-09-06, §3.1).
func readManifestModuleName(root, filename string) string {
	switch filename {
	case "go.mod":
		return readGoModModule(filepath.Join(root, filename))
	case "package.json":
		return readPackageJSONName(filepath.Join(root, filename))
	case "Cargo.toml":
		return readTOMLSectionName(filepath.Join(root, filename), "package")
	case "pyproject.toml":
		path := filepath.Join(root, filename)
		if name := readTOMLSectionName(path, "project"); name != "" {
			return name
		}
		return readTOMLSectionName(path, "tool.poetry")
	default:
		return ""
	}
}

func readGoModModule(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func readPackageJSONName(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var v struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	return v.Name
}

// readTOMLSectionName does a minimal, dependency-free scan for a
// `name = "..."` (or '...') key inside a `[section]` header — not a
// general TOML parser, just enough to pull one string key out of one
// section for the content fingerprint's manifest allow-list (Cargo.toml
// [package], pyproject.toml [project] / [tool.poetry]).
func readTOMLSectionName(path, section string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	want := "[" + section + "]"
	inSection := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inSection = trimmed == want
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(trimmed, "name") {
			if eq := strings.Index(trimmed, "="); eq >= 0 {
				val := strings.TrimSpace(trimmed[eq+1:])
				val = strings.Trim(val, `"'`)
				return val
			}
		}
	}
	return ""
}

// DefaultRootCommit runs `git rev-list --max-parents=0 HEAD` in repoRoot
// with a 2s timeout and returns the lexicographically smallest SHA when
// the repository has multiple root commits (possible after a
// --allow-unrelated-histories merge). Returns "" and a wrapped error when
// the git binary is missing, the command times out, the context is
// already done, or the repository has no root commit — callers (see
// internal/store's RootCommitNeedsCheck 7-day retry fence) treat any
// error as "unknown, retry later", never fatal.
func DefaultRootCommit(ctx context.Context, repoRoot string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, "git", "rev-list", "--max-parents=0", "HEAD")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git.DefaultRootCommit: %w", err)
	}

	shas := strings.Fields(string(out))
	if len(shas) == 0 {
		return "", fmt.Errorf("git.DefaultRootCommit: no root commit found in %s", repoRoot)
	}
	sort.Strings(shas)
	return shas[0], nil
}
