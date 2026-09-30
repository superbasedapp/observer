package gitview

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	// perCommandTimeout bounds each individual git invocation.
	perCommandTimeout = 3 * time.Second
	// waitDelay bounds how long Wait blocks for I/O after the git process exits
	// or the context is cancelled, so a descendant (hook/helper) that inherited
	// the output pipes cannot keep Wait blocked forever.
	waitDelay = 2 * time.Second
	// maxOutputBytes caps stdout/stderr captured from a single git invocation
	// (~1MB) so a pathological repository cannot exhaust memory.
	maxOutputBytes = 1 << 20
	// logLimit bounds the commit graph returned by Snapshot.
	logLimit = 100
	// statusLimit caps the number of working-tree status entries returned. A
	// repository with an enormous dirty set is truncated and status_truncated is
	// reported true.
	statusLimit = 1000
)

// ErrGitUnavailable is returned when the git binary cannot be found or executed.
// The dashboard maps it to a git_available:false meta payload rather than a
// hard error.
var ErrGitUnavailable = errors.New("gitview: git binary unavailable")

// GitError structurally describes one non-zero git exit: its exit code
// and the raw (LC_ALL=C-pinned) stderr text git wrote, if any. A caller
// classifying a failure can then branch on that STRUCTURE — the exit
// code, and whether git printed a diagnostic at all — instead of
// matching a particular diagnostic's English wording, which drifts
// across git versions/locales and cannot reliably tell one failure
// class apart from another (2026-09-22 review finding S8: the pre-fix
// IsNoCommitsError matched the literal substring "Needed a single
// revision", indistinguishable from a malformed/dangling HEAD that
// happens to print similar text). runGitCapped returns *GitError for
// every non-zero git exit that isn't a missing-binary
// (ErrGitUnavailable) failure.
type GitError struct {
	Args     []string
	ExitCode int
	Stderr   string
}

// Error renders the same shape runGit's pre-GitError text used, so
// existing log lines / %v formatting stay readable.
func (e *GitError) Error() string {
	if e.Stderr == "" {
		return fmt.Sprintf("gitview.runGit %v: exit status %d", e.Args, e.ExitCode)
	}
	return fmt.Sprintf("gitview.runGit %v: exit status %d (%s)", e.Args, e.ExitCode, e.Stderr)
}

// IsNoCommitsError classifies an error from a `--quiet` git lookup probe
// — `git rev-parse --verify --quiet HEAD`, or the structurally identical
// `git show-ref --verify --quiet <ref>` — as "this target did not
// resolve, and git said nothing about why": EXACTLY exit code 1 with
// EMPTY stderr, `--quiet`'s own documented contract for a failed lookup
// ("do not output an error message ... instead exit with non-zero
// status silently"). This is a STRUCTURAL classification (the exact
// exit code plus the literal absence of any diagnostic text), not a
// match on any particular wording, so it holds across git versions/
// locales without tracking a message string (2026-09-22 review finding
// S8).
//
// The check requires ExitCode == 1 EXACTLY, never "any positive code"
// (2026-09-22 review finding 11): a corrupt repository, a permission
// failure, or git refusing to run at all ("not a git repository") all
// exit non-zero and can print NOTHING to stderr under some git
// versions/configurations, but git documents 128 (not 1) for "fatal"
// startup-level failures — a caller must not read exit 128 as a quiet
// lookup miss. Exit 1 also cannot collide with ExitCode()'s -1 sentinel
// for a signal-killed or still-running process (e.g. a context
// deadline), which a naive "!= 0" check would.
//
// This signal alone is NOT sufficient to conclude "healthy, no commits
// yet" for the rev-parse probe: a detached HEAD pointing at a missing/
// invalid object fails the exact same way. internal/commitscan's
// resolveHeadSHA treats IsNoCommitsError==true on the rev-parse probe as
// only the FIRST of two probes, following it with an independent
// ref-state probe (`git symbolic-ref -q HEAD` then `git show-ref
// --verify --quiet <that ref>`, ALSO classified through this same
// predicate — its `--quiet` failure contract is identical) before
// concluding "no commits yet" — see resolveHeadSHA's doc comment for the
// full decision table.
func IsNoCommitsError(err error) bool {
	var gitErr *GitError
	if !errors.As(err, &gitErr) {
		return false
	}
	return gitErr.ExitCode == 1 && gitErr.Stderr == ""
}

// missingObjectPhrases are git's C-locale (the envelope forces LC_ALL=C)
// fatal diagnostics for "that object is not in this repository": a commit
// garbage-collected after a rebase, one beyond a shallow clone's boundary,
// or one a partial clone would have to fetch (GIT_NO_LAZY_FETCH=1 turns
// that fetch into this error). Data, not a ladder.
var missingObjectPhrases = []string{
	"not a tree object",
	"bad object",
	"not a valid object name",
	"invalid object name",
	"unable to read tree",
	"could not fetch",
	"lazy fetching disabled",
}

// IsMissingObjectError reports whether err is a git fatal (exit 128) whose
// diagnostic says the named object does not exist locally. The skills
// history step (internal/skillscan) records such a commit as "missing"
// instead of retrying it forever; any other failure stays retryable.
func IsMissingObjectError(err error) bool {
	var gitErr *GitError
	if !errors.As(err, &gitErr) || gitErr.ExitCode != 128 {
		return false
	}
	msg := strings.ToLower(gitErr.Stderr)
	for _, p := range missingObjectPhrases {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// notRepoPhrase is git's C-locale (the envelope forces LC_ALL=C) fatal
// diagnostic for a directory that is not inside any work tree: "fatal: not a
// git repository (or any of the parent directories): .git", and the
// GIT_DIR-pointed variant "fatal: not a git repository: '<path>'".
const notRepoPhrase = "not a git repository"

// IsNotRepoError reports whether err is a git fatal (exit 128) saying the
// directory it ran in is not inside a git repository at all. The commit
// scanner (internal/commitscan, wired in cmd/observer/commitscan_wire.go)
// uses it to treat a project root that exists but was never `git init`-ed
// as "not scannable right now" - logged once, re-probed on a slow cadence -
// instead of a per-tick "scan failed" WARN. Any other failure (a timeout,
// a corrupt repository, dubious ownership) is not this class.
func IsNotRepoError(err error) bool {
	var gitErr *GitError
	if !errors.As(err, &gitErr) || gitErr.ExitCode != 128 {
		return false
	}
	return strings.Contains(strings.ToLower(gitErr.Stderr), notRepoPhrase)
}

// FileStatus is one changed path in the working tree. Staged and Worktree are
// single-character porcelain-v2 status codes for the index (X) and working-tree
// (Y) axes respectively ("." = unmodified in that axis, "?" = untracked).
// RenamedFrom is the original path for a rename/copy, else empty.
type FileStatus struct {
	Path        string `json:"path"`
	Staged      string `json:"staged"`
	Worktree    string `json:"worktree"`
	RenamedFrom string `json:"renamed_from"`
}

// Commit is one node in the commit graph.
type Commit struct {
	Hash    string   `json:"hash"`
	Parents []string `json:"parents"`
	Author  string   `json:"author"`
	Date    string   `json:"date"` // RFC3339 (git %aI)
	Refs    []string `json:"refs"`
	Subject string   `json:"subject"`
}

// Info is the read-only snapshot of a repository's state. Status and Log (and
// each Commit's Parents/Refs) are always non-nil so the JSON encoding satisfies
// the frontend's array contract ([] never null).
type Info struct {
	IsGit           bool         `json:"is_git"`
	Branch          string       `json:"branch"`
	Upstream        string       `json:"upstream"`
	Ahead           int          `json:"ahead"`
	Behind          int          `json:"behind"`
	Status          []FileStatus `json:"status"`
	StatusTruncated bool         `json:"status_truncated"`
	Log             []Commit     `json:"log"`
	LogTruncated    bool         `json:"log_truncated"`
}

// EmptyInfo returns a normalized not-a-repo snapshot with non-nil empty
// Status/Log slices. A caller that must emit the array-contract wire shape
// without running git (e.g. a git-level error fallback) uses this so the
// frontend never receives status:null / log:null.
func EmptyInfo() Info {
	return normalizeInfo(Info{})
}

// normalizeInfo replaces every nil slice (Status, Log, and each commit's
// Parents/Refs) with a non-nil empty slice so the JSON encoding is always an
// array, satisfying the frontend contract that calls .length / iterates them.
func normalizeInfo(info Info) Info {
	if info.Status == nil {
		info.Status = []FileStatus{}
	}
	if info.Log == nil {
		info.Log = []Commit{}
	}
	for i := range info.Log {
		if info.Log[i].Parents == nil {
			info.Log[i].Parents = []string{}
		}
		if info.Log[i].Refs == nil {
			info.Log[i].Refs = []string{}
		}
	}
	return info
}

// Snapshot collects a read-only view of the repository rooted at root. A path
// that is not a git work tree returns Info{IsGit:false} with a nil error. A
// missing git binary returns ErrGitUnavailable. Status/log parse failures are
// non-fatal: the snapshot returns whatever it could gather.
func Snapshot(ctx context.Context, root string) (Info, error) {
	out, _, err := runGit(ctx, root, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		if errors.Is(err, ErrGitUnavailable) {
			return Info{}, ErrGitUnavailable
		}
		// Not a work tree (or any other git-level error): report not-a-repo.
		return EmptyInfo(), nil
	}
	if strings.TrimSpace(string(out)) != "true" {
		return EmptyInfo(), nil
	}

	info := Info{IsGit: true}

	if statusOut, overflow, serr := runGit(ctx, root,
		"status", "--porcelain=v2", "--branch", "-z", "--"); serr == nil {
		// On a stdout byte-cap overflow, drop the trailing possibly-partial
		// NUL-terminated record before parsing and flag truncation (finding 11).
		if overflow {
			statusOut = dropTrailingPartial(statusOut, 0x00)
			info.StatusTruncated = true
		}
		info.Branch, info.Upstream, info.Ahead, info.Behind, info.Status = parseStatusPorcelainV2(statusOut)
		// Cap the returned status set (finding 10): drop the rest, flag truncation.
		if len(info.Status) > statusLimit {
			info.Status = info.Status[:statusLimit]
			info.StatusTruncated = true
		}
	}

	if logOut, overflow, lerr := runGit(ctx, root,
		"log", "-n", strconv.Itoa(logLimit), "--branches", "--tags", "HEAD",
		"--topo-order",
		"--pretty=format:%H%x00%P%x00%an%x00%aI%x00%D%x00%s%x1e", "--"); lerr == nil {
		// On overflow, drop the trailing partial record (0x1e-separated) so a
		// truncated final commit is not parsed as complete, and flag truncation.
		if overflow {
			logOut = dropTrailingPartial(logOut, 0x1e)
		}
		var hitLimit bool
		info.Log, hitLimit = parseLog(logOut)
		info.LogTruncated = hitLimit || overflow
	}

	return normalizeInfo(info), nil
}

// runGit executes a read-only git command rooted at root and returns captured
// stdout (capped at maxOutputBytes) plus whether that cap was hit (stdout
// overflowed). A missing/unrunnable binary is reported as ErrGitUnavailable; a
// non-zero exit wraps the underlying error with %w (so timeout/cancellation
// stays classifiable) and includes the trimmed stderr for context.
func runGit(ctx context.Context, root string, args ...string) ([]byte, bool, error) {
	return runGitCapped(ctx, root, maxOutputBytes, perCommandTimeout, nil, args...)
}

// RunReadOnly is runGit with a CALLER-CHOSEN stdout byte cap, exported so a
// second consumer (internal/commitscan's commit-log scan, which needs a
// larger cap than the default 1MiB status/log snapshot) can reuse the exact
// same safe-invocation envelope — the -C root pin, the lock-free/no-hook/
// no-pager config overrides, the LC_ALL=C + GIT_TERMINAL_PROMPT=0
// environment, the WaitDelay bound, and the ErrGitUnavailable /
// stderr-wrapped-error classification — rather than growing a second,
// drifting implementation of any of that. Every existing gitview caller
// keeps going through runGit (and therefore maxOutputBytes) unchanged;
// this is purely an additional entry point.
func RunReadOnly(ctx context.Context, root string, maxBytes int, args ...string) ([]byte, bool, error) {
	return RunReadOnlyTimeout(ctx, root, maxBytes, perCommandTimeout, args...)
}

// RunReadOnlyTimeout is RunReadOnly with a CALLER-CHOSEN per-invocation
// timeout (<= 0 falls back to the dashboard's perCommandTimeout). The
// dashboard's 3 s bound is right for a status/branch snapshot on a
// request path; a background commit-log page (`git log --numstat` over
// hundreds of commits) legitimately needs tens of seconds on a large
// repository, and a scan that always times out is a scanner that never
// captures anything. Same envelope, same caps, one more knob.
func RunReadOnlyTimeout(ctx context.Context, root string, maxBytes int, timeout time.Duration, args ...string) ([]byte, bool, error) {
	if maxBytes <= 0 {
		maxBytes = maxOutputBytes
	}
	if timeout <= 0 {
		timeout = perCommandTimeout
	}
	return runGitCapped(ctx, root, maxBytes, timeout, nil, args...)
}

// RunReadOnlyNoLazyFetch is RunReadOnlyTimeout with GIT_NO_LAZY_FETCH=1
// added: on a PARTIAL clone (--filter=blob:none / tree:0) a missing object
// becomes an error instead of a fetch from the promisor remote. Same
// envelope, same caps, one more environment entry.
//
// It is deliberately NOT the default for every invocation: the commit
// scanner's line counts need blob contents, and on a blobless clone they
// only exist remotely, so forcing the variable there turns every scan into
// a failure (verified 2026-09-23, docs/security.md SKILL-2). The skills
// history step only lists trees and reads the reflog, so it can refuse a
// fetch without losing anything but the missing object itself.
func RunReadOnlyNoLazyFetch(ctx context.Context, root string, maxBytes int, timeout time.Duration, args ...string) ([]byte, bool, error) {
	if maxBytes <= 0 {
		maxBytes = maxOutputBytes
	}
	if timeout <= 0 {
		timeout = perCommandTimeout
	}
	return runGitCapped(ctx, root, maxBytes, timeout, []string{noLazyFetchEnv}, args...)
}

// runGitCapped is runGit's implementation, parameterized on the stdout/
// stderr byte cap and the per-invocation timeout so runGit (fixed at
// maxOutputBytes / perCommandTimeout) and RunReadOnly[Timeout]
// (caller-chosen) share one envelope.
func runGitCapped(ctx context.Context, root string, maxBytes int, timeout time.Duration, extraEnv []string, args ...string) ([]byte, bool, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Force a safe, non-executing command-line configuration BEFORE the
	// subcommand. A hostile repository's own .git/config (or an inherited env
	// config) must not be able to run a program from a read-only dashboard
	// request: core.fsmonitor runs a helper on every status; core.hookspath +
	// hooks run arbitrary scripts; the pager can spawn a program. Command-line
	// -c overrides repo/global/system config, so these win regardless of the
	// repository. --no-pager + core.pager=cat also keep output non-interactive.
	full := []string{
		"-C", root,
		"--no-optional-locks",
		"--no-pager",
		"-c", "core.fsmonitor=false",
		"-c", "core.untrackedcache=false",
		"-c", "core.hookspath=",
		"-c", "core.pager=cat",
	}
	full = append(full, args...)
	cmd := exec.CommandContext(cctx, "git", full...)
	cmd.Env = append(append(os.Environ(), gitEnvOverrides...), extraEnv...)
	// Bound the time Wait blocks for I/O after the process exits or the context
	// cancels, so a descendant holding the output pipes cannot keep Wait blocked
	// forever (finding 6).
	cmd.WaitDelay = waitDelay
	var stdout cappedBuffer
	stdout.cap = maxBytes
	// stderr is capped identically so a hook/helper cannot exhaust memory by
	// writing unbounded diagnostics within the timeout window (finding 6).
	var stderr cappedBuffer
	stderr.cap = maxBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, false, ErrGitUnavailable
		}
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			return nil, false, ErrGitUnavailable
		}
		// exitCode stays -1 (never a real git exit code) when the
		// failure wasn't cmd.Run() itself reporting a plain non-zero
		// exit (e.g. a context deadline) — IsNoCommitsError's `!= 0`
		// check never mismatches that as a git-exit signal.
		exitCode := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		return nil, false, &GitError{
			Args:     append([]string(nil), args...),
			ExitCode: exitCode,
			Stderr:   strings.TrimSpace(string(stderr.Bytes())),
		}
	}
	return stdout.Bytes(), stdout.overflowed, nil
}

// gitEnvOverrides is appended to the inherited environment of every git
// invocation: a stable, lock-free, non-interactive, NETWORK-FREE
// environment for parsing. GIT_ASKPASS + GIT_TERMINAL_PROMPT=0 guarantee
// git never blocks on a credential prompt or runs an askpass helper;
// LC_ALL=C keeps porcelain output (and error text) parseable.
var gitEnvOverrides = []string{
	"LC_ALL=C",
	"GIT_OPTIONAL_LOCKS=0",
	"GIT_TERMINAL_PROMPT=0",
	"GIT_ASKPASS=/bin/false",
}

// noLazyFetchEnv is added only by RunReadOnlyNoLazyFetch (the skills
// history step, S10-SKILLS, docs/security.md SKILL-2).
const noLazyFetchEnv = "GIT_NO_LAZY_FETCH=1"

// cappedBuffer is an io.Writer that accumulates at most cap bytes, discards the
// rest, and records whether any bytes were dropped (overflowed), bounding memory
// for a pathological repository.
type cappedBuffer struct {
	buf        bytes.Buffer
	cap        int
	overflowed bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := c.cap - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
			c.overflowed = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.overflowed = true
	}
	// Report the full length so the writer (git) never sees a short write.
	return len(p), nil
}

func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }

// dropTrailingPartial trims any bytes after the final sep occurrence (keeping
// the sep), discarding a record left incomplete when the stdout byte cap cut the
// stream mid-record. Returns nil when sep never occurs (nothing complete
// survived the cap).
func dropTrailingPartial(data []byte, sep byte) []byte {
	if i := bytes.LastIndexByte(data, sep); i >= 0 {
		return data[:i+1]
	}
	return nil
}

// parseStatusPorcelainV2 parses `git status --porcelain=v2 --branch -z` output.
// Records are NUL-terminated; rename/copy ("2 ") records consume a following
// NUL-separated origin-path token.
func parseStatusPorcelainV2(data []byte) (branch, upstream string, ahead, behind int, files []FileStatus) {
	tokens := strings.Split(string(data), "\x00")
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "" {
			continue
		}
		switch {
		case strings.HasPrefix(tok, "# branch.head "):
			branch = strings.TrimPrefix(tok, "# branch.head ")
		case strings.HasPrefix(tok, "# branch.upstream "):
			upstream = strings.TrimPrefix(tok, "# branch.upstream ")
		case strings.HasPrefix(tok, "# branch.ab "):
			ahead, behind = parseAheadBehind(strings.TrimPrefix(tok, "# branch.ab "))
		case strings.HasPrefix(tok, "1 "):
			if fs, ok := parseChangedEntry(tok, 8); ok {
				files = append(files, fs)
			}
		case strings.HasPrefix(tok, "2 "):
			// Rename/copy: path is field 9; the origin path is the next token.
			if fs, ok := parseChangedEntry(tok, 9); ok {
				if i+1 < len(tokens) {
					fs.RenamedFrom = tokens[i+1]
					i++
				}
				files = append(files, fs)
			}
		case strings.HasPrefix(tok, "u "):
			// Unmerged: path is field 10.
			if fs, ok := parseChangedEntry(tok, 10); ok {
				files = append(files, fs)
			}
		case strings.HasPrefix(tok, "? "):
			files = append(files, FileStatus{
				Path: strings.TrimPrefix(tok, "? "), Staged: "?", Worktree: "?",
			})
		}
		// "! " (ignored) records are intentionally skipped.
	}
	return branch, upstream, ahead, behind, files
}

// parseChangedEntry extracts the XY status and the path (at 0-based field index
// pathField, space-delimited) from a porcelain-v2 "1"/"2"/"u" record.
func parseChangedEntry(tok string, pathField int) (FileStatus, bool) {
	fields := strings.SplitN(tok, " ", pathField+1)
	if len(fields) <= pathField {
		return FileStatus{}, false
	}
	xy := fields[1]
	if len(xy) < 2 {
		return FileStatus{}, false
	}
	return FileStatus{
		Path:     fields[pathField],
		Staged:   string(xy[0]),
		Worktree: string(xy[1]),
	}, true
}

// parseAheadBehind parses a "+A -B" branch.ab value into counts.
func parseAheadBehind(v string) (ahead, behind int) {
	for _, part := range strings.Fields(v) {
		if len(part) < 2 {
			continue
		}
		n, err := strconv.Atoi(part[1:])
		if err != nil {
			continue
		}
		switch part[0] {
		case '+':
			ahead = n
		case '-':
			behind = n
		}
	}
	return ahead, behind
}

// parseLog parses the record-separated (0x1e) commit stream produced by the
// Snapshot log format. It returns the commits and whether the log hit the
// logLimit cap (an approximate "there may be more" signal).
func parseLog(data []byte) ([]Commit, bool) {
	records := strings.Split(string(data), "\x1e")
	commits := make([]Commit, 0, len(records))
	for _, rec := range records {
		// git separates entries with a newline; strip the leading one left after
		// splitting on our record separator.
		rec = strings.TrimLeft(rec, "\n")
		if rec == "" {
			continue
		}
		fields := strings.SplitN(rec, "\x00", 6)
		if len(fields) < 6 {
			continue
		}
		commits = append(commits, Commit{
			Hash:    fields[0],
			Parents: strings.Fields(fields[1]),
			Author:  fields[2],
			Date:    fields[3],
			Refs:    parseRefs(fields[4]),
			Subject: fields[5],
		})
	}
	return commits, len(commits) >= logLimit
}

// parseRefs cleans a git %D ref-decoration string ("HEAD -> main, origin/main,
// tag: v1.0") into a flat list of ref names, dropping the bare "HEAD" pointer
// and the "tag:" prefix.
func parseRefs(d string) []string {
	d = strings.TrimSpace(d)
	if d == "" {
		return nil
	}
	var refs []string
	for _, part := range strings.Split(d, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if idx := strings.Index(p, "-> "); idx >= 0 {
			p = strings.TrimSpace(p[idx+len("-> "):])
		}
		p = strings.TrimPrefix(p, "tag: ")
		if p == "" || p == "HEAD" {
			continue
		}
		refs = append(refs, p)
	}
	return refs
}
