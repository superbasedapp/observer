package landingscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/delivery"
)

// Defaults for the per-pass bounds. Every git call is bounded by the Exec
// envelope's own timeout; these bound how many calls one pass makes.
const (
	defaultWindow             = 90 * 24 * time.Hour
	defaultPollInterval       = 10 * time.Minute
	defaultMaxFingerprints    = 50
	defaultMaxAncestorChecks  = 200
	defaultMaxDefaultCommits  = 500
	defaultMaxDefaultFPs      = 100
	defaultMaxBranches        = 20
	defaultMaxRangeCommits    = 250
	defaultMaxRemoteChecks    = 200
	defaultMaxLandedVia       = 20
	defaultMaxPRFingerprints  = 20
	smallOutput               = 64 << 10
	logOutput                 = 1 << 20
	fingerprintCacheCap       = 20000
	defaultBranchCandidates   = "main,master"
	preferredEvidenceRemotes  = "upstream,origin"
	gitExitFalse              = 1
	fieldSep                  = "\x1f"
	fetchHeadFile             = "FETCH_HEAD"
	remoteURLConfigPattern    = `^remote\..*\.url$`
	remoteTrackingRefPrefix   = "refs/remotes/"
	mirrorBranchRefPrefix     = "refs/heads/"
	localBranchRefPrefix      = "refs/heads/"
	defaultCommitLookbackSlop = 24 * time.Hour
)

// Target is one successfully scanned project root, as the commit scanner
// hands it over (the root already translated by commitscan_wire's
// commitScanRoot).
type Target struct {
	ProjectID int64
	RootPath  string
	HeadSHA   string
}

// Options wires the step. Exec and every store func except the optional ones
// are required; New fills the bounds' defaults.
type Options struct {
	// Exec runs one read-only git invocation rooted at dir (the project
	// root, or an Observer mirror directory). Production: gitview's
	// read-only envelope with lazy fetching refused.
	Exec func(ctx context.Context, dir string, maxBytes int, args ...string) ([]byte, bool, error)
	// ExitCode extracts git's exit code from an Exec error (ok=false when
	// git did not run to an exit, e.g. a timeout).
	ExitCode func(err error) (int, bool)
	// ModTime returns a file's modification time (ok=false when absent).
	ModTime func(path string) (time.Time, bool)

	// Store reads.
	Commits      func(ctx context.Context, projectID int64, since time.Time) ([]delivery.Commit, error)
	Landings     func(ctx context.Context, projectID int64, since, until time.Time) ([]delivery.Landing, error)
	PullRequests func(ctx context.Context, projectID int64, since time.Time) ([]delivery.PullRequest, error)
	PRCommits    func(ctx context.Context, prID int64) ([]delivery.PRCommit, error)
	BranchTips   func(ctx context.Context, projectID int64) ([]delivery.BranchTip, error)
	// Mirrors lists the Observer mirrors (optional: nil means none).
	Mirrors func(ctx context.Context) ([]delivery.Mirror, error)

	// Store writes.
	SetFingerprint func(ctx context.Context, commitID int64, fp, state string) error
	// SetPRCommitFingerprint is optional (nil skips PR commit fingerprints).
	SetPRCommitFingerprint func(ctx context.Context, prID int64, sha, fp string) error
	SaveRemote             func(ctx context.Context, r delivery.Remote) error
	SaveBranchTips         func(ctx context.Context, tips []delivery.BranchTip) error
	SaveLandings           func(ctx context.Context, ls []delivery.Landing) error

	// Window is how far back AI-touched commits are evaluated (default 90d).
	Window time.Duration
	// PollInterval is the minimum time between two passes of one project
	// when neither HEAD nor FETCH_HEAD moved (default 10m).
	PollInterval time.Duration
	// AbandonAfter feeds rules L7 and L8 (default 30d).
	AbandonAfter time.Duration

	MaxFingerprints   int
	MaxAncestorChecks int
	MaxDefaultCommits int
	MaxDefaultFPs     int
	MaxBranches       int
	MaxRangeCommits   int
	MaxRemoteChecks   int

	Now    func() time.Time
	Logger *slog.Logger
}

// Result summarises one pass.
type Result struct {
	ProjectID     int64
	Skipped       bool // throttled: nothing moved since the last pass
	Remotes       int
	Fingerprinted int
	Evaluated     int
	Source        delivery.EvidenceSource
}

// Step is the landing step. Safe for concurrent use on different roots.
type Step struct {
	opts Options

	mu    sync.Mutex
	memo  map[int64]passMemo
	fpMem map[string]fpEntry
}

// passMemo is what the throttle compares.
type passMemo struct {
	head      string
	fetchHead time.Time
	at        time.Time
}

// fpEntry is one cached default-branch commit fingerprint (a commit's patch
// never changes, so the cache is keyed by sha alone).
type fpEntry struct {
	fp    string
	files []string
}

// New returns a Step with the bounds defaulted.
func New(o Options) *Step {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&o.MaxFingerprints, defaultMaxFingerprints)
	def(&o.MaxAncestorChecks, defaultMaxAncestorChecks)
	def(&o.MaxDefaultCommits, defaultMaxDefaultCommits)
	def(&o.MaxDefaultFPs, defaultMaxDefaultFPs)
	def(&o.MaxBranches, defaultMaxBranches)
	def(&o.MaxRangeCommits, defaultMaxRangeCommits)
	def(&o.MaxRemoteChecks, defaultMaxRemoteChecks)
	if o.Window <= 0 {
		o.Window = defaultWindow
	}
	if o.PollInterval <= 0 {
		o.PollInterval = defaultPollInterval
	}
	if o.AbandonAfter <= 0 {
		o.AbandonAfter = delivery.DefaultAbandonAfter
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	return &Step{opts: o, memo: map[int64]passMemo{}, fpMem: map[string]fpEntry{}}
}

// errNoGit marks a git call that did not produce output.
var errNoGit = errors.New("landingscan: git call failed")

// git runs one read-only git call and returns its output.
func (s *Step) git(ctx context.Context, dir string, maxBytes int, args ...string) ([]byte, bool, error) {
	out, overflow, err := s.opts.Exec(ctx, dir, maxBytes, args...)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %w", errNoGit, args[0], err)
	}
	return out, overflow, nil
}

// boolGit runs a git predicate command (merge-base --is-ancestor): exit 0 is
// true, exit 1 false, anything else unknown (ok=false).
func (s *Step) boolGit(ctx context.Context, dir string, args ...string) (value, ok bool) {
	_, _, err := s.opts.Exec(ctx, dir, smallOutput, args...)
	if err == nil {
		return true, true
	}
	if s.opts.ExitCode != nil {
		if code, has := s.opts.ExitCode(err); has && code == gitExitFalse {
			return false, true
		}
	}
	return false, false
}

// Run evaluates one project root. It never writes to the repository; every
// error is returned for the caller to log, and a partial pass still persists
// what it learned.
func (s *Step) Run(ctx context.Context, t Target) (Result, error) {
	res := Result{ProjectID: t.ProjectID}
	now := s.opts.Now().UTC()

	fetchHead := s.fetchHeadTime(ctx, t.RootPath)
	if s.throttled(t, fetchHead, now) {
		res.Skipped = true
		return res, nil
	}

	remotes, err := s.readRemotes(ctx, t, fetchHead, now)
	if err != nil {
		return res, fmt.Errorf("landingscan.Run: remotes: %w", err)
	}
	res.Remotes = len(remotes)
	for _, r := range remotes {
		if err := s.opts.SaveRemote(ctx, r); err != nil {
			return res, fmt.Errorf("landingscan.Run: save remote: %w", err)
		}
	}

	since := now.Add(-s.opts.Window)
	commits, err := s.opts.Commits(ctx, t.ProjectID, since)
	if err != nil {
		return res, fmt.Errorf("landingscan.Run: commits: %w", err)
	}
	if len(commits) == 0 {
		s.remember(t, fetchHead, now)
		return res, nil
	}
	prevList, err := s.opts.Landings(ctx, t.ProjectID, since, now.Add(time.Minute))
	if err != nil {
		return res, fmt.Errorf("landingscan.Run: landings: %w", err)
	}
	prev := make(map[int64]delivery.Landing, len(prevList))
	for _, l := range prevList {
		prev[l.CommitID] = l
	}

	res.Fingerprinted, err = s.fingerprintPending(ctx, t, commits)
	if err != nil {
		return res, fmt.Errorf("landingscan.Run: %w", err)
	}

	ev := s.chooseEvidence(ctx, t, remotes)
	res.Source = ev.source
	unlanded := unlandedCommits(commits, prev)

	in := delivery.EvalInput{
		Commits:         commits,
		Previous:        prev,
		Source:          ev.source,
		Now:             now,
		AbandonAfter:    s.opts.AbandonAfter,
		RemoteReachable: s.remoteReachable(ctx, t, ev, unlanded),
	}
	in.Default = s.defaultEvidence(ctx, ev, unlanded, prev)
	tips, err := s.branchTips(ctx, t, ev, unlanded, now)
	if err != nil {
		return res, fmt.Errorf("landingscan.Run: %w", err)
	}
	in.BranchTips = tips
	in.PRs, err = s.pullRequests(ctx, t, since)
	if err != nil {
		return res, fmt.Errorf("landingscan.Run: %w", err)
	}

	landings := delivery.Evaluate(in)
	if err := s.opts.SaveLandings(ctx, landings); err != nil {
		return res, fmt.Errorf("landingscan.Run: save landings: %w", err)
	}
	res.Evaluated = len(landings)
	s.remember(t, fetchHead, now)
	return res, nil
}

// throttled reports whether this root was evaluated recently and nothing
// that moves landings (HEAD, FETCH_HEAD) changed since.
func (s *Step) throttled(t Target, fetchHead, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.memo[t.ProjectID]
	return ok && m.head == t.HeadSHA && m.fetchHead.Equal(fetchHead) && now.Sub(m.at) < s.opts.PollInterval
}

func (s *Step) remember(t Target, fetchHead, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memo[t.ProjectID] = passMemo{head: t.HeadSHA, fetchHead: fetchHead, at: now}
}

// fetchHeadTime is the newest FETCH_HEAD mtime of the repository's git dir
// and common dir (a linked worktree has its own git dir). Zero when absent.
func (s *Step) fetchHeadTime(ctx context.Context, root string) time.Time {
	if s.opts.ModTime == nil {
		return time.Time{}
	}
	out, _, err := s.git(ctx, root, smallOutput, "rev-parse", "--absolute-git-dir", "--git-common-dir")
	if err != nil {
		return time.Time{}
	}
	var newest time.Time
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dir := strings.TrimSpace(line)
		if dir == "" {
			continue
		}
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(root, dir)
		}
		if mt, ok := s.opts.ModTime(filepath.Join(dir, fetchHeadFile)); ok && mt.After(newest) {
			newest = mt
		}
	}
	return newest
}

// readRemotes lists the project's remotes with their default branch and the
// user's own tracking tip. Remote URLs pass through delivery.ParseRemoteURL
// (userinfo stripped) before anything keeps them; one that is not a code host
// is skipped. A remote URL is never logged.
func (s *Step) readRemotes(ctx context.Context, t Target, fetchHead, now time.Time) ([]delivery.Remote, error) {
	out, _, err := s.opts.Exec(ctx, t.RootPath, smallOutput, "config", "--get-regexp", remoteURLConfigPattern)
	if err != nil {
		if code, ok := s.exitCode(err); ok && code == gitExitFalse {
			return nil, nil // no remotes configured
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	var remotes []delivery.Remote
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(key, "remote."), ".url")
		if name == key || !safeRemoteName(name) {
			continue
		}
		url, host, provider, slug, ok := delivery.ParseRemoteURL(value)
		if !ok {
			continue
		}
		r := delivery.Remote{
			ProjectID: t.ProjectID, Name: name, URL: url, Host: host, Provider: provider, RepoSlug: slug,
			FetchHeadAt: fetchHead, ObservedAt: now,
		}
		r.DefaultBranch, r.DefaultRefSHA = s.defaultBranch(ctx, t.RootPath, remoteTrackingRefPrefix+name+"/")
		remotes = append(remotes, r)
	}
	sort.Slice(remotes, func(i, j int) bool { return remotes[i].Name < remotes[j].Name })
	return remotes, nil
}

func (s *Step) exitCode(err error) (int, bool) {
	if s.opts.ExitCode == nil {
		return 0, false
	}
	return s.opts.ExitCode(err)
}

// defaultBranch resolves a remote's default branch under refPrefix
// ("refs/remotes/origin/" or, in a mirror, "refs/heads/"): the symbolic
// <prefix>HEAD first, then main, then master. It returns the branch name and
// the tip sha ("" when none resolves).
func (s *Step) defaultBranch(ctx context.Context, dir, refPrefix string) (string, string) {
	var candidates []string
	if out, _, err := s.git(ctx, dir, smallOutput, "symbolic-ref", "--quiet", refPrefix+"HEAD"); err == nil {
		if b := strings.TrimPrefix(strings.TrimSpace(string(out)), refPrefix); b != "" && !strings.HasPrefix(b, "refs/") {
			candidates = append(candidates, b)
		}
	}
	candidates = append(candidates, strings.Split(defaultBranchCandidates, ",")...)
	for _, b := range candidates {
		out, _, err := s.git(ctx, dir, smallOutput, "rev-parse", "--verify", "--quiet", refPrefix+b+"^{commit}")
		if err != nil {
			continue
		}
		if sha := strings.TrimSpace(string(out)); isSHA(sha) {
			return b, sha
		}
	}
	return "", ""
}

// evidence is where default-branch evidence is read.
type evidence struct {
	source delivery.EvidenceSource
	// dir and ref are the repository and default ref the evidence comes from
	// ("" ref: no default branch known anywhere).
	dir, ref, branch string
	// userRef is the user's own remote-tracking default ref ("" when absent),
	// used for branch ranges and reachability, which need the user's objects.
	userRef string
	mirror  bool
}

// chooseEvidence picks the evidence remote (upstream, then origin, then the
// first with a default branch) and, when an Observer mirror with status ok
// exists for its URL, reads the default branch from the mirror.
func (s *Step) chooseEvidence(ctx context.Context, t Target, remotes []delivery.Remote) evidence {
	ev := evidence{source: delivery.SourceUserRefs, dir: t.RootPath}
	var pick *delivery.Remote
	for _, want := range strings.Split(preferredEvidenceRemotes, ",") {
		for i := range remotes {
			if remotes[i].Name == want && remotes[i].DefaultRefSHA != "" {
				pick = &remotes[i]
				break
			}
		}
		if pick != nil {
			break
		}
	}
	if pick == nil {
		for i := range remotes {
			if remotes[i].DefaultRefSHA != "" {
				pick = &remotes[i]
				break
			}
		}
	}
	if pick != nil {
		ev.branch = pick.DefaultBranch
		ev.ref = remoteTrackingRefPrefix + pick.Name + "/" + pick.DefaultBranch
		ev.userRef = ev.ref
	}
	if s.opts.Mirrors == nil {
		return ev
	}
	mirrors, err := s.opts.Mirrors(ctx)
	if err != nil {
		s.opts.Logger.Debug("landingscan: mirrors unavailable", "project_id", t.ProjectID, "err", err)
		return ev
	}
	for _, r := range remotes {
		if pick != nil && r.Name != pick.Name {
			continue
		}
		for _, m := range mirrors {
			if m.Status != "ok" || m.Path == "" || m.URL == "" || m.URL != r.URL {
				continue
			}
			branch := s.mirrorDefaultBranch(ctx, m)
			if branch == "" {
				continue
			}
			return evidence{
				source: delivery.SourceMirror, dir: m.Path, ref: mirrorBranchRefPrefix + branch,
				branch: branch, userRef: ev.userRef, mirror: true,
			}
		}
	}
	return ev
}

// mirrorDefaultBranch is the mirror's default branch: the one deliverynet
// recorded, else the bare clone's own HEAD, verified to resolve to a commit
// in the mirror. "" when neither resolves.
func (s *Step) mirrorDefaultBranch(ctx context.Context, m delivery.Mirror) string {
	branch := m.DefaultBranch
	if branch == "" {
		out, _, err := s.git(ctx, m.Path, smallOutput, "symbolic-ref", "--quiet", "HEAD")
		if err != nil {
			return ""
		}
		branch = strings.TrimPrefix(strings.TrimSpace(string(out)), mirrorBranchRefPrefix)
	}
	if branch == "" || strings.HasPrefix(branch, "-") || strings.HasPrefix(branch, "refs/") {
		return ""
	}
	out, _, err := s.git(ctx, m.Path, smallOutput, "rev-parse", "--verify", "--quiet", mirrorBranchRefPrefix+branch+"^{commit}")
	if err != nil || !isSHA(strings.TrimSpace(string(out))) {
		return ""
	}
	return branch
}

// fingerprintPending computes the fingerprint of commits still pending,
// bounded per pass, and records it.
func (s *Step) fingerprintPending(ctx context.Context, t Target, commits []delivery.Commit) (int, error) {
	n := 0
	for i := range commits {
		c := &commits[i]
		if c.PatchFPState != "" && c.PatchFPState != delivery.FPPending {
			continue
		}
		if c.IsMerge || !isSHA(c.SHA) {
			continue
		}
		if n >= s.opts.MaxFingerprints {
			break
		}
		fp, state, _ := s.fingerprint(ctx, t.RootPath, c.SHA)
		if err := s.opts.SetFingerprint(ctx, c.ID, fp, state); err != nil {
			return n, fmt.Errorf("set fingerprint: %w", err)
		}
		c.PatchFP, c.PatchFPState = fp, state
		n++
	}
	return n, nil
}

// fingerprint runs `git diff-tree -p` for one commit (or a base..tip range
// when two revisions are given) and fingerprints it. It returns the state
// in the delivery vocabulary and the touched files.
func (s *Step) fingerprint(ctx context.Context, dir string, revs ...string) (string, string, []string) {
	args := []string{"diff-tree", "-p", "--no-renames", "-r"}
	if len(revs) == 1 {
		args = append(args, "--no-commit-id", "--root")
	}
	args = append(args, revs...)
	out, overflow, err := s.git(ctx, dir, commitlog.MaxPatchBytes, args...)
	switch {
	case err != nil:
		return "", delivery.FPError, nil
	case overflow:
		return "", delivery.FPTooLarge, nil
	}
	fp, st := commitlog.PatchFingerprint(out)
	return fp, string(st), commitlog.PatchFiles(out)
}

// unlandedCommits are the evaluated set's commits that have not landed yet:
// the ones the expensive evidence is gathered for.
func unlandedCommits(commits []delivery.Commit, prev map[int64]delivery.Landing) []delivery.Commit {
	var out []delivery.Commit
	for _, c := range commits {
		if c.IsMerge || c.ForeignAuthor || !c.AIContributor || !isSHA(c.SHA) {
			continue
		}
		if p, ok := prev[c.ID]; ok && p.Status == delivery.StatusLanded {
			continue
		}
		out = append(out, c)
	}
	return out
}

// defaultEvidence gathers the default-branch facts the L rules read.
func (s *Step) defaultEvidence(ctx context.Context, ev evidence, unlanded []delivery.Commit, prev map[int64]delivery.Landing) delivery.DefaultEvidence {
	d := delivery.DefaultEvidence{Branch: ev.branch, Ancestor: map[string]bool{}, LandedVia: map[string]delivery.DefaultCommit{}}
	if ev.ref == "" {
		return d
	}
	d.Known = true

	checks := 0
	for _, c := range unlanded {
		if checks >= s.opts.MaxAncestorChecks {
			break
		}
		checks++
		if v, ok := s.boolGit(ctx, ev.dir, "merge-base", "--is-ancestor", c.SHA, ev.ref); ok {
			d.Ancestor[c.SHA] = v
		}
	}
	// Previously landed commits: is the landing commit still on the default
	// branch (rule M1, landing_lost)?
	for _, l := range sortedLandings(prev) {
		if checks >= s.opts.MaxAncestorChecks {
			break
		}
		if l.Status != delivery.StatusLanded || !isSHA(l.LandingSHA) {
			continue
		}
		checks++
		if v, ok := s.boolGit(ctx, ev.dir, "merge-base", "--is-ancestor", l.LandingSHA, ev.ref); ok {
			d.Ancestor[l.LandingSHA] = v
		}
	}

	if len(unlanded) == 0 {
		return d
	}
	oldest := unlanded[0].CommittedAt
	for _, c := range unlanded {
		if c.CommittedAt.Before(oldest) {
			oldest = c.CommittedAt
		}
	}
	d.Commits = s.defaultCommits(ctx, ev, oldest.Add(-defaultCommitLookbackSlop))

	via := 0
	for _, c := range unlanded {
		if !d.Ancestor[c.SHA] || via >= defaultMaxLandedVia {
			continue
		}
		via++
		if mc, ok := s.landedVia(ctx, ev, c.SHA); ok {
			d.LandedVia[c.SHA] = mc
		}
	}
	return d
}

// defaultCommits lists default-branch commits since `since` (newest first,
// bounded) and fingerprints the non-merge ones, from the cache first. In a
// blobless mirror diffs would need a network fetch, so mirror evidence has
// subjects and parents only.
func (s *Step) defaultCommits(ctx context.Context, ev evidence, since time.Time) []delivery.DefaultCommit {
	out, _, err := s.git(ctx, ev.dir, logOutput, "log",
		"--format=%H"+"%x1f"+"%P"+"%x1f"+"%ct"+"%x1f"+"%s",
		"--max-count="+strconv.Itoa(s.opts.MaxDefaultCommits),
		"--since="+strconv.FormatInt(since.Unix(), 10), ev.ref)
	if err != nil {
		return nil
	}
	var commits []delivery.DefaultCommit
	computed := 0
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, fieldSep, 4)
		if len(parts) != 4 || !isSHA(parts[0]) {
			continue
		}
		dc := delivery.DefaultCommit{SHA: parts[0], Parents: len(strings.Fields(parts[1])), Subject: parts[3]}
		if secs, err := strconv.ParseInt(parts[2], 10, 64); err == nil {
			dc.CommittedAt = time.Unix(secs, 0).UTC()
		}
		if !ev.mirror && dc.Parents <= 1 {
			if e, ok := s.cachedFP(dc.SHA); ok {
				dc.PatchFP, dc.Files = e.fp, e.files
			} else if computed < s.opts.MaxDefaultFPs {
				computed++
				fp, st, files := s.fingerprint(ctx, ev.dir, dc.SHA)
				if st != delivery.FPError {
					if st != delivery.FPOK {
						fp = ""
					}
					s.cacheFP(dc.SHA, fpEntry{fp: fp, files: files})
				}
				dc.PatchFP, dc.Files = fp, files
			}
		}
		commits = append(commits, dc)
	}
	return commits
}

func (s *Step) cachedFP(sha string) (fpEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.fpMem[sha]
	return e, ok
}

func (s *Step) cacheFP(sha string, e fpEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.fpMem) >= fingerprintCacheCap {
		s.fpMem = map[string]fpEntry{}
	}
	s.fpMem[sha] = e
}

// landedVia finds the merge commit that brought sha onto the default branch:
// the oldest merge on the ancestry path sha..ref.
func (s *Step) landedVia(ctx context.Context, ev evidence, sha string) (delivery.DefaultCommit, bool) {
	out, _, err := s.git(ctx, ev.dir, smallOutput, "log", "--ancestry-path", "--merges",
		"--format=%H"+"%x1f"+"%P"+"%x1f"+"%ct"+"%x1f"+"%s", sha+".."+ev.ref)
	if err != nil {
		return delivery.DefaultCommit{}, false
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	parts := strings.SplitN(lines[len(lines)-1], fieldSep, 4)
	if len(parts) != 4 || !isSHA(parts[0]) {
		return delivery.DefaultCommit{}, false
	}
	dc := delivery.DefaultCommit{SHA: parts[0], Parents: len(strings.Fields(parts[1])), Subject: parts[3]}
	if secs, err := strconv.ParseInt(parts[2], 10, 64); err == nil {
		dc.CommittedAt = time.Unix(secs, 0).UTC()
	}
	return dc, true
}

// remoteReachable answers rule L6: is each unlanded commit on any
// remote-tracking ref of the user's repository (or, with a mirror, on any
// branch of the mirror)?
func (s *Step) remoteReachable(ctx context.Context, t Target, ev evidence, unlanded []delivery.Commit) map[string]bool {
	out := map[string]bool{}
	for i, c := range unlanded {
		if i >= s.opts.MaxRemoteChecks {
			break
		}
		if s.containedIn(ctx, t.RootPath, c.SHA, remoteTrackingRefPrefix) {
			out[c.SHA] = true
			continue
		}
		if ev.mirror && s.containedIn(ctx, ev.dir, c.SHA, mirrorBranchRefPrefix) {
			out[c.SHA] = true
		}
	}
	return out
}

func (s *Step) containedIn(ctx context.Context, dir, sha, refPrefix string) bool {
	out, _, err := s.git(ctx, dir, smallOutput, "for-each-ref", "--count=1", "--format=%(refname)",
		"--contains", sha, refPrefix)
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// branchTips records each local branch that holds an unlanded AI commit,
// with the fingerprint and file set of its cumulative diff from the merge
// base with the user's default ref, and returns every stored tip (including
// tips of branches deleted since) for the squash rules. A tip whose sha did
// not move since it was stored is not recomputed.
func (s *Step) branchTips(ctx context.Context, t Target, ev evidence, unlanded []delivery.Commit, now time.Time) ([]delivery.BranchTip, error) {
	stored, err := s.opts.BranchTips(ctx, t.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("branch tips: %w", err)
	}
	if ev.userRef == "" || len(unlanded) == 0 {
		return stored, nil
	}
	pending := map[string]bool{}
	for _, c := range unlanded {
		pending[c.SHA] = true
	}
	storedTip := map[string]string{}
	for _, st := range stored {
		storedTip[st.RefNameHash] = st.TipSHA
	}
	out, _, err := s.git(ctx, t.RootPath, smallOutput, "for-each-ref",
		"--count="+strconv.Itoa(s.opts.MaxBranches), "--sort=-committerdate",
		"--format=%(refname)"+"%1f"+"%(objectname)", localBranchRefPrefix)
	if err != nil {
		return stored, nil
	}
	var fresh []delivery.BranchTip
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ref, tip, ok := strings.Cut(line, fieldSep)
		if !ok || !isSHA(tip) {
			continue
		}
		hash := refNameHash(ref)
		if storedTip[hash] == tip {
			continue
		}
		baseOut, _, err := s.git(ctx, t.RootPath, smallOutput, "merge-base", tip, ev.userRef)
		base := strings.TrimSpace(string(baseOut))
		if err != nil || !isSHA(base) || base == tip {
			continue
		}
		revs, _, err := s.git(ctx, t.RootPath, smallOutput, "rev-list",
			"--max-count="+strconv.Itoa(s.opts.MaxRangeCommits), base+".."+tip)
		if err != nil {
			continue
		}
		members := strings.Fields(string(revs))
		holds := false
		for _, m := range members {
			if pending[m] {
				holds = true
				break
			}
		}
		if !holds {
			continue
		}
		fp, st, files := s.fingerprint(ctx, t.RootPath, base, tip)
		fresh = append(fresh, delivery.BranchTip{
			ProjectID: t.ProjectID, RefNameHash: hash, RefName: ref, TipSHA: tip, MergeBaseSHA: base,
			RangeFP: fp, RangeFPState: st, MemberSHAs: members, Files: files, ObservedAt: now,
		})
	}
	if len(fresh) == 0 {
		return stored, nil
	}
	if err := s.opts.SaveBranchTips(ctx, fresh); err != nil {
		return nil, fmt.Errorf("save branch tips: %w", err)
	}
	merged := append([]delivery.BranchTip(nil), fresh...)
	seen := map[string]bool{}
	for _, f := range fresh {
		seen[f.RefNameHash] = true
	}
	for _, st := range stored {
		if !seen[st.RefNameHash] {
			merged = append(merged, st)
		}
	}
	return merged, nil
}

// pullRequests loads the stored PRs linked to the project and their commit
// lists, filling missing PR commit fingerprints from local objects when they
// exist (bounded; a commit that is not local stays without one).
func (s *Step) pullRequests(ctx context.Context, t Target, since time.Time) ([]delivery.PRWithCommits, error) {
	prs, err := s.opts.PullRequests(ctx, t.ProjectID, since)
	if err != nil {
		return nil, fmt.Errorf("pull requests: %w", err)
	}
	out := make([]delivery.PRWithCommits, 0, len(prs))
	computed := 0
	for _, pr := range prs {
		pcs, err := s.opts.PRCommits(ctx, pr.ID)
		if err != nil {
			return nil, fmt.Errorf("pull request commits: %w", err)
		}
		for i := range pcs {
			if pcs[i].PatchFP != "" || s.opts.SetPRCommitFingerprint == nil || !isSHA(pcs[i].SHA) || computed >= defaultMaxPRFingerprints {
				continue
			}
			computed++
			fp, st, _ := s.fingerprint(ctx, t.RootPath, pcs[i].SHA)
			if st != delivery.FPOK {
				continue
			}
			if err := s.opts.SetPRCommitFingerprint(ctx, pr.ID, pcs[i].SHA, fp); err != nil {
				return nil, fmt.Errorf("set PR commit fingerprint: %w", err)
			}
			pcs[i].PatchFP = fp
		}
		out = append(out, delivery.PRWithCommits{PR: pr, Commits: pcs})
	}
	return out, nil
}

// sortedLandings returns the landings ordered by commit id (deterministic
// bounded iteration).
func sortedLandings(m map[int64]delivery.Landing) []delivery.Landing {
	out := make([]delivery.Landing, 0, len(m))
	for _, l := range m {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CommitID < out[j].CommitID })
	return out
}

// isSHA reports whether s is a full hex object id (40 or 64 characters). Every
// sha passed to git as an argument is checked first, so no value read from
// the store or from git output can be taken for an option.
func isSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// safeRemoteName accepts the remote names git itself would create: no
// leading dash, no whitespace, no "..", path characters only.
func safeRemoteName(n string) bool {
	if n == "" || strings.HasPrefix(n, "-") || strings.Contains(n, "..") {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/-", r)) {
			return false
		}
	}
	return true
}

// refNameHash is the stored key of a branch name (the M2 precedent: the
// name itself stays on the node for display only).
func refNameHash(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return hex.EncodeToString(sum[:])
}
