package secquickscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
)

// Verdict is the quick scan's answer.
type Verdict string

const (
	// VerdictClean: the diff the commit would record is clean.
	VerdictClean Verdict = "clean"
	// VerdictBlocking: a blocking finding is in the diff.
	VerdictBlocking Verdict = "blocking"
	// VerdictUnknown: the scan could not finish or could not see the
	// diff. Never clean.
	VerdictUnknown Verdict = "unknown"
)

// UnknownReason says why a scan ended unknown.
type UnknownReason string

const (
	ReasonNone        UnknownReason = ""
	ReasonBudget      UnknownReason = "budget"
	ReasonGit         UnknownReason = "git_unavailable"
	ReasonDiffOverCap UnknownReason = "diff_over_cap"
	ReasonIncomplete  UnknownReason = "scan_incomplete"
	ReasonNoUpstream  UnknownReason = "no_upstream"
	ReasonBadRequest  UnknownReason = "bad_request"
	// ReasonUnmodelled: the command records or sends something the scan
	// does not model (a merge, a rebase, a `git -C` directory, a push
	// whose refspecs it cannot read), so it cannot say what is recorded.
	ReasonUnmodelled UnknownReason = "form_not_modelled"
)

// Form is the parsed commit the scan covers (policy.CommitIntent's form).
type Form struct {
	// Push scans the commits a push would send instead of a commit: every
	// commit, one by one, so a secret added and removed again before the
	// push is still found.
	Push bool
	// PushOperands are the push's operands (the repository, then the
	// refspecs); empty for a bare `git push`, which sends the current
	// branch to its upstream.
	PushOperands []string
	// PushOpaque marks a push option the scan does not model (--all,
	// --mirror, --tags and the like): the scan answers unknown.
	PushOpaque bool
	// All is `git commit -a`.
	All bool
	// Amend is `git commit --amend` (scanned like a plain commit: the
	// commit being amended was scanned when it was made).
	Amend bool
	// Pathspecs are the paths `git commit <paths>` records from the
	// working tree.
	Pathspecs []string
	// From and To scan landed commits instead (the commit scan, S-723):
	// every commit in From..To, one by one (never the net tree, so a
	// secret added and removed between two scans is still found), or the
	// To commit alone when From is empty.
	// Both must be commit ids (hex); anything else is a bad request.
	From, To string
}

// Request is one quick-scan request.
type Request struct {
	// Root is the repository the commit runs in (the project root, or the
	// run's workspace root for a copy workspace visible on the host).
	Root string
	Form Form
	// DirtySeen is the dirty counter value the hook saw.
	DirtySeen uint64
	// Budget overrides the engine's budget (a managed floor's picker:
	// 5, 10 or 30 s); zero uses the engine's.
	Budget time.Duration
	// MaxDiffBytes overrides MaxDiffBytes (the daemon's commit scan has a
	// budget of its own, CommitMaxDiffBytes); zero uses MaxDiffBytes.
	MaxDiffBytes int
}

// CIFinding is one workflow rule hit: the file, the rule and its line,
// never repository text.
type CIFinding struct {
	Path     string
	RuleID   string
	Line     int
	Severity secciwf.Severity
	FlagOnly bool
}

// Finding is one hit in the diff. A high-confidence hit outside a fixture
// path blocks; a hit in a fixture or test-data path (Fixture) is reported
// but never blocks, as S-721 asks there instead of denying and verify
// lowers it to a flag. It never carries the matched value.
type Finding struct {
	Path       string
	Line       int
	Type       string
	Confidence secdetect.Confidence
	Fixture    bool
	// Identity is the hit's keyed, value-free identity (the engine's
	// Scanner.Identify; "" when none is set).
	Identity string
}

// Result is the quick scan's answer.
type Result struct {
	Verdict Verdict
	Reason  UnknownReason
	// Findings are the high-confidence hits (at most MaxFindings): the
	// blocking ones and those in a fixture path (Finding.Fixture), which
	// never make the verdict blocking.
	Findings []Finding
	// Removed are the high-confidence secrets a commit range removed and
	// did not add back (range forms only; at most MaxFindings): what lets
	// a removed secret's finding close.
	Removed []Finding
	// Deleted are the files a commit range deleted (range forms only; at
	// most MaxFindings; none when the list could not be read whole): a
	// finding sighted at a deleted file is no longer seen there.
	Deleted []string
	// Observations are the flag-only diff observations (S-761, S-767 to
	// S-769; internal/secdiffobs). They never change the verdict.
	Observations []secdiffobs.Observation
	// CI are the native workflow rule hits (S-771 to S-778,
	// internal/secciwf) on the workflows the change records, each checked
	// whole. They never change the verdict: an agent's workflow edit is
	// blocked only where R-166 protects the path (security plan 5.6).
	CI []CIFinding
	// CIUnchecked counts changed workflows the scan could not check whole
	// (a push, a form with no reader for the working tree, a read error,
	// over the cap, unparsable YAML): never read as clean.
	CIUnchecked int
	// CIChecked are the changed workflows the scan checked whole (at most
	// MaxFindings): a workflow rule finding there that CI does not report
	// again is no longer seen.
	CIChecked []string
	// Files is the number of changed files the diff touched.
	Files int
	// DiffHash identifies the diff ("" when it could not be read).
	DiffHash string
	// Cached reports an answer from the clean-result cache.
	Cached bool
	// CoveredDirty is the dirty counter value a clean answer covers (the
	// request's DirtySeen); zero otherwise.
	CoveredDirty uint64
	// Elapsed is the scan's wall time.
	Elapsed time.Duration
	// Retained are the parsed diffs of the files Engine.Retain accepts (at
	// most MaxRetained), for a caller that reads more out of a file than
	// the scan does (the install gate's S-747 at commit, lane SEC-D1FIX2).
	// A cached clean answer retains nothing: that diff was read before.
	Retained []secdiffobs.FileDiff
}

// MaxRetained caps Result.Retained.
const MaxRetained = 16

// GitFunc runs one read-only git command in root with a stdout cap and a
// timeout, returning stdout and whether the cap was hit (the gitview
// envelope: gitview.RunReadOnlyTimeout).
type GitFunc func(ctx context.Context, root string, maxBytes int, timeout time.Duration, args ...string) ([]byte, bool, error)

const (
	// IndividualBudget is the individual node's fixed budget (D-764 Q21).
	IndividualBudget = 2 * time.Second
	// MaxDiffBytes caps the diff read; a larger diff is unknown.
	MaxDiffBytes = 8 << 20
	// MaxRemovedBytes caps the removed text a range scan reads for removed
	// secrets, apart from the added text (whose cap is the diff's): beyond
	// it the rest of the removed text is not read, so a removal there
	// closes nothing (never a false close).
	MaxRemovedBytes = 4 << 20
	// MaxFindings caps the findings returned.
	MaxFindings = 64
	// cacheEntries bounds the clean-result cache.
	cacheEntries = 256
)

// Engine runs quick scans. The zero value is not usable: Git is required.
// It is safe for concurrent use.
type Engine struct {
	// Git is the read-only git envelope.
	Git GitFunc
	// Budget is the default budget (zero: IndividualBudget).
	Budget time.Duration
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// Detect, when set, replaces the secret scanner's detector (tests).
	Scanner secdetect.Scanner
	// Version names the detector pack; it keys the cache so a pack change
	// never reuses an old clean answer.
	Version string
	// ReadFile, when set, reads a working-tree file under root (capped;
	// over reports the cap was hit) for the forms that record the working
	// tree (`commit -a`, `commit <paths>`); nil leaves those workflows
	// unchecked.
	ReadFile func(root, rel string, maxBytes int) (content []byte, over bool, err error)
	// Retain, when set, names the files whose parsed diff the result
	// carries (Result.Retained); nil retains nothing.
	Retain func(path string) bool

	mu    sync.Mutex
	clean map[string]time.Time
	order []string
}

// errNoUpstream marks a push with no upstream to compare against.
var errNoUpstream = errors.New("secquickscan: no upstream")

// Scan runs one quick scan.
func (e *Engine) Scan(ctx context.Context, req Request) Result {
	now := e.Now
	if now == nil {
		now = time.Now
	}
	start := now()
	budget := req.Budget
	if budget <= 0 {
		budget = e.Budget
	}
	if budget <= 0 {
		budget = IndividualBudget
	}
	deadline := start.Add(budget)
	res := e.scan(ctx, req, deadline, now)
	res.Elapsed = now().Sub(start)
	if res.Verdict == VerdictClean {
		res.CoveredDirty = req.DirtySeen
	}
	return res
}

func (e *Engine) scan(ctx context.Context, req Request, deadline time.Time, now func() time.Time) Result {
	if e.Git == nil || strings.TrimSpace(req.Root) == "" || !validRange(req.Form) {
		return Result{Verdict: VerdictUnknown, Reason: ReasonBadRequest}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	diff, err := e.readDiff(ctx, req, deadline.Sub(now()))
	switch {
	case errors.Is(err, errNoUpstream):
		return Result{Verdict: VerdictUnknown, Reason: ReasonNoUpstream}
	case errors.Is(err, errDiffOverCap):
		return Result{Verdict: VerdictUnknown, Reason: ReasonDiffOverCap}
	case errors.Is(err, errUnmodelled):
		return Result{Verdict: VerdictUnknown, Reason: ReasonUnmodelled}
	case err != nil:
		if ctx.Err() != nil {
			return Result{Verdict: VerdictUnknown, Reason: ReasonBudget}
		}
		return Result{Verdict: VerdictUnknown, Reason: ReasonGit}
	}
	return e.scanBytes(ctx, req, diff, deadline, now)
}

// ScanDiff runs the commit-scope detectors over a unified diff the caller
// already holds (lane LEFT-SEC: a hosted box's staged diff saved home at
// teardown, never applied): the same secret, workflow and observation rows
// as a staged commit's scan, within budget. No git runs, so a changed
// workflow is reported unchecked (the box's tree is not on the host) and
// nothing is cached clean. An empty diff is clean.
func (e *Engine) ScanDiff(ctx context.Context, diff []byte, budget time.Duration) Result {
	now := e.Now
	if now == nil {
		now = time.Now
	}
	if budget <= 0 {
		budget = e.Budget
	}
	if budget <= 0 {
		budget = IndividualBudget
	}
	start := now()
	// A fresh engine over the same detectors: no git, no shared clean
	// cache (a diff file's clean answer never stands for a commit).
	noGit := &Engine{
		Git: func(context.Context, string, int, time.Duration, ...string) ([]byte, bool, error) {
			return nil, false, errDiffOnly
		},
		Budget: budget, Now: now, Scanner: e.Scanner, Version: e.Version, Retain: e.Retain,
	}
	ctx, cancel := context.WithDeadline(ctx, start.Add(budget))
	defer cancel()
	res := noGit.scanBytes(ctx, Request{Root: "diff"}, diff, start.Add(budget), now)
	res.Elapsed = now().Sub(start)
	return res
}

// errDiffOnly answers every git call of a ScanDiff: there is no tree.
var errDiffOnly = errors.New("secquickscan: a diff scan has no tree to read")

// scanBytes is scan after the diff is read.
func (e *Engine) scanBytes(ctx context.Context, req Request, diff []byte, deadline time.Time, now func() time.Time) Result {
	sum := sha256.Sum256(append([]byte(e.Version+"\x00"), diff...))
	hash := hex.EncodeToString(sum[:])
	files := parseDiffLines(diff, req.Form.To != "")
	if e.cachedClean(hash) && !touchesWorkflow(files) && req.Form.To == "" {
		return Result{Verdict: VerdictClean, DiffHash: hash, Files: len(files), Cached: true}
	}
	parsed := secdiffobs.ParseUnifiedDiff(diff)
	res := Result{DiffHash: hash, Files: len(files), Observations: secdiffobs.Observe(parsed), Retained: e.retained(parsed)}
	if len(res.Observations) > MaxFindings {
		res.Observations = res.Observations[:MaxFindings]
	}
	res.CI, res.CIChecked, res.CIUnchecked = e.checkWorkflows(ctx, req, files)
	incomplete, blocking := false, false
	for _, f := range files {
		if f.text == "" {
			continue
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return Result{Verdict: VerdictUnknown, Reason: ReasonBudget, DiffHash: hash, Files: len(files)}
		}
		lim := secdetect.PostWriteLimits(0)
		lim.Deadline = remaining
		r := e.Scanner.Scan(f.text, f.path, lim)
		if r.Status == secdetect.StatusIncomplete {
			incomplete = true
		}
		for _, h := range r.Hits {
			if !h.Blocking() || len(res.Findings) >= MaxFindings {
				continue
			}
			line := h.Line
			if line-1 < len(f.lines) && line >= 1 {
				line = f.lines[line-1]
			}
			res.Findings = append(res.Findings, Finding{Path: f.path, Line: line, Type: h.Type, Confidence: h.Confidence, Fixture: h.Fixture, Identity: h.Identity})
			if !h.Fixture {
				blocking = true
			}
		}
	}
	if req.Form.To != "" {
		res.Removed = e.removedSecrets(files, res.Findings, deadline, now)
		res.Deleted = e.deletedFiles(ctx, req, deadline.Sub(now()))
	}
	switch {
	case blocking:
		res.Verdict = VerdictBlocking
	case incomplete:
		res.Verdict, res.Reason = VerdictUnknown, ReasonIncomplete
	default:
		res.Verdict = VerdictClean
		e.rememberClean(hash, now())
	}
	return res
}

// retained returns the parsed diffs Retain accepts, capped.
func (e *Engine) retained(parsed []secdiffobs.FileDiff) []secdiffobs.FileDiff {
	if e.Retain == nil {
		return nil
	}
	var out []secdiffobs.FileDiff
	for _, fd := range parsed {
		if !fd.Deleted && len(out) < MaxRetained && e.Retain(fd.Path) {
			out = append(out, fd)
		}
	}
	return out
}

// removedSecrets scans a range's removed text (up to MaxRemovedBytes, and
// only while the budget lasts) and returns the high-confidence secrets it
// removed whose identity the range did not add back. A removal it does not
// read is simply not reported: nothing closes on what was not seen.
func (e *Engine) removedSecrets(files []addedFile, added []Finding, deadline time.Time, now func() time.Time) []Finding {
	kept := map[string]bool{}
	for _, f := range added {
		if f.Identity != "" {
			kept[f.Type+"\x00"+f.Identity] = true
		}
	}
	var out []Finding
	budget := MaxRemovedBytes
	for _, f := range files {
		if f.removed == "" || budget <= 0 {
			continue
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			break
		}
		text := f.removed
		if len(text) > budget {
			// Cut at a line end so no secret is read in part.
			text = text[:budget]
			if i := strings.LastIndexByte(text, '\n'); i >= 0 {
				text = text[:i+1]
			}
		}
		budget -= len(text)
		lim := secdetect.PostWriteLimits(0)
		lim.Deadline = remaining
		r := e.Scanner.Scan(text, f.path, lim)
		for _, h := range r.Hits {
			if !h.Blocking() || h.Identity == "" || kept[h.Type+"\x00"+h.Identity] || len(out) >= MaxFindings {
				continue
			}
			kept[h.Type+"\x00"+h.Identity] = true
			out = append(out, Finding{Path: f.path, Type: h.Type, Confidence: h.Confidence, Fixture: h.Fixture, Identity: h.Identity})
		}
	}
	return out
}

// maxDeletedListBytes caps the deleted-file listing of one range.
const maxDeletedListBytes = 64 << 10

// deletedFiles lists the files a range form deleted (git's -z name list,
// no renames, so a moved file reads as deleted at its old path). A listing
// that fails, is cut by its cap or runs out of budget gives none: nothing
// closes on a list that was not read whole.
func (e *Engine) deletedFiles(ctx context.Context, req Request, timeout time.Duration) []string {
	if timeout <= 0 {
		return nil
	}
	var args []string
	if req.Form.From == "" {
		args = []string{"show", "--format=", "-m", "--first-parent", "--no-renames", "--diff-filter=D", "--name-only", "-z", req.Form.To}
	} else {
		args = []string{"diff", "--no-renames", "--diff-filter=D", "--name-only", "-z", req.Form.From, req.Form.To, "--"}
	}
	out, over, err := e.Git(ctx, req.Root, maxDeletedListBytes, timeout, args...)
	if err != nil || over {
		return nil
	}
	var paths []string
	seen := map[string]bool{}
	for _, p := range strings.Split(string(out), "\x00") {
		if p = strings.TrimSpace(p); p == "" || seen[p] {
			continue
		}
		if len(paths) >= MaxFindings {
			return nil
		}
		seen[p] = true
		paths = append(paths, p)
	}
	return paths
}

// errDiffOverCap marks a diff larger than MaxDiffBytes.
var errDiffOverCap = errors.New("secquickscan: diff over cap")

// diffFlags are the flags every diff read carries: no colour, no external
// diff or textconv program, no rename detection, added and modified files
// only (a deletion adds nothing), and no context lines.
var diffFlags = []string{"--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--diff-filter=ACMRT", "-U0"}

// readDiff reads the diff the commit (or push) would record.
func (e *Engine) readDiff(ctx context.Context, req Request, timeout time.Duration) ([]byte, error) {
	args := DiffArgs(req.Form)
	if req.Form.Push {
		pa, err := pushLogArgs(req.Form)
		if err != nil {
			return nil, err
		}
		args = pa
		if len(req.Form.PushOperands) == 0 {
			if _, _, err := e.Git(ctx, req.Root, 4096, timeout, "rev-parse", "--verify", "--quiet", "@{upstream}"); err != nil {
				if ctx.Err() != nil {
					return nil, err
				}
				return nil, errNoUpstream
			}
		}
	}
	maxDiff := req.MaxDiffBytes
	if maxDiff <= 0 {
		maxDiff = MaxDiffBytes
	}
	out, over, err := e.Git(ctx, req.Root, maxDiff, timeout, args...)
	if err != nil && !req.Form.Push && (req.Form.All || len(req.Form.Pathspecs) > 0) && ctx.Err() == nil {
		// An unborn HEAD (the first commit) has nothing to diff against:
		// the index holds the whole commit.
		out, over, err = e.Git(ctx, req.Root, maxDiff, timeout, append([]string{"diff", "--cached"}, diffFlags...)...)
	}
	if err != nil {
		return nil, err
	}
	if over {
		return nil, errDiffOverCap
	}
	return out, nil
}

// errUnmodelled marks a form the scan cannot read.
var errUnmodelled = errors.New("secquickscan: form not modelled")

// logFlags read every commit of a range one by one: no commit header, and
// a merge's diff against each parent (-m), so nothing a merge brings is
// skipped. The diff flags are the same as a single diff's.
var logFlags = append([]string{"log", "-p", "--format=", "-m"}, diffFlags...)

// pushLogArgs returns the git log arguments that read every commit the
// push would send: the sources its refspecs name (HEAD when none), minus
// what the remote already has (its remote-tracking refs, or the upstream
// for a bare push). A form it cannot read is errUnmodelled: an opaque
// option, a repository given as a URL or path, or a source that is not a
// plain ref name.
func pushLogArgs(f Form) ([]string, error) {
	if f.PushOpaque {
		return nil, errUnmodelled
	}
	if len(f.PushOperands) == 0 {
		return append(append([]string(nil), logFlags...), "@{upstream}..HEAD", "--"), nil
	}
	remote := f.PushOperands[0]
	if !isRemoteName(remote) {
		return nil, errUnmodelled
	}
	var srcs []string
	for _, spec := range f.PushOperands[1:] {
		spec = strings.TrimPrefix(spec, "+")
		src, _, _ := strings.Cut(spec, ":")
		if src == "" {
			continue // a deletion (":dst") sends no commits
		}
		if !isRefName(src) {
			return nil, errUnmodelled
		}
		srcs = append(srcs, src)
	}
	if len(f.PushOperands) == 1 {
		srcs = []string{"HEAD"}
	}
	if len(srcs) == 0 {
		return nil, errUnmodelled // deletions only: nothing to read, and nothing to call clean
	}
	args := append(append([]string(nil), logFlags...), srcs...)
	return append(args, "--not", "--remotes="+remote, "--"), nil
}

// isRemoteName reports a configured-remote-shaped name (no URL, no path).
func isRemoteName(s string) bool {
	if s == "" || s[0] == '-' || s[0] == '.' || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// isRefName reports a plain ref name a refspec source may carry: letters,
// digits, '-', '_', '.', '/', not starting with '-' or '.', without "..";
// no revision expression (~, ^, @{) reaches git through it.
func isRefName(s string) bool {
	if s == "" || s[0] == '-' || s[0] == '.' || len(s) > 256 || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '/') {
			return false
		}
	}
	return true
}

// DiffArgs returns the git arguments that read what form would record.
// A push's arguments come from pushLogArgs instead; DiffArgs answers a
// bare push's range.
func DiffArgs(f Form) []string {
	switch {
	case f.To != "" && f.From == "":
		return append(append([]string{"show", "--format=", "-m", "--first-parent"}, diffFlags...), f.To)
	case f.To != "":
		return append(append([]string(nil), logFlags...), f.From+".."+f.To, "--")
	case f.Push:
		return append(append([]string(nil), logFlags...), "@{upstream}..HEAD", "--")
	case len(f.Pathspecs) > 0:
		args := append(append([]string{"diff"}, diffFlags...), "HEAD", "--")
		return append(args, f.Pathspecs...)
	case f.All:
		return append(append([]string{"diff"}, diffFlags...), "HEAD")
	default:
		return append([]string{"diff", "--cached"}, diffFlags...)
	}
}

// validRange reports whether a commit-range form names commit ids only
// (no option or revision expression can reach git through it).
func validRange(f Form) bool {
	if f.To == "" {
		return f.From == ""
	}
	return isCommitID(f.To) && (f.From == "" || isCommitID(f.From))
}

// isCommitID reports a 7 to 64 character hexadecimal id.
func isCommitID(s string) bool {
	if len(s) < 7 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// addedFile is one file's added lines, joined, with each joined line's
// line number in the new file, and (for a range scan) its removed lines,
// joined.
type addedFile struct {
	path    string
	text    string
	lines   []int
	removed string
}

// parseDiffLines reads a -U0 unified diff into the added lines per file
// and, when withRemoved is set, the removed lines too. A file with neither
// is left out.
func parseDiffLines(diff []byte, withRemoved bool) []addedFile {
	var (
		out    []addedFile
		cur    *addedFile
		b, rm  strings.Builder
		newLn  int
		inHunk bool
	)
	flush := func() {
		if cur != nil && (b.Len() > 0 || rm.Len() > 0) {
			cur.text, cur.removed = b.String(), rm.String()
			out = append(out, *cur)
		}
		cur, inHunk = nil, false
		b.Reset()
		rm.Reset()
	}
	for _, line := range strings.Split(string(diff), "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flush()
		case strings.HasPrefix(line, "+++ ") && !inHunk:
			// Inside a hunk a "+++ " line is an added line whose text
			// starts "++ " (internal/secdiffobs has the same guard): only
			// a line between "diff --git" and the first hunk is a header.
			p := strings.TrimPrefix(line, "+++ ")
			if p == "/dev/null" {
				cur = nil
				continue
			}
			p = strings.TrimPrefix(unquoteGitPath(p), "b/")
			cur = &addedFile{path: p}
		case strings.HasPrefix(line, "@@ "):
			newLn, inHunk = hunkNewStart(line), true
		case inHunk && cur != nil && strings.HasPrefix(line, "+"):
			b.WriteString(line[1:])
			b.WriteByte('\n')
			cur.lines = append(cur.lines, newLn)
			newLn++
		case inHunk && cur != nil && withRemoved && strings.HasPrefix(line, "-"):
			rm.WriteString(line[1:])
			rm.WriteByte('\n')
		case inHunk && strings.HasPrefix(line, " "):
			newLn++
		}
	}
	flush()
	return out
}

// hunkNewStart reads the new-file start line of a hunk header
// "@@ -a,b +c,d @@".
func hunkNewStart(h string) int {
	i := strings.Index(h, " +")
	if i < 0 {
		return 1
	}
	rest := h[i+2:]
	n := 0
	for _, c := range rest {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 {
		return 1
	}
	return n
}

// unquoteGitPath strips git's C-style quoting from a path ("\"b/a b\"").
func unquoteGitPath(p string) string {
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		p = p[1 : len(p)-1]
		p = strings.ReplaceAll(p, `\"`, `"`)
		p = strings.ReplaceAll(p, `\\`, `\`)
	}
	return p
}

func (e *Engine) cachedClean(hash string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.clean[hash]
	return ok
}

func (e *Engine) rememberClean(hash string, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.clean == nil {
		e.clean = map[string]time.Time{}
	}
	if _, ok := e.clean[hash]; ok {
		return
	}
	e.clean[hash] = at
	e.order = append(e.order, hash)
	for len(e.order) > cacheEntries {
		delete(e.clean, e.order[0])
		e.order = e.order[1:]
	}
}

// touchesWorkflow reports a change to a workflow file (its CI hits are not
// cached with the clean verdict).
func touchesWorkflow(files []addedFile) bool {
	for _, f := range files {
		if secciwf.IsWorkflowPath(f.path) {
			return true
		}
	}
	return false
}

// checkWorkflows runs the native workflow rules over every changed
// workflow, read whole as the change records it: the index for a plain
// commit, the working tree for -a and pathspecs, the To commit for a
// range. A push is not read (its refspecs may name several tips) and
// counts as unchecked, like any read that fails.
func (e *Engine) checkWorkflows(ctx context.Context, req Request, files []addedFile) ([]CIFinding, []string, int) {
	var (
		out       []CIFinding
		checked   []string
		unchecked int
	)
	for _, f := range files {
		if !secciwf.IsWorkflowPath(f.path) {
			continue
		}
		content, ok := e.readWorkflow(ctx, req, f.path)
		if !ok {
			unchecked++
			continue
		}
		rep := secciwf.Check(content)
		if !rep.Complete() {
			unchecked++
			continue
		}
		if len(checked) < MaxFindings {
			checked = append(checked, f.path)
		}
		for _, h := range rep.Findings {
			if len(out) >= MaxFindings {
				break
			}
			out = append(out, CIFinding{Path: f.path, RuleID: h.RuleID, Line: h.Line, Severity: h.Severity, FlagOnly: h.FlagOnly})
		}
	}
	return out, checked, unchecked
}

// readWorkflow reads one workflow as the request's form records it, capped
// one byte past the rules' cap so an over-cap file is reported, never cut.
func (e *Engine) readWorkflow(ctx context.Context, req Request, rel string) ([]byte, bool) {
	limit := secciwf.MaxWorkflowBytes + 1
	var spec string
	switch {
	case req.Form.Push:
		return nil, false
	case req.Form.To != "":
		spec = req.Form.To + ":" + rel
	case req.Form.All || len(req.Form.Pathspecs) > 0:
		if e.ReadFile == nil {
			return nil, false
		}
		b, over, err := e.ReadFile(req.Root, rel, limit)
		if err != nil {
			return nil, false
		}
		if over {
			return make([]byte, limit), true
		}
		return b, true
	default:
		spec = ":" + rel
	}
	b, over, err := e.Git(ctx, req.Root, limit, IndividualBudget, "cat-file", "blob", spec)
	if err != nil {
		return nil, false
	}
	if over {
		return make([]byte, limit), true
	}
	return b, true
}
