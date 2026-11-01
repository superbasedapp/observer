package secquickscan

import (
	"context"
	"strings"
	"sync"
	"time"
)

// The daemon commit scan's own limits (lane SEC-GATEFIX milestone 2b):
// it is not the hook's quick scan, so it does not borrow the hook's 2 s
// budget or its 8 MiB diff cap.
const (
	// CommitBudget bounds one AfterScan call: every commit it walks.
	CommitBudget = 60 * time.Second
	// CommitPerCommitBudget bounds one commit's scan inside the call.
	CommitPerCommitBudget = 15 * time.Second
	// CommitMaxDiffBytes caps one commit's diff.
	CommitMaxDiffBytes = 32 << 20
	// MaxCommitsPerScan bounds the commits one call walks (the newest
	// ones); the rest of a big pull or branch switch is counted as
	// skipped, recorded as an unknown run, and never re-scanned.
	MaxCommitsPerScan = 200
)

// CommitScan scans the commits that landed in a repository since the last
// call (security plan section 5.3 (d), S-723): every new commit's diff,
// one commit at a time, oldest first, including a human's commit and a
// watcher-only tool's, through the commit scanner's AfterScan callback
// (internal/commitscan). It remembers the last head it walked to per root
// in memory; the first call for a root scans only the head commit, so a
// daemon start never re-scans the whole history (the bounded history scan
// is a separate, on-demand path).
type CommitScan struct {
	Engine *Engine
	// Budget bounds one call (zero: CommitBudget); PerCommit one commit
	// (zero: CommitPerCommitBudget); MaxCommits the commits walked (zero:
	// MaxCommitsPerScan); MaxDiffBytes one commit's diff (zero:
	// CommitMaxDiffBytes).
	Budget       time.Duration
	PerCommit    time.Duration
	MaxCommits   int
	MaxDiffBytes int
	// MaxBoxRefs caps one box ref listing (zero: MaxBoxRefs) and
	// MaxBoxWalks the box refs one tick walks (zero: MaxBoxWalksPerTick).
	MaxBoxRefs  int
	MaxBoxWalks int

	mu   sync.Mutex
	last map[string]string
}

// CommitResult is one walked commit's scan.
type CommitResult struct {
	SHA string
	Result
}

// CommitScanResult is one AfterScan call's answer.
type CommitScanResult struct {
	// Commits are the commits scanned, oldest first.
	Commits []CommitResult
	// Skipped counts the commits of the range that were not scanned (over
	// MaxCommits, or the call's budget ran out), and SkipReason says why;
	// RangeUnread reports that the range itself could not be listed (the
	// previous head is gone, or git failed), so only the head was scanned.
	// Either one is an unknown run, never a clean one.
	Skipped     int
	SkipReason  UnknownReason
	RangeUnread bool
}

// ReasonCommitCap: a range had more commits than one call walks.
const ReasonCommitCap UnknownReason = "commit_cap"

// AfterScan scans root's commits after the last head it walked up to head,
// and returns them; a head equal to the last one walked returns false
// without running git. An empty head (an unborn repository) is skipped.
// The walked-to head advances on every call that ran, also when a commit
// answered unknown or the walk was cut short (those are reported in the
// result, for the caller to record as an unknown run): a big pull or a
// branch switch is walked once, not re-scanned on every tick.
func (c *CommitScan) AfterScan(ctx context.Context, root, head string) (CommitScanResult, bool) {
	if c.Engine == nil || head == "" || !isCommitID(head) {
		return CommitScanResult{}, false
	}
	c.mu.Lock()
	from := c.last[root]
	c.mu.Unlock()
	if from == head {
		return CommitScanResult{}, false
	}
	budget := orDuration(c.Budget, CommitBudget)
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var out CommitScanResult
	maxCommits := c.maxCommits()
	shas := []string{head}
	if from != "" {
		list, ok := c.revList(ctx, root, from, head, maxCommits)
		if ok {
			shas = list
		} else {
			out.RangeUnread = true
		}
	}
	if len(shas) > maxCommits {
		out.Skipped, out.SkipReason = len(shas)-maxCommits, ReasonCommitCap
		shas = shas[len(shas)-maxCommits:]
	}
	per := orDuration(c.PerCommit, CommitPerCommitBudget)
	maxDiff := c.MaxDiffBytes
	if maxDiff <= 0 {
		maxDiff = CommitMaxDiffBytes
	}
	for i, sha := range shas {
		if ctx.Err() != nil {
			out.Skipped += len(shas) - i
			out.SkipReason = ReasonBudget
			break
		}
		r := c.Engine.Scan(ctx, Request{Root: root, Form: Form{To: sha}, Budget: per, MaxDiffBytes: maxDiff})
		out.Commits = append(out.Commits, CommitResult{SHA: sha, Result: r})
	}
	c.mu.Lock()
	if c.last == nil {
		c.last = map[string]string{}
	}
	c.last[root] = head
	c.mu.Unlock()
	return out, true
}

// maxCommits is the walk's commit cap (MaxCommits, else MaxCommitsPerScan).
func (c *CommitScan) maxCommits() int {
	if c.MaxCommits > 0 {
		return c.MaxCommits
	}
	return MaxCommitsPerScan
}

// revListSpan is how many commits past the walk's cap the listing reads, so
// a range a little over the cap is still counted exactly; a range past
// that reads the head alone (RangeUnread).
const revListSpan = 50

// revList lists the commits in from..head, oldest first, through the
// engine's read-only git envelope, reading at most revListSpan times the
// walk's cap (maxCommits). false when the range cannot be read (from is gone
// after a history rewrite, git failed, or the listing was cut).
func (c *CommitScan) revList(ctx context.Context, root, from, head string, maxCommits int) ([]string, bool) {
	if !isCommitID(from) {
		return nil, false
	}
	// 41 bytes a line (a 40-hex id and its newline).
	limit := 41 * (maxCommits*revListSpan + 1)
	out, over, err := c.Engine.Git(ctx, root, limit, orDuration(c.PerCommit, CommitPerCommitBudget), "rev-list", "--reverse", from+".."+head, "--")
	if err != nil {
		return nil, false
	}
	var shas []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if isCommitID(l) {
			shas = append(shas, l)
		}
	}
	if over && len(shas) > 0 {
		// The cap cut the listing: the newest commits are past it. Read
		// the head alone rather than a stale tail, and say the range was
		// not read whole.
		return nil, false
	}
	return shas, true
}

func orDuration(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Verdict combines the walk: blocking when one commit was blocking,
// unknown when one was unknown or the range was not walked whole, clean
// only when every commit of the range was scanned clean.
func (r CommitScanResult) Verdict() Verdict {
	v := VerdictClean
	if r.Skipped > 0 || r.RangeUnread {
		v = VerdictUnknown
	}
	for _, c := range r.Commits {
		switch c.Verdict {
		case VerdictBlocking:
			return VerdictBlocking
		case VerdictUnknown:
			v = VerdictUnknown
		}
	}
	return v
}

// Findings are every walked commit's findings, oldest commit first.
func (r CommitScanResult) Findings() []Finding {
	var out []Finding
	for _, c := range r.Commits {
		out = append(out, c.Findings...)
	}
	return out
}
