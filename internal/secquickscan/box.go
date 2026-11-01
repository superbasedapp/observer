package secquickscan

import (
	"bytes"
	"context"
	"strings"
	"time"
)

// box.go: the commit scan over box work (security plan 4.8 "Copy
// workspaces", 5.3 (d), M7; lane sec-box). A sandbox run with a copy
// workspace commits in its copy, and that work reaches the source
// repository on a box ref, not on HEAD: the return step's
// refs/observer/sandbox/<run> (sandbox plan section 6) and the worktree
// source's refs/heads/observer-sandbox/<id>/<label> branch. The HEAD walk
// (AfterScan) never reaches either, so the commit scan walks them here,
// with the same scan per commit, the same per-commit budget and diff cap,
// and ONE call budget and commit cap shared by every range of the call.

// BoxRefPrefixes are the ref namespaces box work lives under, in the order
// they are listed.
var BoxRefPrefixes = []string{"refs/observer/sandbox/", "refs/heads/observer-sandbox/"}

// BoxRefTip is one box ref and the commit it names.
type BoxRefTip struct {
	Ref string
	Tip string
}

// maxBoxRefListBytes caps the box ref listing's bytes (above MaxBoxRefs
// refs of ordinary length).
const maxBoxRefListBytes = 256 << 10

// MaxBoxRefs caps the box refs one listing returns (CommitScan.MaxBoxRefs
// zero), and MaxBoxWalksPerTick the box refs one tick walks
// (CommitScan.MaxBoxWalks zero; lane sec-box audit findings 2 and 3).
const (
	MaxBoxRefs         = 2000
	MaxBoxWalksPerTick = 64
)

// BoxRefList is one listing of a repository's box refs.
type BoxRefList struct {
	// Refs are the box refs listed, in ref order.
	Refs []BoxRefTip
	// OverCap: the listing went past the byte cap or the ref cap; Refs
	// holds the first whole entries, at most the ref cap, and the caller
	// records the cut, never silent (a box with the main .git writable can
	// plant thousands of refs).
	OverCap bool
	// Cap is the ref cap the listing was read under.
	Cap int
}

func (c *CommitScan) maxBoxRefs() int {
	if c.MaxBoxRefs > 0 {
		return c.MaxBoxRefs
	}
	return MaxBoxRefs
}

// BoxWalksPerTick is the box refs one tick walks (MaxBoxWalks, else
// MaxBoxWalksPerTick).
func (c *CommitScan) BoxWalksPerTick() int {
	if c.MaxBoxWalks > 0 {
		return c.MaxBoxWalks
	}
	return MaxBoxWalksPerTick
}

// ListBoxRefs lists root's box refs with one git call (for-each-ref over
// BoxRefPrefixes), sorted by ref name. A ref whose name or object is not
// one the walk can name safely is left out. A listing past the byte cap or
// the ref cap keeps its first whole entries and says so (OverCap). false
// when the listing could not be read at all.
func (c *CommitScan) ListBoxRefs(ctx context.Context, root string) (BoxRefList, bool) {
	if c.Engine == nil || c.Engine.Git == nil || strings.TrimSpace(root) == "" {
		return BoxRefList{}, false
	}
	args := append([]string{"for-each-ref", "--format=%(objectname) %(refname)"}, BoxRefPrefixes...)
	out, over, err := c.Engine.Git(ctx, root, maxBoxRefListBytes, orDuration(c.PerCommit, CommitPerCommitBudget), args...)
	if err != nil {
		return BoxRefList{}, false
	}
	if over {
		// The last line may be cut mid-name: keep whole lines only.
		if i := bytes.LastIndexByte(out, '\n'); i >= 0 {
			out = out[:i+1]
		} else {
			out = nil
		}
	}
	list := BoxRefList{Refs: ParseBoxRefList(out), OverCap: over, Cap: c.maxBoxRefs()}
	if len(list.Refs) > list.Cap {
		list.Refs, list.OverCap = list.Refs[:list.Cap], true
	}
	return list, true
}

// ParseBoxRefList reads for-each-ref's "<object> <ref>" lines, keeping a
// line whose object is a commit id and whose ref lies under one of
// BoxRefPrefixes and is a plain ref name.
func ParseBoxRefList(out []byte) []BoxRefTip {
	var refs []BoxRefTip
	for _, line := range strings.Split(string(out), "\n") {
		obj, ref, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || !isCommitID(obj) || !IsBoxRef(ref) {
			continue
		}
		refs = append(refs, BoxRefTip{Ref: ref, Tip: obj})
	}
	return refs
}

// IsBoxRef reports whether ref is a plain ref name under one of
// BoxRefPrefixes.
func IsBoxRef(ref string) bool {
	if !isRefName(ref) {
		return false
	}
	for _, p := range BoxRefPrefixes {
		if strings.HasPrefix(ref, p) && len(ref) > len(p) {
			return true
		}
	}
	return false
}

// BoxExclude says which refs a box range excludes besides its own Not.
type BoxExclude int

const (
	// ExcludeAllRefs: every ref and HEAD of this worktree (the return
	// step: the new ref is not written yet, so what no ref reaches is what
	// the box brought).
	ExcludeAllRefs BoxExclude = iota
	// ExcludeOtherRefs: every ref outside the box namespaces, and HEAD of
	// this worktree (a box ref seen for the first time: its commits that
	// another box ref also reaches are listed too, and the caller skips
	// the ones the store already holds a run for).
	ExcludeOtherRefs
	// ExcludeNone: only Not (a moved box ref: its previous tip).
	ExcludeNone
)

// BoxRange is one range of a box walk: the commits Tip reaches that Not
// and the Exclude refs do not.
type BoxRange struct {
	// Key names the range in the result (the ref, or the return's ref).
	Key     string
	Tip     string
	Not     []string
	Exclude BoxExclude
}

// BoxRangeResult is one range's walk.
type BoxRangeResult struct {
	Key string
	CommitScanResult
}

// rangeArgs is the rev-list argv of r: oldest first, this worktree only
// (another worktree's HEAD is the worktree source's own branch, which must
// not hide its commits), and the exclusions.
func (r BoxRange) rangeArgs() ([]string, bool) {
	if !isCommitID(r.Tip) {
		return nil, false
	}
	args := []string{"rev-list", "--reverse", r.Tip}
	for _, n := range r.Not {
		if !isCommitID(n) {
			return nil, false
		}
		args = append(args, "^"+n)
	}
	switch r.Exclude {
	case ExcludeAllRefs:
		args = append(args, "--single-worktree", "--not", "--all")
	case ExcludeOtherRefs:
		args = append(args, "--single-worktree", "--not")
		for _, p := range BoxRefPrefixes {
			args = append(args, "--exclude="+p+"*")
		}
		args = append(args, "--all")
	}
	return append(args, "--"), true
}

// WalkBox lists and scans every range in order, oldest commit first within
// a range, under ONE budget (Budget, else CommitBudget) and ONE commit cap
// (MaxCommits, else MaxCommitsPerScan) for the whole call. scanned, when
// set, is asked once per range with the listed commits and returns the
// ones the store already holds a run for: those are neither scanned nor
// counted as skipped, nor is a commit an earlier range of the same call
// scanned. A range whose listing fails scans its tip alone
// (RangeUnread, an unknown remainder, as AfterScan does); commits past the
// cap or the budget are counted in Skipped with their reason. Nothing is
// remembered between calls: the caller keeps the tips it walked.
func (c *CommitScan) WalkBox(ctx context.Context, root string, ranges []BoxRange, scanned func(shas []string) map[string]bool) []BoxRangeResult {
	if c.Engine == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, orDuration(c.Budget, CommitBudget))
	defer cancel()
	left := c.maxCommits()
	per := orDuration(c.PerCommit, CommitPerCommitBudget)
	maxDiff := c.MaxDiffBytes
	if maxDiff <= 0 {
		maxDiff = CommitMaxDiffBytes
	}
	out := make([]BoxRangeResult, 0, len(ranges))
	// A commit two ranges reach (two box refs at one tip) is scanned once
	// per call.
	walked := map[string]bool{}
	for _, r := range ranges {
		res := BoxRangeResult{Key: r.Key}
		if ctx.Err() != nil {
			res.Skipped, res.SkipReason = 1, ReasonBudget
			out = append(out, res)
			continue
		}
		shas, ok := c.listBoxRange(ctx, root, r, per)
		if !ok {
			res.RangeUnread = true
			shas = nil
			if isCommitID(r.Tip) {
				shas = []string{r.Tip}
			}
		}
		var done map[string]bool
		if scanned != nil && len(shas) > 0 {
			done = scanned(shas)
		}
		kept := shas[:0:0]
		for _, s := range shas {
			if !done[s] && !walked[s] {
				kept = append(kept, s)
			}
		}
		shas = kept
		if len(shas) > left {
			// The newest commits are walked, as AfterScan does.
			res.Skipped, res.SkipReason = len(shas)-left, ReasonCommitCap
			shas = shas[len(shas)-left:]
		}
		for i, sha := range shas {
			if ctx.Err() != nil {
				res.Skipped += len(shas) - i
				res.SkipReason = ReasonBudget
				break
			}
			walked[sha] = true
			sr := c.Engine.Scan(ctx, Request{Root: root, Form: Form{To: sha}, Budget: per, MaxDiffBytes: maxDiff})
			res.Commits = append(res.Commits, CommitResult{SHA: sha, Result: sr})
			left--
		}
		out = append(out, res)
	}
	return out
}

// listBoxRange lists r's commits, oldest first, reading at most
// revListSpan times the walk's cap; false when the range cannot be read
// whole.
func (c *CommitScan) listBoxRange(ctx context.Context, root string, r BoxRange, timeout time.Duration) ([]string, bool) {
	args, ok := r.rangeArgs()
	if !ok {
		return nil, false
	}
	limit := 41 * (c.maxCommits()*revListSpan + 1)
	out, over, err := c.Engine.Git(ctx, root, limit, timeout, args...)
	if err != nil || over {
		return nil, false
	}
	var shas []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); isCommitID(l) {
			shas = append(shas, l)
		}
	}
	return shas, true
}
