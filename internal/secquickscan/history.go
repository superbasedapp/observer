package secquickscan

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The unpushed-history check (security pillar plan sections 4.8 and 5.3;
// lane sec-gate3 milestone 1b, decision log P-033). A finding a commit
// scan recorded stays open while the commit that adds it is history the
// next push would send, whatever the working tree says: a human edit, an
// `rm`, a later commit that deletes the line or `git rm --cached` removes
// the secret from the tree, not from the commit. The daemon asks this
// check, one commit at a time, whether that commit is still such history.

// HistoryState is what the check found out about one commit.
type HistoryState string

const (
	// HistoryUnpushed: a ref (a local branch, a tag, a remote-tracking
	// ref, the stash or any other), HEAD, a linked worktree's HEAD or a
	// reflog entry holds the commit and at least one
	// configured remote is not credited with it (or there is no remote),
	// so a push can still send it there. HistoryVerdict.Remotes names the
	// remotes credited with it: a push to one of them sends nothing new of
	// it (lane sec-gate4 milestone 1a).
	HistoryUnpushed HistoryState = "unpushed"
	// HistoryPushed: every configured remote is credited with the commit,
	// so no push can send it anywhere new.
	HistoryPushed HistoryState = "pushed"
	// HistoryGone: the commit no longer exists: it was rewritten away and
	// git pruned the object. A commit an amend or a reset left reachable
	// through a reflog entry (HEAD@{1}) is still pushable by name or id,
	// so it stays held until the reflog no longer reaches it (lane
	// SEC-GATE5 milestone 2, SECP-18), and a commit nothing reaches but
	// whose object still exists (dangling) stays held too, since a push by
	// its id still sends it (lane SEC-P4 decision 5): `git gc
	// --prune=now` releases it.
	HistoryGone HistoryState = "gone"
	// HistoryUnknown: git could not answer (unavailable, not a repository,
	// a timeout, an output over its cap). Never treated as pushed or gone.
	HistoryUnknown HistoryState = "unknown"
)

// HistoryFacts are the git answers the decision table reads.
type HistoryFacts struct {
	// Answered is false when any git call needed could not be answered.
	Answered bool
	// Exists: the commit object is in the repository.
	Exists bool
	// Refs are the refs that contain the commit (full names).
	Refs []string
	// OnHEAD: HEAD, or the HEAD of a linked worktree, contains the commit
	// (a detached HEAD has no branch).
	OnHEAD bool
	// Reflog: a reflog entry (of any ref, HEAD or a linked worktree's
	// HEAD) is the commit or descends from it; read only when no ref and
	// no HEAD holds it.
	Reflog bool
	// Remotes are the repository's configured remotes (`git remote`), read
	// when a local branch, tag, HEAD or a remote-tracking ref holds the
	// commit.
	Remotes []string
	// ReflogPastCap names the reflog cap (HistoryReasonReflogCapAge or
	// HistoryReasonReflogCapEntries) past which the only reflog entries
	// reaching the commit lie, when caps are set (HistoryChecker
	// ReflogMaxAge, ReflogMaxEntries; lane LEFT-SEC). Reflog is false then.
	// "" when no cap is set or a reach lies inside the caps.
	ReflogPastCap string
	// UnknownReason names why git's answer is unknown when a named cap
	// made it so: HistoryReasonReflogListingCap when the reflog listing the
	// caps need is over its byte cap (lane LEFT-SEC audit F6). "" for any
	// other unknown, and whenever the check answered.
	UnknownReason string
	// PushDiffers are the remotes whose effective push URL differs from
	// their fetch URL (a pushurl, several urls, or a url.*.pushInsteadOf
	// that matches its url; lane sec-gate4 audit finding 3): a push to one
	// goes somewhere its tracking refs do not show, so it is never
	// credited.
	PushDiffers map[string]bool
}

// HistoryVerdict is the check's answer for one commit: its state and the
// remotes credited with it.
type HistoryVerdict struct {
	State   HistoryState
	Remotes []string
	// Reason names why an unpushed commit is held when it is not one a
	// push of a branch would send: HistoryReasonDangling for a commit
	// nothing reaches whose object still exists; "" otherwise.
	Reason string
}

// HistoryReasonDangling is HistoryVerdict.Reason for a commit no ref, HEAD
// or reflog entry reaches but whose object git has not pruned: a push by
// its id still sends it, so it is held until `git gc --prune=now` (lane
// SEC-P4 decision 5).
const HistoryReasonDangling = "dangling"

// HistoryReasonReflogCapAge and HistoryReasonReflogCapEntries are
// HistoryVerdict.Reason for a commit only reflog entries past a reflog cap
// reach (lane LEFT-SEC, SECP-18 "the reflog caps"): older than
// HistoryChecker.ReflogMaxAge, or deeper in their ref's reflog than
// ReflogMaxEntries. It is still unpushed (a push by its id or a reflog
// spelling still sends it); the daemon records the cap so the push gate
// asks instead of denying, never allows. A dangling commit (no reflog entry
// left at all) is not past a cap: it keeps HistoryReasonDangling whatever
// the caps (lane LEFT-SEC audit F2).
const (
	HistoryReasonReflogCapAge     = "reflog_cap_age"
	HistoryReasonReflogCapEntries = "reflog_cap_entries"
)

// HistoryReasonReflogListingCap is HistoryVerdict.Reason for an unknown
// answer because the reflog listing the caps need (`git log -g --all`, or
// the reflog tips) is over its byte cap (historyMaxBytes): the caps cannot
// apply, so the commit stays held as before, and the daemon records an
// unknown run naming the listing cap instead of answering nothing (lane
// LEFT-SEC audit F6).
const HistoryReasonReflogListingCap = "reflog_listing_cap"

// historyRow is one row of the decision table: the first row whose match
// holds decides.
type historyRow struct {
	name  string
	match func(HistoryFacts) bool
	state HistoryState
	// reason is HistoryVerdict.Reason when this row decides.
	reason string
}

func refUnder(f HistoryFacts, prefixes ...string) bool {
	for _, r := range f.Refs {
		for _, p := range prefixes {
			if strings.HasPrefix(r, p) {
				return true
			}
		}
	}
	return false
}

// heldLocally: a ref other than a remote-tracking one (a local branch, a
// tag, the stash, a note, any other), HEAD, a linked worktree's HEAD or a
// reflog entry holds the commit, so a push can send it (by name, or by a
// reflog spelling or its id).
func heldLocally(f HistoryFacts) bool {
	if f.OnHEAD || f.Reflog {
		return true
	}
	for _, r := range f.Refs {
		if !strings.HasPrefix(r, "refs/remotes/") {
			return true
		}
	}
	return false
}

// RemotesHolding returns the configured remotes credited with the commit,
// sorted: one of the remote's remote-tracking refs holds it and its push
// URL is its fetch URL (PushDiffers). A ref is credited to the one
// configured remote whose name it starts with; a ref two configured names
// fit (remotes `a` and `a/b`, the ref refs/remotes/a/b/main) credits none
// (lane sec-gate4 audit finding 6), and a ref under no configured remote
// (a remote since removed) credits none.
func (f HistoryFacts) RemotesHolding() []string {
	set := map[string]bool{}
	for _, ref := range f.Refs {
		rest, ok := strings.CutPrefix(ref, "refs/remotes/")
		if !ok {
			continue
		}
		fit := ""
		n := 0
		for _, r := range dedupe(f.Remotes) {
			if strings.HasPrefix(rest, r+"/") {
				fit = r
				n++
			}
		}
		if n == 1 && !f.PushDiffers[fit] {
			set[fit] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

// everyRemoteHolds: there is at least one configured remote and every one
// of them is credited with the commit.
func everyRemoteHolds(f HistoryFacts) bool {
	return len(f.Remotes) > 0 && len(f.RemotesHolding()) == len(dedupe(f.Remotes))
}

func dedupe(xs []string) []string {
	set := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !set[x] {
			set[x] = true
			out = append(out, x)
		}
	}
	return out
}

// historyTable is THE decision table, walked top down. A remote-tracking
// ref is a valid push source (`git push backup origin/f:refs/heads/x`), so
// a commit only such a ref holds stays held for every remote not credited
// with it (lane sec-gate4 audit finding 4; it used to be released).
var historyTable = []historyRow{
	{"git could not answer", func(f HistoryFacts) bool { return !f.Answered }, HistoryUnknown, ""},
	{"the commit no longer exists", func(f HistoryFacts) bool { return !f.Exists }, HistoryGone, ""},
	{"every remote has it", everyRemoteHolds, HistoryPushed, ""},
	{"held locally and a remote still lacks it", heldLocally, HistoryUnpushed, ""},
	{"only a remote-tracking ref holds it and a remote still lacks it", func(f HistoryFacts) bool { return refUnder(f, "refs/remotes/") }, HistoryUnpushed, ""},
	// Lane LEFT-SEC: only reflog entries past a reflog cap reach it (or,
	// with a cap set, nothing does). Still unpushed; the reason carries the
	// cap (decideHistoryRow reads it off the facts).
	{"only reflog entries past a cap reach it", func(f HistoryFacts) bool { return f.ReflogPastCap != "" }, HistoryUnpushed, historyReasonFromFacts},
	// A commit that exists but nothing reaches (dangling) is pushable by
	// its id until git prunes the object (lane SEC-P4 decision 5; it read
	// gone before, which released the hold on a commit still there).
	{"nothing reaches it but the object still exists", func(HistoryFacts) bool { return true }, HistoryUnpushed, HistoryReasonDangling},
}

// historyReasonFromFacts marks a row whose reason is the facts' own
// ReflogPastCap.
const historyReasonFromFacts = "\x00facts"

// DecideHistory walks the decision table.
func DecideHistory(f HistoryFacts) HistoryState {
	return decideHistoryRow(f).state
}

// decideHistoryRow returns the first row of the table that matches.
func decideHistoryRow(f HistoryFacts) historyRow {
	for _, r := range historyTable {
		if r.match(f) {
			return r
		}
	}
	return historyRow{state: HistoryUnknown}
}

// Verdict is DecideHistory with the remotes credited with the commit.
func (f HistoryFacts) Verdict() HistoryVerdict {
	row := decideHistoryRow(f)
	v := HistoryVerdict{State: row.state, Reason: row.reason}
	if v.Reason == historyReasonFromFacts {
		v.Reason = f.ReflogPastCap
	}
	if v.State == HistoryUnknown {
		v.Reason = f.UnknownReason
	}
	if v.State == HistoryUnpushed || v.State == HistoryPushed {
		v.Remotes = f.RemotesHolding()
	}
	return v
}

// HistoryChecker reads the facts for one commit through the injected git
// envelope.
type HistoryChecker struct {
	// Git is the read-only git envelope.
	Git GitFunc
	// ExitCode returns the exit code of a git call that ran and exited
	// non-zero, false for anything else (git unavailable, a timeout): only
	// a real exit is ever read as "no".
	ExitCode func(error) (int, bool)
	// Timeout bounds one git call (zero: 5 seconds).
	Timeout time.Duration
	// ReflogMaxAge and ReflogMaxEntries are the reflog caps
	// ([security.scanning] reflog_hold_max_age_days and
	// reflog_hold_max_entries, lane LEFT-SEC): a reflog entry older than
	// ReflogMaxAge, or at position ReflogMaxEntries or deeper in its ref's
	// reflog (HEAD@{0} is position 0), no longer holds a commit. Zero, the
	// default, is no cap: the reflog check is exactly as before.
	ReflogMaxAge     time.Duration
	ReflogMaxEntries int
	// Now is the clock the age cap reads (nil: time.Now).
	Now func() time.Time
}

// capped reports whether a reflog cap is set.
func (h HistoryChecker) capped() bool { return h.ReflogMaxAge > 0 || h.ReflogMaxEntries > 0 }

// historyMaxBytes caps the ref list one check reads.
const historyMaxBytes = 256 << 10

// maxWorktrees bounds the linked worktrees one check asks about; a
// repository with more is unknown.
const maxWorktrees = 32

func (h HistoryChecker) timeout() time.Duration {
	if h.Timeout <= 0 {
		return 5 * time.Second
	}
	return h.Timeout
}

// Check returns the state of commit sha in the repository at root. A sha
// that is not a full hex commit id is unknown, so no caller can put an
// option on git's command line.
func (h HistoryChecker) Check(ctx context.Context, root, sha string) HistoryState {
	return DecideHistory(h.Facts(ctx, root, sha))
}

// Inspect is Check with the remotes credited with the commit.
func (h HistoryChecker) Inspect(ctx context.Context, root, sha string) HistoryVerdict {
	return h.Facts(ctx, root, sha).Verdict()
}

// isAncestor asks whether sha is an ancestor of tip: known is false for
// anything but a plain yes or no.
func (h HistoryChecker) isAncestor(ctx context.Context, root, sha, tip string) (yes, known bool) {
	switch _, _, err := h.Git(ctx, root, 4096, h.timeout(), "merge-base", "--is-ancestor", sha, tip); {
	case err == nil:
		return true, true
	default:
		if code, ok := h.ExitCode(err); ok && code == 1 {
			return false, true
		}
		return false, false
	}
}

// Facts reads the git answers for one commit.
func (h HistoryChecker) Facts(ctx context.Context, root, sha string) HistoryFacts {
	if h.Git == nil || h.ExitCode == nil || root == "" || !isCommitID(sha) || (len(sha) != 40 && len(sha) != 64) {
		return HistoryFacts{}
	}
	timeout := h.timeout()
	if _, _, err := h.Git(ctx, root, 4096, timeout, "rev-parse", "--git-dir"); err != nil {
		return HistoryFacts{}
	}
	if _, _, err := h.Git(ctx, root, 4096, timeout, "cat-file", "-e", sha+"^{commit}"); err != nil {
		if code, ok := h.ExitCode(err); ok && code != 0 {
			return HistoryFacts{Answered: true}
		}
		return HistoryFacts{}
	}
	out, over, err := h.Git(ctx, root, historyMaxBytes, timeout, "for-each-ref", "--contains", sha, "--format=%(refname)")
	if err != nil || over {
		return HistoryFacts{}
	}
	f := HistoryFacts{Answered: true, Exists: true, Refs: lines(out)}
	if !heldLocally(f) {
		yes, known := h.isAncestor(ctx, root, sha, "HEAD")
		if !known {
			// Not a plain "no" (an unborn HEAD answers 128): unknown.
			return HistoryFacts{}
		}
		f.OnHEAD = yes
		if !f.OnHEAD {
			// P-041: the check runs in the main checkout, so a commit
			// only a linked worktree's HEAD holds (detached or not) is
			// asked about there too (lane sec-gate4 audit finding 7).
			on, ok := h.onWorktreeHEAD(ctx, root, sha)
			if !ok {
				return HistoryFacts{}
			}
			f.OnHEAD = on
		}
	}
	if !heldLocally(f) && !refUnder(f, "refs/remotes/") {
		// No ref and no HEAD: a reflog entry may still reach it (an
		// amend, a reset, a deleted branch).
		on, ok := h.onReflog(ctx, root, sha)
		if !ok {
			return HistoryFacts{}
		}
		if on && h.capped() {
			// Lane LEFT-SEC: only an entry inside the caps holds it.
			within, past, ok := h.onReflogWithinCaps(ctx, root, sha)
			if !ok {
				return HistoryFacts{UnknownReason: past}
			}
			if !within {
				f.ReflogPastCap = past
				return f
			}
		}
		// A dangling commit (no reflog entry left at all) keeps its own
		// reason whatever the caps (audit F2): the caps never loosen the
		// SEC-P4 decision 5 hold.
		if f.Reflog = on; !on {
			return f
		}
	}
	remotes, over, err := h.Git(ctx, root, historyMaxBytes, timeout, "remote")
	if err != nil || over {
		return HistoryFacts{}
	}
	f.Remotes = lines(remotes)
	differs, ok := h.pushDiffers(ctx, root, f.Remotes)
	if !ok {
		return HistoryFacts{}
	}
	f.PushDiffers = differs
	return f
}

// onReflog asks whether a reflog entry reaches sha: one names it, or one
// descends from it (`rev-list --reflog` walks every ref's reflog, HEAD's
// and the linked worktrees'). ok is false when git could not answer or a
// list is over its cap (the commit then stays held).
func (h HistoryChecker) onReflog(ctx context.Context, root, sha string) (bool, bool) {
	tips, over, err := h.Git(ctx, root, historyMaxBytes, h.timeout(), "rev-list", "--reflog", "--no-walk=unsorted")
	if err != nil || over {
		return false, false
	}
	for _, t := range lines(tips) {
		if strings.EqualFold(t, sha) {
			return true, true
		}
	}
	desc, over, err := h.Git(ctx, root, 4096, h.timeout(), "rev-list", "--reflog", "--ancestry-path", "--max-count=1", "^"+sha)
	if err != nil || over {
		return false, false
	}
	return len(lines(desc)) > 0, true
}

// maxCapTips bounds the reflog entry tips inside the caps one check passes
// to git; a repository with more reads every entry as inside (the hold
// stays, never looser).
const maxCapTips = 1024

// reflogEntry is one reflog entry: its commit, the ref whose reflog it is
// in, its position there (0 is newest) and its time.
type reflogEntry struct {
	sha string
	ref string
	pos int
	at  time.Time
}

// onReflogWithinCaps asks whether a reflog entry inside the caps is sha or
// descends from it. past names the cap that excluded the reach when none
// does. The entries come from two listings of every reflog (`git log -g
// --all` plus HEAD's), one with positions and one with times, zipped line
// by line; a reflog tip `rev-list --reflog` lists that neither listing
// dates (a linked worktree's HEAD reflog) is read as inside the caps, so a
// listing gap keeps the hold (never looser). ok is false when git could not
// answer; past is then HistoryReasonReflogListingCap when a listing was
// over its byte cap.
func (h HistoryChecker) onReflogWithinCaps(ctx context.Context, root, sha string) (within bool, past string, ok bool) {
	entries, over, ok := h.reflogEntries(ctx, root)
	if !ok {
		if over {
			return false, HistoryReasonReflogListingCap, false
		}
		return false, "", false
	}
	tips, over, err := h.Git(ctx, root, historyMaxBytes, h.timeout(), "rev-list", "--reflog", "--no-walk=unsorted")
	if over {
		return false, HistoryReasonReflogListingCap, false
	}
	if err != nil {
		return false, "", false
	}
	dated := map[string]bool{}
	for _, e := range entries {
		dated[strings.ToLower(e.sha)] = true
	}
	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	inside := map[string]bool{}
	pastAge := false
	for _, e := range entries {
		age := h.ReflogMaxAge > 0 && now.Sub(e.at) > h.ReflogMaxAge
		deep := h.ReflogMaxEntries > 0 && e.pos >= h.ReflogMaxEntries
		if age || deep {
			pastAge = pastAge || age
			continue
		}
		inside[strings.ToLower(e.sha)] = true
	}
	for _, t := range lines(tips) {
		if !dated[strings.ToLower(t)] {
			inside[strings.ToLower(t)] = true
		}
	}
	if inside[strings.ToLower(sha)] {
		return true, "", true
	}
	if len(inside) > maxCapTips {
		return true, "", true
	}
	if len(inside) > 0 {
		args := []string{"rev-list", "--ancestry-path", "--max-count=1", "^" + sha}
		for t := range inside {
			args = append(args, t)
		}
		desc, over, err := h.Git(ctx, root, 4096, h.timeout(), args...)
		if err != nil || over {
			return false, "", false
		}
		if len(lines(desc)) > 0 {
			return true, "", true
		}
	}
	if pastAge {
		return false, HistoryReasonReflogCapAge, true
	}
	return false, HistoryReasonReflogCapEntries, true
}

// reflogEntries lists every reflog entry of every ref and of HEAD with its
// position and time (two listings in the same order, zipped). ok is false
// (the third result) when git could not answer or the listings disagree;
// the second is true when a listing was over its byte cap.
func (h HistoryChecker) reflogEntries(ctx context.Context, root string) ([]reflogEntry, bool, bool) {
	var out []reflogEntry
	for _, which := range [][]string{{"--all"}, {"HEAD"}} {
		pos, over, err := h.Git(ctx, root, historyMaxBytes, h.timeout(), append([]string{"log", "-g", "--format=%H %gD"}, which...)...)
		if over {
			return nil, true, false
		}
		if err != nil {
			return nil, false, false
		}
		at, over, err := h.Git(ctx, root, historyMaxBytes, h.timeout(), append([]string{"log", "-g", "--date=unix", "--format=%H %gD"}, which...)...)
		if over {
			return nil, true, false
		}
		if err != nil {
			return nil, false, false
		}
		pl, al := lines(pos), lines(at)
		if len(pl) != len(al) {
			return nil, false, false
		}
		for i := range pl {
			e, ok := parseReflogPair(pl[i], al[i])
			if !ok {
				return nil, false, false
			}
			out = append(out, e)
		}
	}
	return out, false, true
}

// parseReflogPair reads one entry from its position line ("<sha>
// <ref>@{<n>}") and its time line ("<sha> <ref>@{<unix>}").
func parseReflogPair(posLine, atLine string) (reflogEntry, bool) {
	sha, sel, ok := strings.Cut(strings.TrimSpace(posLine), " ")
	sha2, sel2, ok2 := strings.Cut(strings.TrimSpace(atLine), " ")
	if !ok || !ok2 || sha != sha2 || !isCommitID(sha) {
		return reflogEntry{}, false
	}
	ref, n, ok := reflogSelector(sel)
	ref2, ts, ok2 := reflogSelector(sel2)
	if !ok || !ok2 || ref != ref2 {
		return reflogEntry{}, false
	}
	return reflogEntry{sha: sha, ref: ref, pos: int(n), at: time.Unix(ts, 0)}, true
}

// reflogSelector splits "<ref>@{<n>}" into the ref and the number.
func reflogSelector(sel string) (string, int64, bool) {
	i := strings.LastIndex(sel, "@{")
	if i <= 0 || !strings.HasSuffix(sel, "}") {
		return "", 0, false
	}
	n, err := strconv.ParseInt(sel[i+2:len(sel)-1], 10, 64)
	if err != nil || n < 0 {
		return "", 0, false
	}
	return sel[:i], n, true
}

// onWorktreeHEAD asks whether a linked worktree's HEAD holds sha.
func (h HistoryChecker) onWorktreeHEAD(ctx context.Context, root, sha string) (bool, bool) {
	wts, ok := h.worktrees(ctx, root)
	if !ok {
		return false, false
	}
	for i, w := range wts {
		if i == 0 || w.head == "" {
			continue // the main worktree's HEAD was asked already
		}
		yes, known := h.isAncestor(ctx, root, sha, w.head)
		if !known {
			return false, false
		}
		if yes {
			return true, true
		}
	}
	return false, true
}

// worktreeEntry is one `git worktree list --porcelain` entry.
type worktreeEntry struct {
	path   string
	head   string
	branch string // the full ref name, "" when detached or bare
	// prunable: git reports the worktree's checkout gone (`git worktree
	// prune` would remove it). Its HEAD still holds commits; its config is
	// never read (lane SEC-P4 decision 4).
	prunable bool
}

// worktrees lists the repository's worktrees, the main one first. ok is
// false when git could not answer or there are more than maxWorktrees.
func (h HistoryChecker) worktrees(ctx context.Context, root string) ([]worktreeEntry, bool) {
	out, over, err := h.Git(ctx, root, historyMaxBytes, h.timeout(), "worktree", "list", "--porcelain")
	if err != nil || over {
		return nil, false
	}
	wts := parseWorktrees(string(out))
	if len(wts) > maxWorktrees {
		return nil, false
	}
	return wts, true
}

// parseWorktrees reads `git worktree list --porcelain` output.
func parseWorktrees(out string) []worktreeEntry {
	var wts []worktreeEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "worktree "):
			wts = append(wts, worktreeEntry{path: strings.TrimSpace(line[len("worktree "):])})
		case len(wts) == 0:
		case strings.HasPrefix(line, "HEAD "):
			if c := strings.ToLower(strings.TrimSpace(line[len("HEAD "):])); isCommitID(c) && (len(c) == 40 || len(c) == 64) {
				wts[len(wts)-1].head = c
			}
		case strings.HasPrefix(line, "branch "):
			wts[len(wts)-1].branch = strings.TrimSpace(line[len("branch "):])
		case line == "prunable" || strings.HasPrefix(line, "prunable "):
			wts[len(wts)-1].prunable = true
		}
	}
	return wts
}

// remoteConfigRegexp selects the config keys the push-URL check and the
// default push remote read (canonical names: section and variable lower
// case, the subsection as written).
const remoteConfigRegexp = `^(remote\..+\.(url|pushurl)|url\..+\.pushinsteadof|branch\..+\.(remote|pushremote)|remote\.pushdefault)$`

// remoteConfig reads the config entries remoteConfigRegexp selects, every
// value in order. ok is false when git could not answer (a plain "none"
// is exit 1).
func (h HistoryChecker) remoteConfig(ctx context.Context, root string) ([][2]string, bool) {
	out, over, err := h.Git(ctx, root, historyMaxBytes, h.timeout(), "config", "-z", "--get-regexp", remoteConfigRegexp)
	if err != nil {
		if code, ok := h.ExitCode(err); ok && code == 1 {
			return nil, true
		}
		return nil, false
	}
	if over {
		return nil, false
	}
	var kv [][2]string
	for _, rec := range strings.Split(string(out), "\x00") {
		if rec == "" {
			continue
		}
		k, v, _ := strings.Cut(rec, "\n")
		kv = append(kv, [2]string{k, v})
	}
	return kv, true
}

// pushDiffers reads which of remotes push somewhere other than they fetch
// from, in any worktree: with extensions.worktreeConfig each linked
// worktree's config.worktree is read too, and a remote that pushes
// elsewhere from one worktree is never credited.
func (h HistoryChecker) pushDiffers(ctx context.Context, root string, remotes []string) (map[string]bool, bool) {
	views, ok := h.worktreeConfigs(ctx, root)
	if !ok {
		return nil, false
	}
	var out map[string]bool
	for _, v := range views {
		for r := range PushURLDiffers(remotes, v.kv) {
			if out == nil {
				out = map[string]bool{}
			}
			out[r] = true
		}
	}
	return out, true
}

// worktreeConfigView is the remote config one worktree sees, and its
// checked-out branch ("" when detached or bare).
type worktreeConfigView struct {
	branch string
	kv     [][2]string
}

// worktreeConfigs returns the remote config every worktree sees, the main
// one first (lane SEC-GATE5 milestone 2, SECP-18). git reads a worktree's
// own config.worktree only when extensions.worktreeConfig is set and only
// for the worktree it runs in, so with the extension set the config is
// read in every linked worktree; without it every worktree sees the main
// one's. ok is false when git could not answer.
func (h HistoryChecker) worktreeConfigs(ctx context.Context, root string) ([]worktreeConfigView, bool) {
	wts, ok := h.worktrees(ctx, root)
	if !ok {
		return nil, false
	}
	main, ok := h.remoteConfig(ctx, root)
	if !ok {
		return nil, false
	}
	perWorktree, ok := h.worktreeConfigOn(ctx, root)
	if !ok {
		return nil, false
	}
	if len(wts) == 0 {
		return []worktreeConfigView{{kv: main}}, true
	}
	out := make([]worktreeConfigView, 0, len(wts))
	for i, w := range wts {
		if i > 0 && w.prunable {
			// A deleted, not yet pruned checkout has no config of its own
			// to read and no push to make: skipped for the push URLs and
			// the default push remote, where reading it failed the whole
			// check before (unknown forever; lane SEC-P4 decision 4). Its
			// HEAD still holds commits (onWorktreeHEAD).
			continue
		}
		kv := main
		if perWorktree && i > 0 {
			if w.path == "" {
				return nil, false
			}
			if kv, ok = h.remoteConfig(ctx, w.path); !ok {
				return nil, false
			}
		}
		out = append(out, worktreeConfigView{branch: w.branch, kv: kv})
	}
	return out, true
}

// worktreeConfigOn reads extensions.worktreeConfig (unset is false).
func (h HistoryChecker) worktreeConfigOn(ctx context.Context, root string) (bool, bool) {
	out, _, err := h.Git(ctx, root, 4096, h.timeout(), "config", "--bool", "--get", "extensions.worktreeconfig")
	if err != nil {
		if code, ok := h.ExitCode(err); ok && code == 1 {
			return false, true
		}
		return false, false
	}
	return strings.TrimSpace(string(out)) == "true", true
}

// PushURLDiffers decides, from the remote and url config entries (canonical
// key, value), which remotes' effective push URL differs from their fetch
// URL: a remote.<r>.pushurl, more than one remote.<r>.url (a push goes to
// every one, a fetch to the first), or a url.<base>.pushInsteadOf whose
// value starts one of the remote's urls.
func PushURLDiffers(remotes []string, kv [][2]string) map[string]bool {
	urls := map[string][]string{}
	pushurl := map[string]bool{}
	var pushInsteadOf []string
	for _, e := range kv {
		k, v := e[0], e[1]
		switch {
		case strings.HasPrefix(k, "url.") && strings.HasSuffix(k, ".pushinsteadof"):
			pushInsteadOf = append(pushInsteadOf, v)
		case strings.HasPrefix(k, "remote.") && strings.HasSuffix(k, ".pushurl"):
			pushurl[k[len("remote."):len(k)-len(".pushurl")]] = true
		case strings.HasPrefix(k, "remote.") && strings.HasSuffix(k, ".url"):
			r := k[len("remote.") : len(k)-len(".url")]
			urls[r] = append(urls[r], v)
		}
	}
	out := map[string]bool{}
	for _, r := range remotes {
		if pushurl[r] || len(urls[r]) > 1 {
			out[r] = true
			continue
		}
		for _, u := range urls[r] {
			for _, p := range pushInsteadOf {
				if p != "" && strings.HasPrefix(u, p) {
					out[r] = true
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pushDefaultLadder is where a plain `git push` on branch b goes, walked
// top down (lane sec-gate4 audit finding 5): the first key that is set
// decides. "%s" is the branch name. git's own last fallback ("origin" when
// none is set) is deliberately not taken: an unresolved default is unknown.
var pushDefaultLadder = []string{"branch.%s.pushremote", "remote.pushdefault", "branch.%s.remote"}

// DecideDefaultPushRemote resolves the remote a plain push goes to from
// the checked-out branches (full ref names; every worktree's), the config
// entries and the configured remotes: each branch walks pushDefaultLadder,
// and the answer is the one remote every branch resolves to, "" when a
// branch resolves to nothing, to a name that is not a configured remote,
// or the branches disagree, or no branch is checked out.
func DecideDefaultPushRemote(branches []string, kv [][2]string, remotes []string) string {
	cfg := map[string]string{}
	for _, e := range kv {
		cfg[e[0]] = e[1] // the last value wins, as in git
	}
	configured := map[string]bool{}
	for _, r := range remotes {
		configured[r] = true
	}
	answer := ""
	for _, ref := range branches {
		b, ok := strings.CutPrefix(ref, "refs/heads/")
		if !ok || b == "" {
			return ""
		}
		got := ""
		for _, k := range pushDefaultLadder {
			if v := cfg[strings.Replace(k, "%s", b, 1)]; v != "" {
				got = v
				break
			}
		}
		if got == "" || !configured[got] || (answer != "" && answer != got) {
			return ""
		}
		answer = got
	}
	return answer
}

// DefaultPushRemote resolves the repository's default push remote at root:
// DecideDefaultPushRemote for every worktree's checked-out branch under the
// config that worktree sees (its config.worktree included when
// extensions.worktreeConfig is set, worktreeConfigs), and the one remote
// they all agree on; a detached or bare worktree has no plain push and is
// skipped. ok is false when git could not answer.
func (h HistoryChecker) DefaultPushRemote(ctx context.Context, root string) (string, bool) {
	if h.Git == nil || h.ExitCode == nil || root == "" {
		return "", false
	}
	views, ok := h.worktreeConfigs(ctx, root)
	if !ok {
		return "", false
	}
	remotes, over, err := h.Git(ctx, root, historyMaxBytes, h.timeout(), "remote")
	if err != nil || over {
		return "", false
	}
	answer := ""
	for _, v := range views {
		if v.branch == "" {
			continue
		}
		got := DecideDefaultPushRemote([]string{v.branch}, v.kv, lines(remotes))
		if got == "" || (answer != "" && got != answer) {
			return "", true
		}
		answer = got
	}
	return answer, true
}

// lines splits git output into its non-empty trimmed lines.
func lines(out []byte) []string {
	var r []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			r = append(r, line)
		}
	}
	return r
}
