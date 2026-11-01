package delivery

import (
	"sort"
	"time"
)

// evaluate.go is THE matching rule (plan section 4): one ordered table,
// walked top down per AI-touched commit, first matching row decides.
//
//	G1  not AI-touched (merge, foreign author, no AI contributor): skipped
//	G2  fingerprint not computed yet: deferred to the next pass
//	P1  merged PR lists our sha                          landed  exact
//	L1  our sha is an ancestor of the default ref        landed  exact_sha
//	P2  merged PR holds a commit with our fingerprint    landed  high
//	L2  a default-branch commit has our fingerprint      landed  patch_id
//	L3  a default-branch commit has the fingerprint of a
//	    local branch range that contains our sha         landed  squash
//	M1  previously landed, landing commit no longer on
//	    the default branch                               landing_lost
//	M2  previously landed under this rule version        kept (monotonic)
//	M3  previously landing_lost                          kept
//	P3  open or draft PR holds our sha (or fingerprint)  in_pr
//	P4  closed-unmerged PR lists our sha, L4 does not
//	    land it                                          abandoned pr_closed
//	L4  a default-branch commit with a PR number in its
//	    subject touches exactly the files of a branch
//	    range containing our sha                         landed  squash_files
//	L6  our sha is on a remote-tracking ref              pushed
//	L7  rewritten away and older than the abandon window abandoned dropped
//	L8  nothing else                                     in_flight / local_only
//
// L5 (content overlap, likely_landed) is NOT IMPLEMENTED in this release:
// it needs the default branch's file contents and a line-overlap measure,
// and no row produces StatusLikelyLanded. [delivery].content_overlap_min is
// accepted and documented as reserved for it.
//
// The M rows make landing monotonic (plan section 4 notes): once landed, a
// commit stays landed unless the landing commit itself is proven gone from
// the default branch (a force-pushed default branch), which records
// landing_lost instead of silently forgetting. A row stored under an older
// RuleVersion is not kept by M2, so a changed rule re-evaluates it.

// PRWithCommits is one stored PR together with its commit list.
type PRWithCommits struct {
	PR      PullRequest
	Commits []PRCommit
}

// DefaultCommit is one commit on the default branch, as the landing scan read
// it.
type DefaultCommit struct {
	SHA         string
	Parents     int
	Subject     string
	CommittedAt time.Time
	// PatchFP is the commit's patch fingerprint, "" when it was not
	// computed (mirror evidence has no blobs; over-cap diffs).
	PatchFP string
	// Files are the repository-relative paths the commit touches, nil when
	// unknown.
	Files []string
}

// DefaultEvidence is everything known about the default branch.
type DefaultEvidence struct {
	// Known is true when a default ref was found and read.
	Known bool
	// Branch is the default branch name; PRs into another base never land.
	Branch string
	// Ancestor answers "is this sha an ancestor of the default ref" for the
	// shas the scan checked. A missing key means unknown, never false.
	Ancestor map[string]bool
	// Commits are default-branch commits since the oldest unlanded AI
	// commit (bounded), newest first.
	Commits []DefaultCommit
	// LandedVia names, for a sha that is an ancestor of the default ref, the
	// merge commit that brought it there (when the scan looked it up).
	LandedVia map[string]DefaultCommit
}

// EvalInput is everything one evaluation pass of one project reads. All
// plain values; the landing scan and the provider service assemble it.
type EvalInput struct {
	Commits []Commit
	PRs     []PRWithCommits
	Default DefaultEvidence
	// RemoteReachable is true for a sha reachable from any remote-tracking
	// ref (or present in the Observer mirror). Missing means no.
	RemoteReachable map[string]bool
	BranchTips      []BranchTip
	// Previous are the stored landings, keyed by commit id.
	Previous map[int64]Landing
	// Source is the evidence source for the local rules (user_refs or
	// mirror); P rows always record SourceProvider.
	Source       EvidenceSource
	Now          time.Time
	AbandonAfter time.Duration
}

// DefaultAbandonAfter is the default abandon window ([delivery].
// abandon_after_days = 30).
const DefaultAbandonAfter = 30 * 24 * time.Hour

// evaluator holds one pass's indexes.
type evaluator struct {
	in          EvalInput
	prBySHA     map[string][]*PRWithCommits
	prByFP      map[string][]*PRWithCommits
	defaultFP   map[string]DefaultCommit
	defaultSHA  map[string]DefaultCommit
	tipsBySHA   map[string][]BranchTip
	abandonSpan time.Duration
}

// outcome is what a row decides: skip (no landing written) or a landing.
type outcome struct {
	skip    bool
	landing Landing
}

// evalRule is one row of evalRules.
type evalRule struct {
	id    string
	apply func(e *evaluator, c Commit) (outcome, bool)
}

// evalRules is the ordered matching table. See the file comment.
var evalRules = []evalRule{
	{"G1", ruleG1},
	{"G2", ruleG2},
	{"P1", ruleP1},
	{"L1", ruleL1},
	{"P2", ruleP2},
	{"L2", ruleL2},
	{"L3", ruleL3},
	{"M1", ruleM1},
	{"M2", ruleM2},
	{"M3", ruleM3},
	{"P3", ruleP3},
	{"P4", ruleP4},
	{"L4", ruleL4},
	{"L6", ruleL6},
	{"L7", ruleL7},
	{"L8", ruleL8},
}

// Evaluate walks the rule table for every commit and returns one landing per
// evaluated commit, ordered by commit id. Commits skipped by G1 or deferred
// by G2 produce no landing (the stored row, if any, is left alone).
func Evaluate(in EvalInput) []Landing {
	e := newEvaluator(in)
	var out []Landing
	for _, c := range in.Commits {
		for _, r := range evalRules {
			oc, ok := r.apply(e, c)
			if !ok {
				continue
			}
			if !oc.skip {
				out = append(out, e.finish(r.id, c, oc.landing))
			}
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CommitID < out[j].CommitID })
	return out
}

func newEvaluator(in EvalInput) *evaluator {
	e := &evaluator{
		in:          in,
		prBySHA:     map[string][]*PRWithCommits{},
		prByFP:      map[string][]*PRWithCommits{},
		defaultFP:   map[string]DefaultCommit{},
		defaultSHA:  map[string]DefaultCommit{},
		tipsBySHA:   map[string][]BranchTip{},
		abandonSpan: in.AbandonAfter,
	}
	if e.abandonSpan <= 0 {
		e.abandonSpan = DefaultAbandonAfter
	}
	prs := make([]*PRWithCommits, len(in.PRs))
	for i := range in.PRs {
		prs[i] = &in.PRs[i]
	}
	sort.SliceStable(prs, func(i, j int) bool { return prs[i].PR.Number < prs[j].PR.Number })
	for _, p := range prs {
		for _, pc := range p.Commits {
			e.prBySHA[pc.SHA] = appendPR(e.prBySHA[pc.SHA], p)
			if pc.PatchFP != "" {
				e.prByFP[pc.PatchFP] = appendPR(e.prByFP[pc.PatchFP], p)
			}
		}
	}
	// Commits arrive newest first; the oldest commit carrying a fingerprint
	// is the one that landed it, so later (older) entries overwrite.
	for _, d := range in.Default.Commits {
		e.defaultSHA[d.SHA] = d
		if d.PatchFP != "" {
			e.defaultFP[d.PatchFP] = d
		}
	}
	for _, t := range in.BranchTips {
		for _, sha := range t.MemberSHAs {
			e.tipsBySHA[sha] = append(e.tipsBySHA[sha], t)
		}
	}
	return e
}

func appendPR(list []*PRWithCommits, p *PRWithCommits) []*PRWithCommits {
	for _, q := range list {
		if q == p {
			return list
		}
	}
	return append(list, p)
}

// finish stamps the fields every outcome shares.
func (e *evaluator) finish(ruleID string, c Commit, l Landing) Landing {
	prev, hadPrev := e.in.Previous[c.ID]
	kept := ruleID == "M2" || ruleID == "M3"
	l.CommitID = c.ID
	l.EvaluatedAt = e.in.Now
	if len(l.SessionIDs) == 0 {
		l.SessionIDs = c.SessionIDs
	}
	if kept {
		return l
	}
	l.RuleID = ruleID
	l.RuleVersion = RuleVersion
	if l.Source == "" {
		l.Source = e.in.Source
	}
	switch l.Status {
	case StatusPushed, StatusInPR, StatusLanded, StatusLandingLost, StatusLikelyLanded:
		l.FirstPushedAt = e.in.Now
		if hadPrev && !prev.FirstPushedAt.IsZero() {
			l.FirstPushedAt = prev.FirstPushedAt
		}
	}
	if l.Status == StatusLanded && l.LandedAt.IsZero() {
		if hadPrev && prev.Status == StatusLanded && !prev.LandedAt.IsZero() {
			l.LandedAt, l.LandedAtSource = prev.LandedAt, prev.LandedAtSource
		} else {
			l.LandedAt, l.LandedAtSource = e.in.Now, LandedAtFirstSeen
		}
	}
	return l
}

// baseOK reports whether a PR targets the default branch (unknown on either
// side counts as yes).
func (e *evaluator) baseOK(p PullRequest) bool {
	return p.BaseRef == "" || e.in.Default.Branch == "" || p.BaseRef == e.in.Default.Branch
}

// fpOK reports whether the commit carries a usable fingerprint.
func fpOK(c Commit) bool { return c.PatchFPState == FPOK && c.PatchFP != "" }

// kindForPR is the landing kind of a merged PR: its merge method, else the
// method the local merge commit's shape implies, else exact_sha when our sha
// itself is on the default branch, else "" (unknown).
func (e *evaluator) kindForPR(p PullRequest, sha string) LandingKind {
	m := p.MergeMethod
	if m == "" {
		if d, ok := e.defaultSHA[p.MergeCommitSHA]; ok {
			m = MergeMethodFromCommit(d.Parents, d.Subject, p.Number)
		}
	}
	switch m {
	case MergeCommit:
		return KindMerge
	case MergeSquash:
		return KindSquash
	case MergeRebase:
		return KindRebase
	}
	if e.in.Default.Ancestor[sha] {
		return KindExactSHA
	}
	return ""
}

// prLanding builds a provider landing from a merged PR.
func (e *evaluator) prLanding(p PullRequest, sha string, conf Confidence) Landing {
	l := Landing{
		Status:     StatusLanded,
		Kind:       e.kindForPR(p, sha),
		Confidence: conf,
		LandingSHA: p.MergeCommitSHA,
		PRID:       p.ID,
		PRNumber:   p.Number,
		Source:     SourceProvider,
	}
	if !p.MergedAt.IsZero() {
		l.LandedAt, l.LandedAtSource = p.MergedAt, LandedAtProvider
	}
	return l
}

// defaultLanding builds a local landing on a default-branch commit d.
func defaultLanding(kind LandingKind, conf Confidence, d DefaultCommit) Landing {
	l := Landing{Status: StatusLanded, Kind: kind, Confidence: conf, LandingSHA: d.SHA}
	if n, ok := PRNumberFromSubject(d.Subject); ok {
		l.PRNumber = n
	}
	if !d.CommittedAt.IsZero() {
		l.LandedAt, l.LandedAtSource = d.CommittedAt, LandedAtMergeCommit
	}
	return l
}

func ruleG1(_ *evaluator, c Commit) (outcome, bool) {
	return outcome{skip: true}, c.IsMerge || c.ForeignAuthor || !c.AIContributor
}

func ruleG2(_ *evaluator, c Commit) (outcome, bool) {
	return outcome{skip: true}, c.PatchFPState == "" || c.PatchFPState == FPPending
}

func ruleP1(e *evaluator, c Commit) (outcome, bool) {
	for _, p := range e.prBySHA[c.SHA] {
		if p.PR.State == PRMerged && e.baseOK(p.PR) {
			return outcome{landing: e.prLanding(p.PR, c.SHA, ConfExact)}, true
		}
	}
	return outcome{}, false
}

func ruleL1(e *evaluator, c Commit) (outcome, bool) {
	if !e.in.Default.Ancestor[c.SHA] {
		return outcome{}, false
	}
	l := Landing{Status: StatusLanded, Kind: KindExactSHA, Confidence: ConfExact, LandingSHA: c.SHA}
	if via, ok := e.in.Default.LandedVia[c.SHA]; ok {
		if n, ok := PRNumberFromSubject(via.Subject); ok {
			l.PRNumber = n
		}
		if !via.CommittedAt.IsZero() {
			l.LandedAt, l.LandedAtSource = via.CommittedAt, LandedAtMergeCommit
		}
	}
	return outcome{landing: l}, true
}

func ruleP2(e *evaluator, c Commit) (outcome, bool) {
	if !fpOK(c) {
		return outcome{}, false
	}
	for _, p := range e.prByFP[c.PatchFP] {
		if p.PR.State != PRMerged || !e.baseOK(p.PR) || listsSHA(p.Commits, c.SHA) {
			continue
		}
		l := e.prLanding(p.PR, c.SHA, ConfHigh)
		if l.Kind == "" {
			l.Kind = KindPatchID
		}
		return outcome{landing: l}, true
	}
	return outcome{}, false
}

func ruleL2(e *evaluator, c Commit) (outcome, bool) {
	if !fpOK(c) {
		return outcome{}, false
	}
	d, ok := e.defaultFP[c.PatchFP]
	if !ok || d.SHA == c.SHA {
		return outcome{}, false
	}
	return outcome{landing: defaultLanding(KindPatchID, ConfHigh, d)}, true
}

func ruleL3(e *evaluator, c Commit) (outcome, bool) {
	for _, t := range e.tipsBySHA[c.SHA] {
		if t.RangeFPState != FPOK || t.RangeFP == "" {
			continue
		}
		if d, ok := e.defaultFP[t.RangeFP]; ok {
			return outcome{landing: defaultLanding(KindSquash, ConfHigh, d)}, true
		}
	}
	return outcome{}, false
}

func ruleM1(e *evaluator, c Commit) (outcome, bool) {
	prev, ok := e.in.Previous[c.ID]
	if !ok || prev.Status != StatusLanded || prev.LandingSHA == "" || !e.in.Default.Known {
		return outcome{}, false
	}
	onDefault, checked := e.in.Default.Ancestor[prev.LandingSHA]
	if !checked || onDefault {
		return outcome{}, false
	}
	lost := prev
	lost.Status = StatusLandingLost
	lost.Source = e.in.Source
	return outcome{landing: lost}, true
}

func ruleM2(e *evaluator, c Commit) (outcome, bool) {
	prev, ok := e.in.Previous[c.ID]
	if !ok || prev.Status != StatusLanded || prev.RuleVersion != RuleVersion {
		return outcome{}, false
	}
	return outcome{landing: prev}, true
}

func ruleM3(e *evaluator, c Commit) (outcome, bool) {
	prev, ok := e.in.Previous[c.ID]
	if !ok || prev.Status != StatusLandingLost || prev.RuleVersion != RuleVersion {
		return outcome{}, false
	}
	return outcome{landing: prev}, true
}

func ruleP3(e *evaluator, c Commit) (outcome, bool) {
	open := func(p *PRWithCommits) bool { return p.PR.State == PROpen || p.PR.State == PRDraft }
	for _, p := range e.prBySHA[c.SHA] {
		if open(p) {
			return outcome{landing: Landing{Status: StatusInPR, Confidence: ConfExact, PRID: p.PR.ID, PRNumber: p.PR.Number, Source: SourceProvider}}, true
		}
	}
	if fpOK(c) {
		for _, p := range e.prByFP[c.PatchFP] {
			if open(p) {
				return outcome{landing: Landing{Status: StatusInPR, Confidence: ConfHigh, PRID: p.PR.ID, PRNumber: p.PR.Number, Source: SourceProvider}}, true
			}
		}
	}
	return outcome{}, false
}

func ruleP4(e *evaluator, c Commit) (outcome, bool) {
	if _, landsByL4 := e.matchL4(c); landsByL4 {
		return outcome{}, false
	}
	for _, p := range e.prBySHA[c.SHA] {
		if p.PR.State == PRClosedUnmerged {
			return outcome{landing: Landing{
				Status: StatusAbandoned, Confidence: ConfExact, AbandonReason: AbandonPRClosed,
				PRID: p.PR.ID, PRNumber: p.PR.Number, Source: SourceProvider,
			}}, true
		}
	}
	return outcome{}, false
}

func ruleL4(e *evaluator, c Commit) (outcome, bool) {
	d, ok := e.matchL4(c)
	if !ok {
		return outcome{}, false
	}
	return outcome{landing: defaultLanding(KindSquashFiles, ConfMedium, d)}, true
}

// matchL4 finds a default-branch commit, committed after ours, whose subject
// names a PR and whose file set equals the file set of a branch range that
// contains our sha: the squash of that branch, with the patch changed while
// merging (a conflict fixed), so L3's fingerprint did not match.
func (e *evaluator) matchL4(c Commit) (DefaultCommit, bool) {
	for _, t := range e.tipsBySHA[c.SHA] {
		if len(t.Files) == 0 {
			continue
		}
		for _, d := range e.in.Default.Commits {
			if len(d.Files) == 0 || d.CommittedAt.Before(c.CommittedAt) {
				continue
			}
			if _, named := PRNumberFromSubject(d.Subject); !named {
				continue
			}
			if sameSet(t.Files, d.Files) {
				return d, true
			}
		}
	}
	return DefaultCommit{}, false
}

func ruleL6(e *evaluator, c Commit) (outcome, bool) {
	if !e.in.RemoteReachable[c.SHA] {
		return outcome{}, false
	}
	return outcome{landing: Landing{Status: StatusPushed, Confidence: ConfExact}}, true
}

func ruleL7(e *evaluator, c Commit) (outcome, bool) {
	if c.Reachable || e.in.Now.Sub(c.CommittedAt) < e.abandonSpan {
		return outcome{}, false
	}
	return outcome{landing: Landing{Status: StatusAbandoned, Confidence: ConfMedium, AbandonReason: AbandonDropped}}, true
}

func ruleL8(e *evaluator, c Commit) (outcome, bool) {
	if e.in.Now.Sub(c.CommittedAt) < e.abandonSpan {
		return outcome{landing: Landing{Status: StatusInFlight}}, true
	}
	return outcome{landing: Landing{Status: StatusLocalOnly}}, true
}

// listsSHA reports whether a PR commit list contains sha.
func listsSHA(list []PRCommit, sha string) bool {
	for _, pc := range list {
		if pc.SHA == sha {
			return true
		}
	}
	return false
}

// sameSet reports whether two path lists hold the same distinct paths.
func sameSet(a, b []string) bool {
	as := map[string]bool{}
	for _, p := range a {
		as[p] = true
	}
	bs := map[string]bool{}
	for _, p := range b {
		bs[p] = true
	}
	if len(as) != len(bs) {
		return false
	}
	for p := range as {
		if !bs[p] {
			return false
		}
	}
	return true
}
