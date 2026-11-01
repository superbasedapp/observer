//go:build !sbo_omit_security

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_fixobs.go is the security.code loop of lane SEC-G5 (security
// pillar plan sections 5.7 and 5.11 (a)), started by one line in
// security_module.go:
//
//   - inferences: each new agent edit's old and new text (the stored,
//     scrubbed tool input) runs through secdiffobs.ObserveWith with the
//     regressions S-762 to S-766 on and, when the session's prompt before
//     the edit is stored, scope drift S-770; the prompt is read here and
//     never kept. Every hit is a low-confidence, flag-only finding labelled
//     an inference.
//   - fix observations: a finding a rescan already moved to not_reproduced
//     moves to fixed_verified only on recorded evidence
//     (secdiffobs.DecideFix: an observed test-class command after the
//     session's last edit of the file whose success the host reported, no
//     test file edited), never after a close by a run with another rule
//     pack version (store.SecClosedPackChanged).
//   - unverified_fix: a commit whose stored (scrubbed) subject claims a
//     security fix (secdiffobs.ClaimsFix) for a file holding an open or
//     not_reproduced finding raises one flag-only finding per commit and
//     file. It closes as not reproduced once the file holds no such
//     finding any more (settleFixClaims: the questioned finding gained its
//     fix evidence or was dismissed) and its commit no longer holds it.
//   - an inference closes when its file is deleted, or when the file's
//     committed change since the edit (the diff from before the first
//     later commit of the file to its newest one) no longer raises the
//     same rule at the same file AND the working tree no longer holds it
//     (the same diff to the working tree; settleInferences, lane SEC-P4
//     decision 13, lane LEFT-SEC); otherwise only triage (the manual
//     dismiss) closes it; SECP-27.
//   - inferences and unverified_fix are flag-only, non-secret findings: the
//     commit hold never keeps them open and they never get the secrets
//     note (store.secCommitHoldRows).
//
// It runs only when a [components] block selects security.code
// (fixObsSelected): an install with no block gains nothing.

const (
	fixObsFirst = 30 * time.Second
	fixObsTick  = 60 * time.Second
	// fixObsEditBatch caps the agent edits one pass reads.
	fixObsEditBatch = 256
	// fixObsWindow is how long after its close a not_reproduced finding is
	// re-checked for evidence (a test may run after the close).
	fixObsWindow = 24 * time.Hour
	// fixObsCommitLookback is how far before the loop's start commits are
	// read on the first pass.
	fixObsCommitLookback = time.Hour
)

// fixObsSelected: security.code is selected by a [components] block. The
// legacy snapshot (no block) resolves it active, so this asks for the block
// too: the inferences and fix observations are new behaviour no existing
// install chose.
func fixObsSelected(snap componentstate.Snapshot) bool {
	return snap.BlockSelects("security.code") && securitySelected(snap, "security.code")
}

// startSecurityFixObs starts the loop when fixObsSelected.
func startSecurityFixObs(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	if !fixObsSelected(snap) {
		return
	}
	ng.Go("security.code.fixobs", func() error {
		_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
		if err != nil {
			slog.Default().Warn("security: fix observations not started", "err", err)
			return nil
		}
		defer cleanup()
		l := &fixObsLoop{st: store.New(database), logger: slog.Default(), started: time.Now()}
		wait := fixObsFirst
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
			l.pass(ctx, time.Now())
			wait = fixObsTick
		}
	})
}

// fixObsLoop owns the loop's watermarks.
type fixObsLoop struct {
	st      *store.Store
	logger  *slog.Logger
	started time.Time
	// afterID is the agent-edit watermark; 0 until the first pass sets it
	// to the newest action (a start never re-reads history).
	afterID    int64
	primed     bool
	commitSeen map[string]time.Time
	// inferChecked remembers, per inference finding, the newest commit of
	// its file the last check read, so a check runs again only when a new
	// commit touches the file.
	inferChecked map[string]string
	// gitDiff reads a diff (gitview.RunReadOnly; a test stands in).
	gitDiff func(ctx context.Context, root string, maxBytes int, args ...string) ([]byte, bool, error)
}

// pass runs the four steps once.
func (l *fixObsLoop) pass(ctx context.Context, now time.Time) {
	l.inferNewEdits(ctx)
	l.verifyFixes(ctx, now)
	l.flagFixClaims(ctx, now)
	l.settleFixClaims(ctx, now)
	l.settleInferences(ctx, now)
}

// inferNewEdits runs the inferences over the agent edits stored since the
// last pass.
func (l *fixObsLoop) inferNewEdits(ctx context.Context) {
	if !l.primed {
		id, err := l.st.MaxActionID(ctx)
		if err != nil {
			return
		}
		l.afterID, l.primed = id, true
		return
	}
	edits, last, err := l.st.AgentEditsAfter(ctx, l.afterID, fixObsEditBatch)
	if err != nil {
		l.logger.Warn("security: inferences: edits not read", "err", err)
		return
	}
	l.afterID = last
	for _, e := range edits {
		fs := inferEdit(ctx, l.st, e)
		if len(fs) > 0 {
			recordSecurityFindings(ctx, l.st, e.ProjectRoot, policy.FindingScopePostWrite, fs, secscan.Coverage{Outcome: secscan.OutcomeFindings}, secsvc.Gone{}, l.logger)
		}
	}
}

// inferEdit is the inference findings of one agent edit.
func inferEdit(ctx context.Context, st *store.Store, e store.AgentEdit) []secfinding.Finding {
	rel, ok := fixObsRelative(e.ProjectRoot, e.Target)
	if !ok {
		return nil
	}
	pairs := editPairs(e.RawInput)
	if len(pairs) == 0 {
		return nil
	}
	var diffs []secdiffobs.FileDiff
	for _, p := range pairs {
		diffs = append(diffs, secdiffobs.FromEdit(rel, p[0], p[1]))
	}
	o := secdiffobs.Options{Inferences: true}
	if text, ok, err := st.SessionPromptBefore(ctx, e.SessionID, e.At); err == nil && ok {
		o.Prompt = &secdiffobs.Prompt{Text: text}
	}
	hash := secposture.ProjectRootHash(e.ProjectRoot)
	var out []secfinding.Finding
	seen := map[string]bool{}
	for _, ob := range secdiffobs.ObserveWith(diffs, o) {
		if !ob.Inference || seen[ob.RuleID] {
			continue
		}
		seen[ob.RuleID] = true
		out = append(out, inferenceFinding(hash, e, ob))
	}
	return out
}

// inferenceFinding is one inference as a finding: low severity, low
// confidence (never blocking), labelled an inference, with the edit's
// session and action as lineage.
func inferenceFinding(rootHash string, e store.AgentEdit, o secdiffobs.Observation) secfinding.Finding {
	rule := "code." + strings.ToLower(o.RuleID)
	cat := policy.FindingSecurityRegression
	if o.RuleID == "S-770" {
		cat = policy.FindingScopeDrift
	}
	return secfinding.Normalize(secfinding.Finding{
		LocalKey:    secfinding.LocalKey(rootHash, rule, secfinding.TextIdentity(o.Path)),
		Location:    secfinding.Location{RelPath: o.Path, StartLine: o.Line, EndLine: o.Line},
		Rule:        secfinding.Rule{ID: rule, Pack: securityCodePack, PackVersion: secrules.PackVersion},
		Engine:      secfinding.Engine{Driver: "native"},
		Category:    cat,
		Severity:    policy.FindingSeverityLow,
		Confidence:  policy.FindingConfidenceLow,
		Scope:       policy.FindingScopePostWrite,
		Project:     secfinding.Project{RootHash: rootHash},
		Message:     o.RuleID + ": " + o.Message,
		Baseline:    policy.FindingBaselineNew,
		Attribution: secfinding.InferredAttribution{Class: policy.FindingAttributionAI, Method: "secdiffobs.inference.v1", Confidence: policy.FindingConfidenceLow},
		Lineage:     secfinding.Lineage{SessionID: e.SessionID, ActionID: itoa64(e.ID)},
		Status:      policy.FindingStatusOpen,
		// The edit's own time: the closure reads only commits after it.
		FirstSeen: e.At,
	})
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// editPairs reads the old and new text of a stored tool input: an edit's
// old_string/new_string (or old_str/new_str), each entry of an edits list,
// or a write's content (old text empty). Anything else yields nothing.
func editPairs(raw string) [][2]string {
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil
	}
	pair := func(v map[string]any) ([2]string, bool) {
		for _, k := range [][2]string{{"old_string", "new_string"}, {"old_str", "new_str"}, {"oldText", "newText"}} {
			o, ok1 := v[k[0]].(string)
			n, ok2 := v[k[1]].(string)
			if ok1 && ok2 {
				return [2]string{o, n}, true
			}
		}
		if c, ok := v["content"].(string); ok {
			return [2]string{"", c}, true
		}
		return [2]string{}, false
	}
	var out [][2]string
	if p, ok := pair(m); ok {
		out = append(out, p)
	}
	if list, ok := m["edits"].([]any); ok {
		for _, x := range list {
			if v, ok := x.(map[string]any); ok {
				if p, ok := pair(v); ok {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// fixObsRelative turns a stored target into a slash path under root.
func fixObsRelative(root, target string) (string, bool) {
	if root == "" || strings.TrimSpace(target) == "" {
		return "", false
	}
	p := target
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// fixObsRoots maps project root hashes to roots.
func fixObsRoots(ctx context.Context, st *store.Store) map[string]string {
	roots, err := st.ProjectRoots(ctx)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(roots))
	for _, r := range roots {
		out[secposture.ProjectRootHash(r)] = r
	}
	return out
}

// verifyFixes moves recently closed not_reproduced findings to
// fixed_verified where the evidence holds.
func (l *fixObsLoop) verifyFixes(ctx context.Context, now time.Time) {
	got, err := l.st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusNotReproduced, Limit: 1000})
	if err != nil || len(got) == 0 {
		return
	}
	roots := fixObsRoots(ctx, l.st)
	for _, f := range got {
		if f.ClosedAt.IsZero() || now.Sub(f.ClosedAt) > fixObsWindow || f.Location.RelPath == "" || fixObsFlagRule(f.Rule.ID) {
			continue
		}
		root := roots[f.Project.RootHash]
		if root == "" {
			continue
		}
		v, err := fixVerdict(ctx, l.st, root, f)
		if err != nil || !v.Verified {
			continue
		}
		if _, err := l.st.MarkSecFindingFixedVerified(ctx, f.ID, v.Detail(), fixObservations(v), now); err != nil {
			l.logger.Warn("security: fix observation not recorded", "err", err)
		}
	}
}

// fixObsFlagRule reports a rule of this loop's own flags (an inference or
// unverified_fix): a flag is never a fix to verify.
func fixObsFlagRule(rule string) bool {
	return rule == unverifiedFixRule || fixObsInferenceRules[rule]
}

// fixObsInferenceRules are the inference rule ids inferenceFinding records
// (S-762 to S-766 and S-770, lowercased under code.).
var fixObsInferenceRules = map[string]bool{
	"code.s-762": true, "code.s-763": true, "code.s-764": true, "code.s-765": true, "code.s-766": true, "code.s-770": true,
}

// fixObservations are the facts the fixed_verified move records in
// fix_json, which the org row's fix fields read (audit finding 4): the rule
// no longer reports the finding (it is not_reproduced), a test-class
// command was observed after the edit with the success the host reported
// (exit code 0), and no test file was edited. NoNewFindingInRegion stays
// false: nothing here checks the changed region.
func fixObservations(v secdiffobs.FixVerdict) secfinding.FixObservations {
	return secfinding.FixObservations{RuleNoLongerFires: true, TestCommandObserved: true, TestExitCode: v.ExitCode}
}

// fixVerdict loads the evidence for one finding and decides.
func fixVerdict(ctx context.Context, st *store.Store, root string, f secfinding.Finding) (secdiffobs.FixVerdict, error) {
	rows, err := st.LoadFixEvidence(ctx, root, f.Location.RelPath, f.ClosedAt)
	if err != nil {
		return secdiffobs.FixVerdict{}, err
	}
	ev := secdiffobs.FixEvidence{LastEditAt: rows.LastEditAt}
	for _, c := range rows.Commands {
		ev.Commands = append(ev.Commands, secdiffobs.SessionCommand{At: c.At, Command: c.Command, ExitKnown: c.ExitKnown, ExitCode: c.ExitCode, HostReportedSuccess: c.HostReportedSuccess})
	}
	for _, t := range rows.EditedTargets {
		if rel, ok := fixObsRelative(root, t); ok {
			ev.EditedPaths = append(ev.EditedPaths, rel)
		} else {
			ev.EditedPaths = append(ev.EditedPaths, filepath.ToSlash(t))
		}
	}
	return secdiffobs.DecideFix(ev), nil
}

// flagFixClaims raises unverified_fix for new commits whose subject claims
// a security fix for a file holding an open or not_reproduced finding.
func (l *fixObsLoop) flagFixClaims(ctx context.Context, now time.Time) {
	if l.commitSeen == nil {
		l.commitSeen = map[string]time.Time{}
	}
	for k, at := range l.commitSeen {
		if now.Sub(at) > 7*24*time.Hour {
			delete(l.commitSeen, k)
		}
	}
	since := l.started.Add(-fixObsCommitLookback)
	projects, err := l.st.ActiveProjectRoots(ctx, 30)
	if err != nil {
		return
	}
	for _, p := range projects {
		commits, err := l.st.LoadProjectCommits(ctx, p.ID, since, now.Add(time.Minute), 200)
		if err != nil {
			continue
		}
		var claimed []store.ProjectCommitRow
		for _, c := range commits {
			key := itoa64(p.ID) + ":" + c.SHA
			if _, done := l.commitSeen[key]; done || c.IsMerge {
				continue
			}
			l.commitSeen[key] = now
			if secdiffobs.ClaimsFix(c.Subject) {
				claimed = append(claimed, c)
			}
		}
		if len(claimed) == 0 {
			continue
		}
		if fs := unverifiedFixFindings(ctx, l.st, p.RootPath, claimed, since, now); len(fs) > 0 {
			recordSecurityFindings(ctx, l.st, p.RootPath, policy.FindingScopeCommit, fs, secscan.Coverage{Outcome: secscan.OutcomeFindings}, secsvc.Gone{}, l.logger)
		}
	}
}

// fixObsHeldFiles maps the files holding an open or not_reproduced finding
// of another rule than unverified_fix (a fixed_verified one has its
// evidence) to true. complete is false when the list hit its limit, so a
// missing file proves nothing.
func fixObsHeldFiles(ctx context.Context, st *store.Store, rootHash string) (held map[string]bool, complete bool) {
	const limit = 1000
	got, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: rootHash, Limit: limit})
	if err != nil {
		return nil, false
	}
	held = map[string]bool{}
	for _, f := range got {
		if f.Status == policy.FindingStatusOpen || f.Status == policy.FindingStatusNotReproduced {
			if !strings.HasPrefix(f.Rule.ID, unverifiedFixRule) {
				held[f.Location.RelPath] = true
			}
		}
	}
	return held, len(got) < limit
}

// settleFixClaims is the closure path of unverified_fix (audit finding 6):
// an open unverified_fix finding whose file no longer holds an open or
// not_reproduced finding (the questioned finding moved to fixed_verified or
// was dismissed) closes as not reproduced through the hold-aware close, so
// its own commit still holds it while unpushed, and once pushed it stays
// open until triage (SECP-27). A project whose finding list hit its limit
// is skipped: a missing file there proves nothing.
func (l *fixObsLoop) settleFixClaims(ctx context.Context, now time.Time) {
	got, err := l.st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen, Limit: 1000})
	if err != nil {
		return
	}
	type heldSet struct {
		files    map[string]bool
		complete bool
	}
	byProject := map[string]heldSet{}
	for _, f := range got {
		if f.Rule.ID != unverifiedFixRule {
			continue
		}
		h, ok := byProject[f.Project.RootHash]
		if !ok {
			h.files, h.complete = fixObsHeldFiles(ctx, l.st, f.Project.RootHash)
			byProject[f.Project.RootHash] = h
		}
		if !h.complete || h.files[f.Location.RelPath] {
			continue
		}
		if _, err := l.st.CloseSecFindingNotReproduced(ctx, f.ID, now); err != nil {
			l.logger.Warn("security: unverified_fix not closed", "err", err)
		}
	}
}

// unverifiedFixFindings is one finding per claimed commit and file that
// holds an open or not_reproduced finding (a fixed_verified one has its
// evidence).
func unverifiedFixFindings(ctx context.Context, st *store.Store, root string, claimed []store.ProjectCommitRow, since, now time.Time) []secfinding.Finding {
	pid, err := st.ProjectIDForRoot(ctx, root)
	if err != nil || pid == 0 {
		return nil
	}
	files, err := st.LoadCommitFiles(ctx, pid, since, now.Add(time.Minute), 2000)
	if err != nil {
		return nil
	}
	hash := secposture.ProjectRootHash(root)
	held, _ := fixObsHeldFiles(ctx, st, hash)
	if held == nil {
		return nil
	}
	bySHA := map[string]bool{}
	for _, c := range claimed {
		bySHA[c.SHA] = true
	}
	var out []secfinding.Finding
	for _, cf := range files {
		if !bySHA[cf.SHA] || !held[cf.RelPath] {
			continue
		}
		out = append(out, secfinding.Normalize(secfinding.Finding{
			LocalKey:   secfinding.LocalKey(hash, unverifiedFixRule, secfinding.TextIdentity(cf.SHA+":"+cf.RelPath)),
			Location:   secfinding.Location{RelPath: cf.RelPath},
			Rule:       secfinding.Rule{ID: unverifiedFixRule, Pack: securityCodePack, PackVersion: secrules.PackVersion},
			Engine:     secfinding.Engine{Driver: "native"},
			Category:   policy.FindingSecurityRegression,
			Severity:   policy.FindingSeverityInfo,
			Confidence: policy.FindingConfidenceLow,
			Scope:      policy.FindingScopeCommit,
			Project:    secfinding.Project{RootHash: hash},
			Message:    "unverified_fix: a commit message claims a security fix for this file, and the file still holds a finding that is open or closed without fix evidence",
			Baseline:   policy.FindingBaselineNew,
			Commit:     secfinding.Commit{SHA: cf.SHA},
			Status:     policy.FindingStatusOpen,
		}))
	}
	return out
}

// unverifiedFixRule is the rule id of an unverified_fix finding.
const unverifiedFixRule = "code.unverified_fix"

const (
	// inferCheckBudget caps the git reads one pass makes for the
	// inference closure.
	inferCheckBudget = 16
	// inferDiffCap caps one closure diff; a longer one proves nothing.
	inferDiffCap = 4 << 20
	// inferCommitRows caps the commit file rows one check reads.
	inferCommitRows = 2000
)

// inferClosure is what the closure decided for one inference.
type inferClosure int

const (
	inferKeep inferClosure = iota
	inferCloseDeleted
	inferCloseNotRaised
)

// settleInferences is the closure path of an inference (lane SEC-P4
// decision 13): an open inference closes as not reproduced (the hold-aware
// close) when its file is gone from the project, or when the file's
// committed change since the edit no longer raises the same rule at the
// same file; anything else (no later commit, a diff that cannot be read
// whole, S-770 with no stored prompt) keeps it open for triage.
func (l *fixObsLoop) settleInferences(ctx context.Context, now time.Time) {
	got, err := l.st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen, Limit: 1000})
	if err != nil || len(got) == 0 {
		return
	}
	if l.inferChecked == nil {
		l.inferChecked = map[string]string{}
	}
	roots := fixObsRoots(ctx, l.st)
	budget := inferCheckBudget
	for _, f := range got {
		if !fixObsInferenceRules[f.Rule.ID] || f.Location.RelPath == "" {
			continue
		}
		root := roots[f.Project.RootHash]
		if root == "" {
			continue
		}
		if l.inferenceClosure(ctx, root, f, now, &budget) == inferKeep {
			continue
		}
		delete(l.inferChecked, f.ID)
		if _, err := l.st.CloseSecFindingNotReproduced(ctx, f.ID, now); err != nil {
			l.logger.Warn("security: inference not closed", "err", err)
		}
	}
}

// inferenceClosure decides one inference.
func (l *fixObsLoop) inferenceClosure(ctx context.Context, root string, f secfinding.Finding, now time.Time, budget *int) inferClosure {
	rel := f.Location.RelPath
	if securityFileDeleted(root, rel) {
		return inferCloseDeleted
	}
	if *budget <= 0 || f.FirstSeen.IsZero() {
		return inferKeep
	}
	pid, err := l.st.ProjectIDForRoot(ctx, root)
	if err != nil || pid == 0 {
		return inferKeep
	}
	rows, err := l.st.LoadCommitFiles(ctx, pid, f.FirstSeen, now.Add(time.Minute), inferCommitRows)
	if err != nil || len(rows) >= inferCommitRows {
		return inferKeep // a cut list may hide the first commit
	}
	var newest, oldest string
	for _, r := range rows { // newest commit first
		if r.RelPath != rel || !store.IsCommitSHA(r.SHA) {
			continue
		}
		if newest == "" {
			newest = r.SHA
		}
		oldest = r.SHA
	}
	if newest == "" || l.inferChecked[f.ID] == newest {
		return inferKeep
	}
	var prompt *secdiffobs.Prompt
	if f.Rule.ID == "code.s-770" {
		text, ok, err := l.st.SessionPromptBefore(ctx, f.Lineage.SessionID, f.FirstSeen)
		if err != nil || !ok {
			return inferKeep // scope drift needs the prompt to be judged
		}
		prompt = &secdiffobs.Prompt{Text: text}
	}
	*budget--
	diff := l.gitDiff
	if diff == nil {
		diff = gitview.RunReadOnly
	}
	out, truncated, err := diff(ctx, root, inferDiffCap, "diff", "--no-color", "--no-ext-diff", "--no-textconv",
		"--no-renames", "-U3", oldest+"^", newest, "--", rel)
	if err != nil || truncated {
		return inferKeep
	}
	if inferenceRaised(f.Rule.ID, rel, out, prompt) {
		l.inferChecked[f.ID] = newest
		return inferKeep
	}
	// SECP-27 (lane LEFT-SEC): the commits lack it, but the working tree
	// may still hold the edit (a commit of another hunk, an edit never
	// committed). The same diff, from the same base to the working tree,
	// must lack it too; a tree diff not read whole keeps it.
	wt, truncated, err := diff(ctx, root, inferDiffCap, "diff", "--no-color", "--no-ext-diff", "--no-textconv",
		"--no-renames", "-U3", oldest+"^", "--", rel)
	if err != nil || truncated || inferenceRaised(f.Rule.ID, rel, wt, prompt) {
		// Not remembered as checked: the tree can drop it without a new
		// commit, so the next pass looks again (within the pass budget).
		return inferKeep
	}
	l.inferChecked[f.ID] = newest
	return inferCloseNotRaised
}

// inferenceRaised reports whether diff still raises the inference rule
// (code.<id>) at rel. The anchor is the rule and the file, the finding's
// own identity: an edit's line numbers are relative to the edit, so they
// cannot be matched against a commit's.
func inferenceRaised(rule, rel string, diff []byte, prompt *secdiffobs.Prompt) bool {
	for _, ob := range secdiffobs.ObserveWith(secdiffobs.ParseUnifiedDiff(diff), secdiffobs.Options{Inferences: true, Prompt: prompt}) {
		if ob.Inference && ob.Path == rel && "code."+strings.ToLower(ob.RuleID) == rule {
			return true
		}
	}
	return false
}
