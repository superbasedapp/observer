//go:build !sbo_omit_security

package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_box.go is the security module's half of copy-workspace coverage
// (security pillar plan 4.8 "Copy workspaces", 5.3, M7; lane sec-box):
// recording a walk over box work (a commit the sandbox return step brings
// back, or a box ref the commit scan walks) with the sandbox run in each
// finding's lineage. Built with the security module alone; what binds it
// to the sandbox module lives in security_box_wire.go, so a build without
// either leaves every hook of this lane nil and today's paths unchanged.

// recordBox stores one box range's walk: a run per commit (through the
// same recordCommit as the HEAD walk, under a box context, so each finding
// carries the run and the run row names the commit; secsvc.WithBoxCommit),
// and an unknown run for what the walk skipped or could not list, never
// silent.
func (step *securityCommitStep) recordBox(ctx context.Context, root, runID, ref string, r secquickscan.BoxRangeResult) {
	if step == nil || step.st == nil {
		return
	}
	step.recordBoxCommits(ctx, root, runID, ref, r)
	if r.Skipped > 0 || r.RangeUnread {
		reason := string(r.SkipReason)
		if reason == "" {
			reason = "range_unread"
		}
		step.recordBoxUnknown(ctx, root, secsvc.BoxCommit{RunID: runID, Ref: ref}, reason)
	}
}

// recordBoxCommits stores a box range's scanned commits, one run each,
// with the run in each finding's lineage.
func (step *securityCommitStep) recordBoxCommits(ctx context.Context, root, runID, ref string, r secquickscan.BoxRangeResult) {
	hash := secposture.ProjectRootHash(root)
	for _, c := range r.Commits {
		step.recordCommit(secsvc.WithBoxCommit(ctx, secsvc.BoxCommit{RunID: runID, Ref: ref, Commit: c.SHA}), root, hash, c)
	}
}

// recordBoxUnknown stores one unknown commit-scope run for box work the
// walk did not scan, with b on its target.
func (step *securityCommitStep) recordBoxUnknown(ctx context.Context, root string, b secsvc.BoxCommit, reason string) {
	recordSecurityFindings(secsvc.WithBoxCommit(ctx, b), step.st, root, policy.FindingScopeCommit, nil,
		secscan.Coverage{Outcome: secscan.OutcomeUnknown, Reason: reason}, secsvc.Gone{}, step.logger)
}

// The reasons of a tick's aggregate unknown runs (lane sec-box audit
// findings 2 and 3).
const (
	// boxRefsOverCap: the box ref listing went past its cap; the first
	// refs were walked and the rest were not seen.
	boxRefsOverCap = "box_refs_over_cap"
	// boxRefsLeft: refs this tick did not finish (past the per-tick walk
	// cap, or cut short by the tick's budget or commit cap); they are
	// walked again next tick.
	boxRefsLeft = "box_refs_left"
)

// securityHostedReturnsTick scans the hosted runs' saved staged diffs and
// kept diff errors once each (security_box_wire.go, lane LEFT-SEC), on the
// post-write loop's minute tick; securityDir is the posture's directory,
// where its markers live. nil in a build without the sandbox module.
var securityHostedReturnsTick func(ctx context.Context, step *securityCommitStep, securityDir string)

// securityBoxRunOwns reports whether the host's relay run records hold run
// runID and that run is root's (security_box_wire.go): the check a run id
// read from a ref name the box can write must pass before a finding
// carries it (lane sec-box audit finding 5). nil in a build without the
// sandbox module, where no run id the box claims is confirmed.
var securityBoxRunOwns func(ctx context.Context, root, runID string) bool

// securityScanReturn is the return step's scan (sandbox plan section 6,
// revision 5 M7): the commits the box brought, the returned commit's new
// range in the SOURCE repository (what no existing ref reaches; the
// objects are already fetched and checked, and the ref is not written
// yet), each scanned with the commit scan's own scan and recorded with the
// run in its findings' lineage, before the caller writes the ref. A
// finding never refuses the return (the work stays the developer's, the
// ref is local and namespaced, and the commit gate still holds a secret at
// push); a scan that cannot run records an unknown run and the return
// proceeds.
func securityScanReturn(ctx context.Context, step *securityCommitStep, repo, commit, ref, runID string) {
	res := step.scan.WalkBox(ctx, repo, []secquickscan.BoxRange{{Key: ref, Tip: commit, Exclude: secquickscan.ExcludeAllRefs}}, nil)
	if len(res) == 0 {
		// No engine: nothing could run.
		res = []secquickscan.BoxRangeResult{{Key: ref, CommitScanResult: secquickscan.CommitScanResult{RangeUnread: true}}}
	}
	for _, r := range res {
		step.recordBox(ctx, repo, runID, ref, r)
	}
}

// securityCopyWorkspace is the ONE injected lookup over the sandbox
// module's run records (security_box_wire.go): for a tree (a project root
// as the store records it, or the tree a commit runs in) it answers
// live, a copy the host can see and where, or a copy only inside a box.
// st, when set, resolves a run's backend; nil reads only the records. It
// is nil in a build without the sandbox module, where every tree is live.
var securityCopyWorkspace func(ctx context.Context, st *store.Store, tree string) secsvc.CopyResolution

// securityPostWriteFor is the post-write feed's Write for one stored
// write (the security plan 4.8 table, post-write column). A tree no copy
// run works on, or a host-visible copy whose tree is the recorded root
// itself (today's clone-local runs, whose sessions are recorded under the
// clone), gives exactly today's Write. A host-visible copy elsewhere is
// read under that copy (secpostwrite's no-follow reader refuses a symlink
// or a path outside it); a copy only inside a box is marked so, and the
// queue reports it not_scanned: copy_workspace, never clean.
func securityPostWriteFor(ctx context.Context, st *store.Store, w store.PostWrite) secpostwrite.Write {
	out := secpostwrite.Write{
		SessionID: w.SessionID, ActionID: w.ActionID, ProjectRoot: w.ProjectRoot, Path: w.Path,
		Checkout: w.Checkout, CheckoutPath: w.CheckoutPath,
	}
	if securityCopyWorkspace == nil {
		return out
	}
	r := securityCopyWorkspace(ctx, st, w.ProjectRoot)
	switch r.Kind {
	case secsvc.CopyInBox:
		out.CopyWorkspace = true
	case secsvc.CopyVisible:
		if filepath.Clean(r.Root) != filepath.Clean(w.ProjectRoot) {
			out.CopyWorkspace, out.WorkspaceRoot = true, r.Root
		}
	}
	return out
}

// recordPostWriteNotScanned records a write the post-write scan could not
// read because its tree is only inside a box: a not_scanned run with
// reason copy_workspace, no finding and no close (never clean). The return
// step's scan and the box-ref walk are the fallback.
func recordPostWriteNotScanned(ctx context.Context, st *store.Store, r secpostwrite.Result, logger *slog.Logger) {
	recordSecurityFindings(ctx, st, r.Write.ProjectRoot, policy.FindingScopePostWrite, nil,
		secscan.Coverage{Outcome: secscan.OutcomeNotScanned, Reason: string(secpostwrite.NotScannedCopyWorkspace)}, secsvc.Gone{}, logger)
}

// securityQuickScanRoot is the tree a commit's quick scan reads (the
// security plan 4.8 table, quick-scan column): root itself on the host path
// and for a live run (today's request, unchanged); for a relayed event of a
// copy run, the copy's tree on the host when the run records one the host
// can see, and no tree at all (ok false: the plan is opaque, so the answer
// is unknown, never clean) when the copy lives only inside a box (a remote
// box, a disk image) or cannot be placed. The facts are the host's launch
// record and the run's recorded backend, never a path the box reported.
func securityQuickScanRoot(root string) (string, bool) {
	delivery, copyHostPath := hookctx.Process().WorkspaceDelivery()
	if delivery != hookctx.DeliveryCopy {
		return root, true
	}
	if securityCopyWorkspace == nil {
		// No run-record lookup in this build: the record's host path is
		// all there is (the relay path as before lane sec-box).
		return root, copyHostPath != ""
	}
	r := securityCopyWorkspace(context.Background(), securityHookStore(), root)
	if r.Kind != secsvc.CopyVisible {
		// In a box, or a run the records do not place: unknown.
		return "", false
	}
	return r.Root, true
}

// securityHookStore opens the node's database once per hook process for
// the copy-run lookup (the backend of a relayed copy run), only when a
// relayed commit in a copy run asks for it; nil when it cannot be opened
// (the run then reads as inside its box: unknown, never clean).
var securityHookStore = sync.OnceValue(func() *store.Store {
	_, database, _, err := loadConfigAndDB(context.Background(), securityHookConfig())
	if err != nil {
		return nil
	}
	// The handle lives as long as the hook process.
	return store.New(database)
})

// securityHookConfig is the config path the hook invocation's security
// state was read for (currentHookSecurity), "" when none was read yet.
func securityHookConfig() string {
	hookSecMu.Lock()
	defer hookSecMu.Unlock()
	if hookSecCur == nil {
		return ""
	}
	return hookSecCur.config
}

// boxRefTips is the commit scan's memory of the box refs it walked, per
// repository root: one owner, the commit scan's after-scan step. A daemon
// start begins empty, so every box ref is seen once more; the commits the
// store already holds a box run for are skipped (store.SecBoxCommitsScanned).
type boxRefTips struct {
	mu    sync.Mutex
	roots map[string]map[string]string
	// cursor is, per root, the last ref a tick cut short by the walk cap
	// walked (lane LEFT-SEC): the next tick resumes after it, round robin
	// (secsvc.RotateBoxWalks). Absent when the last tick walked every ref.
	cursor map[string]string
}

func (b *boxRefTips) after(root string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cursor[root]
}

func (b *boxRefTips) setAfter(root, ref string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cursor == nil {
		b.cursor = map[string]string{}
	}
	if ref == "" {
		delete(b.cursor, root)
		return
	}
	b.cursor[root] = ref
}

// securityBoxRefs is the daemon's one boxRefTips.
var securityBoxRefs = &boxRefTips{}

func (b *boxRefTips) get(root string) map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.roots[root]
}

func (b *boxRefTips) set(root string, tips map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.roots == nil {
		b.roots = map[string]map[string]string{}
	}
	if len(tips) == 0 {
		delete(b.roots, root)
		return
	}
	b.roots[root] = tips
}

// walkBoxRefs is the commit scan's box-ref walk for one repository (the
// security plan 4.8 and 5.3 (d), M7): one ref listing a tick (all a
// repository with no box ref costs), then each new or moved box ref's new
// commits under the commit scan's own cap and budget, recorded with the
// ref's run in their lineage. Never silent and bounded per tick (lane
// sec-box audit findings 2 and 3): a listing past its cap records one
// unknown run naming the cap and walks the first refs; at most
// BoxWalksPerTick refs are walked a tick; the refs the tick did not finish
// (past that cap, or cut short by the budget or the commit cap) are ONE
// aggregate unknown run with their count, and are not remembered as
// walked, so the next tick walks them again (the commits already recorded
// are skipped then); a range that could not be listed is an unknown run of
// its own. A listing that fails changes nothing (the next tick lists
// again). The walk never writes a ref and never edits the commit scanner's
// own state.
func (step *securityCommitStep) walkBoxRefs(ctx context.Context, root string, tips *boxRefTips) {
	if step == nil || step.scan == nil || step.st == nil || root == "" {
		return
	}
	listed, ok := step.scan.ListBoxRefs(ctx, root)
	if !ok {
		return
	}
	if listed.OverCap {
		step.recordBoxUnknown(ctx, root, secsvc.BoxCommit{ListCap: listed.Cap}, boxRefsOverCap)
	}
	refs := make([]secsvc.BoxRef, 0, len(listed.Refs))
	for _, r := range listed.Refs {
		refs = append(refs, secsvc.BoxRef{Ref: r.Ref, Tip: r.Tip})
	}
	prev := tips.get(root)
	walks, next := secsvc.PlanBoxRefs(prev, refs)
	// Round robin past the per-tick cap (lane LEFT-SEC): resume after the
	// last ref a cut-short tick walked.
	walks = secsvc.RotateBoxWalks(walks, tips.after(root))
	walks, deferred := secsvc.CapBoxWalks(walks, step.scan.BoxWalksPerTick())
	tips.setAfter(root, secsvc.NextBoxCursor(walks, deferred))
	left := make([]string, 0, len(deferred))
	for _, w := range deferred {
		left = append(left, w.Ref)
	}
	if len(walks) > 0 {
		ranges := make([]secquickscan.BoxRange, 0, len(walks))
		runs := make(map[string]string, len(walks))
		for _, w := range walks {
			r := secquickscan.BoxRange{Key: w.Ref, Tip: w.Tip, Exclude: secquickscan.ExcludeOtherRefs}
			if w.From != "" {
				r.Not, r.Exclude = []string{w.From}, secquickscan.ExcludeNone
			}
			ranges = append(ranges, r)
			runs[w.Ref] = w.RunID
			if w.Claimed && (securityBoxRunOwns == nil || !securityBoxRunOwns(ctx, root, w.RunID)) {
				// The box can write this ref's name: a run id no host run
				// record owns is not trusted (lane sec-box audit finding 5).
				runs[w.Ref] = secfinding.UnknownRunID
			}
		}
		hash := secposture.ProjectRootHash(root)
		scanned := func(shas []string) map[string]bool {
			done, err := step.st.SecBoxCommitsScanned(ctx, hash, shas)
			if err != nil {
				return nil
			}
			return done
		}
		for _, r := range step.scan.WalkBox(ctx, root, ranges, scanned) {
			step.recordBoxCommits(ctx, root, runs[r.Key], r.Key, r)
			switch {
			case r.Skipped > 0:
				left = append(left, r.Key)
			case r.RangeUnread:
				step.recordBoxUnknown(ctx, root, secsvc.BoxCommit{RunID: runs[r.Key], Ref: r.Key}, "range_unread")
			}
		}
	}
	if len(left) > 0 {
		step.recordBoxUnknown(ctx, root, secsvc.BoxCommit{RefsLeft: len(left)}, boxRefsLeft)
	}
	tips.set(root, secsvc.KeepUnwalked(prev, next, left))
}
