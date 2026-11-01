package arena

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/costtext"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// keep.go — the explicit merge-back decision. Squash is the default
// strategy (operator ruling 2026-08-22); judge-managed delegation exists
// for candidates whose conflicts the operator would rather let an agent
// resolve. Every path leaves a provenance footer on the resulting commit.

// KeepStrategy names how a kept candidate lands on the project branch.
type KeepStrategy string

const (
	// KeepSquash (default): `git merge --squash` of the candidate branch,
	// committed as one arena commit with a provenance footer.
	KeepSquash KeepStrategy = "squash"
	// KeepJudgeMerge: the judge harness is driven headlessly in a
	// temporary keep worktree of the branch HEAD with instructions to merge
	// the candidate branch and commit, and the verified result is
	// fast-forwarded onto the project branch (OSH-R-006) - for candidates
	// needing conflict resolution the operator prefers not to do by hand.
	// It runs only where the harness may skip its own permission checks
	// (permlane.go, audit F3).
	KeepJudgeMerge KeepStrategy = "judge_merge"
)

// ErrMergeConflict is returned by Keep when the squash merge hits
// conflicts; the merge has been aborted and the candidate remains
// available (nothing half-landed).
var ErrMergeConflict = errors.New("arena.Keep: merge conflicts; aborted cleanly")

// JudgeSpec names the harness delegated the merge in KeepJudgeMerge
// (the run's judge_tool/judge_model — the dashboard passes them through).
type JudgeSpec struct {
	Tool  string
	Model string
}

// Keep merges a judged candidate onto the project's working branch using
// the chosen strategy and stamps the resulting SHA on the row.
// KeepJudgeMerge requires a grounded judge (judge.Tool must resolve).
func (r *Runner) Keep(ctx context.Context, row *models.ArenaCandidate, projectRoot string, strategy KeepStrategy, judge ...JudgeSpec) (string, error) {
	if row == nil {
		return "", errors.New("arena.Keep: candidate required")
	}
	canonical, run, err := r.candidateForMutation(ctx, row.ID, projectRoot)
	if err != nil {
		return "", fmt.Errorf("arena.Keep: %w", err)
	}
	row = canonical
	if !arenaRunIsTerminal(run.Status) {
		return "", fmt.Errorf("arena.Keep: run status %q is still active", run.Status)
	}
	if row.Status != models.ArenaCandidateStatusJudged {
		return "", fmt.Errorf("arena.Keep: candidate status %q is not judged", row.Status)
	}
	if row.BranchName == "" {
		return "", errors.New("arena.Keep: candidate has no branch")
	}
	branch, err := git.CurrentBranch(ctx, projectRoot)
	if err != nil {
		return "", fmt.Errorf("arena.Keep: %w", err)
	}
	if branch != run.BaseBranch {
		return "", fmt.Errorf("arena.Keep: current branch %q does not match run base branch %q", branch, run.BaseBranch)
	}
	baseHead, err := git.HeadSHA(ctx, projectRoot)
	if err != nil {
		return "", fmt.Errorf("arena.Keep: %w", err)
	}
	var (
		sha     string
		landErr error
	)
	// The provenance footer follows the developer cost display once per keep,
	// so the footer written and the footer verified agree (T-204).
	mode := r.costMode()
	switch strategy {
	case KeepSquash:
		sha, landErr = r.squashKeep(ctx, row, projectRoot, mode)
	case KeepJudgeMerge:
		var js JudgeSpec
		if len(judge) > 0 {
			js = judge[0]
		}
		sha, landErr = r.judgeMergeKeep(ctx, row, projectRoot, js, mode)
	default:
		landErr = fmt.Errorf("arena.Keep: unknown strategy %q", strategy)
	}
	if landErr != nil {
		return "", landErr
	}
	// Once a commit has landed the record is finalized on a context detached
	// from the request (OSH-R-006): a client that disconnects now must not
	// turn a completed land into a rollback, or strand the two apart.
	fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), keepFinishTimeout)
	defer fcancel()
	if err := r.opts.Store.SetCandidateKept(fctx, row.ID, sha); err != nil {
		// The repository and DB must not disagree. Roll back only when HEAD is
		// still exactly our clean landed commit; otherwise preserve the user's
		// newer state and report the manual recovery requirement.
		if rbErr := rollbackExactCleanHead(fctx, projectRoot, sha, baseHead); rbErr != nil {
			return "", fmt.Errorf("arena.Keep: land %s succeeded but store finalization failed (%w); automatic rollback also failed: %w", sha, err, rbErr)
		}
		return "", fmt.Errorf("arena.Keep: store finalization failed; landed commit was rolled back: %w", err)
	}
	// The candidate is fully contained in the project branch after a
	// squash land — prune its worktree and branch like a discard would
	// (plan §2f). Best-effort: the land itself already succeeded.
	if row.WorktreePath != "" {
		_ = git.WorktreeRemove(context.WithoutCancel(ctx), projectRoot, row.WorktreePath)
	}
	if row.BranchName != "" {
		_ = git.DeleteBranch(context.WithoutCancel(ctx), projectRoot, row.BranchName)
	}
	return sha, nil
}

func (r *Runner) squashKeep(ctx context.Context, row *models.ArenaCandidate, projectRoot, mode string) (string, error) {
	// Keep requires a clean tree: a conflicted squash merge leaves no
	// MERGE_HEAD, so `merge --abort` cannot roll it back — the only
	// rollback is `reset --hard`, which is safe ONLY on a clean repo,
	// where it reverts exactly the merge artifacts.
	dirty, err := git.IsDirty(ctx, projectRoot)
	if err != nil {
		return "", fmt.Errorf("arena.squashKeep: %w", err)
	}
	if dirty {
		return "", errors.New("arena.squashKeep: working tree dirty; commit or clean before keeping")
	}
	baseHead, err := git.HeadSHA(ctx, projectRoot)
	if err != nil {
		return "", fmt.Errorf("arena.squashKeep: %w", err)
	}
	merge := exec.CommandContext(ctx, "git", "-C", projectRoot, "merge", "--squash", row.BranchName) //nolint:gosec // G204: fixed git argv; projectRoot is a validated arena project root and the branch name is arena's own generated ref, not request input
	out, err := merge.CombinedOutput()
	if err != nil {
		// The request context may have expired while git was resolving the
		// squash. Cleanup must still restore the exact clean HEAD we proved
		// above; otherwise a cancelled HTTP request can strand merge residue.
		rbErr := git.ResetHard(context.WithoutCancel(ctx), projectRoot, baseHead)
		if strings.Contains(strings.ToLower(string(out)), "conflict") ||
			strings.Contains(strings.ToLower(string(out)), "would be overwritten") {
			if rbErr != nil {
				return "", fmt.Errorf("arena.squashKeep: merge conflicted and rollback failed: %w", rbErr)
			}
			return "", ErrMergeConflict
		}
		if rbErr != nil {
			return "", fmt.Errorf("arena.squashKeep: merge failed (%w: %s); rollback failed: %w", err, truncateStr(string(out), 400), rbErr)
		}
		return "", fmt.Errorf("arena.squashKeep: merge: %w: %s", err, truncateStr(string(out), 400))
	}
	sha, err := git.CommitAll(ctx, projectRoot, provenanceMessage(row, mode))
	if err != nil {
		if rbErr := git.ResetHard(context.WithoutCancel(ctx), projectRoot, baseHead); rbErr != nil {
			return "", fmt.Errorf("arena.squashKeep: commit failed (%w); rollback failed: %w", err, rbErr)
		}
		return "", fmt.Errorf("arena.squashKeep: commit failed and merge was rolled back: %w", err)
	}
	return sha, nil
}

// keepFinishTimeout bounds the checks and the land after a judge_merge drive
// returns. They run on their own context, detached from the request's, so a
// client that disconnects in that window cannot strand a half-checked keep
// (OSH-R-006); the bound keeps a wedged git from holding the keep forever.
const keepFinishTimeout = 2 * time.Minute

// keepWorktreeFor names the isolated worktree and scratch branch a
// judge_merge keep of row works in: under the run's own workspace directory
// (a dot name, so it can never collide with a candidate slot named after a
// tool), on a branch beside the candidate's own.
func (r *Runner) keepWorktreeFor(row *models.ArenaCandidate) (dir, branch string) {
	return filepath.Join(r.opts.WorkspaceDir, row.RunID, ".keep-"+row.Tool),
		fmt.Sprintf("arena/%s/keep-%s", row.RunID, row.Tool)
}

// judgeMergeKeep delegates the merge to the judge harness (operator ruling
// Q2's keep-time option), in an ISOLATED worktree (OSH-R-006): the agent is
// driven headlessly inside a temporary worktree of the project branch's HEAD
// with instructions to merge the candidate branch, resolve any conflicts
// itself, and commit. The engine never merges on the judge's behalf; it
// verifies the outcome in that worktree (a new commit with a clean tree that
// history-merges the candidate branch and carries the provenance footer) and
// only then fast-forwards the real checkout to it, provided the checkout is
// still clean and still at the HEAD the keep started from. The real checkout
// is therefore either moved in one step to a verified commit or not touched
// at all. A cancelled request stops the agent; the checks and the land after
// the drive run detached from the request (keepFinishTimeout).
func (r *Runner) judgeMergeKeep(ctx context.Context, row *models.ArenaCandidate, projectRoot string, js JudgeSpec, mode string) (string, error) {
	if js.Tool == "" {
		return "", errors.New("arena.judgeMergeKeep: no judge tool supplied")
	}
	jc, ok := integration.For(js.Tool)
	if !ok {
		return "", fmt.Errorf("arena.judgeMergeKeep: unknown judge tool %q", js.Tool)
	}
	// Refuse before any worktree exists when the merge agent has no lane
	// it may run in here (audit F3): the drive asks again per process.
	bypass := r.bypassFor(ctx, js.Tool)
	if _, _, lerr := permissionArgs(jc.Headless, js.Tool, roleMerge, bypass); lerr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: %w", lerr)
	}
	dirty, err := git.IsDirty(ctx, projectRoot)
	if err != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: %w", err)
	}
	if dirty {
		return "", errors.New("arena.judgeMergeKeep: working tree dirty; commit or clean before keeping")
	}
	baseHead, err := git.HeadSHA(ctx, projectRoot)
	if err != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: %w", err)
	}

	cfgDir, cerr := prepareClaudeSandbox(
		filepath.Join(r.opts.WorkspaceDir, row.RunID), "judge-merge", r.opts.WorkspaceDir,
	)
	if cerr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: %w", cerr)
	}
	keepDir, keepBranch := r.keepWorktreeFor(row)
	removeKeep := func() {
		// Detached from the request so a cancel still cleans up, and
		// bounded so a wedged git cannot hold the keep forever (audit F7).
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), keepFinishTimeout)
		defer cancel()
		_ = git.WorktreeRemove(c, projectRoot, keepDir)
		_ = os.RemoveAll(keepDir)
		_ = git.DeleteBranch(c, projectRoot, keepBranch)
	}
	// A keep that crashed earlier may have left its worktree behind; the
	// cleanup is convergent, so clear it before adding a fresh one.
	removeKeep()
	if err := git.WorktreeAdd(ctx, projectRoot, keepDir, keepBranch, baseHead); err != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: isolated keep worktree: %w", err)
	}
	defer removeKeep()

	res, derr := driveHarness(ctx, driveRequest{
		Tool:         js.Tool,
		Model:        js.Model,
		WorktreePath: keepDir,
		SourceRoot:   projectRoot,
		ProjectRoot:  projectRoot,
		Prompt:       renderJudgeMergePrompt(row, mode),
		ProxyURL:     r.opts.ProxyURL,
		ConfigDir:    cfgDir,
		Timeout:      DefaultTimeout,
		Admission:    r.opts.Admission,
		Role:         roleMerge,
		Bypass:       bypass,
	})
	if res.TimedOut {
		return "", fmt.Errorf("arena.judgeMergeKeep: judge drive timed out after %s; your checkout is untouched", DefaultTimeout)
	}
	if cerr := ctx.Err(); cerr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: cancelled before landing; your checkout is untouched: %w", cerr)
	}

	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), keepFinishTimeout)
	defer cancel()
	landed, err := verifyJudgeMerge(fctx, row, keepDir, baseHead, res, derr, mode)
	if err != nil {
		return "", err
	}
	if err := landKeep(fctx, projectRoot, baseHead, landed); err != nil {
		return "", err
	}
	return landed, nil
}

// verifyJudgeMerge checks the judge's result in the isolated keep worktree
// and returns the commit to land, the provenance footer amended on when the
// judge left it out. Nothing here touches the real checkout.
func verifyJudgeMerge(ctx context.Context, row *models.ArenaCandidate, keepDir, baseHead string, res driveResult, derr error, mode string) (string, error) {
	newHead, herr := git.HeadSHA(ctx, keepDir)
	if herr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: %w", herr)
	}
	stillDirty, dirtyErr := git.IsDirty(ctx, keepDir)
	if dirtyErr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: post-drive dirty check: %w", dirtyErr)
	}

	// A landed commit whose tree matches the pre-keep HEAD is an empty
	// commit, not a land (git itself refuses to amend one).
	if newHead != baseHead {
		sameTree, terr := git.TreesEqual(ctx, keepDir, baseHead, newHead)
		if terr != nil {
			return "", fmt.Errorf("arena.judgeMergeKeep: compare landed tree: %w", terr)
		}
		if sameTree {
			return "", errors.New("arena.judgeMergeKeep: judge committed but the tree is unchanged from the base - nothing landed")
		}
	}

	switch {
	case derr != nil && newHead == baseHead:
		return "", fmt.Errorf("arena.judgeMergeKeep: judge drive failed before landing (%w)", derr)
	case newHead == baseHead && stillDirty:
		return "", errors.New("arena.judgeMergeKeep: judge left conflicts unresolved and landed nothing - your checkout is untouched")
	case newHead == baseHead:
		return "", fmt.Errorf("arena.judgeMergeKeep: judge landed no commit (exit %d): %s",
			res.ExitCode, truncateStr(stripANSI(res.FinalAnswer), 300))
	case stillDirty:
		return "", fmt.Errorf("arena.judgeMergeKeep: judge committed %s but left the tree dirty - nothing landed", newHead)
	}
	merged, aerr := git.IsAncestor(ctx, keepDir, row.BranchName, newHead)
	if aerr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: verify candidate ancestry: %w", aerr)
	}
	if !merged {
		return "", errors.New("arena.judgeMergeKeep: judge changed HEAD without history-merging the candidate branch - nothing landed")
	}
	if ok, aerr := git.IsAncestor(ctx, keepDir, baseHead, newHead); aerr != nil || !ok {
		return "", errors.New("arena.judgeMergeKeep: judge commit does not descend from the branch head the keep started at - nothing landed")
	}

	// Ensure the provenance footer survives regardless of what message the
	// judge wrote: amend it onto the landed commit when missing.
	msg, merr := git.CommitMessage(ctx, keepDir, newHead)
	if merr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: read landed provenance; nothing landed: %w", merr)
	}
	if !hasArenaProvenance(msg, row, mode) {
		amended, aerr := git.AmendCommitMessage(ctx, keepDir,
			strings.TrimRight(msg, "\n")+"\n\n"+provenanceFooter(row, mode))
		if aerr != nil {
			return "", fmt.Errorf("arena.judgeMergeKeep: provenance amend failed; nothing landed: %w", aerr)
		}
		newHead = amended
	}
	return newHead, nil
}

// landKeep fast-forwards the real checkout to the verified commit, only when
// the checkout is still clean and still at the HEAD the keep started from:
// the operator may have committed or edited while the judge worked, and a
// keep never lands over that. A failed fast-forward changes nothing; if HEAD
// somehow moved anyway it is put back only while it is exactly our commit
// on a clean tree.
func landKeep(ctx context.Context, projectRoot, baseHead, landed string) error {
	cur, err := git.HeadSHA(ctx, projectRoot)
	if err != nil {
		return fmt.Errorf("arena.judgeMergeKeep: %w", err)
	}
	if cur != baseHead {
		return fmt.Errorf("arena.judgeMergeKeep: your branch moved from %s to %s while the judge worked - nothing landed", baseHead, cur)
	}
	dirty, err := git.IsDirty(ctx, projectRoot)
	if err != nil {
		return fmt.Errorf("arena.judgeMergeKeep: %w", err)
	}
	if dirty {
		return errors.New("arena.judgeMergeKeep: your working tree changed while the judge worked - nothing landed")
	}
	if ferr := git.FastForward(ctx, projectRoot, landed); ferr != nil {
		if now, herr := git.HeadSHA(ctx, projectRoot); herr == nil && now != baseHead {
			if rbErr := rollbackExactCleanHead(ctx, projectRoot, now, baseHead); rbErr != nil {
				return fmt.Errorf("arena.judgeMergeKeep: land failed (%w); rollback also failed: %w", ferr, rbErr)
			}
		}
		return fmt.Errorf("arena.judgeMergeKeep: land failed; your checkout is unchanged: %w", ferr)
	}
	return nil
}

func hasArenaProvenance(message string, row *models.ArenaCandidate, mode string) bool {
	if row == nil {
		return false
	}
	markers := []string{
		fmt.Sprintf("Arena-Run:  %s\n", row.RunID),
		provenanceUsage(row, mode),
		"Generated-by: observer agent arena",
	}
	harness := fmt.Sprintf("Harness:    %s", row.Tool)
	if row.Model != "" {
		harness += fmt.Sprintf(" (%s)", row.Model)
	}
	markers = append(markers, harness+"\n")
	if len(row.SessionIDs) > 0 {
		markers = append(markers, fmt.Sprintf("Sessions:   %s\n", strings.Join(row.SessionIDs, ", ")))
	}
	for _, marker := range markers {
		if !strings.Contains(message, marker) {
			return false
		}
	}
	return true
}

func rollbackExactCleanHead(ctx context.Context, projectRoot, landedHead, baseHead string) error {
	current, err := git.HeadSHA(ctx, projectRoot)
	if err != nil {
		return err
	}
	if current != landedHead {
		return fmt.Errorf("HEAD moved from landed commit %s to %s", landedHead, current)
	}
	dirty, err := git.IsDirty(ctx, projectRoot)
	if err != nil {
		return err
	}
	if dirty {
		return errors.New("working tree is dirty")
	}
	return git.ResetHard(context.WithoutCancel(ctx), projectRoot, baseHead)
}

// renderJudgeMergePrompt builds the judge-driven merge instruction. The
// judge works inside the temporary keep worktree (a checkout of the
// project branch's HEAD): merge the candidate branch, resolve conflicts
// itself, commit with the provenance footer.
func renderJudgeMergePrompt(row *models.ArenaCandidate, mode string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "In this git repository, merge the branch %q into the current branch and commit the result.\n", row.BranchName)
	b.WriteString("Resolve any merge conflicts yourself - do not leave conflicts unresolved or ask for help; pick the resolution that preserves BOTH the candidate's intent and the current branch's content.\n")
	fmt.Fprintf(&b, "Use a plain merge (history-preserving), NOT --squash. Stage everything the merge needs (git add -A) before committing.\n\n")
	fmt.Fprintf(&b, "The commit message MUST end with exactly this provenance block:\n\n%s", provenanceFooter(row, mode))
	b.WriteString("\nWhen done, reply with only the resulting commit SHA.")
	return b.String()
}

// provenanceMessage is the squash-keep commit message: header + footer.
func provenanceMessage(row *models.ArenaCandidate, mode string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "arena: land %s candidate\n\n", row.Tool)
	b.WriteString(provenanceFooter(row, mode))
	return b.String()
}

// provenanceFooter answers "which model wrote this" in history: what
// landed, from which harness/model/run.
func provenanceFooter(row *models.ArenaCandidate, mode string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Arena-Run:  %s\n", row.RunID)
	fmt.Fprintf(&b, "Harness:    %s", row.Tool)
	if row.Model != "" {
		fmt.Fprintf(&b, " (%s)", row.Model)
	}
	b.WriteString("\n")
	if len(row.SessionIDs) > 0 {
		fmt.Fprintf(&b, "Sessions:   %s\n", strings.Join(row.SessionIDs, ", "))
	}
	b.WriteString(provenanceUsage(row, mode))
	fmt.Fprintf(&b, "Kept:       %s\n", time.Now().UTC().Format(time.RFC3339))
	b.WriteString("\nGenerated-by: observer agent arena\n")
	return b.String()
}

// provenanceUsage is the footer's usage line. A kept commit lands in shared
// git history, so under the token-usage developer cost display (D-013) it
// carries the token counts only; in dollar mode it also carries the cost.
func provenanceUsage(row *models.ArenaCandidate, mode string) string {
	if costtext.Tokens(mode) {
		return fmt.Sprintf("Usage:      %d input / %d output\n", row.InputTokens, row.OutputTokens)
	}
	// no-bare-usd:allow (reached only when the display shows dollars)
	return fmt.Sprintf("Usage:      %d input / %d output / $%.6f\n", row.InputTokens, row.OutputTokens, row.CostUSD)
}

// costMode is the developer cost display for one keep; dollars when the
// runner was built without a resolver.
func (r *Runner) costMode() string {
	if r.opts.CostDisplay == nil {
		return costtext.ModeUSD
	}
	return r.opts.CostDisplay()
}
