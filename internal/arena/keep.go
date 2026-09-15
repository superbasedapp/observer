package arena

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
	// KeepJudgeMerge: the judge harness is driven headlessly in the main
	// repository with instructions to merge the candidate branch and
	// commit — for candidates needing conflict resolution the operator
	// prefers not to do by hand.
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
	switch strategy {
	case KeepSquash:
		sha, landErr = r.squashKeep(ctx, row, projectRoot)
	case KeepJudgeMerge:
		var js JudgeSpec
		if len(judge) > 0 {
			js = judge[0]
		}
		sha, landErr = r.judgeMergeKeep(ctx, row, projectRoot, js)
	default:
		landErr = fmt.Errorf("arena.Keep: unknown strategy %q", strategy)
	}
	if landErr != nil {
		return "", landErr
	}
	if err := r.opts.Store.SetCandidateKept(ctx, row.ID, sha); err != nil {
		// The repository and DB must not disagree. Roll back only when HEAD is
		// still exactly our clean landed commit; otherwise preserve the user's
		// newer state and report the manual recovery requirement.
		if rbErr := rollbackExactCleanHead(ctx, projectRoot, sha, baseHead); rbErr != nil {
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

func (r *Runner) squashKeep(ctx context.Context, row *models.ArenaCandidate, projectRoot string) (string, error) {
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
	sha, err := git.CommitAll(ctx, projectRoot, provenanceMessage(row))
	if err != nil {
		if rbErr := git.ResetHard(context.WithoutCancel(ctx), projectRoot, baseHead); rbErr != nil {
			return "", fmt.Errorf("arena.squashKeep: commit failed (%w); rollback failed: %w", err, rbErr)
		}
		return "", fmt.Errorf("arena.squashKeep: commit failed and merge was rolled back: %w", err)
	}
	return sha, nil
}

// judgeMergeKeep delegates the merge to the judge harness (operator ruling
// Q2's keep-time option): the agent is driven headlessly INSIDE the main
// repository with instructions to merge the candidate branch, resolve any
// conflicts itself, and commit. The engine never merges on the judge's
// behalf — it verifies outcomes honestly: a new HEAD commit on the project
// branch with a clean tree, else an error that leaves triage to the
// operator (a half-resolved state is reported, never silently reset).
func (r *Runner) judgeMergeKeep(ctx context.Context, row *models.ArenaCandidate, projectRoot string, js JudgeSpec) (string, error) {
	if js.Tool == "" {
		return "", errors.New("arena.judgeMergeKeep: no judge tool supplied")
	}
	if _, ok := integration.For(js.Tool); !ok {
		return "", fmt.Errorf("arena.judgeMergeKeep: unknown judge tool %q", js.Tool)
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
	res, derr := driveHarness(ctx, driveRequest{
		Tool:         js.Tool,
		Model:        js.Model,
		WorktreePath: projectRoot,
		Prompt:       renderJudgeMergePrompt(row),
		ProxyURL:     r.opts.ProxyURL,
		ConfigDir:    cfgDir,
		Timeout:      DefaultTimeout,
		Admission:    r.opts.Admission,
	})
	if res.TimedOut {
		return "", fmt.Errorf("arena.judgeMergeKeep: judge drive timed out after %s", DefaultTimeout)
	}

	newHead, herr := git.HeadSHA(ctx, projectRoot)
	if herr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: %w", herr)
	}
	stillDirty, dirtyErr := git.IsDirty(ctx, projectRoot)
	if dirtyErr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: post-drive dirty check: %w", dirtyErr)
	}

	// A landed commit whose tree matches the pre-keep HEAD is an empty
	// commit, not a land (git itself refuses to amend one).
	if newHead != baseHead {
		sameTree, terr := git.TreesEqual(ctx, projectRoot, baseHead, newHead)
		if terr != nil {
			return "", fmt.Errorf("arena.judgeMergeKeep: compare landed tree: %w", terr)
		}
		if sameTree {
			if rbErr := rollbackExactCleanHead(ctx, projectRoot, newHead, baseHead); rbErr != nil {
				return "", fmt.Errorf("arena.judgeMergeKeep: judge committed an unchanged tree and rollback failed: %w", rbErr)
			}
			return "", errors.New("arena.judgeMergeKeep: judge committed but the tree is unchanged from the base — commit rolled back")
		}
	}

	switch {
	case derr != nil && newHead == baseHead:
		return "", fmt.Errorf("arena.judgeMergeKeep: judge drive failed before landing (%w)", derr)
	case newHead == baseHead && stillDirty:
		return "", errors.New("arena.judgeMergeKeep: judge left conflicts unresolved and landed nothing — resolve or reset manually")
	case newHead == baseHead:
		return "", fmt.Errorf("arena.judgeMergeKeep: judge landed no commit (exit %d): %s",
			res.ExitCode, truncateStr(stripANSI(res.FinalAnswer), 300))
	case stillDirty:
		return "", fmt.Errorf("arena.judgeMergeKeep: judge committed %s but left the tree dirty — commit or clean the residue", newHead)
	}
	landed, aerr := git.IsAncestor(ctx, projectRoot, row.BranchName, newHead)
	if aerr != nil {
		return "", fmt.Errorf("arena.judgeMergeKeep: verify candidate ancestry: %w", aerr)
	}
	if !landed {
		if rbErr := rollbackExactCleanHead(ctx, projectRoot, newHead, baseHead); rbErr != nil {
			return "", fmt.Errorf("arena.judgeMergeKeep: judge commit does not contain candidate branch and rollback failed: %w", rbErr)
		}
		return "", errors.New("arena.judgeMergeKeep: judge changed HEAD without history-merging the candidate branch — commit rolled back")
	}

	// Ensure the provenance footer survives regardless of what message the
	// judge wrote: amend it onto the landed commit when missing.
	msg, merr := git.CommitMessage(ctx, projectRoot, newHead)
	if merr != nil {
		if rbErr := rollbackExactCleanHead(ctx, projectRoot, newHead, baseHead); rbErr != nil {
			return "", fmt.Errorf("arena.judgeMergeKeep: read landed provenance (%w); rollback failed: %w", merr, rbErr)
		}
		return "", fmt.Errorf("arena.judgeMergeKeep: read landed provenance; commit rolled back: %w", merr)
	}
	if !hasArenaProvenance(msg, row) {
		amended, aerr := git.AmendCommitMessage(ctx, projectRoot,
			strings.TrimRight(msg, "\n")+"\n\n"+provenanceFooter(row))
		if aerr != nil {
			if rbErr := rollbackExactCleanHead(ctx, projectRoot, newHead, baseHead); rbErr != nil {
				return "", fmt.Errorf("arena.judgeMergeKeep: provenance amend failed (%w); rollback failed: %w", aerr, rbErr)
			}
			return "", fmt.Errorf("arena.judgeMergeKeep: provenance amend failed; commit rolled back: %w", aerr)
		}
		newHead = amended
	}
	return newHead, nil
}

func hasArenaProvenance(message string, row *models.ArenaCandidate) bool {
	if row == nil {
		return false
	}
	markers := []string{
		fmt.Sprintf("Arena-Run:  %s\n", row.RunID),
		fmt.Sprintf("Usage:      %d input / %d output / $%.6f\n", row.InputTokens, row.OutputTokens, row.CostUSD),
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
// judge works INSIDE the main repository: merge the candidate branch,
// resolve conflicts itself, commit with the provenance footer.
func renderJudgeMergePrompt(row *models.ArenaCandidate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "In this git repository, merge the branch %q into the current branch and commit the result.\n", row.BranchName)
	b.WriteString("Resolve any merge conflicts yourself — do not leave conflicts unresolved or ask for help; pick the resolution that preserves BOTH the candidate's intent and the current branch's content.\n")
	fmt.Fprintf(&b, "Use a plain merge (history-preserving), NOT --squash. Stage everything the merge needs (git add -A) before committing.\n\n")
	fmt.Fprintf(&b, "The commit message MUST end with exactly this provenance block:\n\n%s", provenanceFooter(row))
	b.WriteString("\nWhen done, reply with only the resulting commit SHA.")
	return b.String()
}

// provenanceMessage is the squash-keep commit message: header + footer.
func provenanceMessage(row *models.ArenaCandidate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "arena: land %s candidate\n\n", row.Tool)
	b.WriteString(provenanceFooter(row))
	return b.String()
}

// provenanceFooter answers "which model wrote this" in history: what
// landed, from which harness/model/run.
func provenanceFooter(row *models.ArenaCandidate) string {
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
	fmt.Fprintf(&b, "Usage:      %d input / %d output / $%.6f\n", row.InputTokens, row.OutputTokens, row.CostUSD)
	fmt.Fprintf(&b, "Kept:       %s\n", time.Now().UTC().Format(time.RFC3339))
	b.WriteString("\nGenerated-by: observer agent arena\n")
	return b.String()
}
