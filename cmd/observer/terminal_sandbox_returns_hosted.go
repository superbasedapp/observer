//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_returns_hosted.go keeps, beside a hosted run's saved
// diff (<observer>/sandbox-hosted/returns/<run>.diff), the facts that say
// where the diff starts (<run>.json, lane RETURNS, audit item H6): the
// folder's HEAD commit and whether its `git status` was clean when its
// files were sent (measured by the host helper at the upload, the moment
// the bytes the box started from were read), whether the agent made commits
// of its own in the box, and whether the diff was cut at its cap.
// workspace.DecideDiffBase turns them into "opens as a branch" or "offered
// as a file only". A diff with no record (saved by an earlier build) is
// offered as a file only. The security module's reader of saved diffs
// (security_box_wire.go) reads <run>.diff only, so the record changes
// nothing there.

// hostedDiffRecordVersion is the record's version.
const hostedDiffRecordVersion = 1

// hostedDiffBase is what a hosted run measured about its diff's start.
type hostedDiffBase struct {
	// Commit is the folder's HEAD when its files were sent, or the commit a
	// box-side clone cloned ("" when not known).
	Commit string `json:"commit,omitempty"`
	// RemoteClone: the box cloned the repository itself.
	RemoteClone bool `json:"remote_clone,omitempty"`
	// StatusKnown and StatusClean are the folder's `git status` at the
	// upload.
	StatusKnown bool `json:"status_known"`
	StatusClean bool `json:"status_clean"`
	// Excluded counts the files the upload left out (credential-shaped,
	// links, too large): a branch keeps them as they are in the commit.
	Excluded int `json:"excluded,omitempty"`
	// AgentCommits is how many commits the agent made in the box (-1 when
	// it could not be read).
	AgentCommits int `json:"agent_commits"`
	// Truncated: the box's diff was cut at its cap.
	Truncated bool `json:"truncated,omitempty"`
	// DiffFromStart: the diff was taken in the box against the commit it
	// started from (the upload's observer-baseline commit, or the commit a
	// box-side clone cloned), so the agent's own commits are in it.
	DiffFromStart bool `json:"diff_from_start,omitempty"`
	// NoRepository: the files were sent from a folder that is not a git
	// repository (SBXD-8), so there is no branch to open.
	NoRepository bool `json:"no_repository,omitempty"`
}

// hostedDiffRecord is the record beside a saved diff.
type hostedDiffRecord struct {
	V        int            `json:"v"`
	RunID    string         `json:"run_id"`
	Root     string         `json:"root"`
	Provider string         `json:"provider,omitempty"`
	CloneURL string         `json:"clone_url,omitempty"`
	SavedAt  time.Time      `json:"saved_at"`
	Base     hostedDiffBase `json:"base"`
}

// facts is the record's base as workspace.DecideDiffBase reads it.
func (b hostedDiffBase) facts() workspace.DiffBaseFacts {
	return workspace.DiffBaseFacts{
		RemoteClone: b.RemoteClone, Commit: b.Commit, StatusKnown: b.StatusKnown, StatusClean: b.StatusClean,
		AgentCommits: b.AgentCommits, Truncated: b.Truncated, IncludesAgentCommits: b.DiffFromStart, NoRepository: b.NoRepository,
	}
}

// hostedDiffAgainstBaseline reports whether an upload run's saved diff is
// taken against the box's observer-baseline commit
// ([terminal.sandbox.hosted].diff_against "baseline", or "" from a plan
// written before the key), rather than against the box's HEAD ("head").
func hostedDiffAgainstBaseline(plan hostedPlanFile) bool {
	return plan.DiffAgainst != config.HostedDiffAgainstHead
}

// hostedReturnsDir is observerDir's saved-diff directory.
func hostedReturnsDir(observerDir string) string {
	return filepath.Join(hostedStateDir(observerDir), "returns")
}

// hostedDiffPaths are runID's saved diff and its record.
func hostedDiffPaths(observerDir, runID string) (diff, record string) {
	dir := hostedReturnsDir(observerDir)
	return filepath.Join(dir, runID+".diff"), filepath.Join(dir, runID+".json")
}

// writeHostedDiffRecord writes runID's record whole (0600, renamed into
// place).
func writeHostedDiffRecord(observerDir string, rec hostedDiffRecord) error {
	if !returnsRunIDOK(rec.RunID) {
		return fmt.Errorf("the run id %q is not a clean token", rec.RunID)
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	_, p := hostedDiffPaths(observerDir, rec.RunID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return replaceFileAtomic(p, b, 0o600)
}

// readHostedDiffRecord reads runID's record; ok is false when there is
// none (or it does not read).
func readHostedDiffRecord(observerDir, runID string) (hostedDiffRecord, bool) {
	_, p := hostedDiffPaths(observerDir, runID)
	b, err := readRegularCapped(p, 1<<20)
	if err != nil {
		return hostedDiffRecord{}, false
	}
	var rec hostedDiffRecord
	if json.Unmarshal(b, &rec) != nil || rec.V != hostedDiffRecordVersion || rec.RunID != runID {
		return hostedDiffRecord{}, false
	}
	return rec, true
}

// hostedMeasureUploadBase reads the folder's HEAD commit and whether its
// `git status` shows anything, through the read-only hardened envelope, at
// the moment a hosted run's files are sent (a variable so tests stand it
// in). It never fails a launch: what it cannot read stays unknown, and the
// diff is then offered as a file only.
var hostedMeasureUploadBase = func(ctx context.Context, root string, excluded int) hostedDiffBase {
	b := hostedDiffBase{Excluded: excluded, AgentCommits: -1}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	env := extrun.GitHardeningEnv("")
	if out, _, err := gitview.RunReadOnlyEnv(ctx, root, 4096, 20*time.Second, env, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"); err == nil {
		if c := strings.TrimSpace(string(out)); workspace.ValidSHA(c) {
			b.Commit = c
		}
	}
	out, over, err := gitview.RunReadOnlyEnv(ctx, root, 1<<20, 40*time.Second, env, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none")
	if err == nil {
		b.StatusKnown = true
		b.StatusClean = !over && len(strings.TrimSpace(string(out))) == 0
	}
	return b
}

// hostedDiffCloneCommit is the commit a box-side clone cloned, from the
// run's plan ("" while the plan does not record one; lane CLONE records it).
var hostedDiffCloneCommit = func(hostedPlanFile) string { return "" }

// returnsRunIDOK reports a run id that is one clean file-name token (the
// rule security_box_wire.go's hostedRunIDOK applies to the same files, kept
// here so a build without the security module has it too).
func returnsRunIDOK(id string) bool {
	if id == "" || len(id) > 128 || strings.HasPrefix(id, ".") || strings.HasPrefix(id, "-") {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
