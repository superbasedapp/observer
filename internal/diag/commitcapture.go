package diag

import (
	"fmt"
	"os/exec"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// checkCommitCapture surfaces whether the read-only git-commit-history
// scanner (internal/commitscan, docs/plans/projects-page-roi-and-commit-
// alignment-plan-2026-09-21.md §2 R9) can actually run on this machine.
// The scanner's only precondition is a `git` binary on PATH — no
// repository state, no credentials — so this check is a plain
// exec.LookPath probe, never a StatusFail: a missing git binary means the
// Projects page's commit ledger stays honestly empty
// ("commit capture unavailable (git not found)"), not that anything is
// broken.
func checkCommitCapture(cfg config.Config) Check {
	const name = "commit-capture"
	if !cfg.Projects.CommitScan {
		return Check{Name: name, Status: StatusOK, Message: "off ([projects].commit_scan = false)"}
	}
	path, err := exec.LookPath("git")
	if err != nil {
		return Check{
			Name: name, Status: StatusWarn,
			Message: "git not found on PATH — commit-capture scanner idle; the Projects page's commit ledger and every ROI proxy that depends on it stay empty",
		}
	}
	return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("git found (%s)", path)}
}
