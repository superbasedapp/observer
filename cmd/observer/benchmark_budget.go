//go:build !sbo_omit_benchmark

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
)

// enforceBenchmarkBudget keeps the originating node's authority across an
// isolated benchmark daemon. Vendor/provider overrides and isolated spend
// accounting do not establish coverage by that node's managed hard cap.
//
// It carries no executable evidence, for two reasons that both hold: the
// process a driver starts is Observer's own harness launcher (which runs this
// gate again with the vendor binary's real evidence), and "benchmark" is not a
// registry adapter at all — it has no installed surface a process cutoff could
// be attested over, so there is nothing to recover to.
//
// The walk is the unattended one (enforceDaemonStartedLaunch) and at says
// where the process runs (benchmarkTrustLaunch for an attempt, a scorer's
// notAgent launch, or no directory for the up-front spend check). It
// returns the environment entries the started process carries.
func enforceBenchmarkBudget(ctx context.Context, configPath string, at daemonLaunch) ([]string, error) {
	return enforceDaemonStartedLaunch(ctx, configPath, "benchmark",
		budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}, at)
}

// benchmarkRelauncher is the capability of a driver whose harness process
// is Observer's own `observer <tool>` launcher, which walks the launch-gate
// table again in the attempt's workspace (the codex driver).
type benchmarkRelauncher interface{ ChecksLaunchAgain() bool }

// benchmarkTrustLaunch is where one attempt runs, for the repository trust
// row, and the environment entries the attempt's harness process carries
// for it. The attempt runs in workspace, a fresh checkout, never in the
// runner's own working directory, and nobody answers a question at an
// attempt, so an ask refuses with where to accept. A workspace is new for
// every attempt, so its own accepts would never apply: when the task's
// repository is a local directory, the attempt honours the accepts given
// for that directory, so one accept covers every attempt (the way an Arena
// worktree honours its source's), and an inner `observer <tool>` launcher
// learns the same source (repoTrustBenchmarkSourceEnv). When the task's
// repository is not a local directory there is nothing to accept: a driver
// whose harness is the inner launcher skips this outer check and says why
// (the inner launch checks the workspace again), and any other driver
// checks the workspace here, its own accepts only; its refusal then says
// to point the task at a local clone and accept there, since an accept of
// the throwaway workspace would never apply to the next attempt.
//
// The environment entries carry the source with the driver-set marker
// (repoTrustBenchmarkMarkerEnv, the attempt's workspace): an inner launcher
// honours the source only with the marker naming its own launch directory.
func benchmarkTrustLaunch(taskRepo, workspace string, relaunches bool) (daemonLaunch, []string) {
	at := daemonLaunch{dir: workspace}
	if src := benchmarkTaskSource(taskRepo); src != "" {
		at.acceptDir = src
		return at, []string{repoTrustBenchmarkSourceEnv + "=" + src, repoTrustBenchmarkMarkerEnv + "=" + workspace}
	}
	if relaunches {
		at.trustSkip = "the benchmark task's repository is not a local directory, so no accept can cover the attempt's fresh workspace; the `observer <tool>` launcher the attempt starts checks the workspace"
	} else {
		at.trustAdvice = benchmarkRemoteTrustAdvice
	}
	return at, nil
}

// benchmarkRemoteTrustAdvice is what a refused attempt from a task whose
// repository is not a local directory tells the developer: every attempt
// runs in a fresh workspace, so no accept of one covers the next.
const benchmarkRemoteTrustAdvice = "the benchmark task's repository is not a local directory, so every attempt runs in a fresh workspace no accept can cover; " +
	"clone the repository locally, point the task's repo at the clone as a file:// URL (or an absolute path), " +
	"accept it there with `observer security trust accept --all --dir <clone>` (or in the dashboard's New Terminal dialog for that directory), then run the benchmark again"

// benchmarkTaskSource is a task repository that names an existing local
// directory (an absolute path or a file:// URL), resolved, or "".
func benchmarkTaskSource(repo string) string {
	repo = strings.TrimSpace(repo)
	if p, ok := strings.CutPrefix(repo, "file://"); ok {
		repo = p
	}
	if repo == "" || !filepath.IsAbs(repo) {
		return ""
	}
	fi, err := os.Stat(repo) //nolint:gosec // G703: false positive; the operator's own absolute benchmark repo path, only stat'd to check it is a directory
	if err != nil || !fi.IsDir() {
		return ""
	}
	if abs, err := filepath.EvalSymlinks(repo); err == nil {
		repo = abs
	}
	return filepath.Clean(repo)
}

// budgetControlledBenchmarkDrivers wraps every production driver at the
// registry boundary. Each attempt rechecks the originating node so a budget
// delivered after the matrix started still prevents the next AI process.
func budgetControlledBenchmarkDrivers(observerBin, dbPath, configPath string) map[string]HarnessDriver {
	drivers := newBenchmarkDrivers(observerBin, dbPath)
	for name, driver := range drivers {
		drivers[name] = budgetControlledBenchmarkDriver{HarnessDriver: driver, configPath: configPath}
	}
	return drivers
}

type budgetControlledBenchmarkDriver struct {
	HarnessDriver
	configPath string
}

func (d budgetControlledBenchmarkDriver) Drive(ctx context.Context, req DriveRequest) (DriveResult, error) {
	relaunches := false
	if rl, ok := d.HarnessDriver.(benchmarkRelauncher); ok {
		relaunches = rl.ChecksLaunchAgain()
	}
	at, sourceEnv := benchmarkTrustLaunch(req.TaskRepo, req.WorkspaceDir, relaunches)
	env, err := enforceBenchmarkBudget(ctx, d.configPath, at)
	if err != nil {
		return DriveResult{}, err
	}
	req.TrustEnv = append(append([]string(nil), env...), sourceEnv...)
	return d.HarnessDriver.Drive(ctx, req)
}

// Preflight preserves a wrapped driver's existing isolation requirements.
// Dry runs perform preflight but do not invoke the spending admission check.
func (d budgetControlledBenchmarkDriver) Preflight() error {
	if inner, ok := d.HarnessDriver.(preflightDriver); ok {
		return inner.Preflight()
	}
	return nil
}

type budgetControlledBenchmarkScorer struct {
	inner      attemptScorer
	configPath string
}

// Score runs the budget rows before a scorer that may spend (an LLM judge),
// but no repository trust check: scoring is not an agent launch, and the
// workspace now holds what the agent wrote (a `.mcp.json` it added must not
// turn scoring into a scoring error).
func (s budgetControlledBenchmarkScorer) Score(ctx context.Context, in scoreInput) ([]benchmark.ScoreRecord, error) {
	if _, err := enforceBenchmarkBudget(ctx, s.configPath, daemonLaunch{dir: in.WorkspaceDir, notAgent: true}); err != nil {
		return nil, err
	}
	return s.inner.Score(ctx, in)
}
