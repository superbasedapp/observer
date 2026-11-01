//go:build sbo_omit_security || sbo_omit_security_trust

package main

import (
	"context"
	"database/sql"
	"io"
	"os"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launch_trust_omit.go stands in for launch_trust.go in a build without the
// security module or its security.trust component (-tags sbo_omit_security
// or sbo_omit_security_trust): the repo.trust launch row is then always
// inert, and neither internal/sectrust nor internal/secrules is linked.

// repoTrustDeps has no fields in a build without the module.
type repoTrustDeps struct{}

// newRepoTrustDeps always gives none: the row is inert.
func newRepoTrustDeps(config.Config, componentstate.Snapshot, *store.Store, func(string) bool) *repoTrustDeps {
	return nil
}

// dashboardRepoTrust always gives none: the row is inert.
func dashboardRepoTrust(config.Config, *sql.DB) func() *repoTrustDeps { return nil }

// repoTrustDashboardOwn gives none: there is no trust check to mark.
func repoTrustDashboardOwn(string) func(code, file, key, content string) bool { return nil }

// repoTrustSourceEnv repeats launch_trust.go's name so the daemon still
// strips an inherited copy from a child's environment.
const repoTrustSourceEnv = "OBSERVER_TRUST_SOURCE_ROOT_HASH"

// repoTrustCheckedEnv repeats launch_trust.go's name for the same reason.
const repoTrustCheckedEnv = "OBSERVER_TRUST_CHECKED_ROOT"

// daemonRepoTrustDeps always gives none: the row is inert.
func daemonRepoTrustDeps(config.Config, componentstate.Snapshot, *store.Store, daemonLaunch) *repoTrustDeps {
	return nil
}

// cliRepoTrustDeps always gives none: the row is inert.
func cliRepoTrustDeps(config.Config, componentstate.Snapshot, *store.Store, io.Writer) *repoTrustDeps {
	return nil
}

// repoTrustBenchmarkSourceEnv repeats launch_trust.go's name so the daemon
// and the benchmark drivers still strip an inherited copy.
const repoTrustBenchmarkSourceEnv = "OBSERVER_TRUST_BENCHMARK_SOURCE"

// repoTrustBenchmarkMarkerEnv repeats launch_trust.go's name for the same
// reason.
const repoTrustBenchmarkMarkerEnv = "OBSERVER_TRUST_BENCHMARK_WORKSPACE"

// repoTrustChildEnv adds nothing without the module.
func repoTrustChildEnv(string) []string { return nil }

// terminalAsk is unused without the module.
func terminalAsk(*os.File, io.Writer) func(string) bool { return nil }

// startRepoTrustBaseline starts nothing without the module.
func startRepoTrustBaseline(context.Context, *gatedGroup, string, componentstate.Snapshot) {}

// recordSessionStartTrust flags nothing without the module.
func recordSessionStartTrust(context.Context, string, []byte, string, io.Writer) {}

// registrationPinPluginPaths never pins without the module.
func registrationPinPluginPaths(string) bool { return false }

// repoTrustRun is never reached (no dependencies are ever built).
func repoTrustRun(*launchGateRun, *repoTrustDeps) launchGateStep { return launchGateStep{} }
