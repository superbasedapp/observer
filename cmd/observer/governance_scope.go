package main

import (
	"context"
	"log/slog"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The org push's project scope under governance (control-coverage audit
// CG-13). The node's [org_client.scope] lists narrow what pushes. Before
// this, they were passed to the push seam as written on every node, so on a
// managed node they also narrowed the guard verdicts the org's own policy
// enforced, and the org's governed scope raise (govern.RaiseScope*,
// authorized by extract.scope) had no caller.

// The org publishes the raise as two node.governance DIRECTIVE keys (R3-85):
// `scope.unrestricted` (true lifts the allowlist) and `scope.denylist_remove`
// (entries taken off the denylist), rows of nodegov.ShareKeys with their own
// kinds rather than the list fields they act on. govern.Effective.RaiseScope
// applies both and is the one owner the dashboard's transparency card reads.

// governedScopeOptions resolves the scope one push selects under:
//
//   - the node's own lists, as written;
//   - on a managed node holding extract.scope, the org's raise: the
//     unrestricted sentinel clears the allowlist, a removal list takes
//     entries off the denylist (govern.RaiseScopeUnrestricted /
//     RaiseScopeDenylistRemoval, both inert off the managed plane);
//   - GuardEventsUnscoped on a managed node (the managed-defaults posture:
//     managed and the grant not refused), so a verdict the org enforced
//     reaches the org whatever the local lists say.
func governedScopeOptions(local config.OrgClientScopeConfig, eff govern.Effective) store.ScopeOptions {
	out := store.ScopeOptions{
		ProjectRootAllowlist: local.ProjectRootAllowlist,
		ProjectRootDenylist:  local.ProjectRootDenylist,
	}
	out.ProjectRootAllowlist, out.ProjectRootDenylist = eff.RaiseScope(out.ProjectRootAllowlist, out.ProjectRootDenylist)
	out.GuardEventsUnscoped = eff.ManagedDefaultsApply()
	return out
}

// governanceScopeProvider is governanceShareProvider's scope twin: resolved
// on every push from the live governance handle.
func governanceScopeProvider(cfg config.OrgClientConfig, ngov *nodeGovernanceHandle) func() store.ScopeOptions {
	if ngov == nil {
		return func() store.ScopeOptions { return governedScopeOptions(cfg.Scope, govern.Effective{}) }
	}
	return func() store.ScopeOptions {
		return governedScopeOptions(cfg.Scope, ngov.Effective(context.Background()))
	}
}

// cliGovernanceScopeProvider is cliGovernanceShareProvider's scope twin for a
// client built outside the daemon (`observer org push-now` and the other org
// verbs): the governance handle is built from the verified last-known-good
// cache on the first resolve.
func cliGovernanceScopeProvider(cfg config.Config, st *store.Store, logger *slog.Logger) func() store.ScopeOptions {
	var (
		once    sync.Once
		resolve func() store.ScopeOptions
	)
	return func() store.ScopeOptions {
		once.Do(func() {
			if logger == nil {
				logger = slog.Default()
			}
			ngov := newNodeGovernanceHandle(governanceIdentityLoader(st), logger)
			loadNodeGovernanceLKG(context.Background(), cfg, st, ngov, logger)
			resolve = governanceScopeProvider(cfg.OrgClient, ngov)
		})
		return resolve()
	}
}
