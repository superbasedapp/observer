package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Stale local disables on a managed node (2026-11-12 operator rulings:
// "Enterprise has absolute visibility" and stale entries of an older build
// do not persist). On a managed node, with or without an org guard bundle in
// force, the guard ignores a `[guard.rules] disable` entry for any built-in
// or rule-pack rule (internal/guard managedlock.go). The daemon removes those
// entries from the node's own config file at start, beside the config
// auto-migration, and again from the policy-state report whenever it finds
// one (a node that enrolled as managed while the daemon ran, or an entry
// added since), so the file says what the node runs; it logs what it
// removed, records a guard event (which reaches the organization on the
// guard_events push) and keeps the record the guard policy-state row reports
// (removed_disables, gen9). An individual node is untouched.

// managedDisableRemoval is what the daemon last removed.
type managedDisableRemoval struct {
	ids []string
	at  time.Time
}

// processManagedDisableRemoval is the one record of this daemon's removal,
// read by the policy-state reporter (policystate_localrules.go). nil when the
// daemon removed nothing.
var processManagedDisableRemoval atomic.Pointer[managedDisableRemoval]

// managedDisableRemovedKind is the degraded_from token of the guard event
// the removal records.
const managedDisableRemovedKind = "managed_disable_removed"

// stripManagedGuardDisables removes the stale managed-node disables from the
// global config file at configPath and reports whether it removed any. g is
// the daemon's guard (its tenancy decides what is stale); cfg is the config
// as loaded. Fail-open: an error is logged and the caller continues, and the
// guard ignores the entries either way. The write holds the config lock and
// keeps its own backup (config.RemoveGuardRuleDisables).
func stripManagedGuardDisables(ctx context.Context, configPath string, cfg config.Config, g *guard.Guard, st *store.Store, logger *slog.Logger) bool {
	if g == nil {
		return false
	}
	if logger == nil {
		logger = slog.Default()
	}
	stale := g.ManagedIgnoredConfigDisables(cfg.Guard.Rules.Disable)
	if len(stale) == 0 {
		return false
	}
	path, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		logger.Warn("guard: could not resolve the config file to remove stale rule disables", "err", err)
		return false
	}
	removed, err := config.RemoveGuardRuleDisables(path, stale)
	if err != nil {
		logger.Warn("guard: could not remove stale rule disables from the config file; the guard ignores them", "rules", stale, "err", err)
		return false
	}
	if len(removed) == 0 {
		return false
	}
	now := time.Now().UTC()
	logger.Info("guard: removed rule disables your organization does not allow on this managed machine",
		"rules", removed, "config", path, "backup", config.GuardStripBackupPath(path))
	processManagedDisableRemoval.Store(&managedDisableRemoval{ids: removed, at: now})
	if st != nil {
		if _, err := st.PersistGuardVerdicts(ctx, []guard.ActionVerdict{managedDisableRemovedVerdict(removed, now)}); err != nil {
			logger.Warn("guard: record the removed rule disables", "err", err)
		}
	}
	return true
}

// managedDisableRemovedVerdict is the guard event of a removal: a guard_error
// flag (nothing was blocked) naming the removed rule ids, degraded_from
// managed_disable_removed, so it reaches the organization on the normal
// guard_events push.
func managedDisableRemovedVerdict(ids []string, at time.Time) guard.ActionVerdict {
	return guard.ActionVerdict{
		Input:    guard.ActionInput{Tool: "observer", Target: "config.toml", Timestamp: at},
		Kind:     policy.KindConfigChange,
		Category: "guard",
		Verdict: policy.Verdict{
			Decision: policy.DecisionFlag,
			RuleID:   guard.GuardErrorRuleID,
			Severity: policy.SeverityWarn,
			Reason: fmt.Sprintf("removed local rule disables your organization does not allow on this managed machine: %s",
				strings.Join(ids, ", ")),
			Advice: "Your organization manages every built-in rule on this machine. Ask an admin to change a rule in the organization's guard policy instead.",
			Source: policy.SourceBuiltin,
		},
		GuardError:   true,
		DegradedFrom: managedDisableRemovedKind,
	}
}
