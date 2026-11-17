package main

import (
	"context"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Gen9 guard-row input (2026-11-12 operator ruling: "Enterprise has
// absolute visibility, so any changes that are happening, especially on the
// policy front, have to be available to the org"): the rule changes a
// managed machine makes for itself, and the stale disables the daemon
// removed at start (guard_managed_disables.go), carried on the gen3
// LocalGuard posture as orgcontract.LocalRuleChange rows.

// localRuleProjectRootLimit is how many project roots a report reads policy
// files for: every root the node knows (G14, managed policy visibility; a
// root with no policy file costs one failed stat per file), bounded only so a
// corrupt store cannot make a report unbounded. The wire bound is
// orgcontract.MaxLocalRuleChanges, and a node past either says so in
// rule_changes_truncated.
const localRuleProjectRootLimit = 100000

// localRuleReport is one report's gen9 content.
type localRuleReport struct {
	changes   []orgcontract.LocalRuleChange
	truncated bool
	removed   []string
	removedAt time.Time
	inputs    *orgcontract.LocalGuardInputs
	node      *orgcontract.LocalNodePosture
}

// localNodePostureFrom summarises the node-local settings that shape policy
// and enforcement (gen9, orgcontract.LocalNodePosture): switches, config
// enums, backend ids, counts and list shapes. No path, host, tool name or
// pattern leaves this function.
func localNodePostureFrom(cfg config.Config) *orgcontract.LocalNodePosture {
	b := cfg.Guard.Budget
	caps := 0
	for _, set := range []bool{
		b.SessionUSD > 0, b.DailyUSD > 0, b.WeeklyUSD > 0, b.MonthlyUSD > 0,
		b.SessionTokens > 0, b.DailyTokens > 0, b.WeeklyTokens > 0, b.MonthlyTokens > 0,
	} {
		if set {
			caps++
		}
	}
	window := orgcontract.LocalListDefault
	if w := b.Window; w.Util5hWarn > 0 || w.Util5hDeny > 0 || w.UtilWeeklyWarn > 0 || w.UtilWeeklyDeny > 0 {
		window = orgcontract.LocalListCustom
	}
	workspace := orgcontract.LocalListDefault
	if strings.TrimSpace(cfg.Workspace.DefaultDir) != "" {
		workspace = orgcontract.LocalListCustom
	}
	sb := cfg.Terminal.Sandbox
	n := &orgcontract.LocalNodePosture{
		GuardLevel:                localNodeToken(cfg.Guard.Level),
		GuardStrict:               cfg.Guard.Strict,
		RulesCEL:                  cfg.Guard.Rules.CEL,
		EvasionWindowSeconds:      clampCount(cfg.Guard.Rules.EvasionWindowSeconds),
		PromptHookLane:            cfg.Guard.Prompt.HookLane,
		PromptProxyLane:           cfg.Guard.Prompt.ProxyLane,
		PromptEnforceIndependent:  cfg.Guard.Prompt.EnforceIndependent,
		PromptSuppressInCode:      cfg.Guard.Prompt.SuppressInCode,
		BudgetLocalCaps:           caps,
		BudgetWindow:              window,
		BudgetHard:                b.Hard,
		BudgetFromOrg:             b.FromOrg,
		BudgetFailClosed:          b.FailClosed,
		RoutingEnabled:            cfg.Routing.Enabled,
		RoutingMode:               localNodeToken(cfg.Routing.Mode),
		RoutingPolicy:             localNodeToken(cfg.Routing.Policy),
		RoutingRuleCount:          clampCount(len(cfg.Routing.Rules)),
		LaunchAllowFreshAgent:     cfg.Terminal.Launch.AllowFreshAgent,
		LaunchAllowShell:          cfg.Terminal.Launch.AllowShell,
		LaunchAllowInstall:        cfg.Terminal.Launch.AllowInstall,
		LaunchAllowedTools:        clampCount(len(cfg.Terminal.Launch.AllowedTools)),
		LaunchAllowedProjectRoots: clampCount(len(cfg.Terminal.Launch.AllowedProjectRoots)),
		DefaultWorkspace:          workspace,
		ProxyEnabled:              cfg.Proxy.Enabled,
		ProxyMaintainRoutes:       cfg.Proxy.MaintainRoutes,
		ProxyRequireClientAuth:    cfg.Proxy.RequireClientAuth,
		HooksAutoRegister:         cfg.Observer.Hooks.AutoRegister,
		HooksPeriodicRegister:     localNodeToken(cfg.Observer.Hooks.PeriodicRegister),
		HooksTimeoutMS:            clampCount(cfg.Observer.Hooks.TimeoutMS),
		SandboxEnabled:            sb.Enabled,
		SandboxDefaultOn:          sb.DefaultOn,
		SandboxBackend:            localNodeToken(sb.Backend),
		SandboxEgress:             localNodeToken(sb.Egress),
		SandboxMinIsolation:       localNodeToken(sb.MinIsolation),
		MCPRelayEnabled:           cfg.MCPRelay.Enabled,
		MCPRelayMode:              localNodeToken(cfg.MCPRelay.Mode),
		MCPRelayAuditMode:         localNodeToken(cfg.MCPRelay.AuditMode),
		Share:                     localShareSwitches(cfg.OrgClient.Share),
	}
	for _, id := range sb.Backends {
		if t := localNodeToken(id); t != "" && len(n.SandboxBackends) < orgcontract.MaxLocalNodeListLen {
			n.SandboxBackends = append(n.SandboxBackends, t)
		}
	}
	return n
}

// localNodeToken is a config enum or id as the wire carries it: lowercase,
// and "" when it does not fit the closed token shape (the loader refuses
// such values, so this is a hand-built config).
func localNodeToken(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if !orgcontract.LocalNodeTokenOK(t) {
		return ""
	}
	return t
}

// clampCount bounds a count to the wire range.
func clampCount(n int) int {
	switch {
	case n < 0:
		return 0
	case n > orgcontract.MaxLocalGuardInputCount:
		return orgcontract.MaxLocalGuardInputCount
	}
	return n
}

// localShareSwitches is every boolean [org_client.share] switch by its TOML
// key (a nested table's keys dotted under its name), read off the struct so
// the key set is the config's own closed vocabulary.
func localShareSwitches(share config.OrgClientShareConfig) map[string]bool {
	out := map[string]bool{}
	var walk func(v reflect.Value, prefix string)
	walk = func(v reflect.Value, prefix string) {
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			key := strings.Split(t.Field(i).Tag.Get("toml"), ",")[0]
			if key == "" || key == "-" {
				continue
			}
			switch f := v.Field(i); f.Kind() {
			case reflect.Bool:
				if len(out) < orgcontract.MaxLocalNodeListLen {
					out[prefix+key] = f.Bool()
				}
			case reflect.Struct:
				walk(f, prefix+key+".")
			}
		}
	}
	walk(reflect.ValueOf(share), "")
	if len(out) == 0 {
		return nil
	}
	return out
}

// localGuardInputsFrom summarises a [guard] config's engine inputs as the
// gen9 wire shape: list shapes and counts, closed enums and bools. No path,
// host, branch name or pattern leaves this function.
func localGuardInputsFrom(gc config.GuardConfig) *orgcontract.LocalGuardInputs {
	action := gc.Proxy.EgressAction
	if action != "flag" && action != "mask" && action != "deny" {
		// The loader refuses any other value; report the weakest reading.
		action = "flag"
	}
	return &orgcontract.LocalGuardInputs{
		BoundaryAllowPaths:       localListShape(gc.Boundary.AllowPaths),
		BoundaryAllowCount:       len(gc.Boundary.AllowPaths),
		ProtectedBranches:        localListShape(gc.Boundary.ProtectedBranches),
		NetworkAllowCount:        len(gc.Network.AllowHosts),
		NetworkDenyCount:         len(gc.Network.DenyHosts),
		DatabaseProdPatternCount: len(gc.Database.ProdPatterns),
		EgressScan:               gc.Proxy.EgressScan,
		EgressAction:             action,
		EgressAllowCount:         len(gc.Proxy.EgressAllow),
		ResponseScan:             gc.Proxy.ResponseScan,
		InjectionHeuristics:      gc.Proxy.InjectionHeuristics,
		TaintEnabled:             gc.Taint.Enabled,
		MCPPinning:               gc.MCP.Pinning,
		MCPPoisoningHeuristics:   gc.MCP.PoisoningHeuristics,
	}
}

// localListShape is a config list's shape: unset (nil) keeps the built-in
// list, an explicitly empty list means none.
func localListShape(list []string) string {
	switch {
	case list == nil:
		return orgcontract.LocalListDefault
	case len(list) == 0:
		return orgcontract.LocalListNone
	}
	return orgcontract.LocalListCustom
}

// withLocalRuleChanges decorates the guard point reader with the gen9 local
// rule report: report(ctx) fills it, and it lands on the LocalGuard posture
// the reader already carries (a copy; the reader's value is not modified). A
// row with no LocalGuard posture (a config that did not load) carries none.
// nil leaves the reader unchanged.
func withLocalRuleChanges(r policystate.PointReader, report func(ctx context.Context) localRuleReport) policystate.PointReader {
	if report == nil {
		return r
	}
	return func(ctx context.Context) (policystate.PointFacts, error) {
		f, err := r(ctx)
		if err != nil || f.LocalGuard == nil {
			return f, err
		}
		rep := report(ctx)
		lg := *f.LocalGuard
		lg.RuleChanges, lg.RuleChangesTruncated = rep.changes, rep.truncated
		lg.Inputs = rep.inputs
		lg.Node = rep.node
		if n := len(rep.removed); n > 0 {
			if n > orgcontract.MaxRemovedDisables {
				n = orgcontract.MaxRemovedDisables
			}
			lg.RemovedDisables = append([]string(nil), rep.removed[:n]...)
			lg.RemovedDisablesAt = rep.removedAt.UTC().Format(time.RFC3339)
		}
		f.LocalGuard = &lg
		return f, nil
	}
}

// localRuleReportFrom builds the gen9 report from the daemon's live guard
// (its org layer and tenancy judge each change), the config as the hook path
// loads it now (configPath), the store's recently active project roots and
// the roots the trusted per-project layer names itself (guard
// LocalRuleChanges). It reports only on a managed node: an individual node
// keeps the posture it reported before gen9. Before it reads, it strips the
// config's stale managed-node disables (stripManagedGuardDisables), so a
// node that became managed while the daemon ran, or an entry added since
// start, leaves the file at the next report rather than the next start. A
// nil guard reports nothing.
func localRuleReportFrom(g *guard.Guard, st *store.Store, configPath func() string, logger *slog.Logger) func(ctx context.Context) localRuleReport {
	if g == nil {
		return nil
	}
	return func(ctx context.Context) localRuleReport {
		if in := g.OrgLockInputs(); !in.TenancyResolved || !in.Managed {
			return localRuleReport{}
		}
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath()})
		if err == nil && stripManagedGuardDisables(ctx, configPath(), cfg, g, st, logger) {
			cfg, err = config.Load(config.LoadOptions{GlobalPath: configPath()})
		}
		var rep localRuleReport
		if rec := processManagedDisableRemoval.Load(); rec != nil {
			rep.removed, rep.removedAt = rec.ids, rec.at
		}
		if err != nil {
			return rep
		}
		var roots []string
		moreRoots := false
		if st != nil {
			// One past the bound tells a node with more projects apart, so
			// the org reads the list as partial.
			roots, _ = st.RecentProjectRoots(ctx, localRuleProjectRootLimit+1)
			if len(roots) > localRuleProjectRootLimit {
				roots, moreRoots = roots[:localRuleProjectRootLimit], true
			}
		}
		rep.node = localNodePostureFrom(cfg)
		rep.changes, rep.truncated = g.LocalRuleChanges(cfg.Guard, roots, store.ProjectIdentityHash)
		rep.truncated = rep.truncated || moreRoots
		rep.inputs = localGuardInputsFrom(cfg.Guard)
		return rep
	}
}
