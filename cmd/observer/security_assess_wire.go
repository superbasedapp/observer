//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_assess_wire.go is the cmd wiring of the agent-run security
// assessments' relaxations (docs/plans/security-assessments-module-plan-2026-11-13.md
// section 13): the guard accessor the dashboard reads before it offers a
// relaxation. The daemon-lifetime loop that ends them is in
// security_assess_loop.go (it links the dashboard package, so it has its own
// ui.dashboard tag twin). With sbo_omit_security the module's packages are not
// linked and security_assess_wire_omit.go stands in.

// securityAssessGuardTTL is how long the dashboard's guard stays built: a
// guard is built from the config, the org bundle and the tenancy, so it is
// rebuilt on a short clock rather than per plan read.
const securityAssessGuardTTL = 10 * time.Second

// dashboardRuleRelaxation is the dashboard's RuleRelaxation seam: a guard
// built the way the daemon builds one (nodeGuard: the enrolment key pin, the
// tenancy, the org bundle), asked for each rule's lock and decision in one
// project. A guard that cannot be built answers nothing, which the dashboard
// reads as locked (fail closed).
func dashboardRuleRelaxation(configPath string, database *sql.DB) func(ctx context.Context, projectRoot string, ruleIDs []string) map[string]dashapi.RuleRelaxationFact {
	var (
		mu    sync.Mutex
		built time.Time
		gd    *guard.Guard
	)
	current := func(ctx context.Context) *guard.Guard {
		mu.Lock()
		defer mu.Unlock()
		if gd != nil && time.Since(built) < securityAssessGuardTTL {
			return gd
		}
		cfg := config.Default()
		if path, err := config.ResolveGlobalPath(configPath); err == nil {
			if loaded, lerr := config.Load(config.LoadOptions{GlobalPath: path}); lerr == nil {
				cfg = loaded
			}
		}
		var st *store.Store
		if database != nil {
			st = store.New(database)
		}
		gd, built = nodeGuard(ctx, cfg, st), time.Now()
		return gd
	}
	return func(ctx context.Context, projectRoot string, ruleIDs []string) map[string]dashapi.RuleRelaxationFact {
		g := current(ctx)
		if g == nil {
			return nil
		}
		out := make(map[string]dashapi.RuleRelaxationFact, len(ruleIDs))
		for _, id := range ruleIDs {
			r := g.RuleRelaxation(id, projectRoot)
			out[id] = dashapi.RuleRelaxationFact{Lock: string(r.Lock), Cause: r.Cause, Decision: r.Decision, Known: r.Known}
		}
		return out
	}
}
