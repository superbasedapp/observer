//go:build !sbo_omit_security && !sbo_omit_ui_dashboard

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_assess_loop.go is the daemon-lifetime loop that ends an agent-run
// security assessment's relaxations (plan section 13.5). It builds the
// reconcile pass's ports from the dashboard package (the audit rows and the
// approval statements live beside the routes), so it exists only where the
// dashboard is linked: a process without ui.dashboard owns no live terminals,
// and security_assess_loop_omit.go stands in. security_assess_wire.go keeps
// the guard accessor, which needs neither.

// securityAssessTerminalFunc adapts the dashboard's session resolver (nil when
// this process owns no terminals) to the reconcile pass's terminal port.
func securityAssessTerminalFunc(res func(string) (dashapi.TerminalSessionLink, bool)) dashboard.TerminalFunc {
	if res == nil {
		return nil
	}
	return func(handle string) (bool, string, float64) {
		link, live := res(handle)
		if !live {
			return false, "", 0
		}
		return true, link.SessionID, link.Confidence
	}
}

// securityAssessRetentionDays reads evidence_retention_days from the node's
// config (the defaults when it cannot be read: keep).
func securityAssessRetentionDays(configPath string) int {
	path, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return 0
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return 0
	}
	return cfg.Security.Assessments.EvidenceRetentionDays
}

// startSecurityAssessRelax starts the security.assessrelax loop on ng: one
// reconcile pass at startup, then one every minute, over the run record beside
// the database. It exists only in the process that owns the live terminals (res
// non-nil): a process that cannot see a terminal must not say it is gone.
// Every pass is idempotent; a failure is kept on the relaxation it concerns.
func startSecurityAssessRelax(ctx context.Context, ng *gatedGroup, configPath, dbPath string, database *sql.DB, res func(string) (dashapi.TerminalSessionLink, bool), closeTerminal func(string)) {
	term := securityAssessTerminalFunc(res)
	if term == nil || database == nil || dbPath == "" {
		return
	}
	ng.Go("security.assessrelax", func() error {
		runs := secassesssvc.Shared(secassesssvc.Path(dbPath))
		ports := dashboard.SecAssessFullPorts(store.New(database), term, runs, dashboard.SecAssessExtra{
			Close: closeTerminal, RetentionDays: func() int { return securityAssessRetentionDays(configPath) }, Snapshots: true,
		})
		pass := func() {
			pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if n := secassesssvc.Reconcile(pctx, runs, ports); n > 0 {
				slog.Default().Debug("security assessments: relaxations reconciled", "runs", n)
			}
		}
		pass()
		t := time.NewTicker(secassess.ReconcileEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
				pass()
			}
		}
	})
}
