package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The org's APP budgets as this machine last verified them (Plane A W4-1,
// ruling D9). The budget rail's composition (orgBudgetHandle.apply) publishes
// the verified body's app caps here; the admission check reads them through
// obs_wire_appbudget.go. It is one process-wide value with one writer (the
// rail), so the admission service never sees the rail's types.
//
// The one Enforce model: an org app cap applies only when the machine opted in
// to the org budget ([guard.budget].from_org, pinned on a managed machine) and
// holds a verified body; it is AUTHORITATIVE (the machine's own
// [observability.admission.budget] per-user caps are then not applied to a
// request an org app cap binds; every other request keeps them, ruling D29
// E-25) only on a managed machine holding enforce.budget whose verified body
// carries at least one app cap, and lowering-only everywhere else. A verified body with
// no app caps (an org with developer budgets only, a server that predates
// app_budgets.v1, or the last app budget deleted) takes nothing over: the
// machine's own caps keep applying (review finding R-C03).
// Whether a breach blocks is the admission mode ([observability.admission]
// mode = enforce), exactly as for the machine's own caps.

// orgAppBudgetSnapshot is the published value.
type orgAppBudgetSnapshot struct {
	Caps          []orgcontract.BudgetAppCap
	OrgID         string
	Apply         bool
	Authoritative bool
	FetchState    string
	At            time.Time
}

var processOrgAppBudget atomic.Pointer[orgAppBudgetSnapshot]

// publishOrgAppBudget records one rail outcome's app caps. fromOrg is the
// machine's opt-in, granted the managed enforce.budget answer the rail's own
// composition uses.
func publishOrgAppBudget(o orgclient.BudgetFetchOutcome, fromOrg, granted bool) {
	snap := &orgAppBudgetSnapshot{
		Caps:          o.Body.AppCaps,
		OrgID:         o.Body.AppOrgID,
		Apply:         fromOrg && o.HaveBody,
		Authoritative: orgAppBudgetAuthoritative(fromOrg && o.HaveBody, granted, o.Body.AppCaps),
		FetchState:    o.State,
		At:            time.Now().UTC(),
	}
	processOrgAppBudget.Store(snap)
}

// orgAppBudgetAuthoritative is the one rule for whether the org's app caps
// replace the machine's own admission budget: applied, granted (a managed
// machine holding enforce.budget) and at least one app cap to replace it
// with. An empty set never removes the machine's caps.
func orgAppBudgetAuthoritative(apply, granted bool, caps []orgcontract.BudgetAppCap) bool {
	return apply && granted && len(caps) > 0
}

// loadOrgAppBudget returns the last published snapshot, ok=false when the
// rail has published nothing yet or the machine does not apply org budgets.
func loadOrgAppBudget() (orgAppBudgetSnapshot, bool) {
	p := processOrgAppBudget.Load()
	if p == nil || !p.Apply {
		return orgAppBudgetSnapshot{}, false
	}
	return *p, true
}

// orgAppBudgetForCLI reads the org app budget from the persisted, verified
// rail document the way the daemon applies it, for a CLI process that has
// made no poll of its own (the guardBudgetPostureLine precedent: the stored
// evidence, never an invented live state).
func orgAppBudgetForCLI(ctx context.Context, cfg config.Config, database *sql.DB) (orgAppBudgetSnapshot, error) {
	if database == nil {
		return orgAppBudgetSnapshot{}, nil
	}
	granted := budgetEnforcementGranted(ctx, cfg, database, slog.Default())
	var (
		cached store.OrgBudgetCache
		err    error
	)
	if granted {
		cached, err = loadVerifiedOrgBudgetCache(ctx, cfg, store.New(database))
	} else {
		cached, err = loadCurrentBoundOrgBudgetCache(ctx, store.New(database))
	}
	if err != nil {
		return orgAppBudgetSnapshot{}, err
	}
	apply := cfg.Guard.Budget.FromOrg && cached.Have
	return orgAppBudgetSnapshot{
		Caps: cached.Body.AppCaps, OrgID: cached.Body.AppOrgID,
		Apply: apply, Authoritative: orgAppBudgetAuthoritative(apply, granted, cached.Body.AppCaps),
	}, nil
}

// orgAppCapLines renders the org app caps for the CLI, one per line. An end
// user is named only as the org-bound key's prefix: the rail never carries the
// raw id.
func orgAppCapLines(snap orgAppBudgetSnapshot, fromOrg bool) []string {
	if len(snap.Caps) == 0 {
		return []string{"org app caps:   (none from your organization)"}
	}
	head := "org app caps:   not applied ([guard.budget].from_org is off)"
	switch {
	case snap.Authoritative:
		head = "org app caps:   applied; they replace this machine's own per-user caps for the requests they cap (managed machine)"
	case snap.Apply:
		head = "org app caps:   applied where lower than this machine's own caps"
	case fromOrg:
		head = "org app caps:   not applied (no verified org budget on this machine)"
	}
	out := []string{head}
	for _, c := range snap.Caps {
		who := map[string]string{
			orgcontract.BudgetAppScopeEndUser:        "end user " + appKeyLabel(c.EndUserKey),
			orgcontract.BudgetAppScopeService:        "service " + appServiceLabel(c.Service),
			orgcontract.BudgetAppScopeEndUserService: "end user " + appKeyLabel(c.EndUserKey) + " of service " + appServiceLabel(c.Service),
		}[c.Scope]
		limit := capLabel(c.CapUSD)
		if c.Exempt() {
			limit = "no cap (exempt from the default)"
		} else if c.CapTokens > 0 {
			limit = fmt.Sprintf("%d tokens", c.CapTokens)
			if c.CapUSD > 0 {
				limit = capLabel(c.CapUSD) + " / " + limit
			}
		}
		out = append(out, fmt.Sprintf("  %-44s %-18s %-14s %s", who, limit, c.Period, c.Enforcement))
	}
	return out
}

func appKeyLabel(k string) string {
	if k == orgcontract.BudgetAppDefault {
		return "(each)"
	}
	if len(k) > 12 {
		return k[:12] + "..."
	}
	return k
}

func appServiceLabel(s string) string {
	if s == orgcontract.BudgetAppDefault {
		return "(each)"
	}
	return s
}
