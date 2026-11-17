package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// grantplan_org.go holds two operator-only verbs under grant-plan (managed-SaaS
// plan 07 wave 15 lane console-fixes):
//
//	grant-plan org        the per-org counterpart of grant-plan (W15-D13): a
//	                      catalog plan granted to ONE org, read by the
//	                      entitlements plan source after a live subscription
//	                      and before the 14-day launch window, so an internal
//	                      org stays on its plan (cloud 0095)
//	grant-plan team-orgs  raise (or lower) one account's team org cap, the
//	                      "raised on request" of W15-D12 (cloud 0094)
//
// Both are CLI verbs run against the admin DSN, never HTTP routes, like
// grant-plan itself. Every change is an append-only row with the actor
// "operator" and a required --reason, so the tables are their own audit
// trail; `show` prints it. They hang off grant-plan so main.go's command list
// is unchanged.

// orgFactsReader reads an org's kind (OrgCreateFacts as the worker role: the
// operator role sees no org rows without an account context).
type orgFactsReader interface {
	OrgCreateFacts(ctx context.Context, orgID string) (store.OrgCreateFacts, error)
}

// orgGrantStore is the operator store's org grant seam.
type orgGrantStore interface {
	GrantOrgPlan(ctx context.Context, in store.OrgPlanGrantInput, now time.Time) (store.OrgPlanGrant, *store.OrgPlanGrant, error)
	RevokeOrgPlan(ctx context.Context, orgID, reason string, now time.Time) (store.OrgPlanGrant, error)
	OrgPlanGrantHistory(ctx context.Context, orgID string) ([]store.OrgPlanGrant, error)
}

// teamOrgLimitStore is the operator store's team org cap seam.
type teamOrgLimitStore interface {
	SetTeamOrgLimit(ctx context.Context, accountID string, maxTeamOrgs int, reason string, now time.Time) (store.TeamOrgAllowance, error)
	TeamOrgLimitHistory(ctx context.Context, accountID string) ([]store.TeamOrgLimitRecord, error)
}

// orgGrantRequest is one `grant-plan org` invocation.
type orgGrantRequest struct {
	OrgID   string
	Plan    string
	Version int
	Until   string // RFC3339, "" for no end
	Reason  string
}

// runOrgGrant grants req's plan to the org and prints what changed.
func runOrgGrant(ctx context.Context, out io.Writer, facts orgFactsReader, s orgGrantStore, req orgGrantRequest, now time.Time) error {
	orgID := strings.TrimSpace(req.OrgID)
	if orgID == "" {
		return errors.New("--org is required (the org UUID)")
	}
	if strings.TrimSpace(req.Plan) == "" {
		return errors.New("--plan is required (a catalog plan of the org's kind, e.g. team)")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return errors.New("--reason is required (it is kept with the grant)")
	}
	var until time.Time
	if u := strings.TrimSpace(req.Until); u != "" {
		t, err := time.Parse(time.RFC3339, u)
		if err != nil {
			return fmt.Errorf("--until %q must be RFC3339 (e.g. 2027-01-01T00:00:00Z): %w", u, err)
		}
		until = t
	}
	f, err := facts.OrgCreateFacts(ctx, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no org %s", orgID)
	}
	if err != nil {
		return fmt.Errorf("read the org: %w", err)
	}
	g, prev, err := s.GrantOrgPlan(ctx, store.OrgPlanGrantInput{
		OrgID: orgID, Kind: f.Kind, Plan: req.Plan, Version: req.Version, Until: until, Reason: req.Reason,
	}, now)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no org %s", orgID)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "observer-cloud: org %s (%s, %s) granted plan %s v%d %s; was %s\n",
		orgID, f.Slug, f.Kind, g.PlanName, g.PlanVersion, untilText(g.EffectiveUntil), grantStateText(prev, now))
	fmt.Fprintln(out, "  a live subscription still wins; the next entitlements issuer pass (worker) issues the document")
	return nil
}

// runOrgRevoke ends the org's grant in force.
func runOrgRevoke(ctx context.Context, out io.Writer, s orgGrantStore, orgID, reason string, now time.Time) error {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return errors.New("--org is required (the org UUID)")
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("--reason is required (it is kept with the revoke)")
	}
	g, err := s.RevokeOrgPlan(ctx, orgID, reason, now)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("org %s has no plan grant in force (or no such org)", orgID)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "observer-cloud: org %s plan grant revoked (was %s v%d); the org falls back to its subscription, launch window or floor at the next issuer pass\n",
		orgID, g.PlanName, g.PlanVersion)
	return nil
}

// runOrgGrantShow prints an org's grant history, newest first.
func runOrgGrantShow(ctx context.Context, out io.Writer, s orgGrantStore, orgID string, now time.Time) error {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return errors.New("--org is required (the org UUID)")
	}
	rows, err := s.OrgPlanGrantHistory(ctx, orgID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintf(out, "observer-cloud: org %s has no plan grant\n", orgID)
		return nil
	}
	fmt.Fprintf(out, "observer-cloud: org %s: %s\n", orgID, grantStateText(&rows[0], now))
	for _, g := range rows {
		what := "revoke"
		if g.Action == store.OrgPlanGrantActionGrant {
			what = fmt.Sprintf("grant %s v%d %s", g.PlanName, g.PlanVersion, untilText(g.EffectiveUntil))
		}
		fmt.Fprintf(out, "  %s  %s  by %s: %s\n", g.At.UTC().Format(time.RFC3339), what, g.Actor, g.Reason)
	}
	return nil
}

func untilText(u *time.Time) string {
	if u == nil {
		return "with no end"
	}
	return "until " + u.UTC().Format(time.RFC3339)
}

// grantStateText words the newest grant row at now.
func grantStateText(g *store.OrgPlanGrant, now time.Time) string {
	switch {
	case g == nil:
		return "no grant"
	case g.InForce(now):
		return fmt.Sprintf("in force: %s v%d %s", g.PlanName, g.PlanVersion, untilText(g.EffectiveUntil))
	case g.Action == store.OrgPlanGrantActionGrant:
		return fmt.Sprintf("ended: %s v%d %s", g.PlanName, g.PlanVersion, untilText(g.EffectiveUntil))
	default:
		return "revoked"
	}
}

// runTeamOrgLimit sets one account's team org cap.
func runTeamOrgLimit(ctx context.Context, out io.Writer, s teamOrgLimitStore, accountID string, maxTeamOrgs int, reason string, now time.Time) error {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return errors.New("--account is required (the account UUID)")
	}
	if maxTeamOrgs < 0 {
		return errors.New("--max is required (0 to bar the account, else the new cap)")
	}
	if strings.TrimSpace(reason) == "" {
		return errors.New("--reason is required (it is kept with the change)")
	}
	prev, err := s.SetTeamOrgLimit(ctx, accountID, maxTeamOrgs, reason, now)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no account %s", accountID)
	}
	if err != nil {
		return err
	}
	was := fmt.Sprintf("%d (the default)", prev.Limit)
	if prev.Raised {
		was = fmt.Sprintf("%d", prev.Limit)
	}
	fmt.Fprintf(out, "observer-cloud: account %s may hold %d team orgs (was %s); orgs it already holds are kept\n",
		accountID, maxTeamOrgs, was)
	return nil
}

// runTeamOrgLimitShow prints one account's cap history, newest first.
func runTeamOrgLimitShow(ctx context.Context, out io.Writer, s teamOrgLimitStore, accountID string) error {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return errors.New("--account is required (the account UUID)")
	}
	rows, err := s.TeamOrgLimitHistory(ctx, accountID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintf(out, "observer-cloud: account %s has the default cap of %d team orgs\n", accountID, store.DefaultMaxTeamOrgs)
		return nil
	}
	fmt.Fprintf(out, "observer-cloud: account %s may hold %d team orgs\n", accountID, rows[0].MaxTeamOrgs)
	for _, r := range rows {
		fmt.Fprintf(out, "  %s  set %d  by %s: %s\n", r.At.UTC().Format(time.RFC3339), r.MaxTeamOrgs, r.Actor, r.Reason)
	}
	return nil
}

// newGrantPlanOrgCmd is `grant-plan org` and its revoke and show verbs.
func newGrantPlanOrgCmd() *cobra.Command {
	var req orgGrantRequest
	cmd := &cobra.Command{
		Use:   "org",
		Short: "grant a catalog plan to one org (operator only; read before the launch window)",
		Long: "Grant a catalog plan of the org's kind to one org (lead decision W15-D13).\n\n" +
			"The entitlements plan source reads it after a live subscription and before\n" +
			"the 14-day launch window, so an internal org stays on its plan. Every grant\n" +
			"and revoke is kept, with its reason (`grant-plan org show`). No payment is\n" +
			"taken and none is implied.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			app, worker, closeFn, err := openOrgGrantStores(ctx)
			if err != nil {
				return err
			}
			defer closeFn()
			return runOrgGrant(ctx, cmd.OutOrStdout(), worker, app, req, time.Now())
		},
	}
	cmd.Flags().StringVar(&req.OrgID, "org", "", "org UUID (required)")
	cmd.Flags().StringVar(&req.Plan, "plan", "", "catalog plan name of the org's kind, e.g. team (required)")
	cmd.Flags().IntVar(&req.Version, "version", 0, "catalog plan version (default 0 = the highest; the grant records the concrete version)")
	cmd.Flags().StringVar(&req.Until, "until", "", "RFC3339 instant the grant ends (default: no end, until revoked)")
	cmd.Flags().StringVar(&req.Reason, "reason", "", "why the org gets this plan (required, kept with the grant)")

	var revokeOrg, revokeReason string
	revoke := &cobra.Command{
		Use:   "revoke",
		Short: "end one org's plan grant",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runOrgRevoke(cmd.Context(), cmd.OutOrStdout(), s, revokeOrg, revokeReason, time.Now())
		},
	}
	revoke.Flags().StringVar(&revokeOrg, "org", "", "org UUID (required)")
	revoke.Flags().StringVar(&revokeReason, "reason", "", "why the grant ends (required)")

	var showOrg string
	show := &cobra.Command{
		Use:   "show",
		Short: "print one org's plan grant history",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runOrgGrantShow(cmd.Context(), cmd.OutOrStdout(), s, showOrg, time.Now())
		},
	}
	show.Flags().StringVar(&showOrg, "org", "", "org UUID (required)")
	cmd.AddCommand(revoke, show)
	return cmd
}

// openOrgGrantStores opens the operator store and, over the same DSN, a
// worker-role store for the org's kind (the deploy's one login can assume
// every application role; serve and worker already do).
func openOrgGrantStores(ctx context.Context) (app, worker *store.Store, closeFn func(), err error) {
	dsn, err := envDSN()
	if err != nil {
		return nil, nil, nil, err
	}
	app, err = openStoreForRole(ctx, store.RoleApp, dsn)
	if err != nil {
		return nil, nil, nil, err
	}
	worker, err = store.NewForRole(app.Pool(), store.RoleWorker)
	if err != nil {
		app.Pool().Close()
		return nil, nil, nil, err
	}
	return app, worker, func() { app.Pool().Close() }, nil
}

// newGrantPlanTeamOrgsCmd is `grant-plan team-orgs` and its show verb.
func newGrantPlanTeamOrgsCmd() *cobra.Command {
	var (
		account string
		maxOrgs int
		reason  string
	)
	cmd := &cobra.Command{
		Use:   "team-orgs",
		Short: "set how many team orgs one account may hold (default 3; raised on request)",
		Long: fmt.Sprintf("Set one account's team org cap (lead decision W15-D12; default %d).\n\n"+
			"The console refuses a create past the cap with 409 team_org_limit and says\n"+
			"it can be raised on request; this is that raise. Lowering it below what\n"+
			"the account holds keeps its orgs and blocks only further creates. Every\n"+
			"change is kept with its reason (`grant-plan team-orgs show`).", store.DefaultMaxTeamOrgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runTeamOrgLimit(cmd.Context(), cmd.OutOrStdout(), s, account, maxOrgs, reason, time.Now())
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "account UUID (required)")
	cmd.Flags().IntVar(&maxOrgs, "max", -1, fmt.Sprintf("the new cap, 0 to %d (required)", store.MaxTeamOrgsCeiling))
	cmd.Flags().StringVar(&reason, "reason", "", "why (required, kept with the change)")

	var showAccount string
	show := &cobra.Command{
		Use:   "show",
		Short: "print one account's team org cap history",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			return runTeamOrgLimitShow(cmd.Context(), cmd.OutOrStdout(), s, showAccount)
		},
	}
	show.Flags().StringVar(&showAccount, "account", "", "account UUID (required)")
	cmd.AddCommand(show)
	return cmd
}
