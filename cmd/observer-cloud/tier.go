package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/enrichbudget"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// newTierCmd groups the operator verbs for the enrichment tiers (ruling
// R-AI1, migration 0078): the platform configuration that maps a tier to a
// route, an evidence budget and the session / daily / monthly token budgets.
// Like `route` and `grant-plan` they run once against the admin DSN and exit;
// no HTTP route reaches them.
func newTierCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tier",
		Short: "show or publish enrichment tiers: route, evidence budget, token budgets (operator-only)",
	}
	cmd.AddCommand(newTierShowCmd(), newTierSetCmd())
	return cmd
}

func newTierShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "list every published tier version, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()
			tiers, err := s.ListTiers(ctx)
			if err != nil {
				return err
			}
			printTiers(cmd.OutOrStdout(), tiers)
			return nil
		},
	}
}

func printTiers(w io.Writer, tiers []store.TierInfo) {
	seen := map[string]bool{}
	for _, ti := range tiers {
		t := ti.Tier
		state := "history"
		if !seen[t.Name] {
			state, seen[t.Name] = "IN FORCE", true
		}
		fmt.Fprintf(w, "%-8s v%-3d %-8s route %s, evidence %d, session %d, daily %d, monthly %d (by %s, %s)",
			t.Name, t.Version, state, t.RouteID, t.EvidenceTokens, t.SessionTokens, t.DailyTokens, t.MonthlyTokens,
			ti.PublishedBy, ti.CreatedAt.UTC().Format(time.RFC3339))
		if ti.Note != "" {
			fmt.Fprintf(w, " - %s", ti.Note)
		}
		fmt.Fprintln(w)
	}
}

// tierRequest is what the operator asked to change. A nil field keeps the
// value of the version in force.
type tierRequest struct {
	Name          string
	RouteID       *string
	Evidence      *int
	Session       *int64
	Daily         *int64
	Monthly       *int64
	CurrentExists bool
}

// planTierSet merges a request over the version in force (zero when the tier
// has none, in which case every field is required). It is pure; the route and
// attestation checks are enrichbudget.CheckTier's, run by the store when it
// publishes.
func planTierSet(current enrichbudget.Tier, req tierRequest) (enrichbudget.Tier, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return enrichbudget.Tier{}, fmt.Errorf("--tier is required (e.g. free or paid)")
	}
	next := enrichbudget.Tier{Name: name}
	if req.CurrentExists {
		next = current
		next.Name = name
	}
	missing := []string{}
	setStr := func(dst *string, v *string, flag string) {
		switch {
		case v != nil:
			*dst = strings.TrimSpace(*v)
		case !req.CurrentExists:
			missing = append(missing, flag)
		}
	}
	setInt := func(dst *int, v *int, flag string) {
		switch {
		case v != nil:
			*dst = *v
		case !req.CurrentExists:
			missing = append(missing, flag)
		}
	}
	setInt64 := func(dst *int64, v *int64, flag string) {
		switch {
		case v != nil:
			*dst = *v
		case !req.CurrentExists:
			missing = append(missing, flag)
		}
	}
	setStr(&next.RouteID, req.RouteID, "--route-id")
	setInt(&next.EvidenceTokens, req.Evidence, "--evidence-tokens")
	setInt64(&next.SessionTokens, req.Session, "--session-tokens")
	setInt64(&next.DailyTokens, req.Daily, "--daily-tokens")
	setInt64(&next.MonthlyTokens, req.Monthly, "--monthly-tokens")
	if len(missing) > 0 {
		return enrichbudget.Tier{}, fmt.Errorf("tier %q has no published version, so every field is required; missing %s", name, strings.Join(missing, ", "))
	}
	if req.CurrentExists && next == current {
		return enrichbudget.Tier{}, fmt.Errorf("nothing to change: tier %q v%d already has these values", name, current.Version)
	}
	next.Version = 0 // assigned by the store
	return next, nil
}

func newTierSetCmd() *cobra.Command {
	var (
		tierName string
		routeID  string
		evidence int
		session  int64
		daily    int64
		monthly  int64
		by       string
		note     string
		dryRun   bool
	)
	cmd := &cobra.Command{
		Use:   "set",
		Short: "publish a new tier version (refuses a route that is not active, bound, priced and attested)",
		Long: "Publish the next version of an enrichment tier. Unset flags keep the values of the\n" +
			"version in force; a tier with no version needs every flag.\n\n" +
			"A tier only SELECTS a route: it never carries an endpoint or a credential. The\n" +
			"route must already be bound (`observer-cloud route bind-*`), active and priced,\n" +
			"and this process's attestor (the same SBCI_* attestation env as serve and worker)\n" +
			"must attest it at its current generation. Rows are immutable; the highest version\n" +
			"of a tier is in force for every plan that names the tier.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()

			req := tierRequest{Name: tierName}
			if f := cmd.Flags(); f != nil {
				if f.Changed("route-id") {
					req.RouteID = &routeID
				}
				if f.Changed("evidence-tokens") {
					req.Evidence = &evidence
				}
				if f.Changed("session-tokens") {
					req.Session = &session
				}
				if f.Changed("daily-tokens") {
					req.Daily = &daily
				}
				if f.Changed("monthly-tokens") {
					req.Monthly = &monthly
				}
			}
			current, cerr := s.ResolveTier(ctx, strings.TrimSpace(tierName))
			req.CurrentExists = cerr == nil
			next, err := planTierSet(current, req)
			if err != nil {
				return err
			}
			route, err := s.RouteByID(ctx, next.RouteID)
			if err != nil {
				return fmt.Errorf("route %q: %w", next.RouteID, err)
			}
			att, err := attestRouteForTier(ctx, s, slog.Default(), route)
			if err != nil {
				return err
			}
			facts := store.RouteFactsFor(route)
			facts.Attested, facts.AttestReason = att.Verified, att.Reason
			fmt.Fprintf(out, "tier:             %s (in force: %s)\n", next.Name, describeCurrent(current, req.CurrentExists))
			fmt.Fprintf(out, "route:            %s (%s, generation %d)\n", next.RouteID, route.Deployment, route.Generation)
			fmt.Fprintf(out, "evidence budget:  %d tokens\n", next.EvidenceTokens)
			fmt.Fprintf(out, "token budgets:    session %d, daily %d, monthly %d\n", next.SessionTokens, next.DailyTokens, next.MonthlyTokens)
			fmt.Fprintf(out, "worst-case call:  %d tokens at the evidence budget\n", enrichbudget.WorstCaseForEvidenceBudget(next.EvidenceTokens, route.MaxOutputTokens))
			fmt.Fprintf(out, "attestation:      verified=%v (%s)\n", att.Verified, att.Reason)
			if err := enrichbudget.CheckTier(next, store.FeatureSessionEnrichment, facts); err != nil {
				return err
			}
			if dryRun {
				fmt.Fprintln(out, "\ndry run: nothing written")
				return nil
			}
			pub, err := s.PublishTier(ctx, store.TierPublish{
				Tier:        next,
				Attestation: store.RouteAttestation{Verified: att.Verified, Reason: att.Reason, Generation: route.Generation},
				PublishedBy: by, Note: note,
			})
			if err != nil {
				return err
			}
			detail := fmt.Sprintf(`{"tier":%q,"version":%d,"route_id":%q,"evidence_tokens":%d,"session_tokens":%d,"daily_tokens":%d,"monthly_tokens":%d}`,
				pub.Name, pub.Version, pub.RouteID, pub.EvidenceTokens, pub.SessionTokens, pub.DailyTokens, pub.MonthlyTokens)
			if err := s.RecordAudit(ctx, "", "enrichment_tier_published", detail); err != nil {
				fmt.Fprintf(out, "warning: audit row not written: %v\n", err)
			}
			fmt.Fprintf(out, "\npublished %s v%d\n", pub.Name, pub.Version)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&tierName, "tier", "", "tier name (e.g. free, paid) (required)")
	f.StringVar(&routeID, "route-id", "", "route_registry row the tier's jobs run on")
	f.IntVar(&evidence, "evidence-tokens", 0, "evidence budget: the most evidence tokens one envelope may carry")
	f.Int64Var(&session, "session-tokens", 0, "cumulative token budget of one session across its re-enrichments")
	f.Int64Var(&daily, "daily-tokens", 0, "per-account token budget per UTC day")
	f.Int64Var(&monthly, "monthly-tokens", 0, "per-account token budget per UTC calendar month")
	f.StringVar(&by, "by", "operator", "who publishes (recorded on the row)")
	f.StringVar(&note, "note", "", "why (recorded on the row)")
	f.BoolVar(&dryRun, "dry-run", false, "print the plan and the checks, write nothing")
	return cmd
}

func describeCurrent(t enrichbudget.Tier, exists bool) string {
	if !exists {
		return "none"
	}
	return fmt.Sprintf("v%d on %s", t.Version, t.RouteID)
}

// attestRouteForTier runs this process's attestor (the serve/worker wiring,
// chooseAttestor) against the route at its current generation. The family is
// the route's own dialect family, so the disclosed-only rule of its provider
// applies; an unknown dialect is refused.
func attestRouteForTier(ctx context.Context, s *store.Store, log *slog.Logger, route store.RouteInfo) (jobs.Attestation, error) {
	spec, ok := inference.SpecFor(route.Dialect)
	if !ok {
		return jobs.Attestation{}, fmt.Errorf("route %q speaks unknown dialect %q", route.RouteID, route.Dialect)
	}
	att, err := chooseAttestor(s, log, spec.Family).Attest(ctx, route, time.Now())
	if err != nil {
		return jobs.Attestation{Reason: "attestation error (fail closed): " + err.Error()}, nil
	}
	return att, nil
}
