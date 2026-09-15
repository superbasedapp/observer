package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// newGrantPlanCmd is the operator-only entitlement-plan assignment path (W4
// deliverable 4, ruling R4). It is a CLI verb, run against the admin DSN, and
// deliberately NOT an HTTP route: there is no payment rail yet, so a beta grant
// must be an operator act, never something a signed-in user can trigger. When
// billing lands (W9/Paddle) the subscription webhook becomes a second FEED into
// the same store.AssignPlan seam, not a competing writer.
//
// Timing follows R4 and is enforced by the store: an upgrade takes effect
// immediately (mid-cycle), a downgrade is floored at the next monthly cycle
// boundary.
func newGrantPlanCmd() *cobra.Command {
	var (
		account   string
		plan      string
		version   int
		effective string
	)
	cmd := &cobra.Command{
		Use:   "grant-plan",
		Short: "assign an entitlement plan to an account (operator beta grant; no billing rail)",
		Long: "Assign an entitlement plan to an account.\n\n" +
			"Upgrades take effect immediately; downgrades are deferred to the next\n" +
			"monthly cycle boundary (ruling R4). This is entitlement plumbing only —\n" +
			"no payment is taken and none is implied.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			accountID := strings.TrimSpace(account)
			if accountID == "" {
				return fmt.Errorf("--account is required (the account UUID)")
			}
			planName := strings.TrimSpace(plan)
			if planName == "" {
				return fmt.Errorf("--plan is required (e.g. %s or %s)", store.PlanFree, store.PlanPlusBeta)
			}
			var from time.Time
			if s := strings.TrimSpace(effective); s != "" {
				t, err := time.Parse(time.RFC3339, s)
				if err != nil {
					return fmt.Errorf("--effective-from %q must be RFC3339 (e.g. 2026-10-01T00:00:00Z): %w", s, err)
				}
				from = t
			}

			s, err := openStore(ctx)
			if err != nil {
				return err
			}
			defer s.Pool().Close()

			res, err := s.AssignPlan(ctx, accountID, planName, version, from, time.Now())
			if err != nil {
				return err
			}
			timing := "effective immediately"
			if res.Deferred {
				timing = "DEFERRED to the next cycle boundary (this assignment lowers a cap)"
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"observer-cloud: account %s → plan %s v%d %q (was %s v%d); %s, from %s\n",
				accountID, res.Plan.Name, res.Plan.Version, res.Plan.Label,
				res.PreviousPlan.Name, res.PreviousPlan.Version,
				timing, res.EffectiveFrom.UTC().Format(time.RFC3339))
			fmt.Fprintf(cmd.OutOrStdout(),
				"  caps: %d/day, %d/month, concurrency %d; budget pool %q\n",
				res.Plan.DailyCap, res.Plan.MonthlyCap, res.Plan.ConcurrencyCap, res.Plan.BudgetPool)
			return nil
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "account UUID to assign the plan to (required)")
	cmd.Flags().StringVar(&plan, "plan", "", "plan name, e.g. plus_beta or free (required)")
	cmd.Flags().IntVar(&version, "version", store.LatestPlanVersion,
		"plan version to pin (default 0 = the highest published version of that name)")
	cmd.Flags().StringVar(&effective, "effective-from", "",
		"RFC3339 instant the assignment starts (default: as soon as R4 allows)")
	return cmd
}
