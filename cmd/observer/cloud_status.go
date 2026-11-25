//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// --- status ----------------------------------------------------------------

func newCloudStatusCmd() *cobra.Command {
	var (
		configPath string
		baseURL    string
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show device key, credential backend, base URL, and outbox summary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			resolved := resolveCloudBaseURL(baseURL, cfg)
			gw, err := openCloudGateway(cfg, resolved, "", nil, nil)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()

			fmt.Fprintln(w, "superbased cloud (Signed-in Free) - status")
			if resolved == "" {
				fmt.Fprintf(w, "  base URL:            (unset - pass --base-url, set %s, or set [cloud].base_url in config.toml)\n", cloudBaseURLEnv)
			} else {
				fmt.Fprintf(w, "  base URL:            %s (from %s)\n", resolved, cloudBaseURLSource(baseURL, cfg))
			}
			if cfg.Cloud.AutoSync {
				fmt.Fprintf(w, "  auto-sync:           on ([cloud].auto_sync=true) - while `observer start` is running it spawns `observer cloud sync` every %d min (consent-gated: nothing is sent without a live grant). Still runs manually here.\n",
					cfg.Cloud.ResolvedCloudAutoSyncMinutes())
			} else {
				fmt.Fprintln(w, "  auto-sync:           off ([cloud].auto_sync=false) - sync only when you run `observer cloud sync`")
			}
			// SUPERSEDED by the enrichment policy below (value-upgrade plan
			// §W3, 2026-09-15): [cloud].auto_enrich is still parsed (an
			// existing config.toml with it set must not fail to load) but
			// nothing reads it anymore — background enrichment is governed
			// entirely by `observer cloud enable`'s Background flag.
			fmt.Fprintln(w, "  auto-enrich:         governed by the enrichment policy below ([cloud].auto_enrich is superseded and ignored)")
			// The developer's own `observer cloud enable`/`disable` choice
			// (migration 115) plus the last `observer cloud sync` outcome
			// (migration 117). A short-lived second DB open, degrading to the
			// honest "not set"/"never" lines on any error — the main
			// outbox-summary DB open below is unaffected.
			if _, policyDB, policyCleanup, perr := loadConfigAndDB(cmd.Context(), configPath); perr == nil {
				policySt := store.New(policyDB)
				cloudPrintEnrichPolicyLine(cmd.Context(), policySt, w)
				cloudPrintLastSyncLine(cmd.Context(), policySt, w)
				cloudPrintPlanLine(cmd.Context(), policySt, w)
				cloudPrintEvidenceBudgetLine(cmd.Context(), policySt, w)
				policyCleanup()
			} else {
				fmt.Fprintln(w, "  enrichment policy:   not set (run observer cloud enable)")
				fmt.Fprintln(w, "  last sync:           never")
				fmt.Fprintln(w, "  plan:                unknown until the next sync")
			}
			// D16 / W5: the allowance is what the last sync's GET /v1/usage
			// read reported (the plan, token and evidence-budget lines above);
			// status itself makes no network call, so it never has a live figure.
			fmt.Fprintln(w, "  allowance:           as of the last sync (plan lines above); status does not contact the service")
			fmt.Fprintf(w, "  credential backend:  %s\n", gw.CredentialBackend())
			if diag := gw.CredentialDiagnostic(); diag != "" {
				fmt.Fprintf(w, "  security:            DEGRADED - %s\n", diag)
			} else {
				fmt.Fprintln(w, "  security:            OS-backed")
			}
			fmt.Fprintf(w, "  device key:          %s\n", presentOrNot(gw.DeviceKeyPresent()))
			fmt.Fprintf(w, "  API token:           %s\n", presentOrNot(gw.APITokenPresent()))
			// The API token is short-lived (server TTL); the persisted WorkOS
			// sign-in is what an expired token is re-exchanged through. Whether
			// that self-heal is POSSIBLE is knowable locally; whether the token
			// is expired right now is not (it carries no expiry) — status never
			// makes a network call to find out, so it says exactly that much.
			fmt.Fprintf(w, "  sign-in (WorkOS):    %s\n", cloudSignInLine(gw))

			// Content-free outbox summary: how many items are awaiting a send.
			_, database, cleanup, dberr := loadConfigAndDB(cmd.Context(), configPath)
			if dberr != nil {
				fmt.Fprintf(w, "  outbox:              (unavailable: %v)\n", dberr)
				return nil
			}
			defer cleanup()
			st := store.New(database)
			items, lerr := st.ListSendableCloudOutbox(cmd.Context())
			if lerr != nil {
				fmt.Fprintf(w, "  outbox:              (unavailable: %v)\n", lerr)
				return nil
			}
			cursor, _ := st.LoadCloudResultCursor(cmd.Context(), cloudHostKey(resolved))
			fmt.Fprintf(w, "  outbox (sendable):   %d item(s)\n", len(items))
			cloudPrintGrantSummary(cmd.Context(), st, w)
			if cursor == "" {
				fmt.Fprintln(w, "  results cursor:      (none pulled yet)")
			} else {
				fmt.Fprintf(w, "  results cursor:      %s\n", cursor)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", cloudBaseURLFlagUsage("Cloud base URL"))
	return cmd
}

// cloudPrintEnrichPolicyLine prints `observer cloud status`'s "enrichment
// policy:" line: the developer's own `observer cloud enable`/`disable`
// choice (migration 115), or the honest "not set" line for a pre-115 schema
// or a schema with no row yet — the same degrade-to-empty-state convention
// every other line in this command follows.
func cloudPrintEnrichPolicyLine(ctx context.Context, st *store.Store, w io.Writer) {
	policy, ok, err := st.GetCloudEnrichPolicy(ctx)
	if err != nil || !ok {
		fmt.Fprintln(w, "  enrichment policy:   not set (run observer cloud enable)")
		return
	}
	bg := "off"
	if policy.Background {
		bg = "on"
	}
	fmt.Fprintf(w, "  enrichment policy:   %s (background %s, set %s via %s)\n",
		policy.Level, bg, cloudDisplayDay(policy.UpdatedAt), policy.Source)
}

// cloudPrintLastSyncLine prints `observer cloud status`'s "last sync:" line:
// the outcome of the most recent `observer cloud sync` run (migration 117's
// cloud_sync_last singleton, dashboard-spawned/auto-sync/manual all write the
// same row), or the honest "never" line when it has never run.
func cloudPrintLastSyncLine(ctx context.Context, st *store.Store, w io.Writer) {
	last, ok, err := st.GetCloudSyncLast(ctx)
	if err != nil || !ok {
		fmt.Fprintln(w, "  last sync:           never")
		return
	}
	state := "failed"
	if last.OK {
		state = "ok"
	}
	if last.WaitingProvider > 0 {
		fmt.Fprintf(w, "  last sync:           %s %s - %d sent, %d waiting on provider, %d results\n",
			last.FinishedAt.Local().Format("2006-01-02 15:04"), state, last.Sent, last.WaitingProvider, last.Results)
		return
	}
	fmt.Fprintf(w, "  last sync:           %s %s - %d sent, %d results\n",
		last.FinishedAt.Local().Format("2006-01-02 15:04"), state, last.Sent, last.Results)
}

// cloudPrintPlanLine prints `observer cloud status`'s "plan:" line — the
// account plan the most recent `observer cloud sync` observed via GET
// /v1/usage (migration 118's cloud_sync_last plan columns), or the honest
// "unknown until the next sync" line when no sync has ever reported one
// (including a sync whose usage fetch failed on every run so far).
func cloudPrintPlanLine(ctx context.Context, st *store.Store, w io.Writer) {
	last, ok, err := st.GetCloudSyncLast(ctx)
	if err != nil || !ok || last.PlanName == "" {
		fmt.Fprintln(w, "  plan:                unknown until the next sync")
		return
	}
	label := last.PlanLabel
	if label == "" {
		label = last.PlanName
	}
	daily := "unknown"
	if last.DailyCap != nil {
		daily = strconv.Itoa(*last.DailyCap)
	}
	monthly := "unknown"
	if last.MonthlyCap != nil {
		monthly = strconv.Itoa(*last.MonthlyCap)
	}
	digestWeekly := "unknown"
	if last.DigestWeekly != nil {
		if *last.DigestWeekly != 0 {
			digestWeekly = "included"
		} else {
			digestWeekly = "not in plan"
		}
	}
	retention := "unknown"
	if last.ResultsRetentionDays != nil {
		retention = fmt.Sprintf("%d days", *last.ResultsRetentionDays)
	}
	if last.BudgetUnit == cloudBudgetUnitTokens {
		// Plan v5 (R-AI1): no count cap; the budget is tokens, and the count
		// caps read 0, so printing them would say "0/day".
		fmt.Fprintf(w, "  plan:                %s (token budget; weekly digests %s; results kept %s)\n",
			label, digestWeekly, retention)
		fmt.Fprintf(w, "  tokens today:        %s\n", cloudTokenWindowText(last.DailyTokensUsed, last.DailyTokenBudget))
		fmt.Fprintf(w, "  tokens this month:   %s\n", cloudTokenWindowText(last.MonthlyTokensUsed, last.MonthlyTokenBudget))
		session := "unknown"
		if last.SessionTokenBudget != nil {
			session = fmt.Sprintf("%d tokens", *last.SessionTokenBudget)
		}
		fmt.Fprintf(w, "  per session:         %s in total across re-enrichments\n", session)
		return
	}
	fmt.Fprintf(w, "  plan:                %s (%s/day, %s/month; weekly digests %s; results kept %s)\n",
		label, daily, monthly, digestWeekly, retention)
}

// cloudTokenWindowText renders one token window as "used of budget, left
// remaining", or "unknown" when the last usage read did not report it.
func cloudTokenWindowText(used, budget *int64) string {
	if used == nil || budget == nil {
		return "unknown"
	}
	left := max(*budget-*used, 0)
	return fmt.Sprintf("%d of %d used, %d left", *used, *budget, left)
}

// cloudPrintEvidenceBudgetLine prints `observer cloud status`'s evidence
// budget line: the per-upload cap the preview and consent build fit to, and
// whether it came from the plan or is the default.
func cloudPrintEvidenceBudgetLine(ctx context.Context, st *store.Store, w io.Writer) {
	budget, known, err := cloudEvidenceBudget(ctx, st)
	switch {
	case err != nil:
		fmt.Fprintln(w, "  evidence budget:     unknown")
	case !known:
		fmt.Fprintf(w, "  evidence budget:     %d tokens per upload (default until a sync reads your plan)\n", budget)
	case budget <= 0:
		fmt.Fprintln(w, "  evidence budget:     none on your plan")
	default:
		fmt.Fprintf(w, "  evidence budget:     %d tokens per upload (larger sessions are sent with a smaller selection)\n", budget)
	}
}

func presentOrNot(present bool) string {
	if present {
		return "present"
	}
	return "not present"
}

// cloudSignInExpiredHint is the one user-facing recovery line for an expired
// sign-in: the API token was rejected and the self-heal could not refresh it.
const cloudSignInExpiredHint = "sign-in expired - run `observer cloud login`"

// cloudSignInLine states, without a network call, whether an expired API token
// can self-heal on this device.
func cloudSignInLine(gw *cloudgateway.Gateway) string {
	switch {
	case gw.WorkOSSignInPresent():
		return "present - an expired API token is re-exchanged automatically on the next `observer cloud` call"
	case gw.APITokenPresent():
		return "not present (a --dev-token session stores none) - when the API token expires, run `observer cloud login`"
	default:
		return "not present - run `observer cloud login`"
	}
}
