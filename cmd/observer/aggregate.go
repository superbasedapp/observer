package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/aggregate"
	"github.com/marmutapp/superbased-observer/internal/aggregateclient"
	"github.com/marmutapp/superbased-observer/internal/aggregatesource"
	"github.com/marmutapp/superbased-observer/internal/aggregatesvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// aggregate.go wires the `observer aggregate` command group — deliberately a
// DISTINCT top-level namespace from the local-only `observer report`, so
// "aggregate = the thing that (once enabled) leaves your machine" is
// unmistakable (design §9.4, Open Q10).
//
// Surface (Phase 3):
//   - preview  — PURE LOCAL trust artifact; prints the exact JSON that WOULD
//     be submitted for a finalized month. No network, no config, no state.
//   - enable   — the gate: preview + full disclosure + typed consent, then
//     records a consent receipt and flips [aggregate_share].enabled = true.
//   - disable  — revokes the receipt and flips enabled = false (revocation is
//     honest: future sharing stops; already-accepted anonymous records cannot
//     be individually located or deleted).
//   - submit   — one gated single-month submission through the egress seam,
//     recording the attempt in the node-local ledger. --dry-run builds + gates
//     without sending.
//   - status   — enabled/endpoint, consent-receipt validity, and the per-month
//     submission ledger.
//
// Phase 4: the submission LIFECYCLE (consent gate -> ledger -> egress -> mark)
// lives in the node-side collector, internal/aggregatesvc — this file only
// wires the real seams (store, aggregatesource builder, live config) into it
// and renders results. The Phase-5 daemon auto-submit tick will reuse the same
// collector via Collector.SubmitDue; wiring it onto `observer start` is
// deliberately NOT done yet.

// newAggregateCmd is the `observer aggregate` group.
func newAggregateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aggregate",
		Short: "Opt-in monthly cost aggregate (off by default; preview-mandatory before it can ever send)",
		Long: "The aggregate rail is an explicit, off-by-default path that can submit a\n" +
			"tiny monthly cost aggregate (per model-family x tool) to a superbased-\n" +
			"operated collector for the \"State of Agent Coding Costs\" report.\n\n" +
			"It carries NO stable machine identifier and NO content — only coarsened\n" +
			"per-(model-family x tool) token/cost aggregates for one finalized month.\n" +
			"`preview` prints the exact JSON that would ever leave the machine;\n" +
			"`enable` requires you to see that preview and type consent first.\n" +
			"Nothing is sent unless you enable it.",
	}
	cmd.AddCommand(
		newAggregatePreviewCmd(),
		newAggregateEnableCmd(),
		newAggregateDisableCmd(),
		newAggregateSubmitCmd(),
		newAggregateStatusCmd(),
	)
	return cmd
}

func newAggregatePreviewCmd() *cobra.Command {
	var (
		configPath string
		month      string
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Print the exact monthly aggregate JSON that WOULD be sent (local, no network)",
		Long: "Build and print the exact Submission for a FINALIZED calendar\n" +
			"month — the literal, coarsened JSON that would ever leave the machine —\n" +
			"plus a plain-English summary and the destination. Entirely local: no\n" +
			"network, and the payload carries only per-(model-family x tool)\n" +
			"aggregates with a provenance split — never project names, paths, model\n" +
			"ids, session titles, or any content.\n\n" +
			"Defaults to the most-recently-finalized month; --month YYYY-MM selects an\n" +
			"earlier finalized month (the current partial month is refused). --json\n" +
			"prints only the JSON.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, db, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			col, err := newAggregateCollector(cfg, db)
			if err != nil {
				return err
			}
			sub, err := col.Preview(cmd.Context(), month)
			if err != nil {
				return err
			}
			pretty, err := json.MarshalIndent(sub, "", "  ")
			if err != nil {
				return fmt.Errorf("aggregate preview: marshal: %w", err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				fmt.Fprintln(out, string(pretty))
				return nil
			}
			printPreviewSummary(cmd, cfg, sub)
			fmt.Fprintln(out, "\nExact JSON that WOULD be submitted (nothing is sent):")
			fmt.Fprintln(out, string(pretty))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&month, "month", "", "finalized month to preview (YYYY-MM); default = most-recently-finalized")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print only the raw JSON payload")
	return cmd
}

func newAggregateEnableCmd() *cobra.Command {
	var (
		configPath string
		yes        bool
		managed    bool
	)
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Consent to and turn on the aggregate rail (preview + disclosure + typed yes)",
		Long: "Enable the opt-in aggregate rail. This prints the current preview\n" +
			"payload and a full disclosure, then requires you to type `yes` (or pass\n" +
			"--yes for non-interactive use). On confirmation it records a consent\n" +
			"receipt pinning exactly what you consented to (schema/endpoint/registry\n" +
			"versions) and sets [aggregate_share].enabled = true.\n\n" +
			"Re-consent is required after any material change: a wire schema-version\n" +
			"bump, an endpoint change, or a tool-registry-version bump suspends\n" +
			"submission until you run `enable` again.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, db, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(db)
			out := cmd.OutOrStdout()

			// (1) Show the exact payload that would be sent.
			col, err := newAggregateCollector(cfg, db)
			if err != nil {
				return err
			}
			sub, err := col.Preview(cmd.Context(), "")
			if err != nil {
				return err
			}
			printPreviewSummary(cmd, cfg, sub)

			// (2) Full disclosure block (hashed into the receipt).
			disclosure := disclosureText(cfg.AggregateShare.Endpoint)
			fmt.Fprintln(out, "\n"+disclosure)

			// (3) Typed consent (unless --yes / --managed).
			actor := aggregate.ActorInteractive
			switch {
			case managed:
				actor = aggregate.ActorManaged
			case yes:
				actor = aggregate.ActorFlag
			}
			if !yes && !managed {
				fmt.Fprint(out, "\nType 'yes' to consent and enable the aggregate rail: ")
				var typed string
				_, _ = fmt.Fscanln(cmd.InOrStdin(), &typed)
				if strings.TrimSpace(strings.ToLower(typed)) != "yes" {
					fmt.Fprintln(out, "aborted — nothing enabled, no receipt written")
					return nil
				}
			}

			// (4) Record the consent receipt.
			now := time.Now().UTC()
			receipt := aggregate.Receipt{
				SchemaVersion:       aggregate.SchemaVersion,
				Endpoint:            aggregate.NormalizeEndpoint(cfg.AggregateShare.Endpoint),
				PricingVersion:      aggregate.PricingVersion,
				CostMethodVersion:   aggregate.CostMethodVersion(),
				ToolRegistryVersion: integration.RegistryVersion,
				Actor:               actor,
				DisclosureHash:      aggregate.HashDisclosure(disclosure),
				ScopeDBPath:         cfg.Observer.DBPath,
				ConsentedAt:         now,
			}
			if err := st.SaveConsentReceipt(cmd.Context(), receipt); err != nil {
				return err
			}

			// (5) Flip [aggregate_share].enabled = true in config.toml.
			if err := setAggregateEnabled(configPath, true); err != nil {
				return err
			}
			fmt.Fprintln(out, "\naggregate rail ENABLED — consent receipt recorded.")
			fmt.Fprintln(out, "Run `observer aggregate submit` to send a month now, or leave it to the daemon (once wired).")
			fmt.Fprintln(out, "Revoke future sharing anytime with `observer aggregate disable`.")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the interactive prompt (records actor=flag)")
	cmd.Flags().BoolVar(&managed, "managed", false, "record an admin-scope consent receipt for a managed/fleet node (actor=managed)")
	return cmd
}

func newAggregateDisableCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Revoke consent and turn the aggregate rail off (idempotent)",
		Long: "Revoke the consent receipt and set [aggregate_share].enabled = false.\n\n" +
			"HONEST REVOCATION: disabling prevents FUTURE submissions. Previously\n" +
			"accepted anonymous records cannot be individually located or deleted —\n" +
			"the rail intentionally carries no per-record handle. This revokes future\n" +
			"sharing; it does not retract past anonymous aggregates.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, db, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(db)
			if err := st.RevokeConsent(cmd.Context(), time.Now().UTC()); err != nil {
				return err
			}
			if err := setAggregateEnabled(configPath, false); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "aggregate rail DISABLED — consent revoked; no future submissions.")
			fmt.Fprintln(out, "Note: previously accepted anonymous records cannot be individually located or deleted.")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

func newAggregateSubmitCmd() *cobra.Command {
	var (
		configPath string
		month      string
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Send one finalized month's aggregate (gated by consent; --dry-run to rehearse)",
		Long: "Perform a single gated submission for a finalized month. Requires the\n" +
			"rail to be enabled AND a valid consent receipt — a schema/endpoint/\n" +
			"registry change since consent blocks the send until you re-run\n" +
			"`observer aggregate enable`.\n\n" +
			"The attempt is recorded in the node-local ledger with a random\n" +
			"submission_id that is REUSED on retry, so a lost response cannot cause a\n" +
			"double count. --dry-run builds the payload and checks the gate but sends\n" +
			"nothing.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, db, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			return runAggregateSubmit(cmd, cfg, db, month, dryRun)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&month, "month", "", "finalized month to submit (YYYY-MM); default = most-recently-finalized")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "build + gate-check the payload but send nothing")
	return cmd
}

func newAggregateStatusCmd() *cobra.Command {
	var (
		configPath string
		raw        bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show enabled/endpoint, consent-receipt validity, and the submission ledger",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, db, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			return runAggregateStatus(cmd, cfg, db, raw)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&raw, "raw", false, "print the last-built raw JSON payload (default: a regenerated summary)")
	return cmd
}

// --- shared helpers -------------------------------------------------------

// liveState assembles the current runtime posture the consent receipt is
// checked against.
func liveState(cfg config.Config) aggregate.LiveState {
	return aggregate.LiveState{
		Enabled:             cfg.AggregateShare.Enabled,
		SchemaVersion:       aggregate.SchemaVersion,
		Endpoint:            cfg.AggregateShare.Endpoint,
		ToolRegistryVersion: integration.RegistryVersion,
	}
}

// newAggregateCollector wires the Phase-4 collector (internal/aggregatesvc)
// over the REAL seams: the store's ledger + consent receipt, the
// aggregatesource joint (model x tool) read as the injected Builder, and the
// live config posture. Every `observer aggregate` surface goes through this
// one collector; the Phase-5 daemon tick reuses the exact same constructor
// (then calls Collector.SubmitDue).
func newAggregateCollector(cfg config.Config, db *sql.DB) (*aggregatesvc.Collector, error) {
	engine := acquireProcessCostEngine(context.Background(), cfg, db, slog.Default())
	return aggregatesvc.New(aggregatesvc.Config{
		Store: store.New(db),
		Build: func(ctx context.Context, month, submissionID string) (aggregate.Submission, error) {
			return aggregatesource.BuildSubmission(ctx, db, engine, aggregate.Meta{
				ObserverVersion: aggregate.CoarsenVersion(version),
				SubmissionID:    submissionID,
				Month:           month,
			})
		},
		Live: func() aggregate.LiveState { return liveState(cfg) },
	})
}

// runAggregateSubmit executes a single gated month submission through the
// collector.
func runAggregateSubmit(cmd *cobra.Command, cfg config.Config, db *sql.DB, month string, dryRun bool) error {
	out := cmd.OutOrStdout()
	col, err := newAggregateCollector(cfg, db)
	if err != nil {
		return err
	}
	res, err := col.SubmitMonth(cmd.Context(), month, dryRun)
	if err != nil {
		if errors.Is(err, aggregateclient.ErrNotConsented) {
			return fmt.Errorf("aggregate submit: %w — run `observer aggregate enable`", err)
		}
		return fmt.Errorf("aggregate submit: %w", err)
	}
	switch {
	case res.Skipped != "":
		fmt.Fprintf(out, "month %s already submitted (%d attempt(s)); nothing to do\n", res.Month, res.Attempts)
	case res.DryRun:
		printPreviewSummary(cmd, cfg, res.Sub)
		fmt.Fprintf(out, "\n[dry-run] consent OK (status=%s); would POST %d bytes to %s. Nothing sent.\n",
			res.Status, res.Bytes, res.Endpoint)
	default:
		fmt.Fprintf(out, "submitted month %s (%d cells, submission_id %s) to %s\n",
			res.Month, res.Cells, res.SubmissionID, res.Endpoint)
	}
	return nil
}

// runAggregateStatus prints the rail's current state via the collector.
func runAggregateStatus(cmd *cobra.Command, cfg config.Config, db *sql.DB, raw bool) error {
	out := cmd.OutOrStdout()
	col, err := newAggregateCollector(cfg, db)
	if err != nil {
		return err
	}
	rep, err := col.Status(cmd.Context())
	if err != nil {
		return err
	}
	status, receipt, rows := rep.Status, rep.Receipt, rep.States

	fmt.Fprintf(out, "aggregate rail\n")
	fmt.Fprintf(out, "  enabled:       %t\n", cfg.AggregateShare.Enabled)
	fmt.Fprintf(out, "  endpoint:      %s\n", cfg.AggregateShare.Endpoint)
	fmt.Fprintf(out, "  wire schema:   v%d (tool-registry v%d, pricing %s, cost-method %s)\n",
		aggregate.SchemaVersion, integration.RegistryVersion, aggregate.PricingVersion, aggregate.CostMethodVersion())
	fmt.Fprintf(out, "  consent:       %s\n", status)
	if receipt != nil {
		fmt.Fprintf(out, "    consented:   %s (actor=%s, schema v%d, endpoint %s)\n",
			receipt.ConsentedAt.Format(time.RFC3339), receipt.Actor, receipt.SchemaVersion, receipt.Endpoint)
	}
	if status != aggregate.ConsentValid && cfg.AggregateShare.Enabled {
		fmt.Fprintf(out, "    (submission is SUSPENDED until re-consent — run `observer aggregate enable`)\n")
	}

	fmt.Fprintf(out, "  submissions:   %d month(s) in the ledger\n", len(rows))
	for _, r := range rows {
		fmt.Fprintf(out, "    %s  state=%-9s attempts=%d  submission_id=%s\n", r.Month, r.State, r.Attempts, r.SubmissionID)
		if r.LastError != "" {
			fmt.Fprintf(out, "        last_error: %s\n", r.LastError)
		}
	}

	// Last-built payload: a regenerated summary by default, raw JSON only on
	// --raw (design §9.4, finding #19).
	if raw {
		for _, r := range rows {
			if r.PayloadJSON != "" {
				fmt.Fprintf(out, "\n[--raw] last built payload for %s:\n%s\n", r.Month, r.PayloadJSON)
				break
			}
		}
	}
	return nil
}

// setAggregateEnabled flips [aggregate_share].enabled in config.toml through
// the shared config-write owner (config.WriteToml's .bak + atomic rename),
// mirroring `observer config set`. Validates before persisting.
func setAggregateEnabled(configPath string, enabled bool) error {
	resolvedPath, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := config.SetConfigKey(&cfg, "aggregate_share.enabled", fmt.Sprintf("%t", enabled)); err != nil {
		return err
	}
	if err := config.Validate(cfg); err != nil {
		return fmt.Errorf("refusing to save: %w", err)
	}
	return config.WriteToml(resolvedPath, cfg)
}

// disclosureText is the full-disclosure block shown at `enable` time and
// hashed into the consent receipt (design §9.4/§9.6). Changing this wording
// changes the hash, which the receipt pins — an honest record of exactly what
// was agreed to.
func disclosureText(endpoint string) string {
	var b strings.Builder
	b.WriteString("DISCLOSURE — what enabling the aggregate rail means:\n")
	b.WriteString("  WHAT LEAVES:  once per FINALIZED calendar month, a coarsened aggregate of\n")
	b.WriteString("                per-(model-family x tool) token counts and cost, split into a\n")
	b.WriteString("                proxy-accurate and an estimated bucket. Model ids collapse to a\n")
	b.WriteString("                closed family vocabulary; rare combinations merge into \"other\".\n")
	b.WriteString("  WHAT NEVER LEAVES: project names, paths, git remotes/branches, session titles,\n")
	b.WriteString("                prompts/responses, raw model ids, timestamps finer than the month,\n")
	b.WriteString("                and any stable machine/user/org identifier.\n")
	fmt.Fprintf(&b, "  WHERE:        %s (HTTPS, no redirects, no cookies, no bearer, no enrolment).\n", endpoint)
	b.WriteString("  RESIDUAL RISK (stated honestly): a single monthly aggregate is still a\n")
	b.WriteString("                high-dimensional fingerprint. There is NO stable application\n")
	b.WriteString("                identifier, but cross-month linkage by fingerprint and network-\n")
	b.WriteString("                layer linkage (source IP, request time observed by infrastructure)\n")
	b.WriteString("                cannot be eliminated by client code alone. \"No stable application\n")
	b.WriteString("                identifier\" is the honest guarantee — not \"unlinkable\".\n")
	b.WriteString("  REVOCATION:   `observer aggregate disable` stops FUTURE sharing. Previously\n")
	b.WriteString("                accepted anonymous records cannot be individually located or deleted.\n")
	return b.String()
}

// printPreviewSummary renders the plain-English framing around the payload.
func printPreviewSummary(cmd *cobra.Command, cfg config.Config, sub aggregate.Submission) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Aggregate preview for %s\n", sub.Month)
	fmt.Fprintf(out, "  status:       enabled=%t (nothing is sent by preview)\n", cfg.AggregateShare.Enabled)
	fmt.Fprintf(out, "  destination:  %s\n", cfg.AggregateShare.Endpoint)
	fmt.Fprintf(out, "  schema v%d, tool-registry v%d, pricing %s, cost-method %s, observer %s\n",
		sub.SchemaVersion, sub.ToolRegistryVersion, sub.PricingVersion, sub.CostMethodVersion, sub.ObserverVersion)
	fmt.Fprintf(out, "  submission_id: %s (random per submission; NOT a machine identifier)\n", sub.SubmissionID)
	fmt.Fprintf(out, "  cells:         %d per-(model-family x tool) rows\n", len(sub.Cells))

	var accTurns, estTurns int64
	var accCost, estCost float64
	for _, c := range sub.Cells {
		accTurns += c.TurnsAcc
		estTurns += c.TurnsEst
		accCost += c.CostUSDAcc
		estCost += c.CostUSDEst
	}
	fmt.Fprintf(out, "  proxy-accurate: %d turns, $%.2f\n", accTurns, accCost)
	fmt.Fprintf(out, "  estimated:      %d turns, $%.2f (reported separately, never blended)\n", estTurns, estCost)
	fmt.Fprintf(out, "  never leaves the machine: project names, paths, git remotes/branches, session\n")
	fmt.Fprintf(out, "                            titles, prompts/responses, raw model ids, timestamps\n")
	fmt.Fprintf(out, "                            finer than the month, or any stable machine identifier.\n")
	if len(sub.Cells) == 0 {
		fmt.Fprintf(out, "  (no activity recorded for this month)\n")
	}
}
