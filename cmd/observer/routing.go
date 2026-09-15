package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newRoutingCmd is the parent for the model-routing P0 advisory
// surfaces (model-routing spec §R17.6 / §R18.1). P0 is read-side only:
// nothing under this command touches live traffic.
func newRoutingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "routing",
		Short: "Model-routing intelligence (P0: advisory only)",
		Long: "Counterfactual analysis and status for the model-routing layer\n" +
			"(docs/model-routing-spec.md). Phase P0 is advisory: simulate replays\n" +
			"recorded traffic under a policy template; no live request is touched.",
	}
	cmd.AddCommand(newRoutingSimulateCmd())
	cmd.AddCommand(newRoutingStatusCmd())
	cmd.AddCommand(newRoutingLintCmd())
	cmd.AddCommand(newRoutingSavingsCmd())
	cmd.AddCommand(newRoutingExplainCmd())
	cmd.AddCommand(newRoutingAdviseCmd())
	cmd.AddCommand(newRoutingShadowCmd())
	cmd.AddCommand(newRoutingImportBenchmarkCmd())
	cmd.AddCommand(newRoutingApplyCmd())
	cmd.AddCommand(newRoutingExportCmd())
	return cmd
}

func newRoutingStatusCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Routing layer state: phase, templates, tier table, decision-log counters (§R17.6)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			decisions, err := st.SelectRouterDecisionStats(cmd.Context())
			if err != nil {
				return err
			}
			calibrations, err := st.CountModelCalibrations(cmd.Context())
			if err != nil {
				return err
			}

			type templateInfo struct {
				Name        string `json:"name"`
				Hash        string `json:"hash"`
				Rules       int    `json:"rules"`
				Description string `json:"description"`
			}
			var templates []templateInfo
			for _, p := range routing.Templates() {
				templates = append(templates, templateInfo{
					Name: p.Name, Hash: p.Hash(), Rules: len(p.Rules), Description: p.Description,
				})
			}
			tierKeys := len(routing.NewTierResolver().Table().Known())

			if jsonOut {
				out := map[string]any{
					"phase":                  "P0",
					"mode":                   string(routing.ModeOff),
					"enforcement_available":  false,
					"templates":              templates,
					"tier_table_entries":     tierKeys,
					"turn_kind_rules":        routing.TurnKindRuleNames(),
					"router_decisions":       decisions.Count,
					"model_calibration_rows": calibrations,
				}
				if !decisions.LastTS.IsZero() {
					out["last_decision_at"] = decisions.LastTS
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}

			w := cmd.OutOrStdout()
			fmt.Fprintln(w, "Model routing — phase P0 (advisory intelligence)")
			fmt.Fprintln(w, "  mode                  off (enforcement ships in P1; nothing touches live traffic)")
			fmt.Fprintf(w, "  tier table            %d model/family placements (+ :free guard, date-strip, family ladder)\n", tierKeys)
			fmt.Fprintf(w, "  turn-kind classifier  %d ordered rules\n", len(routing.TurnKindRuleNames()))
			fmt.Fprintf(w, "  decision log          %d rows", decisions.Count)
			if !decisions.LastTS.IsZero() {
				fmt.Fprintf(w, " (last %s)", decisions.LastTS.Format("2006-01-02 15:04:05Z07:00"))
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "  calibration cells     %d (observer model-value --save-calibration writes them)\n\n", calibrations)
			fmt.Fprintln(w, "  policy templates:")
			tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
			for _, ti := range templates {
				fmt.Fprintf(tw, "    %s\t%s\t%d rules\t%s\n", ti.Name, ti.Hash, ti.Rules, ti.Description)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newRoutingLintCmd() *cobra.Command {
	var (
		policyName string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Validate a policy template's rule table (§R6.6)",
		Long: "Runs the table-driven policy checks (unique rule names, exactly-one\n" +
			"action, closed-enum kinds and reasons, targetable tiers, downshift\n" +
			"direction, shadowed/unreachable rules) and prints every finding.\n" +
			"Exits non-zero when an error-severity finding exists.",
		RunE: func(cmd *cobra.Command, args []string) error {
			policies := routing.Templates()
			if policyName != "" {
				p, ok := routing.TemplateByName(policyName)
				if !ok {
					return fmt.Errorf("unknown policy template %q (have: %v)", policyName, routing.TemplateNames())
				}
				policies = []routing.Policy{p}
			}

			type lintResult struct {
				Policy string              `json:"policy"`
				Hash   string              `json:"hash"`
				Issues []routing.LintIssue `json:"issues"`
			}
			results := make([]lintResult, 0, len(policies))
			hasErrors := false
			for _, p := range policies {
				issues := routing.LintPolicy(p)
				if routing.LintHasErrors(issues) {
					hasErrors = true
				}
				results = append(results, lintResult{Policy: p.Name, Hash: p.Hash(), Issues: issues})
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(results); err != nil {
					return err
				}
			} else {
				w := cmd.OutOrStdout()
				for _, r := range results {
					if len(r.Issues) == 0 {
						fmt.Fprintf(w, "%-12s %s  OK (%s)\n", r.Policy, r.Hash, "no findings")
						continue
					}
					fmt.Fprintf(w, "%-12s %s\n", r.Policy, r.Hash)
					for _, i := range r.Issues {
						rule := i.RuleName
						if rule == "" {
							rule = "-"
						}
						fmt.Fprintf(w, "  [%s] %s rule=%s: %s\n", i.Severity, i.Check, rule, i.Message)
					}
				}
			}
			if hasErrors {
				return fmt.Errorf("policy lint found errors")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&policyName, "policy", "", "Lint one template (default: all built-ins)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

// routingPriceFn adapts the cost engine to the routing package's
// injected pricing seam — the single place the two vocabularies meet.
func routingPriceFn(engine *cost.Engine) routing.PriceFn {
	return func(model string, u routing.PromptUsage) (float64, bool) {
		return engine.Compute(model, cost.TokenBundle{
			Input:             u.Input,
			Output:            u.Output,
			CacheRead:         u.CacheRead,
			CacheCreation:     u.CacheCreation,
			CacheCreation1h:   u.CacheCreation1h,
			Reasoning:         u.Reasoning,
			WebSearchRequests: u.WebSearchRequests,
			Fast:              u.Fast,
		})
	}
}

func newRoutingSimulateCmd() *cobra.Command {
	var (
		configPath  string
		policyName  string
		days        int
		projectRoot string
		turnKind    string
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Replay recorded turns through the decision engine under a policy template (§R18.1)",
		Long: "Replays the recorded api_turns + actions substrate through the routing\n" +
			"decision engine under a named policy template and reports what WOULD have\n" +
			"happened: reroute counts, estimated savings, cache-forfeit costs, and\n" +
			"quality-risk flags (moves lacking Model Value parity evidence). Reads\n" +
			"only — proves value before a single byte of traffic is touched.\n\n" +
			"Deterministic given (data, policy): the engine is pure and the replay\n" +
			"walks sessions in timestamp order.\n\n" +
			"--turn-kind narrows the replay to turns the §R8.2 classifier maps to\n" +
			"one kind (e.g. read_only) — useful for isolating where a template's\n" +
			"savings actually come from.\n\n" +
			"Templates: " + fmt.Sprint(routing.TemplateNames()),
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, ok := routing.TemplateByName(policyName)
			if !ok {
				return fmt.Errorf("unknown policy template %q (have: %v)", policyName, routing.TemplateNames())
			}
			if turnKind != "" && !slices.Contains(routing.AllTurnKinds(), routing.TurnKind(turnKind)) {
				return fmt.Errorf("unknown turn kind %q (have: %v)", turnKind, routing.AllTurnKinds())
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			st := store.New(database)
			facts, err := st.LoadModelValueFacts(cmd.Context(), modelvalue.LoadOptions{
				WindowDays: days, ProjectRoot: projectRoot,
			})
			if err != nil {
				return err
			}
			facts.Price = routingPriceFn(acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()))

			// Evidence for quality-risk flags comes from the Model Value
			// Report over the same window; the replay turns come from
			// the same assembly path the report classified with.
			mvReport := modelvalue.Build(facts, modelvalue.Options{})
			turns := modelvalue.AssembleSimTurns(facts, modelvalue.Options{})
			turns = modelvalue.FilterSimTurnsByKind(turns, routing.TurnKind(turnKind))
			snap := &routing.Snapshot{
				GeneratedAt: facts.GeneratedAt,
				Price:       facts.Price,
				Tiers:       routing.NewTierResolver().Table(),
			}
			rep := routing.Simulate(policy, snap, turns, mvReport.EvidenceByKindTier())

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			printSimReport(cmd.OutOrStdout(), rep, facts.WindowDays)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&policyName, "policy", "value", "Policy template to replay under (value | frugal | plan-exec)")
	cmd.Flags().IntVar(&days, "days", 30, "Evidence window in days")
	cmd.Flags().StringVar(&projectRoot, "project", "", "Filter to a project root path")
	cmd.Flags().StringVar(&turnKind, "turn-kind", "", "Replay only turns of one classified kind (plan | read_only | edit | test_run | housekeeping | subagent | long_context | unknown)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

// printSimReport renders the human view of a simulation.
func printSimReport(w io.Writer, rep routing.SimReport, windowDays int) {
	fmt.Fprintf(w, "Counterfactual replay — policy %q (hash %s, estimate %s), last %d days\n\n",
		rep.PolicyName, rep.PolicyHash, rep.EstimateVersion, windowDays)
	fmt.Fprintf(w, "  turns evaluated     %d\n", rep.TurnsEvaluated)
	fmt.Fprintf(w, "  would reroute       %d\n", rep.WouldReroute)
	fmt.Fprintf(w, "  est. net savings    $%.4f (cache forfeits of $%.4f already deducted)\n",
		rep.EstSavingsUSD, rep.CacheForfeitUSD)
	fmt.Fprintf(w, "  quality-risk flags  %d (reroutes without parity evidence — see observer model-value)\n\n",
		rep.QualityRiskFlags)

	if len(rep.ByMove) > 0 {
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  FROM\tTO\tTURNS\tEST $")
		for _, m := range rep.ByMove {
			fmt.Fprintf(tw, "  %s\t%s\t%d\t$%.4f\n", m.From, m.To, m.Count, m.EstSavingsUSD)
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}
	if len(rep.ByKind) > 0 {
		fmt.Fprintln(w, "  reroutes by turn-kind:")
		for _, k := range sortedTurnKinds(rep.ByKind) {
			risk := ""
			if n := rep.QualityRiskByKind[k]; n > 0 {
				risk = fmt.Sprintf("  (%d quality-risk)", n)
			}
			fmt.Fprintf(w, "    %-14s %d%s\n", k, rep.ByKind[k], risk)
		}
		fmt.Fprintln(w)
	}
	if len(rep.ByReason) > 0 {
		fmt.Fprintln(w, "  decisions by reason:")
		for _, rc := range sortedReasons(rep.ByReason) {
			fmt.Fprintf(w, "    %-24s %d\n", rc, rep.ByReason[rc])
		}
	}
	fmt.Fprintln(w, "\nAdvisory replay only — no live traffic was touched (P0).")
}

func sortedTurnKinds(m map[routing.TurnKind]int) []routing.TurnKind {
	out := make([]routing.TurnKind, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedReasons(m map[routing.ReasonCode]int) []routing.ReasonCode {
	out := make([]routing.ReasonCode, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
