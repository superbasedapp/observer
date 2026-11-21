package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// newObsCmd is the parent for obs-subsystem CLI surfaces that are naturally
// namespaced under obs (admission spec §14 Q1 — nested `observer obs admission
// …` is honest about the [observability] gate). The eval plane keeps its
// established top-level `observer eval` spelling as the documented form; a
// HIDDEN `observer obs eval` alias (plane-separation audit L7) makes the obs
// namespace internally consistent without moving the canonical spelling. Both
// funnel through the same requireObsEnabled gate.
func newObsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "obs",
		Short: "Observability subsystem surfaces (requires [observability] enabled)",
	}
	cmd.AddCommand(newAdmissionCmd())
	cmd.AddCommand(newObsAlertsCmd())
	cmd.AddCommand(newObsEgressCmd())
	cmd.AddCommand(newObsTracesCmd())
	cmd.AddCommand(newObsPromptsCmd())
	cmd.AddCommand(newObsViewsCmd())
	evalAlias := newEvalCmd()
	evalAlias.Hidden = true
	cmd.AddCommand(evalAlias)
	return cmd
}

// newAdmissionCmd is the input-admission CLI. It funnels every obs access
// through the build-tagged wrappers in obs_wire.go, so this file imports no
// internal/obs package (the separability boundary, obs plan §2.3/§11).
func newAdmissionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admission",
		Short: "Input-admission gate: status, dry-run test, and policy lint",
		Long: "Evaluate incoming user requests to a co-resident agentic app against\n" +
			"an admin policy (requires [observability] enabled). P1 is observe-only:\n" +
			"verdicts are recorded but never enforced.",
	}
	cmd.AddCommand(newAdmissionStatusCmd(), newAdmissionTestCmd(), newAdmissionLintCmd(),
		newAdmissionSetupCmd(), newAdmissionSimulateCmd(), newAdmissionBudgetCmd(),
		newAdmissionCalibrateCmd(), newAdmissionVerifyCmd())
	return cmd
}

// admissionVerifyRow is one line of the `observer obs admission verify` report:
// a named check with a PASS/FAIL/WARN/SKIP status and a one-line detail.
type admissionVerifyRow struct {
	Check  string
	Status string // PASS | FAIL | WARN | SKIP
	Detail string
}

// newAdmissionVerifyCmd is the end-to-end admission self-check referenced by
// the status output (`audit chain BROKEN — run observer obs admission verify`).
// It (a) lints the compiled policy, (b) pings the configured judge endpoint
// with a trivial judgment (degrading gracefully when the judge is disabled),
// and (c) verifies the tamper-evident audit chain, then prints a PASS/FAIL
// table. It exits non-zero when any check FAILs (a fatal lint issue, an
// unreachable configured judge, or a diverged audit chain) so it is script-
// usable. It records nothing.
func newAdmissionVerifyCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "End-to-end self-check: policy lint, judge reachability, and audit-chain integrity",
		Long: "Run a fast end-to-end health check of the admission gate: lint the\n" +
			"policy, ping the configured judge endpoint with a trivial judgment\n" +
			"(skipped when no judge is configured - the deterministic layers still\n" +
			"work), and verify the tamper-evident audit chain. Prints a PASS/FAIL\n" +
			"table and exits non-zero if any check fails. Records nothing.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireObsEnabled(cfg); err != nil {
				return err
			}
			rows, fatalLint := runAdmissionVerify(cmd.Context(), cfg, database)
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "  %-20s %-6s %s\n", "CHECK", "STATUS", "DETAIL")
			failed := 0
			for _, r := range rows {
				fmt.Fprintf(out, "  %-20s %-6s %s\n", r.Check, r.Status, r.Detail)
				if r.Status == "FAIL" {
					failed++
				}
			}
			for _, is := range fatalLint {
				fmt.Fprintf(out, "  - %s\n", is)
			}
			if failed > 0 {
				fmt.Fprintf(out, "\noverall: FAIL (%d check(s) failed)\n", failed)
				return fmt.Errorf("admission verify: %d check(s) failed", failed)
			}
			fmt.Fprintln(out, "\noverall: PASS")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

// runAdmissionVerify assembles the verify report rows and returns them together
// with any FATAL lint messages (listed under the table). It goes only through
// the build-tagged obs wrappers, so this file imports no internal/obs package.
func runAdmissionVerify(ctx context.Context, cfg config.Config, database *sql.DB) ([]admissionVerifyRow, []string) {
	rows := make([]admissionVerifyRow, 0, 3)
	admissionOn := cfg.Observability.Admission.Enabled

	// (a) policy lint.
	issues, fatal := obsAdmissionLintCLI(cfg)
	var fatalMsgs []string
	for _, is := range issues {
		if strings.HasPrefix(is, "FATAL") {
			fatalMsgs = append(fatalMsgs, is)
		}
	}
	switch {
	case fatal:
		rows = append(rows, admissionVerifyRow{"policy lint", "FAIL", fmt.Sprintf("%d fatal issue(s) - see below", len(fatalMsgs))})
	case len(issues) > 0:
		rows = append(rows, admissionVerifyRow{"policy lint", "PASS", fmt.Sprintf("no fatal issues (%d warning(s))", len(issues))})
	default:
		rows = append(rows, admissionVerifyRow{"policy lint", "PASS", "no lint issues"})
	}

	// (b) judge reachability — a trivial ping through the configured judge.
	probe := obsAdmissionProbeJudge(ctx, cfg)
	switch {
	case probe.Off:
		rows = append(rows, admissionVerifyRow{"judge reachability", "SKIP", "no judge configured - deterministic layers only"})
	case probe.Err != "":
		rows = append(rows, admissionVerifyRow{"judge reachability", "FAIL", fmt.Sprintf("%s (%s) unreachable: %s", probe.Model, probe.Hosting, truncateVerifyErr(probe.Err))})
	default:
		rows = append(rows, admissionVerifyRow{"judge reachability", "PASS", fmt.Sprintf("%s (%s) replied in %dms", probe.Model, probe.Hosting, probe.LatencyMS)})
	}

	// (c) audit-chain integrity — only meaningful when admission is enabled and
	// the policy compiles (the status wrapper builds the service to read it).
	if !admissionOn {
		rows = append(rows, admissionVerifyRow{"audit chain", "SKIP", "admission disabled ([observability.admission] enabled = false)"})
		return rows, fatalMsgs
	}
	info, err := obsAdmissionStatusCLI(ctx, cfg, database, slog.Default())
	switch {
	case err != nil:
		rows = append(rows, admissionVerifyRow{"audit chain", "WARN", "obs store unreadable: " + truncateVerifyErr(err.Error())})
	case info.Mode == "off":
		// Service is nil: policy failed to compile (lint FAIL already covers the
		// why) — nothing to verify.
		rows = append(rows, admissionVerifyRow{"audit chain", "SKIP", "policy did not compile - fix lint issues first"})
	case !info.ChainOK:
		rows = append(rows, admissionVerifyRow{"audit chain", "FAIL", fmt.Sprintf("hash chain DIVERGED (%d rows) - tamper/corruption signal", info.ChainRows)})
	default:
		rows = append(rows, admissionVerifyRow{"audit chain", "PASS", fmt.Sprintf("%d rows, hash chain intact", info.ChainRows)})
	}
	return rows, fatalMsgs
}

// truncateVerifyErr keeps a verify-table detail on one line.
func truncateVerifyErr(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= 120 {
		return s
	}
	return s[:117] + "..."
}

// newAdmissionCalibrateCmd probes whether the configured judge model judges an
// NL policy acceptably within a latency target (admission spec §14 Q2). It runs
// a built-in battery through the judge with the verdict cache disabled, reports
// the latency distribution + degraded verdicts, and prints a recommendation.
// `--model` overrides the judge model so an operator can probe a candidate
// smaller/faster model one at a time. Records nothing.
func newAdmissionCalibrateCmd() *cobra.Command {
	var (
		configPath string
		model      string
		targetMS   int64
	)
	cmd := &cobra.Command{
		Use:   "calibrate",
		Short: "Probe the judge model's latency + judging fitness against a target (records nothing)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireObsEnabled(cfg); err != nil {
				return err
			}
			res, err := obsAdmissionCalibrateCLI(cmd.Context(), cfg, database, slog.Default(), model, targetMS)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if res.Off {
				fmt.Fprintln(out, res.Reason)
				return nil
			}
			fmt.Fprintf(out, "judge model:    %s (%s)\n", res.Model, res.Hosting)
			fmt.Fprintf(out, "probes:         %d   judge invoked: %d   degraded: %d\n", res.Probes, res.JudgeUsed, res.Degraded)
			fmt.Fprintf(out, "latency:        p50=%dms  p95=%dms  max=%dms  (target %dms)\n", res.P50MS, res.P95MS, res.MaxMS, res.TargetMS)
			fmt.Fprintf(out, "decisions:      ")
			for _, d := range sortedIntMapKeys(res.Decisions) {
				fmt.Fprintf(out, "%s=%d ", d, res.Decisions[d])
			}
			fmt.Fprintln(out)
			for _, p := range res.PerProbe {
				deg := ""
				if p.Degraded != "" {
					deg = "  degraded=" + p.Degraded
				}
				fmt.Fprintf(out, "  %-16s %-6s judge=%t %5dms%s\n", p.Label, p.Decision, p.JudgeUsed, p.LatencyMS, deg)
			}
			fmt.Fprintf(out, "\n%s\n", res.Verdict)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&model, "model", "", "override the judge model for this run (probe a candidate model)")
	cmd.Flags().Int64Var(&targetMS, "target-ms", 1500, "acceptable p95 judge latency in ms (spec §14 Q2 default 1500)")
	return cmd
}

// newAdmissionBudgetCmd surfaces the per-end-user budget guardrail: configured
// caps + the top spenders per window + the 24h would-block tally.
func newAdmissionBudgetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "budget",
		Short: "Per-end-user spend budgets/limits (5h / weekly / monthly)",
	}
	cmd.AddCommand(newAdmissionBudgetStatusCmd())
	return cmd
}

func newAdmissionBudgetStatusCmd() *cobra.Command {
	var configPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show configured caps, top end-user spenders per window, and 24h breaches",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireObsEnabled(cfg); err != nil {
				return err
			}
			st, err := obsAdmissionBudgetStatusCLI(cmd.Context(), cfg, database, slog.Default(), limit)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "budget gate:    %s\n", enabledLabel(st.Enabled))
			fmt.Fprintf(out, "caps ($/user):  5h=%s  weekly=%s  monthly=%s\n",
				capLabel(st.FiveHourUSD), capLabel(st.WeeklyUSD), capLabel(st.MonthlyUSD))
			fmt.Fprintf(out, "proxy header:   %s\n", st.UserHeader)
			fmt.Fprintf(out, "breaches (24h): %d\n", st.Breaches24h)
			if snap, aerr := orgAppBudgetForCLI(cmd.Context(), cfg, database); aerr == nil {
				for _, line := range orgAppCapLines(snap, cfg.Guard.Budget.FromOrg) {
					fmt.Fprintln(out, line)
				}
			}
			if len(st.TopSpenders) == 0 {
				fmt.Fprintln(out, "top spenders:   (none - no attributed end-user spend yet)")
				return nil
			}
			fmt.Fprintln(out, "top spenders (by month-to-date):")
			fmt.Fprintf(out, "  %-32s %10s %10s %10s\n", "end-user", "5h", "weekly", "monthly")
			for _, s := range st.TopSpenders {
				fmt.Fprintf(out, "  %-32s %10.2f %10.2f %10.2f\n", truncateUser(s.User), s.FiveHour, s.Weekly, s.Monthly)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().IntVar(&limit, "limit", 20, "max end-users to list")
	return cmd
}

// enabledLabel / capLabel / truncateUser render the budget status compactly.
func enabledLabel(b bool) string {
	if b {
		return "enabled"
	}
	return "off"
}

func capLabel(v float64) string {
	if v <= 0 {
		return "off"
	}
	// no-bare-usd:allow (Plane A admission caps, an admin-hosted app's authored dollar caps)
	return fmt.Sprintf("$%.2f", v)
}

func truncateUser(u string) string {
	if len(u) <= 32 {
		return u
	}
	return u[:29] + "..."
}

// newAdmissionSimulateCmd replays captured traffic against the current policy
// (admission spec §9) — the observe→enforce readiness check. It records
// nothing and shows the per-criterion would-block tally.
func newAdmissionSimulateCmd() *cobra.Command {
	var (
		configPath string
		limit      int
	)
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Replay captured requests against the current policy (records nothing)",
		Long: "Replay recent captured request bodies through the current admission\n" +
			"policy and report the enforce-mode decision each would receive, plus a\n" +
			"per-criterion would-block tally. Use this before flipping to enforce to\n" +
			"catch false positives. Only traffic the node retained under its content\n" +
			"posture is replayable; NL criteria make one judge call per sample.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireObsEnabled(cfg); err != nil {
				return err
			}
			res, err := obsAdmissionSimulateCLI(cmd.Context(), cfg, database, slog.Default(), limit)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if res.Disabled {
				fmt.Fprintln(out, "admission is not enabled ([observability.admission] enabled = false)")
				return nil
			}
			if res.Replayed == 0 {
				fmt.Fprintln(out, "no replayable captured traffic found (needs prompt bodies retained under the node's content posture).")
				return nil
			}
			fmt.Fprintf(out, "replayed:     %d captured request(s)\n", res.Replayed)
			if res.PolicyHash != "" {
				fmt.Fprintf(out, "policy hash:  %s\n", res.PolicyHash[:min(12, len(res.PolicyHash))])
			}
			fmt.Fprintf(out, "would block:  %d (ask+deny)\n", res.WouldBlock)
			fmt.Fprintf(out, "judge calls:  %d\n", res.JudgeCalls)
			fmt.Fprintf(out, "decisions:    allow=%d flag=%d ask=%d deny=%d\n",
				res.Decisions["allow"], res.Decisions["flag"], res.Decisions["ask"], res.Decisions["deny"])
			if len(res.PerCriterion) > 0 {
				fmt.Fprintln(out, "per-criterion (would fire):")
				for _, id := range sortedIntMapKeys(res.PerCriterion) {
					fmt.Fprintf(out, "  %-20s %d\n", id, res.PerCriterion[id])
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().IntVar(&limit, "limit", 100, "max captured requests to replay")
	return cmd
}

// sortedIntMapKeys returns a map's keys in stable ascending order
// (deterministic report output).
func sortedIntMapKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// newAdmissionSetupCmd is the admin setup wizard (docs/admission-setup.md §2).
// Zero flags on a TTY runs the interactive walkthrough; any flag (or a
// non-terminal stdin) takes the flag-driven batch path — the same idiom as
// `observer init`.
func newAdmissionSetupCmd() *cobra.Command {
	var (
		configPath   string
		purpose      string
		hosting      string
		baseURL      string
		model        string
		apiKeyEnv    string
		adopt        []string
		deniedTopics []string
		mode         string
		enableObs    bool
		assumeYes    bool
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Interactive wizard to configure usage rules + the judge LLM",
		Long: "Set up the input-admission guardrail: pick where the judge LLM runs\n" +
			"(local/no-egress by default, or a hosted provider), adopt starter usage\n" +
			"rules, and choose observe/enforce. Zero flags on a terminal runs the\n" +
			"interactive wizard; pass flags (or redirect stdin) for scripted setup.\n" +
			"Judge hosting is DERIVED from base_url - there is no hosting= field.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := resolveAdmissionConfigPath(configPath)
			if err != nil {
				return err
			}
			cfg, err := loadConfigForSetup(path)
			if err != nil {
				return err
			}
			interactive := cmd.Flags().NFlag() == 0 && setupStdinIsTerminal()
			if interactive {
				return runInteractiveAdmissionSetup(cmd.Context(), cmd.OutOrStdout(), cmd.InOrStdin(), cfg, path)
			}
			ch := admissionSetupChoices{
				EnableObs:      enableObs,
				Purpose:        purpose,
				AdoptTemplates: adopt,
				DeniedTopics:   deniedTopics,
				Mode:           mode,
			}
			if baseURL != "" || model != "" || apiKeyEnv != "" || hosting != "" {
				ch.SetJudge = true
				ch.JudgeBaseURL, ch.JudgeModel, ch.JudgeAPIKeyEnv = batchJudge(hosting, baseURL, model, apiKeyEnv)
			}
			return runBatchAdmissionSetup(cmd.OutOrStdout(), cfg, path, ch, assumeYes)
		},
	}
	f := cmd.Flags()
	f.StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")
	f.StringVar(&purpose, "purpose", "", "app purpose (seeds the on-scope valid_use_case rule)")
	f.StringVar(&hosting, "hosting", "", "judge hosting hint: local|provider|aggregator|private (fills base_url/api_key_env defaults)")
	f.StringVar(&baseURL, "base-url", "", "judge base_url (OpenAI-compatible)")
	f.StringVar(&model, "model", "", "judge model")
	f.StringVar(&apiKeyEnv, "api-key-env", "", "env var name holding the judge API key (never the key)")
	f.StringSliceVar(&adopt, "adopt", nil, "starter template keys to adopt (on_scope,denied_topics,jailbreak)")
	f.StringSliceVar(&deniedTopics, "denied-topics", nil, "topics for the denied_topics template")
	f.StringVar(&mode, "mode", "", "admission mode: observe|enforce (default observe)")
	f.BoolVar(&enableObs, "enable-obs", false, "also enable [observability] if it is off")
	f.BoolVar(&assumeYes, "yes", false, "write without the confirmation prompt (batch mode)")
	return cmd
}

// batchJudge resolves batch-mode judge fields, applying hosting-hint defaults
// so `--hosting provider --model gpt-4o-mini` needs no explicit base_url/key.
func batchJudge(hosting, baseURL, model, apiKeyEnv string) (string, string, string) {
	switch strings.ToLower(strings.TrimSpace(hosting)) {
	case "local":
		if baseURL == "" {
			baseURL = "http://127.0.0.1:11434/v1"
		}
	case "provider":
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		if apiKeyEnv == "" {
			apiKeyEnv = "OPENAI_API_KEY" //nolint:gosec // G101: env var NAME to read at run time, not a secret
		}
	case "aggregator":
		if baseURL == "" {
			baseURL = "https://openrouter.ai/api/v1"
		}
		if apiKeyEnv == "" {
			apiKeyEnv = "OPENROUTER_API_KEY" //nolint:gosec // G101: env var NAME to read at run time, not a secret
		}
	}
	return baseURL, model, apiKeyEnv
}

// runBatchAdmissionSetup applies the flag-driven choices, lints, and either
// writes (with --yes) or prints the resolved posture as a dry run.
func runBatchAdmissionSetup(out io.Writer, cfg config.Config, path string, ch admissionSetupChoices, assumeYes bool) error {
	newCfg := applyAdmissionSetup(cfg, ch)
	issues, fatal := obsAdmissionLintCLI(newCfg)
	for _, is := range issues {
		fmt.Fprintf(out, "lint: %s\n", is)
	}
	if fatal {
		return fmt.Errorf("admission policy has fatal lint issues - not written")
	}
	printAdmissionSummary(out, newCfg)
	if !assumeYes {
		fmt.Fprintf(out, "\ndry run - re-run with --yes to write %s\n", path)
		return nil
	}
	if err := writeAdmissionSetup(path, cfg, newCfg); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s (a .bak backup was kept).\n", path)
	return nil
}

func newAdmissionStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show mode, criteria, judge hosting, 24h verdicts, and chain health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireObsEnabled(cfg); err != nil {
				return err
			}
			info, err := obsAdmissionStatusCLI(cmd.Context(), cfg, database, slog.Default())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "mode:           %s\n", info.Mode)
			fmt.Fprintf(out, "enabled:        %t\n", info.Enabled)
			fmt.Fprintf(out, "criteria:       %d\n", info.CriteriaCount)
			fmt.Fprintf(out, "judge hosting:  %s\n", info.JudgeHosting)
			if info.PolicyHash != "" {
				fmt.Fprintf(out, "policy hash:    %s\n", info.PolicyHash[:min(12, len(info.PolicyHash))])
			}
			fmt.Fprintf(out, "verdicts (24h): allow=%d flag=%d ask=%d deny=%d\n",
				info.Decisions24h["allow"], info.Decisions24h["flag"], info.Decisions24h["ask"], info.Decisions24h["deny"])
			chain := "ok"
			if !info.ChainOK {
				chain = "BROKEN - run `observer obs admission verify`"
			}
			fmt.Fprintf(out, "audit chain:    %d rows, %s\n", info.ChainRows, chain)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

func newAdmissionTestCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "test <message>",
		Short: "Dry-run one message against the current policy (records nothing)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireObsEnabled(cfg); err != nil {
				return err
			}
			res, err := obsAdmissionTestCLI(cmd.Context(), cfg, database, slog.Default(), args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if res.Disabled {
				fmt.Fprintln(out, "admission is not enabled ([observability.admission] enabled = false)")
				return nil
			}
			fmt.Fprintf(out, "observe decision: allow (observe-only; nothing enforced or recorded)\n")
			fmt.Fprintf(out, "enforce decision: %s", res.EnforceDecision)
			if res.Criterion != "" {
				fmt.Fprintf(out, "  (criterion %s)", res.Criterion)
			}
			fmt.Fprintln(out)
			if res.Reason != "" {
				fmt.Fprintf(out, "reason:           %s\n", res.Reason)
			}
			fmt.Fprintf(out, "judge used:       %t   severity: %s   latency: %dms\n", res.JudgeUsed, res.Severity, res.LatencyMS)
			if res.Degraded != "" {
				fmt.Fprintf(out, "degraded:         %s\n", res.Degraded)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

func newAdmissionLintCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Statically check the admission policy; exit 1 on fatal problems",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			issues, fatal := obsAdmissionLintCLI(cfg)
			out := cmd.OutOrStdout()
			if len(issues) == 0 {
				fmt.Fprintln(out, "policy OK - no lint issues")
				return nil
			}
			for _, is := range issues {
				fmt.Fprintln(out, is)
			}
			if fatal {
				return fmt.Errorf("admission policy has fatal problems (%d issue(s))", countFatal(issues))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

func countFatal(issues []string) int {
	n := 0
	for _, is := range issues {
		if strings.HasPrefix(is, "FATAL") {
			n++
		}
	}
	return n
}
