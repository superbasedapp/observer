package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newGuardCmd is the `observer guard` command tree (guard spec
// §11.1). G5 shipped the observe-phase surfaces: status, rules, test,
// lint, verify-audit; the enforcement-phase surfaces (enable/disable,
// simulate, rescan, approvals) with G8; mcp with G10; export + the
// §14.4 evidence-pack report with G16.
func newGuardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Security & control layer: status, rules, dry-runs, audit verification",
		Long: "The guard layer evaluates agent actions against a table-driven\n" +
			"policy (built-in + user + project rules), records verdicts in a\n" +
			"hash-chained audit table, and — in enforce mode — blocks at the\n" +
			"hook seam. See docs/plans/guard-layer-implementation-spec-2026-06-10.md.",
	}
	cmd.AddCommand(newGuardStatusCmd())
	cmd.AddCommand(newNodeControlProbeChildCmd())
	cmd.AddCommand(newGuardRulesCmd())
	cmd.AddCommand(newGuardTestCmd())
	cmd.AddCommand(newGuardLintCmd())
	cmd.AddCommand(newGuardVerifyAuditCmd())
	cmd.AddCommand(newGuardMCPCmd())
	cmd.AddCommand(newGuardCompileCmd())
	cmd.AddCommand(newGuardExportCmd())
	cmd.AddCommand(newGuardReportCmd())
	cmd.AddCommand(newGuardPromptCmd())
	registerGuardEnforceCmds(cmd)
	return cmd
}

// buildCLIGuard loads config and constructs the guard for a CLI
// surface (status / rules / test). Unlike the hook path this is
// allowed to fail loudly — the operator asked a question and deserves
// the real error.
func buildCLIGuard(configPath string) (config.Config, *guard.Guard, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return config.Config{}, nil, fmt.Errorf("load config: %w", err)
	}
	home, _ := os.UserHomeDir()
	g, err := guard.New(guard.Options{Config: cfg.Guard, Home: home})
	if err != nil {
		return cfg, nil, fmt.Errorf("construct guard: %w", err)
	}
	return cfg, g, nil
}

// newGuardStatusCmd implements `observer guard status`: mode, rule
// counts, policy layers, load issues, last-24h verdict counts and the
// chain quick-check — the cache-health ergonomics (spec §11.1).
func newGuardStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Guard mode, rule counts, recent verdicts, audit-chain quick check",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			cfg, g, err := buildCLIGuard(configPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Guard:        %s\n", onOff(cfg.Guard.Enabled))
			fmt.Fprintf(out, "Mode:         %s\n", cfg.Guard.Mode)
			fmt.Fprintf(out, "Strict:       %v (fail-%s on guard internal error)\n",
				cfg.Guard.Strict, map[bool]string{true: "closed", false: "open"}[cfg.Guard.Strict])
			fmt.Fprintf(out, "Rules:        %d active rows\n", g.RuleCount())
			fmt.Fprintf(out, "Taint:        %s (decay %d turns)\n", onOff(cfg.Guard.Taint.Enabled), cfg.Guard.Taint.DecayTurns)
			fmt.Fprintf(out, "Alerts:       desktop=%s min_severity=%s\n", onOff(cfg.Guard.Alerts.Desktop), cfg.Guard.Alerts.MinSeverity)
			for _, ps := range g.PolicyStates() {
				fmt.Fprintf(out, "Policy layer: %-7s %s (sha256 %.12s…)\n", ps.Layer, ps.Path, ps.ContentHash)
				// Non-fatal parse notes (org-bundle keys this binary
				// predates and ignored). The layer IS loaded — this is
				// deliberately NOT a LOAD ISSUE line.
				for _, note := range ps.Notes {
					fmt.Fprintf(out, "NOTE:         %s\n", note)
				}
			}
			for _, issue := range g.LoadIssues() {
				fmt.Fprintf(out, "LOAD ISSUE:   %s\n", issue)
			}
			// Coverage summary from the §6.5 conformance matrix: which
			// channels can actually BLOCK vs flag post-hoc (the honest
			// F2 line — most adapters are watcher-only).
			var blockers []string
			watcherOnly := 0
			seen := map[string]bool{}
			for _, e := range guard.ConformanceMatrix() {
				if e.Caps.CanBlock {
					blockers = append(blockers, e.Client+" "+strings.TrimPrefix(e.Channel, "hook:"))
				}
				if e.Channel == guard.ChannelWatcher && !seen[e.Client] {
					seen[e.Client] = true
					watcherOnly++
				}
			}
			fmt.Fprintf(out, "Enforcement:  %d block-capable channel(s): %s\n", len(blockers), strings.Join(blockers, ", "))
			fmt.Fprintf(out, "Coverage:     %d adapters captured post-hoc by the watcher (full matrix on the dashboard Security page)\n", watcherOnly)

			// DB-backed half: verdict counts + chain check. A missing/
			// unopenable DB degrades to config-only output — status
			// must work on a fresh install before first capture.
			database, err := db.Open(cmd.Context(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				fmt.Fprintf(out, "\n(DB unavailable — verdict counts and chain check skipped: %v)\n", err)
				return nil
			}
			defer database.Close()
			s := store.New(database)

			// WHICH PRICE TABLE this node's budget is enforced against
			// (pricing arc §3.3). It sits with the guard's own status
			// deliberately: `observer guard status` is where a developer
			// looks to find out what the budget rules are doing, and a cap
			// is a number in a unit. "$500/month" enforced at list prices
			// when the org negotiated 40% off is not the budget the admin
			// authored, and nothing else on this screen would say so.
			fmt.Fprintf(out, "Pricing:      %s\n", guardPricingLine(cmd.Context(), cfg, database))

			// THE ORG BUDGET POSTURE, on the screen a developer already opens
			// when their requests start being denied (finding H5). Before
			// this, the only surface carrying `budget_required` was the org
			// ADMIN's dashboard — so the developer being blocked could see
			// the deny verdicts below and nothing that said why, while the
			// one person who could see the reason was not the one hitting it.
			fmt.Fprintf(out, "Org budget:   %s\n", orgBudgetCLILine(cmd.Context(), cfg, database))
			fmt.Fprintf(out, "Node control: %s\n", nodeInterventionStatusLine(cmd.Context(), s, cfg.Observer.DBPath))

			sum, err := s.SummarizeGuardEvents(cmd.Context(), time.Now().UTC().Add(-24*time.Hour))
			if err != nil {
				return fmt.Errorf("summarize: %w", err)
			}
			fmt.Fprintf(out, "\nVerdicts (24h): %d total, %d enforced\n", sum.Total, sum.Enforced)
			for _, line := range []struct {
				label string
				m     map[string]int
			}{{"by decision", sum.ByDecision}, {"by severity", sum.BySeverity}, {"by category", sum.ByCategory}} {
				if len(line.m) == 0 {
					continue
				}
				fmt.Fprintf(out, "  %-12s %s\n", line.label+":", formatCounts(line.m))
			}

			report, err := s.VerifyGuardChain(cmd.Context())
			if err != nil {
				return fmt.Errorf("verify chain: %w", err)
			}
			if report.OK {
				fmt.Fprintf(out, "Audit chain:  OK (%d rows verified)\n", report.Checked)
			} else {
				fmt.Fprintf(out, "Audit chain:  BROKEN at id %d — %s\n", report.FirstDivergenceID, report.Detail)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// newGuardRulesCmd implements `observer guard rules [--effective]
// [--json]`: the built-in catalog, or this install's effective table
// (overrides applied, user rules included, disabled rules removed).
func newGuardRulesCmd() *cobra.Command {
	var (
		configPath string
		effective  bool
		jsonOut    bool
		markdown   bool
	)
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List the built-in rule catalog (or this install's effective table)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			infos := policy.Catalog()
			if effective {
				_, g, err := buildCLIGuard(configPath)
				if err != nil {
					return err
				}
				infos = g.EffectiveRules()
			}
			if markdown {
				_, err := io.WriteString(out, renderRuleCatalogMarkdown(infos))
				return err
			}
			if jsonOut {
				type row struct {
					ID       string `json:"id"`
					Category string `json:"category"`
					Severity string `json:"severity"`
					Observe  string `json:"observe"`
					Enforce  string `json:"enforce"`
					Source   string `json:"source"`
					Enforced bool   `json:"enforced,omitempty"`
					Doc      string `json:"doc"`
				}
				rows := make([]row, 0, len(infos))
				for _, r := range infos {
					rows = append(rows, row{
						ID: r.ID, Category: string(r.Category), Severity: r.Severity.String(),
						Observe: r.Observe.String(), Enforce: r.Enforce.String(),
						Source: r.Source, Enforced: r.Enforced, Doc: r.Doc,
					})
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			fmt.Fprintf(out, "%-7s %-12s %-9s %-9s %-9s %-8s %s\n",
				"ID", "CATEGORY", "SEVERITY", "OBSERVE", "ENFORCE", "SOURCE", "DOC")
			for _, r := range infos {
				enforce := r.Enforce.String()
				if r.Enforced {
					enforce += "!"
				}
				fmt.Fprintf(out, "%-7s %-12s %-9s %-9s %-9s %-8s %s\n",
					r.ID, r.Category, r.Severity, r.Observe, enforce, r.Source, r.Doc)
			}
			fmt.Fprintln(out, "\n('!' = per-rule enforced even in observe mode)")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&effective, "effective", false, "show THIS install's effective table (user layer + overrides applied) instead of the built-in catalog")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	cmd.Flags().BoolVar(&markdown, "markdown", false, "emit the docs/guard-rules.md catalog markdown (regenerate with `observer guard rules --markdown > docs/guard-rules.md`)")
	return cmd
}

// renderRuleCatalogMarkdown renders the rule catalog as the
// docs/guard-rules.md body. The committed doc is GENERATED from this
// — TestGuardRulesDocInSync is the drift gate, so a rule change that
// forgets to regenerate fails loudly instead of shipping a stale
// catalog.
func renderRuleCatalogMarkdown(infos []policy.RuleInfo) string {
	var b strings.Builder
	b.WriteString("# Guard rule catalog\n\n")
	b.WriteString("GENERATED — do not edit by hand. Regenerate with:\n\n")
	b.WriteString("    observer guard rules --markdown > docs/guard-rules.md\n\n")
	b.WriteString("Rule IDs are stable and never reused (guard spec §5). The\n")
	b.WriteString("Observe/Enforce columns are the mode-decision pair; observe is\n")
	b.WriteString("the fresh-install default (operator decision D2). Multi-row IDs\n")
	b.WriteString("split one catalog rule by sub-shape (e.g. read vs write) and\n")
	b.WriteString("appear once per row.\n\n")
	b.WriteString("| ID | Category | Severity | Observe | Enforce | Trigger |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range infos {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
			r.ID, r.Category, r.Severity, r.Observe, r.Enforce,
			strings.ReplaceAll(r.Doc, "|", "\\|"))
	}
	b.WriteString("\nTune rules without redefining them via `[[override]]` entries in\n")
	b.WriteString("`~/.observer/guard-policy.toml` (guard spec §4.4); disable IDs via\n")
	b.WriteString("`[guard.rules] disable`. Project policy files may only escalate\n")
	b.WriteString("(§4.6 one-way layering).\n")
	return b.String()
}

// newGuardTestCmd implements `observer guard test`: dry-run an action
// against the effective policy — "would this block?" without running
// anything (spec §11.1).
func newGuardTestCmd() *cobra.Command {
	var (
		configPath string
		filePath   string
		eventJSON  string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   `test ["<command>"]`,
		Short: "Dry-run a command, file access, or raw event against the effective policy",
		Long: "Evaluates without executing anything:\n\n" +
			"  observer guard test \"rm -rf ./build\"     # shell command\n" +
			"  observer guard test --file ~/.ssh/config  # file write\n" +
			"  observer guard test --event '{\"kind\":\"shell_exec\",\"target\":\"git push -f\"}'\n\n" +
			"The project root resolves from the current directory's git root,\n" +
			"so boundary rules behave as they would for a session in this repo.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, g, err := buildCLIGuard(configPath)
			if err != nil {
				return err
			}
			ev, err := buildTestEvent(args, filePath, eventJSON)
			if err != nil {
				return err
			}
			verdict, gerr := g.Evaluate(ev)
			if gerr != nil {
				return fmt.Errorf("guard internal error: %w", gerr)
			}

			// Second engine in enforce mode answers "would this block
			// once you flip enforce?" — the pre-enforce confidence
			// question this command exists for.
			enforceCfg := cfg.Guard
			enforceCfg.Mode = "enforce"
			home, _ := os.UserHomeDir()
			eg, err := guard.New(guard.Options{Config: enforceCfg, Home: home})
			if err != nil {
				return fmt.Errorf("construct enforce-mode guard: %w", err)
			}
			enforceVerdict, _ := eg.Evaluate(ev)

			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"kind":             string(ev.Kind),
					"target":           ev.Target,
					"project_root":     ev.ProjectRoot,
					"rule_id":          verdict.RuleID,
					"severity":         verdict.Severity.String(),
					"decision":         verdict.Decision.String(),
					"enforce_decision": enforceVerdict.Decision.String(),
					"reason":           verdict.Reason,
					"advice":           verdict.Advice,
					"source":           verdict.Source,
				})
			}
			printTestVerdict(out, cfg.Guard.Mode, ev, verdict, enforceVerdict)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&filePath, "file", "", "dry-run a file WRITE to this path instead of a command")
	cmd.Flags().StringVar(&eventJSON, "event", "", `dry-run a raw event: {"kind","target","action_type","session_id"}`)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

// buildTestEvent assembles the dry-run event from exactly one of the
// three input forms. The project root resolves from the cwd's git
// root (falling back to the cwd itself) so boundary rules behave as
// they would for a real session here.
func buildTestEvent(args []string, filePath, eventJSON string) (policy.Event, error) {
	cwd, _ := os.Getwd()
	root := cwd
	if r, ok := git.FindRoot(cwd); ok {
		root = r
	}
	base := policy.Event{
		Tool: "guard-test", SessionID: "guard-test",
		Cwd: cwd, ProjectRoot: root, Now: time.Now().UTC(),
	}
	set := 0
	if len(args) == 1 && args[0] != "" {
		set++
	}
	if filePath != "" {
		set++
	}
	if eventJSON != "" {
		set++
	}
	if set != 1 {
		return policy.Event{}, errors.New(`provide exactly one of: a "<command>" argument, --file <path>, or --event <json>`)
	}
	switch {
	case filePath != "":
		base.Kind = policy.KindFileAccess
		base.ActionType = "write_file"
		base.Target = filePath
	case eventJSON != "":
		var raw struct {
			Kind       string `json:"kind"`
			Target     string `json:"target"`
			ActionType string `json:"action_type"`
			SessionID  string `json:"session_id"`
		}
		if err := json.Unmarshal([]byte(eventJSON), &raw); err != nil {
			return policy.Event{}, fmt.Errorf("--event: %w", err)
		}
		if raw.Kind == "" || raw.Target == "" {
			return policy.Event{}, errors.New(`--event requires at least {"kind":..., "target":...}`)
		}
		base.Kind = policy.EventKind(raw.Kind)
		base.Target = raw.Target
		base.ActionType = raw.ActionType
		if raw.SessionID != "" {
			base.SessionID = raw.SessionID
		}
	default:
		base.Kind = policy.KindShellExec
		base.ActionType = "run_command"
		base.Target = args[0]
	}
	return base, nil
}

// printTestVerdict renders the human dry-run report.
func printTestVerdict(out io.Writer, mode string, ev policy.Event, v, enforceV policy.Verdict) {
	fmt.Fprintf(out, "Event:        %s %q (project root %s)\n", ev.Kind, ev.Target, ev.ProjectRoot)
	if v.RuleID == "" {
		fmt.Fprintf(out, "Verdict:      allow — no rule matched\n")
	} else {
		fmt.Fprintf(out, "Verdict:      %s (%s, severity %s, source %s)\n", v.Decision, v.RuleID, v.Severity, v.Source)
		fmt.Fprintf(out, "Reason:       %s\n", v.Reason)
		if v.Advice != "" {
			fmt.Fprintf(out, "Advice:       %s\n", v.Advice)
		}
	}
	fmt.Fprintf(out, "Current mode: %s\n", mode)
	if enforceV.Decision != v.Decision {
		fmt.Fprintf(out, "In enforce:   %s — flipping [guard] mode would change this verdict\n", enforceV.Decision)
	} else {
		fmt.Fprintf(out, "In enforce:   %s (unchanged)\n", enforceV.Decision)
	}
}

// newGuardLintCmd implements `observer guard lint`: strict-check the
// user policy file plus (when present) the current project's policy
// file. Exit 1 on any problem so it composes into pre-commit hooks.
func newGuardLintCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "lint [policy-file...]",
		Short: "Strictly check guard policy files (defaults: the user policy + this repo's project policy)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			out := cmd.OutOrStdout()

			type target struct {
				path  string
				layer string
			}
			var targets []target
			if len(args) > 0 {
				for _, a := range args {
					// Explicit files lint as the user layer (the
					// stricter project checks need root context).
					targets = append(targets, target{a, "user"})
				}
			} else {
				home, _ := os.UserHomeDir()
				if up := expandUserPolicyPath(cfg.Guard.Rules.UserPolicy, home); up != "" {
					targets = append(targets, target{up, "user"})
				}
				cwd, _ := os.Getwd()
				root := cwd
				if r, ok := git.FindRoot(cwd); ok {
					root = r
				}
				if cfg.Guard.Rules.ProjectPolicy != "" {
					targets = append(targets, target{filepath.Join(root, filepath.FromSlash(cfg.Guard.Rules.ProjectPolicy)), "project"})
				}
			}

			problems := 0
			checked := 0
			for _, tgt := range targets {
				raw, err := os.ReadFile(tgt.path)
				if errors.Is(err, os.ErrNotExist) {
					fmt.Fprintf(out, "%-8s %s — not present (ok)\n", tgt.layer, tgt.path)
					continue
				}
				if err != nil {
					fmt.Fprintf(out, "%-8s %s — read error: %v\n", tgt.layer, tgt.path, err)
					problems++
					continue
				}
				checked++
				issues := guard.Lint(raw, tgt.layer)
				if len(issues) == 0 {
					fmt.Fprintf(out, "%-8s %s — OK\n", tgt.layer, tgt.path)
					continue
				}
				for _, issue := range issues {
					fmt.Fprintf(out, "%-8s %s — %s\n", tgt.layer, tgt.path, issue)
					problems++
				}
			}
			if problems > 0 {
				return fmt.Errorf("guard lint: %d problem(s)", problems)
			}
			fmt.Fprintf(out, "lint clean (%d file(s) checked)\n", checked)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// newGuardVerifyAuditCmd implements `observer guard verify-audit`
// (spec §10.4): walk the full guard_events hash chain and report the
// first divergence. Exit 1 on a broken chain.
func newGuardVerifyAuditCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "verify-audit",
		Short: "Verify the tamper-evidence hash chain over the guard audit log",
		Long: "Walks every guard_events row in insert order, recomputing each\n" +
			"chain link (SHA-256 over the previous link + the row's canonical\n" +
			"bytes) and re-anchoring on the retention checkpoint. Reports the\n" +
			"first divergence. Tamper-EVIDENT, not tamper-proof: an attacker\n" +
			"with DB write access could recompute the whole chain — what this\n" +
			"catches is silent edits and mid-chain deletions.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			database, err := db.Open(cmd.Context(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()
			report, err := store.New(database).VerifyGuardChain(cmd.Context())
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			out := cmd.OutOrStdout()
			if report.OK {
				fmt.Fprintf(out, "audit chain OK — %d row(s) verified\n", report.Checked)
				return nil
			}
			fmt.Fprintf(out, "audit chain BROKEN — first divergence at id %d (%d row(s) walked)\n%s\n",
				report.FirstDivergenceID, report.Checked, report.Detail)
			return errors.New("guard verify-audit: chain divergence")
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// expandUserPolicyPath expands a leading ~/ against home (the same
// convention guard.New applies).
func expandUserPolicyPath(p, home string) string {
	if p == "" {
		return ""
	}
	if len(p) >= 2 && p[0] == '~' && (p[1] == '/' || p[1] == '\\') {
		if home == "" {
			return ""
		}
		return filepath.Join(home, p[2:])
	}
	return p
}

// orgBudgetCLILine composes the `observer guard status` "Org budget:" line
// and, when it is displaying a PRIMED cache rather than a live daemon fetch,
// rewrites the fetch-result tokens that would otherwise describe work this
// CLI process did not perform (2026-09-13 W7/W8
// verification finding B).
//
// guardBudgetPostureLine (orgbudget_wire.go) is the single composer of this
// line — coverage, from_org and budget_required are its verdict and stay
// untouched here. But `observer guard status` runs in the
// CLI process, never the daemon: it has made no live fetch of its own, so
// whenever this node's org_budget_cache actually holds a verified body,
// guardBudgetPostureLine necessarily reports fetch_state=unreachable for it
// (the same pair orgclient.Client.LoadPersistedBudget reports on a cold
// daemon start, for the identical reason). Printing the bare word
// "unreachable" there reads as an outage even when the daemon right beside
// it is fetching fine — exactly what the verification found on a healthy
// managed devbox, where the org's own posture row for the same node said
// fetch_state=ok, last_fetch_ok=1.
//
// This is a DISPLAY fix only: orgcontract's fetch-state vocabulary is
// untouched (adding a "primed from cache" member would be a wire change,
// out of scope here) and the daemon's own rendering path never calls this
// function, so it is byte-identical.
func orgBudgetCLILine(ctx context.Context, cfg config.Config, database *sql.DB) string {
	line := guardBudgetPostureLine(ctx, cfg, database)
	if database == nil {
		return line
	}
	// WHICH OF THIS DEVELOPER'S USAGE THE ORG'S RATES ACTUALLY PRICED (ruling
	// A3). Appended rather than folded into the composed posture because the
	// posture answers "is a cap in force" and this answers "in whose dollars";
	// it prints nothing at all when this process could not measure it.
	line += budgetPricingCoverageLine(cliBudgetPricingCoverage(ctx, cfg, database))
	cached, err := store.New(database).LoadOrgBudget(ctx)
	if err != nil || !cached.Have {
		// No verified body persisted (or the read itself failed): the line's
		// own fetch_state — disabled/unverified/the pre-first-poll default —
		// is already honest for "nothing to prime from", so it is left alone.
		return line
	}
	return rewriteCachedBudgetFetchState(line, cached)
}

// rewriteCachedBudgetFetchState replaces the fetch result a composed budget
// line derives from the CLI's cold in-memory state with an honest "cached"
// rendering. It names what was cached and when using the SAME org_budget_cache
// row internal/store/orgbudget.go::LoadOrgBudget exposes (version + fetched_at),
// and marks last_fetch_ok unknown because only the daemon performs fetches.
// It leaves the composer's enforcement verdicts untouched.
func rewriteCachedBudgetFetchState(line string, cached store.OrgBudgetCache) string {
	const fetchMarker = "fetch_state=unreachable"
	if !strings.Contains(line, fetchMarker) {
		return line
	}
	at := "an unknown time"
	if !cached.FetchedAt.IsZero() {
		at = cached.FetchedAt.UTC().Format(time.RFC3339)
	}
	replacement := fmt.Sprintf("fetch_state=cached (CLI read verified body v%d persisted at %s; daemon fetch state unavailable here)",
		cached.Version, at)
	line = strings.Replace(line, fetchMarker, replacement, 1)
	line = strings.Replace(line, "last_fetch_ok=false", "last_fetch_ok=unknown_to_cli", 1)
	return strings.Replace(line, "last_fetch_ok=true", "last_fetch_ok=unknown_to_cli", 1)
}

// onOff renders a bool as on/off for status output.
func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// formatCounts renders a count map as "k=v k=v" sorted by key for
// deterministic output.
func formatCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%s=%d", k, m[k])
	}
	return out
}
