package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/marmutapp/superbased-observer/internal/guardtest"
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
			"hash-chained audit table, and - in enforce mode - blocks at the\n" +
			"hook seam. See docs/plans/guard-layer-implementation-spec-2026-06-10.md.",
	}
	cmd.AddCommand(newGuardStatusCmd())
	cmd.AddCommand(newNodeControlProbeChildCmd())
	cmd.AddCommand(newGuardRulesCmd())
	cmd.AddCommand(newGuardTestCmd())
	cmd.AddCommand(newGuardLintCmd())
	cmd.AddCommand(newGuardVerifyAuditCmd())
	cmd.AddCommand(newGuardDedupEventsCmd())
	cmd.AddCommand(newGuardRepairAnchorsCmd())
	cmd.AddCommand(newGuardRelinkGapsCmd())
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
			// D-672: the managed-node floor and the org bundle state are
			// visible where the developer looks (empty on a node with no
			// org lock).
			for _, line := range guardOrgLockLines(cfg.Guard.Lock, g.OrgLockStatus()) {
				fmt.Fprintln(out, line)
			}
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
			// The org's project_unknown decision, while its bundle carries
			// the project audience (lane sec-p2a).
			if v, ok := g.OrgProjectUnknown(); ok {
				fmt.Fprintf(out, "Project floor: project_unknown = %q (the org bundle's [project_audience]; where a project bundle reaches you and its policy cannot be confirmed, ask asks on an individual node and blocks on a managed one)\n", v)
			}
			// The project half of the org bundle cache (lane sec-p, audit
			// finding 4): a mapped project with no envelope file.
			for _, issue := range g.OrgProjectCacheIssues() {
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
				fmt.Fprintf(out, "\n(DB unavailable - verdict counts and chain check skipped: %v)\n", err)
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
				fmt.Fprintf(out, "Audit chain:  BROKEN at id %d - %s\n", report.FirstDivergenceID, report.Detail)
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

// shellDialectNote is the catalog's note on which shell a command is read
// as (PSRULES lane: the git hook bypass rules met PowerShell on Windows,
// JSP-6 live half).
const shellDialectNote = "\n## Shell dialects\n\n" +
	"Shell rules read a command the way the shell that runs it reads it.\n" +
	"A shell tool named PowerShell or pwsh (Claude Code's PowerShell tool on\n" +
	"Windows, for one) is read as PowerShell. A shell tool with a generic\n" +
	"name (Bash, shell) whose working directory is a Windows one (a drive\n" +
	"letter or UNC path) is read both ways, POSIX and PowerShell, and a hit\n" +
	"in either reading counts: Codex and Copilot CLI ran every command\n" +
	"through Windows PowerShell 5.1 on Windows. The PowerShell reading knows\n" +
	"single, double and here-string (`@'...'@`, `@\"...\"@`) quoting,\n" +
	"backtick escapes and line continuations, comments (`#`, `<# #>`), `;`\n" +
	"and pipelines, the `&` call operator, environment changes (`$env:NAME =`,\n" +
	"`Set-Item env:`, `New-Item -Path Env:`,\n" +
	"`[Environment]::SetEnvironmentVariable`) and `NUL` as the null device.\n" +
	"Nested `cmd /c`, `powershell -Command` / `-EncodedCommand`, `pwsh -c`,\n" +
	"`Invoke-Expression`, script blocks and `Start-Process -ArgumentList`\n" +
	"payloads are read too, to a bounded depth. A line past the parser's\n" +
	"bounds is marked unanalyzed and held by R-157, as on the POSIX path;\n" +
	"it is never silently allowed. R-112, R-113, R-114 and R-165 carry\n" +
	"PowerShell rows, including the commands captured live on Windows, in\n" +
	"their test corpus.\n\n" +
	"When a command is read both ways, a rule's reason quotes the PowerShell\n" +
	"reading, which keeps a Windows path's backslashes (the POSIX reading of\n" +
	"`C:\\Users\\dev` is `C:Usersdev`); a hit in either reading still counts.\n" +
	"`observer guard test` reads a command the same way: on a Windows\n" +
	"directory both ways, and `--shell posix|powershell|cmd` names one shell.\n" +
	"A UNC path (`\\\\server\\share\\x`) is a Windows path of its own: it is\n" +
	"outside every drive or POSIX project, a bare share is a filesystem root,\n" +
	"and it compares case-sensitively with another UNC path.\n"

// guardPackCatalogMarkdown renders the rows of the rule packs this build
// carries beyond the built-in catalog (the install gate's S-741 to S-749,
// set by security_deps.go); "" when none.
var guardPackCatalogMarkdown = func() string { return "" }

// guardCommitGateCatalogMarkdown renders the commit gate's section (S-791
// to S-794, set by security_gate_doc.go); "" when the build has no
// security module.
var guardCommitGateCatalogMarkdown = func() string { return "" }

// renderRuleCatalogMarkdown renders the rule catalog as the
// docs/guard-rules.md body. The committed doc is GENERATED from this
// — TestGuardRulesDocInSync is the drift gate, so a rule change that
// forgets to regenerate fails loudly instead of shipping a stale
// catalog.
func renderRuleCatalogMarkdown(infos []policy.RuleInfo) string {
	var b strings.Builder
	b.WriteString("# Guard rule catalog\n\n")
	b.WriteString("GENERATED - do not edit by hand. Regenerate with:\n\n")
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
	b.WriteString(guardPackCatalogMarkdown())
	b.WriteString(guardCommitGateCatalogMarkdown())
	b.WriteString("\nTune rules without redefining them via `[[override]]` entries in\n")
	b.WriteString("`~/.observer/guard-policy.toml` (guard spec §4.4); disable IDs via\n")
	b.WriteString("`[guard.rules] disable`. Project policy files may only escalate\n")
	b.WriteString("(§4.6 one-way layering).\n")
	b.WriteString(shellDialectNote)
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
		shell      string
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
			"so boundary rules behave as they would for a session in this repo.\n\n" +
			"A command is read as POSIX, and in a Windows directory also as\n" +
			"PowerShell, as a hook reads a generic shell tool there; --shell\n" +
			"posix|powershell|cmd reads it under that shell only.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			dialect, ok := guardtest.ShellDialect(shell)
			if !ok {
				return fmt.Errorf("--shell %q: want posix, powershell or cmd", shell)
			}
			ev, err := buildTestEvent(args, filePath, eventJSON, dialect)
			if err != nil {
				return err
			}
			// guardtest.Run evaluates under the configured mode AND in
			// enforce ("would this block once you flip enforce?" - the
			// pre-enforce confidence question this command exists for).
			// The Security page's Test a command card runs the same call.
			home, _ := os.UserHomeDir()
			res, err := guardtest.Run(cfg.Guard, home, nil, ev)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(res.Report())
			}
			printTestVerdict(out, cfg.Guard.Mode, ev, res.Verdict, res.EnforceVerdict)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&filePath, "file", "", "dry-run a file WRITE to this path instead of a command")
	cmd.Flags().StringVar(&eventJSON, "event", "", `dry-run a raw event: {"kind","target","action_type","session_id"}`)
	cmd.Flags().StringVar(&shell, "shell", "", "read the command under this shell only: posix, powershell or cmd")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

// buildTestEvent assembles the dry-run event from exactly one of the
// three input forms. The project root resolves from the cwd's git
// root (falling back to the cwd itself) so boundary rules behave as
// they would for a real session here.
func buildTestEvent(args []string, filePath, eventJSON string, dialect policy.Dialect) (policy.Event, error) {
	cwd, _ := os.Getwd()
	root := cwd
	if r, ok := git.FindRoot(cwd); ok {
		root = r
	}
	base := guardtest.Base(cwd, root, time.Now().UTC())
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
		return guardtest.FileWrite(base, filePath), nil
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
		return guardtest.Raw(base, raw.Kind, raw.Target, raw.ActionType, raw.SessionID), nil
	default:
		return guardtest.CommandIn(base, args[0], dialect), nil
	}
}

// printTestVerdict renders the human dry-run report.
func printTestVerdict(out io.Writer, mode string, ev policy.Event, v, enforceV policy.Verdict) {
	fmt.Fprintf(out, "Event:        %s %q (project root %s)\n", ev.Kind, ev.Target, ev.ProjectRoot)
	if v.RuleID == "" {
		fmt.Fprintf(out, "Verdict:      allow - no rule matched\n")
	} else {
		fmt.Fprintf(out, "Verdict:      %s (%s, severity %s, source %s)\n", v.Decision, v.RuleID, v.Severity, v.Source)
		fmt.Fprintf(out, "Reason:       %s\n", v.Reason)
		if v.Advice != "" {
			fmt.Fprintf(out, "Advice:       %s\n", v.Advice)
		}
	}
	fmt.Fprintf(out, "Current mode: %s\n", mode)
	if enforceV.Decision != v.Decision {
		fmt.Fprintf(out, "In enforce:   %s - flipping [guard] mode would change this verdict\n", enforceV.Decision)
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
			home, _ := os.UserHomeDir()

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
				// The dashboard-authored trusted per-project layer for THIS
				// repo. It lints via the org-aware guard.LintTrustedProject
				// (not the plain Lint) so a trusted relaxation of an
				// org-floored rule surfaces here instead of a false PASS: a
				// standalone Lint(raw, "trusted_project") has no org context
				// and cannot see the floor the runtime engine correctly
				// enforces (F3).
				if tp := guard.TrustedProjectPolicyPath(cfg.Guard, home, root); tp != "" {
					targets = append(targets, target{tp, "trusted_project"})
				}
			}

			problems := 0
			checked := 0
			for _, tgt := range targets {
				raw, err := os.ReadFile(tgt.path)
				if errors.Is(err, os.ErrNotExist) {
					fmt.Fprintf(out, "%-8s %s - not present (ok)\n", tgt.layer, tgt.path)
					continue
				}
				if err != nil {
					fmt.Fprintf(out, "%-8s %s - read error: %v\n", tgt.layer, tgt.path, err)
					problems++
					continue
				}
				checked++
				var issues []string
				if tgt.layer == "trusted_project" {
					// Org-aware: reads the configured org bundle so an
					// org-floor violation is caught, matching the runtime
					// per-project engine build and the dashboard save-gate.
					issues = guard.LintTrustedProject(cfg.Guard, home, raw)
				} else {
					issues = guard.Lint(raw, tgt.layer)
				}
				if len(issues) == 0 {
					fmt.Fprintf(out, "%-8s %s - OK\n", tgt.layer, tgt.path)
					continue
				}
				for _, issue := range issues {
					fmt.Fprintf(out, "%-8s %s - %s\n", tgt.layer, tgt.path, issue)
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
			"with DB write access could recompute the whole chain - what this\n" +
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
				fmt.Fprintf(out, "audit chain OK - %d row(s) verified\n", report.Checked)
				return nil
			}
			fmt.Fprintf(out, "audit chain BROKEN - first divergence at id %d (%d row(s) walked)\n%s\n",
				report.FirstDivergenceID, report.Checked, report.Detail)
			fmt.Fprintln(out, formatGuardBreaks(report.Breaks))
			return errors.New("guard verify-audit: chain divergence")
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// formatGuardBreaks renders a verify report's per-class break counts, in a
// stable order.
func formatGuardBreaks(breaks map[string]int) string {
	classes := make([]string, 0, len(breaks))
	for class := range breaks {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	parts := make([]string, 0, len(classes))
	for _, class := range classes {
		parts = append(parts, fmt.Sprintf("%s %d", class, breaks[class]))
	}
	return "failing rows by class: " + strings.Join(parts, ", ")
}

// newGuardDedupEventsCmd builds `observer guard dedup-events`: remove the
// repeated watcher-path guard_events rows a re-parse wrote before the
// insertSingleAction fix (2026-10-21) and re-hash the chain after them.
// Reports only, unless --apply.
func newGuardDedupEventsCmd() *cobra.Command {
	var (
		configPath string
		apply      bool
		keepHashes bool
	)
	cmd := &cobra.Command{
		Use:   "dedup-events",
		Short: "Remove repeated guard audit rows written by transcript re-parses",
		Long: "Finds guard_events rows that repeat an earlier row for the same\n" +
			"stored action (same rule, kind, decision and target): copies a\n" +
			"re-parse wrote before the 2026-10-21 fix. Hook rows are never\n" +
			"touched. With --apply it deletes them and re-hashes the audit chain\n" +
			"from the first one on, in one transaction; it refuses when a row in\n" +
			"that range already fails verification, so no existing break is\n" +
			"hidden. --keep-hashes deletes them and rewrites no hash instead:\n" +
			"each deletion becomes a broken link verify-audit reports, for a\n" +
			"chain that is already broken inside that range. Rows already\n" +
			"pushed to an org server stay there. Without --apply it only reports.",
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
			report, err := store.New(database).DedupGuardEvents(cmd.Context(), store.GuardDedupOptions{
				Apply: apply, KeepHashes: keepHashes,
			})
			if err != nil {
				return fmt.Errorf("dedup: %w", err)
			}
			out := cmd.OutOrStdout()
			if report.Duplicates == 0 {
				fmt.Fprintln(out, "no repeated guard rows")
				return nil
			}
			tools := make([]string, 0, len(report.ByTool))
			for tool := range report.ByTool {
				tools = append(tools, tool)
			}
			sort.Strings(tools)
			fmt.Fprintf(out, "%d repeated guard row(s), the first at id %d:\n", report.Duplicates, report.FirstDuplicateID)
			for _, tool := range tools {
				fmt.Fprintf(out, "  %-20s %d\n", tool, report.ByTool[tool])
			}
			switch {
			case report.Refused != "":
				fmt.Fprintf(out, "refused: %s\n", report.Refused)
				return errors.New("guard dedup-events: refused")
			case report.Applied && report.KeptHashes:
				fmt.Fprintf(out, "removed %d row(s); no hash rewritten (verify-audit reports each removal as a broken link)\n", report.Duplicates)
			case report.Applied:
				fmt.Fprintf(out, "removed %d row(s); re-hashed %d chain link(s)\n", report.Duplicates, report.Rehashed)
			default:
				fmt.Fprintln(out, "dry run: pass --apply to remove them")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&apply, "apply", false, "Delete the repeated rows and re-hash the chain (default: report only)")
	cmd.Flags().BoolVar(&keepHashes, "keep-hashes", false, "Delete without re-hashing: no stored hash changes and no verification is required")
	return cmd
}

// newGuardRepairAnchorsCmd builds `observer guard repair-anchors`: restore
// the action id of guard_events rows that action maintenance cleared before
// agent migration 197 (GUARD-CHAIN-1), where the row's stored hash proves
// the id. Reports only, unless --apply.
func newGuardRepairAnchorsCmd() *cobra.Command {
	var (
		configPath string
		apply      bool
		ceiling    int64
	)
	cmd := &cobra.Command{
		Use:   "repair-anchors",
		Short: "Restore guard audit rows whose action id old maintenance cleared",
		Long: "Before agent migration 197, action retention, component purge and\n" +
			"migration 079 set guard_events.action_id to NULL when they removed\n" +
			"the action, and action_id was hashed, so verify-audit reported those\n" +
			"rows as rewritten. For every row that fails that way and has no\n" +
			"action id left, this tries action ids and accepts one only when the\n" +
			"row, with that id and every other column as stored, reproduces its\n" +
			"stored hash. That is a proof, not a guess: a row edited in any other\n" +
			"way matches no id and stays reported. No hash is rewritten, so a\n" +
			"deleted row stays a broken link. With --apply it writes the proven\n" +
			"ids to action_anchor; without it it only reports.",
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
			st := store.New(database)
			report, err := st.RepairGuardAnchors(cmd.Context(), store.GuardAnchorRepairOptions{
				Apply: apply, Ceiling: ceiling,
			})
			if err != nil {
				return fmt.Errorf("repair: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%d row(s) fail as rewritten with no action id; %d proven (action ids 1-%d, %d hash(es) tried)\n",
				report.Candidates, report.Proven, report.Ceiling, report.Tries)
			if report.UnprovenCount > 0 {
				fmt.Fprintf(out, "%d not proven (left as reported), the first: %v\n", report.UnprovenCount, report.Unproven)
			}
			if !report.Applied {
				if report.Proven > 0 {
					fmt.Fprintln(out, "dry run: pass --apply to write the proven ids")
				}
				return nil
			}
			fmt.Fprintf(out, "restored %d action id(s)\n", report.Repaired)
			chain, err := st.VerifyGuardChain(cmd.Context())
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			if chain.OK {
				fmt.Fprintf(out, "audit chain OK - %d row(s) verified\n", chain.Checked)
			} else {
				fmt.Fprintf(out, "audit chain still broken - %s\n%s\n", chain.Detail, formatGuardBreaks(chain.Breaks))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&apply, "apply", false, "Write the proven action ids (default: report only)")
	cmd.Flags().Int64Var(&ceiling, "ceiling", 0, "Highest action id to try (default: the highest id the node ever issued)")
	return cmd
}

// newGuardRelinkGapsCmd builds `observer guard relink-gaps`: re-link the
// audit chain over the deletion gaps `dedup-events --keep-hashes` leaves,
// recording the rewrite as a guard_rechain row. Reports only, unless --apply.
func newGuardRelinkGapsCmd() *cobra.Command {
	var (
		configPath string
		apply      bool
	)
	cmd := &cobra.Command{
		Use:   "relink-gaps",
		Short: "Re-link the guard audit chain over rows deleted by dedup-events",
		Long: "Finds rows whose link fails only because the row before them was\n" +
			"deleted (what `dedup-events --keep-hashes` leaves): the id below is\n" +
			"absent and the row's own content still matches its stored hash.\n" +
			"With --apply it recomputes every link from the first such row and\n" +
			"appends a guard_rechain row recording the gap count and the old\n" +
			"tail hash, in one transaction. Any other kind of break refuses the\n" +
			"whole run, so an edited row is never hidden. Rows already pushed\n" +
			"to an org server keep their old hashes there; a later full re-push\n" +
			"(`backfill --all --confirm`) would send the re-linked rows again.",
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
			st := store.New(database)
			report, err := st.RechainGuardGaps(cmd.Context(), apply, time.Now().UTC())
			if err != nil {
				return fmt.Errorf("relink: %w", err)
			}
			out := cmd.OutOrStdout()
			switch {
			case report.Refused != "":
				fmt.Fprintf(out, "refused: %s\n", report.Refused)
				return errors.New("guard relink-gaps: refused")
			case report.Gaps == 0:
				fmt.Fprintln(out, "no deletion gaps")
				return nil
			case !report.Applied:
				fmt.Fprintf(out, "%d deletion gap(s), the first at id %d\ndry run: pass --apply to re-link them\n",
					report.Gaps, report.FirstGapID)
				return nil
			}
			fmt.Fprintf(out, "re-linked %d deletion gap(s) from id %d: %d link(s) rewritten; marker row %d records the old tail hash %s\n",
				report.Gaps, report.FirstGapID, report.Rehashed, report.MarkerID, report.OldTailHash)
			chain, err := st.VerifyGuardChain(cmd.Context())
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			if chain.OK {
				fmt.Fprintf(out, "audit chain OK - %d row(s) verified\n", chain.Checked)
			} else {
				fmt.Fprintf(out, "audit chain still broken - %s\n%s\n", chain.Detail, formatGuardBreaks(chain.Breaks))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&apply, "apply", false, "Re-link the chain and add the marker row (default: report only)")
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
	if database == nil {
		return guardBudgetPostureLine(ctx, cfg, database)
	}
	granted := budgetEnforcementGranted(ctx, cfg, database, slog.Default())
	line := guardBudgetPostureLineWithGrant(ctx, cfg, database, granted)
	// WINNODE item 8: coverage=proxy_only is the guard's own scan, and stays
	// the wire value; on a managed node the hook-path stop (T-519) also stops
	// direct-provider sessions of tools whose pre-send hooks run here.
	line += budgetHookStopClause(granted, recentHookTools(ctx, database, time.Now()))
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
