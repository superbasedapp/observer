package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newGuardPromptCmd is `observer guard prompt` (Part B item 4,
// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md §8.3
// / FIX-4 of the phase-2 review): the operator surface for the
// prompt-submit intervention feature. FIX-4 flagged that
// hook.promptHouseMessage's own reply text already told developers to
// run `observer guard prompt allow <detector> --session` and
// `observer guard prompt status` — commands that did not exist. This
// file makes those messages true.
func newGuardPromptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prompt",
		Short: "Prompt-submit intervention: status, allow, clear, events",
		Long: "Operator surface for the prompt-submit intervention feature\n" +
			"([guard.prompt]): warn/ask-once/block/redact when the developer's\n" +
			"own prompt contains an API token or deterministic PII, before it\n" +
			"reaches the model. See docs/guard-prompt.md.",
	}
	cmd.AddCommand(newGuardPromptStatusCmd())
	cmd.AddCommand(newGuardPromptAllowCmd())
	cmd.AddCommand(newGuardPromptClearCmd())
	cmd.AddCommand(newGuardPromptEventsCmd())
	return cmd
}

// promptRuleIDForDetector maps a scrub detector name onto the ONE
// rule row the guard-prompt engine actually evaluates it under
// (internal/policy/rules_exfil.go): every secret-class detector
// collapses onto R-172, every PII-class detector onto R-190. There is
// no finer-grained rule per detector — see newGuardPromptAllowCmd's
// help text, which says this plainly rather than implying a precision
// the engine doesn't have.
func promptRuleIDForDetector(detector string) (ruleID string, err error) {
	class, ok := scrub.DetectorClass(detector)
	if !ok {
		return "", fmt.Errorf("unknown detector %q (see `observer guard status` or docs/guard-prompt.md for the full list)", detector)
	}
	if class == scrub.ClassSecret {
		return "R-172", nil
	}
	return "R-190", nil
}

func newGuardPromptStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the prompt-submit intervention configuration and live state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			out := cmd.OutOrStdout()
			p := cfg.Guard.Prompt

			printPromptConfigSummary(out, cfg.Guard.Enabled, cfg.Guard.Mode, p)
			printPromptEffectiveModes(out, p)
			printPromptWiredClients(out, configPath)

			database, err := db.Open(cmd.Context(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()
			total, expired, err := store.New(database).CountPromptReconsider(cmd.Context(), time.Now().UTC())
			if err != nil {
				return fmt.Errorf("count reconsider rows: %w", err)
			}
			fmt.Fprintf(out, "\nreconsider-once grants: %d total, %d expired (not yet pruned)\n", total, expired)

			printPromptApprovals(cmd.Context(), out, database)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// printPromptConfigSummary renders the [guard]/[guard.prompt] config
// values and the derived effective hook-lane state — the top section
// of `observer guard prompt status`.
func printPromptConfigSummary(out io.Writer, guardEnabled bool, guardMode string, p config.GuardPromptConfig) {
	fmt.Fprintf(out, "guard.enabled            = %v\n", guardEnabled)
	fmt.Fprintf(out, "guard.mode               = %s\n", guardMode)
	fmt.Fprintf(out, "guard.prompt.enabled     = %v\n", p.Enabled)
	fmt.Fprintf(out, "guard.prompt.mode        = %s\n", p.Mode)
	fmt.Fprintf(out, "guard.prompt.hook_lane   = %v\n", p.HookLane)
	fmt.Fprintf(out, "guard.prompt.proxy_lane  = %v (wired via internal/guard/proxyguard.go's scanPrompt; a config change here only reaches it after a daemon restart — the hook lane picks it up on the very next hook invocation)\n", p.ProxyLane)
	fmt.Fprintf(out, "guard.prompt.enforce_independent = %v", p.EnforceIndependent)
	if p.EnforceIndependent {
		fmt.Fprintf(out, " (acts on its own mode regardless of guard.mode)\n")
	} else {
		fmt.Fprintf(out, " (inherits guard.mode's observe/enforce gate like every other channel)\n")
	}
	effective := "OFF (nothing will ever block or ask)"
	if guardEnabled && guardMode != "off" && p.Enabled && p.HookLane &&
		(p.EnforceIndependent || guardMode == "enforce") {
		effective = "ACTIVE (the hook lane evaluates and can " + p.Mode + ")"
	} else if guardEnabled && guardMode != "off" && p.Enabled && p.HookLane {
		effective = "OBSERVE-ONLY (evaluates and records, never blocks — set guard.mode=enforce or guard.prompt.enforce_independent=true)"
	}
	fmt.Fprintf(out, "effective hook-lane state = %s\n", effective)
}

// printPromptEffectiveModes renders the F4/F7 (phase-3a review)
// per-detector EFFECTIVE mode section (after the stricter-wins-with-
// floor clamp, guard.EffectivePromptMode) for every known detector,
// not just the ones with a raw config override — a config value alone
// can be misleading now that a looser override clamps UP to the
// global floor (see docs/guard-prompt.md).
func printPromptEffectiveModes(out io.Writer, p config.GuardPromptConfig) {
	fmt.Fprintln(out, "\nper-detector effective mode (after the global-floor clamp; * = overridden in config):")
	names := scrub.DetectorNames()
	sort.Strings(names)
	for _, d := range names {
		eff := guard.EffectivePromptMode(p.Mode, p.Detectors, d)
		mark := " "
		if _, overridden := p.Detectors[d]; overridden {
			mark = "*"
		}
		fmt.Fprintf(out, "  %s%-20s %s\n", mark, d, eff)
	}
}

// printPromptWiredClients renders F4 (phase-3a review)'s REAL per-tool
// hook registration state — reusing the same checkHookRegistration
// probe `observer doctor --probe-hook` already uses — instead of just
// listing every registry row with PromptLane==Hook, which says nothing
// about whether that tool's OWN config file actually points at
// observer today.
func printPromptWiredClients(out io.Writer, configPath string) {
	fmt.Fprintln(out, "\nwired clients (real per-tool hook registration state):")
	binary, binErr := absoluteBinaryPath()
	var wired []string
	for _, c := range integration.Capabilities() {
		if c.PromptLane == integration.PromptLaneHook {
			wired = append(wired, c.Tool)
		}
	}
	sort.Strings(wired)
	for _, tool := range wired {
		printPromptWiredClientRow(out, tool, binary, binErr, configPath)
	}
}

// printPromptWiredClientRow renders one tool's row(s) for
// printPromptWiredClients — split out to keep both functions under the
// project's cyclomatic-complexity gate.
//
// B4 fix: a tool can be wired through its native config, its cross-OS
// "-windows" bridge config, both, or neither — checkHookRegistrationHomes
// walks every home this box can meaningfully probe, and this prints ONE
// line per home so a bridge-only wiring (the common WSL-daemon +
// Windows-native-tool shape) is never collapsed into a single verdict
// that could misreport it as NOT REGISTERED.
func printPromptWiredClientRow(out io.Writer, tool, binary string, binErr error, configPath string) {
	c, _ := integration.For(tool)
	if !c.Hook.AutoWired {
		fmt.Fprintf(out, "  %-16s documented, not auto-wired (no registration writer exists)\n", tool)
		return
	}
	if binErr != nil {
		fmt.Fprintf(out, "  %-16s could not resolve this binary's own path: %v\n", tool, binErr)
		return
	}
	entry, known := hookMechanismDialect[c.Hook.Mechanism]
	if !known {
		fmt.Fprintf(out, "  %-16s no known prompt-submit wire shape to probe\n", tool)
		return
	}
	for _, h := range checkHookRegistrationHomes(binary, configPath, tool, entry.registryEvent) {
		label := tool
		if h.home == "bridge" {
			label = h.tool // "<tool>-windows"
		}
		fmt.Fprintf(out, "  %-16s %s\n", label, formatHookHomeVerdict(h))
	}
}

// printPromptApprovals renders F4's guard_approvals section, scoped to
// the prompt-submit rules (R-172/R-190) — especially a --global/ttl=0
// (never-expiring) grant, which silently exempts an entire rule class
// everywhere on this node until someone notices it here or in
// `observer guard approvals`.
func printPromptApprovals(ctx context.Context, out io.Writer, database *sql.DB) {
	approvals, appErr := store.New(database).ActiveGuardApprovals(ctx, "", time.Now().UTC())
	if appErr != nil {
		fmt.Fprintf(out, "\n(could not load guard_approvals: %v)\n", appErr)
		return
	}
	var promptApprovals []store.GuardApprovalRow
	for _, a := range approvals {
		if a.RuleID == "R-172" || a.RuleID == "R-190" {
			promptApprovals = append(promptApprovals, a)
		}
	}
	if len(promptApprovals) == 0 {
		fmt.Fprintln(out, "\nactive prompt-submit approvals (R-172/R-190): none")
		return
	}
	fmt.Fprintln(out, "\nactive prompt-submit approvals (R-172/R-190):")
	for _, a := range promptApprovals {
		expiry := "never expires"
		if !a.ExpiresAt.IsZero() {
			expiry = "expires " + a.ExpiresAt.Format(time.RFC3339)
		}
		warn := ""
		if a.Scope == "global" && a.ExpiresAt.IsZero() {
			warn = "  *** GLOBAL, NEVER EXPIRES — exempts every detector in this rule class, everywhere on this node ***"
		}
		fmt.Fprintf(out, "  id=%d rule=%s scope=%s granted_by=%s (%s)%s\n",
			a.ID, a.RuleID, a.Scope, a.GrantedBy, expiry, warn)
	}
}

func newGuardPromptAllowCmd() *cobra.Command {
	var (
		configPath string
		sessionID  string
		project    bool
		global     bool
		ttl        time.Duration
	)
	cmd := &cobra.Command{
		Use:   "allow <detector> [--session <id>|--project|--global]",
		Short: "Grant a scoped exception for a prompt-submit detector",
		Long: "Stops the prompt-submit lane from asking/blocking on a detector,\n" +
			"scoped to one of --session <id> (this conversation only, matching\n" +
			"the reply's own suggestion), --project (this repo's root), or\n" +
			"--global (everywhere on this node). Delegates to the SAME\n" +
			"guard_approvals mechanism `observer guard approve` uses — there is\n" +
			"no separate per-detector table. IMPORTANT: the grant is by RULE,\n" +
			"not by exact detector — every secret-class detector (github_pat,\n" +
			"api keys, entropy, ...) shares R-172, and every PII-class detector\n" +
			"(credit_card, us_ssn, email, ...) shares R-190. Allowing one\n" +
			"detector allows every OTHER detector of the same class in that\n" +
			"scope too. `observer guard approvals` lists active grants;\n" +
			"`observer guard revoke <id>` withdraws one.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleID, err := promptRuleIDForDetector(args[0])
			if err != nil {
				return err
			}
			scopeCount := 0
			scope, anchorSession, anchorHash := "", "", ""
			if sessionID != "" {
				scopeCount, scope, anchorSession = scopeCount+1, "session", sessionID
			}
			if project {
				cwd, _ := os.Getwd()
				root := cwd
				if r, ok := git.FindRoot(cwd); ok {
					root = r
				}
				scopeCount, scope, anchorHash = scopeCount+1, "project", guard.HashProjectRoot(root)
			}
			if global {
				scopeCount, scope = scopeCount+1, "global"
			}
			if scopeCount != 1 {
				return errors.New("exactly one scope required: --session <id>, --project, or --global")
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			database, err := db.Open(cmd.Context(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()
			now := time.Now().UTC()
			row := store.GuardApprovalRow{
				TS: now, RuleID: ruleID, Scope: scope,
				SessionID: anchorSession, ProjectRootHash: anchorHash,
				GrantedBy: localOperatorIdentity(),
			}
			if ttl > 0 {
				row.ExpiresAt = now.Add(ttl)
			}
			id, err := store.New(database).InsertGuardApproval(cmd.Context(), row)
			if err != nil {
				return err
			}
			expiry := "no expiry"
			if ttl > 0 {
				expiry = "expires " + row.ExpiresAt.Format(time.RFC3339)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "approval %d granted: detector=%s -> %s scope=%s (%s)\n", id, args[0], ruleID, scope, expiry)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "grant for one session id")
	cmd.Flags().BoolVar(&project, "project", false, "grant for the current directory's project")
	cmd.Flags().BoolVar(&global, "global", false, "grant everywhere on this node")
	cmd.Flags().DurationVar(&ttl, "ttl", 24*time.Hour, "grant lifetime (0 = never expires)")
	return cmd
}

func newGuardPromptClearCmd() *cobra.Command {
	var (
		configPath string
		all        bool
	)
	cmd := &cobra.Command{
		Use:   "clear [fingerprint]",
		Short: "Remove a reconsider-once grant (force a fresh ask-once interrupt)",
		Long: "Removes ONE guard_prompt_reconsider row by its fingerprint —\n" +
			"the opaque sha256 hex `observer guard prompt events` prints as\n" +
			"target_excerpt (never the matched value or raw prompt text) —\n" +
			"so the next identical resend interrupts again instead of\n" +
			"silently confirming. Pass --all to clear every pending grant.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) == 1) {
				return errors.New("pass exactly one of: a fingerprint argument, or --all")
			}
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
			if all {
				n, err := st.DeleteAllPromptReconsider(cmd.Context())
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "cleared %d reconsider-once grant(s)\n", n)
				return nil
			}
			existed, err := st.DeletePromptReconsider(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if !existed {
				return fmt.Errorf("no reconsider-once grant found for fingerprint %q", args[0])
			}
			fmt.Fprintf(cmd.OutOrStdout(), "cleared fingerprint %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&all, "all", false, "clear every pending reconsider-once grant")
	return cmd
}

func newGuardPromptEventsCmd() *cobra.Command {
	var (
		configPath string
		since      string
		limit      int
	)
	cmd := &cobra.Command{
		Use:   "events",
		Short: "List recent prompt-submit guard_events (never prints matched values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			var sinceTime time.Time
			if since != "" {
				d, err := time.ParseDuration(since)
				if err != nil {
					return fmt.Errorf("--since must be a duration (e.g. 24h, 30m): %w", err)
				}
				sinceTime = time.Now().UTC().Add(-d)
			}
			database, err := db.Open(cmd.Context(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()
			rows, err := store.New(database).LoadRecentGuardEvents(cmd.Context(), sinceTime, limit)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			var printed int
			fmt.Fprintf(out, "%-24s %-12s %-6s %-9s %-8s %-64s %s\n", "TIME", "TOOL", "RULE", "DECISION", "SEVERITY", "FINGERPRINT", "REASON")
			for _, r := range rows {
				if r.EventKind != string(policy.KindUserPrompt) {
					continue
				}
				printed++
				// TargetExcerpt IS the opaque reconsider-once fingerprint
				// hex for a prompt-submit row (F5, phase-3a review — see
				// guard.ActionVerdictFromPrompt's doc comment: "TargetExcerpt
				// becomes the opaque fingerprint hex itself"). `clear
				// <fingerprint>`'s own help text already told operators to
				// copy this value from here; print it so that's actually
				// possible. Empty for a row with no reconsider-once
				// fingerprint (e.g. mode=block, which never computes one).
				fp := r.TargetExcerpt
				if fp == "" {
					fp = "-"
				}
				fmt.Fprintf(out, "%-24s %-12s %-6s %-9s %-8s %-64s %s\n",
					r.TS.Format(time.RFC3339), r.Tool, r.RuleID, r.Decision, r.Severity, fp, r.Reason)
			}
			if printed == 0 {
				fmt.Fprintln(out, "(no prompt-submit events in range)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&since, "since", "", "only show events newer than this duration ago (e.g. 24h, 30m)")
	cmd.Flags().IntVar(&limit, "limit", 200, "maximum rows to scan (most-recent-first)")
	return cmd
}
