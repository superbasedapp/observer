package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
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

// G8 enforcement-phase CLI surfaces (guard spec §4.1, §6.3, §11.1):
// enable/disable, the approvals register, simulate and rescan.
// Registered onto the guard command tree from newGuardCmd.

func registerGuardEnforceCmds(root *cobra.Command) {
	root.AddCommand(newGuardEnableCmd())
	root.AddCommand(newGuardDisableCmd())
	root.AddCommand(newGuardApproveCmd())
	root.AddCommand(newGuardApprovalsCmd())
	root.AddCommand(newGuardRevokeCmd())
	root.AddCommand(newGuardSimulateCmd())
	root.AddCommand(newGuardRescanCmd())
}

// setGuardConfigMode surgically rewrites config.toml's [guard] keys:
// `enabled` and `mode` only, preserving every other byte of the file
// (comments included). When no [guard] section exists, one is
// appended. The surgical approach — not a full TOML re-marshal —
// keeps the operator's comments and formatting intact (the same
// reason hook registration edits client configs additively).
func setGuardConfigMode(path string, enabled bool, mode string) error {
	if path == "" {
		return errors.New("config path unresolved — pass --config")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		raw = nil
	} else if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	text := string(raw)

	section := fmt.Sprintf("[guard]\nenabled = %v\nmode = %q\n", enabled, mode)
	secRe := regexp.MustCompile(`(?ms)^\[guard\]\s*$(.*?)(^\[|\z)`)
	loc := secRe.FindStringSubmatchIndex(text)
	if loc == nil {
		// No [guard] section: append one.
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += "\n" + section
	} else {
		body := text[loc[2]:loc[3]]
		body = setOrAppendTOMLKey(body, "enabled", fmt.Sprintf("%v", enabled))
		body = setOrAppendTOMLKey(body, "mode", fmt.Sprintf("%q", mode))
		text = text[:loc[2]] + body + text[loc[3]:]
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// setOrAppendTOMLKey replaces `key = ...` inside a section body, or
// appends the assignment when absent. Top-level keys only — the body
// passed in ends at the next section header.
func setOrAppendTOMLKey(body, key, value string) string {
	keyRe := regexp.MustCompile(`(?m)^(\s*` + regexp.QuoteMeta(key) + `\s*=\s*).*$`)
	if keyRe.MatchString(body) {
		return keyRe.ReplaceAllString(body, "${1}"+value)
	}
	assignment := key + " = " + value + "\n"
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return body + assignment
}

func newGuardEnableCmd() *cobra.Command {
	var (
		configPath string
		enforce    bool
	)
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable the guard (observe mode; --enforce flips to enforcement)",
		Long: "Writes [guard] enabled/mode into config.toml surgically (your\n" +
			"comments and other sections are untouched). --enforce is the D2\n" +
			"opt-in: deny/ask-class rules start actually blocking at the hook\n" +
			"seam. Run `observer guard simulate --since 168h` first to see what\n" +
			"WOULD have blocked. Daemons pick the change up on restart; hook\n" +
			"processes read config per invocation and follow immediately.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := resolveGuardConfigPath(configPath)
			if err != nil {
				return err
			}
			mode := "observe"
			if enforce {
				mode = "enforce"
			}
			if err := setGuardConfigMode(path, true, mode); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "guard enabled (mode %s) in %s\nRestart the daemon (`observer start`) for the watcher seam; hooks follow immediately.\n", mode, path)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&enforce, "enforce", false, "set mode=enforce (deny/ask rules actually block)")
	return cmd
}

func newGuardDisableCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable the guard entirely (no evaluation, no guard_events)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := resolveGuardConfigPath(configPath)
			if err != nil {
				return err
			}
			if err := setGuardConfigMode(path, false, "off"); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "guard disabled in %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// resolveGuardConfigPath resolves the config file the enable/disable
// surgical edit targets.
func resolveGuardConfigPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	path, err := config.ResolveGlobalPath("")
	if err != nil {
		return "", fmt.Errorf("resolve config path: %w", err)
	}
	return path, nil
}

func newGuardApproveCmd() *cobra.Command {
	var (
		configPath string
		sessionID  string
		project    bool
		global     bool
		ttl        time.Duration
	)
	cmd := &cobra.Command{
		Use:   "approve <rule-id>",
		Short: "Grant a scoped exception for a rule (the §6.3 approvals register)",
		Long: "Records an auditable exception in guard_approvals: matching\n" +
			"blocking verdicts downgrade to flag, so the agent's natural retry\n" +
			"succeeds. Scope one of: --session <id>, --project (this repo's\n" +
			"root), --global. --ttl bounds the grant (default 24h; 0 = no\n" +
			"expiry). Grants are part of the audit story — `observer guard\n" +
			"approvals` lists them, `observer guard revoke <id>` withdraws.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleID := args[0]
			if !policy.IsBuiltinRuleID(ruleID) && !strings.ContainsAny(ruleID, "-") {
				return fmt.Errorf("unknown rule id %q (see `observer guard rules`)", ruleID)
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
			// Org-lock gate (org guardrail control wave, Track B): under
			// an org policy bundle only a rule the organization marked
			// `overridable` may be granted a local exception. Refused
			// HERE, at creation, so the register never fills with grants
			// applyApprovals would ignore at evaluation time. A node with
			// no bundle takes the zero-cost path below and behaves
			// exactly as before the wave.
			if err := refuseOrgLockedApproval(cfg, ruleID); err != nil {
				return err
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
			fmt.Fprintf(cmd.OutOrStdout(), "approval %d granted: %s scope=%s (%s)\n", id, ruleID, scope, expiry)
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

// refuseOrgLockedApproval reports the "locked by org policy" refusal
// when the node's org bundle does NOT mark ruleID overridable. A
// guard that cannot be constructed degrades to "no bundle applies"
// (fail-open toward today's behaviour, like every guard CLI surface)
// — the evaluation-time gate in guard.applyApprovals is the backstop
// that actually keeps a locked rule hard.
func refuseOrgLockedApproval(cfg config.Config, ruleID string) error {
	home, _ := os.UserHomeDir()
	g, err := guard.New(guard.Options{Config: cfg.Guard, Home: home})
	if err != nil {
		return nil
	}
	if _, orgLocked := g.OrgOverrideStatus(ruleID); orgLocked {
		return fmt.Errorf("locked by org policy: %s (your organisation did not mark this rule overridable; ask your admin)", ruleID)
	}
	return nil
}

func newGuardApprovalsCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "approvals",
		Short: "List active approval grants (the exception register)",
		Args:  cobra.NoArgs,
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
			rows, err := store.New(database).ActiveGuardApprovals(cmd.Context(), "", time.Now().UTC())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(rows) == 0 {
				fmt.Fprintln(out, "no active approvals")
				return nil
			}
			fmt.Fprintf(out, "%-5s %-8s %-8s %-22s %-14s %s\n", "ID", "RULE", "SCOPE", "ANCHOR", "GRANTED BY", "EXPIRES")
			for _, a := range rows {
				anchor := a.SessionID
				if a.Scope == "project" {
					anchor = a.ProjectRootHash[:min(12, len(a.ProjectRootHash))] + "…"
				}
				expires := "never"
				if !a.ExpiresAt.IsZero() {
					expires = a.ExpiresAt.Format(time.RFC3339)
				}
				fmt.Fprintf(out, "%-5d %-8s %-8s %-22s %-14s %s\n", a.ID, a.RuleID, a.Scope, anchor, a.GrantedBy, expires)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

func newGuardRevokeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "revoke <approval-id>",
		Short: "Withdraw an approval grant by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var id int64
			if _, err := fmt.Sscanf(args[0], "%d", &id); err != nil {
				return fmt.Errorf("approval id must be numeric: %q", args[0])
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
			existed, err := store.New(database).DeleteGuardApproval(cmd.Context(), id)
			if err != nil {
				return err
			}
			if !existed {
				return fmt.Errorf("approval %d not found", id)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "approval %d revoked\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// replaySummary aggregates a simulate/rescan pass.
type replaySummary struct {
	scanned  int
	verdicts int
	byRule   map[string]int
	byDec    map[string]int
	capped   bool
}

// runGuardReplay loads history and evaluates it against CURRENT
// policy with a FRESH guard (its own taint tracker, so source→sink
// sequences replay faithfully and the daemon's live state is never
// touched). persist nil = simulate (dry-run); non-nil = rescan
// (persist via the idempotency-gated callback).
func runGuardReplay(ctx context.Context, cfg config.Config, st *store.Store, since time.Time, persist func(context.Context, []guard.ActionVerdict) (int, error)) (replaySummary, error) {
	sum := replaySummary{byRule: map[string]int{}, byDec: map[string]int{}}
	home, _ := os.UserHomeDir()
	roots, _ := st.ProjectRoots(ctx)
	g, err := guard.New(guard.Options{Config: cfg.Guard, Home: home, KnownProjectRoots: roots})
	if err != nil {
		return sum, fmt.Errorf("construct guard: %w", err)
	}
	const replayCap = 50000
	inputs, err := st.LoadGuardReplayInputs(ctx, since, replayCap)
	if err != nil {
		return sum, err
	}
	sum.scanned = len(inputs)
	sum.capped = len(inputs) == replayCap
	verdicts := g.EvaluateActions(inputs)
	sum.verdicts = len(verdicts)
	for _, v := range verdicts {
		sum.byRule[v.Verdict.RuleID]++
		sum.byDec[v.Verdict.Decision.String()]++
	}
	if persist != nil && len(verdicts) > 0 {
		if _, err := persist(ctx, verdicts); err != nil {
			return sum, err
		}
	}
	return sum, nil
}

func printReplaySummary(cmd *cobra.Command, label string, sum replaySummary) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s: %d actions scanned, %d verdicts\n", label, sum.scanned, sum.verdicts)
	if sum.capped {
		fmt.Fprintln(out, "NOTE: the 50k replay cap was hit — narrow --since for full coverage")
	}
	keys := make([]string, 0, len(sum.byRule))
	for k := range sum.byRule {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return sum.byRule[keys[i]] > sum.byRule[keys[j]] })
	for _, k := range keys {
		fmt.Fprintf(out, "  %-8s %d\n", k, sum.byRule[k])
	}
	if len(sum.byDec) > 0 {
		fmt.Fprintf(out, "  decisions: %s\n", formatCounts(sum.byDec))
	}
}

func newGuardSimulateCmd() *cobra.Command {
	var (
		configPath string
		since      time.Duration
		enforce    bool
	)
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Replay captured history against CURRENT policy (dry-run, nothing persists)",
		Long: "The pre-enforce confidence builder (spec §11.1): what would last\n" +
			"week have flagged or blocked under today's rules? Evaluates the\n" +
			"actions table through a fresh engine — the live guard state and\n" +
			"the audit table are untouched. --enforce simulates enforce-mode\n" +
			"decisions regardless of the configured mode.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if enforce {
				cfg.Guard.Mode = "enforce"
			}
			database, err := db.Open(cmd.Context(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()
			sum, err := runGuardReplay(cmd.Context(), cfg, store.New(database),
				time.Now().UTC().Add(-since), nil)
			if err != nil {
				return err
			}
			printReplaySummary(cmd, fmt.Sprintf("simulate (mode %s, last %s)", cfg.Guard.Mode, since), sum)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().DurationVar(&since, "since", 7*24*time.Hour, "history window to replay")
	cmd.Flags().BoolVar(&enforce, "enforce", false, "simulate enforce-mode decisions")
	return cmd
}

func newGuardRescanCmd() *cobra.Command {
	var (
		configPath string
		since      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "rescan",
		Short: "Re-evaluate captured history and PERSIST new verdicts (after rule changes)",
		Long: "The deliberate retroactive sweep (spec §7): after a policy change,\n" +
			"re-judge history and record verdicts the live seam missed.\n" +
			"Idempotent — an action already carrying a guard event for the same\n" +
			"rule is skipped, so re-running a rescan never duplicates rows.",
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
			persisted := 0
			persist := func(ctx context.Context, verdicts []guard.ActionVerdict) (int, error) {
				fresh := verdicts[:0]
				for _, v := range verdicts {
					exists, err := st.GuardEventExistsForAction(ctx, v.Input.ActionID, v.Verdict.RuleID)
					if err != nil {
						return 0, err
					}
					if !exists {
						fresh = append(fresh, v)
					}
				}
				n, err := st.PersistGuardVerdicts(ctx, fresh)
				persisted = n
				return n, err
			}
			sum, err := runGuardReplay(cmd.Context(), cfg, st, time.Now().UTC().Add(-since), persist)
			if err != nil {
				return err
			}
			printReplaySummary(cmd, fmt.Sprintf("rescan (last %s)", since), sum)
			fmt.Fprintf(cmd.OutOrStdout(), "persisted %d new guard event(s) (already-judged actions skipped)\n", persisted)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().DurationVar(&since, "since", 7*24*time.Hour, "history window to rescan")
	return cmd
}

// localOperatorIdentity names the grant approver for the §14.4
// exception register: the OS user on this node (node-local installs
// are single-operator by design — §14.5).
func localOperatorIdentity() string {
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "operator"
}
