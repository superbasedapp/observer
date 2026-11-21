package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/settingsgate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer config proposals` (Plane A build-out W2-8, ruling D19): the
// settings changes an AI agent asked for through MCP set_setting that wait
// for your approval. Approving writes the value through the same checked
// write `observer config set` uses (planConfigSet + writeConfigSet), so an
// approval is never a way around a pin, a validation or a governance rule.
// R-165 denies an agent running the approve and reject verbs.

// applySettingResult is what one checked write did.
type applySettingResult struct {
	Key      string
	Path     string
	Warnings []string
	Reloaded bool
	// Shown is the value as printed (hidden for a credential-shaped value).
	Shown string
}

// applySetting is the one checked global write of key = value, shared by
// `observer config proposals approve` and MCP set_setting's ordinary-key
// path. confirmed is the caller's confirmation of a sensitive key.
func applySetting(ctx context.Context, configPath, key, value string, confirmed bool) (applySettingResult, error) {
	resolvedPath, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return applySettingResult{}, fmt.Errorf("resolve config path: %w", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
	if err != nil {
		return applySettingResult{}, fmt.Errorf("load config: %w", err)
	}
	gov, err := configSetGovernance(ctx, cfg)
	if err != nil {
		return applySettingResult{}, err
	}
	plan, err := planConfigSet(cfg, key, value, gov, confirmed)
	if err != nil {
		return applySettingResult{}, err
	}
	if err := writeConfigSet(resolvedPath, plan); err != nil {
		return applySettingResult{}, err
	}
	res := applySettingResult{Key: key, Path: resolvedPath, Warnings: plan.warnings, Shown: value}
	if plan.secretShaped {
		res.Shown = "(hidden)"
	}
	res.Reloaded = pokeReload()
	return res, nil
}

// cliDecider names the person deciding from this terminal.
func cliDecider() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli"
}

func newConfigProposalsCmd() *cobra.Command {
	var (
		configPath string
		all        bool
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "proposals",
		Short: "List the settings changes an AI agent asked for that wait for your approval",
		Long: "An AI agent may change an ordinary setting through MCP set_setting, but a\n" +
			"security-sensitive one (the guard, what is captured or shared, where data\n" +
			"or requests go, admission, budgets, or an SDK destination that sends data\n" +
			"online) only files a proposal. List them here, then\n" +
			"  observer config proposals approve <id> --yes\n" +
			"  observer config proposals reject <id>\n" +
			"The dashboard's Settings page shows the same list.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			rows, err := store.New(database).ListSettingsProposals(cmd.Context(), !all, 0)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSONOut(cmd.OutOrStdout(), rows)
			}
			printProposals(cmd.OutOrStdout(), rows, all)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&all, "all", false, "Include decided and superseded proposals")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	cmd.AddCommand(newConfigProposalDecideCmd(true), newConfigProposalDecideCmd(false))
	return cmd
}

func printProposals(out io.Writer, rows []store.SettingsProposal, all bool) {
	if len(rows) == 0 {
		if all {
			fmt.Fprintln(out, "no settings proposals")
		} else {
			fmt.Fprintln(out, "no settings changes are waiting for your approval")
		}
		return
	}
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKEY\tVALUE\tWAS\tSTATUS\tASKED BY\tWHY")
	for _, p := range rows {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, shownText(p.Key), proposalShown(p.Key, p.Value),
			proposalShown(p.Key, p.PrevValue), p.Status, shownText(p.RequestedBy), shownText(p.Reason))
	}
	_ = tw.Flush()
}

func newConfigProposalDecideCmd(approve bool) *cobra.Command {
	var (
		configPath string
		yes        bool
	)
	use, short := "reject <id>", "Reject a settings change an AI agent asked for"
	if approve {
		use, short = "approve <id>", "Approve and apply a settings change an AI agent asked for"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
			if err != nil || id <= 0 {
				return fmt.Errorf("proposal id %q is not a positive number", args[0])
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			p, err := st.GetSettingsProposal(cmd.Context(), id)
			if err != nil {
				return err
			}
			if p.Status != store.SettingsProposalPending {
				return fmt.Errorf("proposal %d is %s; only a pending proposal can be decided", id, p.Status)
			}
			out := cmd.OutOrStdout()
			if !approve {
				if err := st.DecideSettingsProposal(cmd.Context(), id, store.SettingsProposalRejected, cliDecider(), time.Now()); err != nil {
					return err
				}
				fmt.Fprintf(out, "rejected proposal %d (%s = %s); nothing was written\n", id, shownText(p.Key), proposalShown(p.Key, p.Value))
				return nil
			}
			if !yes {
				return fmt.Errorf("approving proposal %d sets %s = %s (%s); re-run with --yes to confirm", id, shownText(p.Key), proposalShown(p.Key, p.Value), shownText(p.Reason))
			}
			res, err := approveSettingsProposal(cmd.Context(), st, configPath, p, cliDecider())
			if err != nil {
				return err
			}
			for _, w := range res.Warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
			}
			shown := proposalShown(p.Key, p.Value)
			if res.Shown != p.Value {
				shown = res.Shown
			}
			fmt.Fprintf(out, "approved proposal %d: set %s = %s (saved to %s)\n", id, shownText(p.Key), shown, res.Path)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	if approve {
		cmd.Flags().BoolVar(&yes, "yes", false, "Confirm the change")
	}
	return cmd
}

// errProposalRefused is returned when the gate now refuses a proposal's key
// (a credential, a key another surface owns, or one the organization pinned).
var errProposalRefused = errors.New("this change cannot be applied")

// errProposalStale is returned when a proposal is too old, or its setting
// changed after it was filed (review E-50).
var errProposalStale = errors.New("this proposal can no longer be approved")

// proposalShown is how a proposal value is printed to the terminal (review
// E-51): quoted with every control character escaped, so an agent-authored
// value cannot redraw the prompt, and hidden when the key is a credential
// leaf or the value looks like a secret.
func proposalShown(key, value string) string {
	if l, ok := configschema.ResolveKey(strings.TrimSpace(key)); ok && l.Secret && value != "" {
		return "(hidden)"
	}
	if agentconfigsvc.DefaultDetect(value) {
		return "(hidden)"
	}
	return strconv.Quote(value)
}

// shownText prints other agent-authored proposal text (the key, the reason,
// the requester) with its control characters escaped, without quotes when
// it holds none.
func shownText(v string) string {
	q := strconv.Quote(v)
	if q[1:len(q)-1] == v {
		return v
	}
	return q
}

// approveSettingsProposal re-checks the proposal through the gate (a refusal
// still refuses: an approval never writes a credential or a pinned key),
// writes it through applySetting and then marks it approved. The write comes
// first: a proposal is marked approved only once its value is in force.
func approveSettingsProposal(ctx context.Context, st *store.Store, configPath string, p store.SettingsProposal, decidedBy string) (applySettingResult, error) {
	cfg, err := loadConfigFile(configPath)
	if err != nil {
		return applySettingResult{}, err
	}
	gov, err := configSetGovernance(ctx, cfg)
	if err != nil {
		return applySettingResult{}, err
	}
	if d := settingsgate.Decide(p.Key, p.Value, gov); d.Verdict == settingsgate.Refuse {
		return applySettingResult{}, fmt.Errorf("%w: %s", errProposalRefused, d.Reason)
	}
	// E-50: refuse an old proposal, and one whose setting changed by hand
	// after the agent asked (approving would overwrite the newer choice).
	if c := settingsgate.CheckApproval(settingsgate.ProposalFacts{
		CreatedAt: p.CreatedAt, PrevValue: p.PrevValue, Current: currentSettingValue(&cfg, p.Key, gov),
	}, time.Now()); !c.OK() {
		return applySettingResult{}, fmt.Errorf("%w: %s", errProposalStale, c.Message)
	}
	res, err := applySetting(ctx, configPath, p.Key, p.Value, true)
	if err != nil {
		return applySettingResult{}, err
	}
	if err := st.DecideSettingsProposal(ctx, p.ID, store.SettingsProposalApproved, decidedBy, time.Now()); err != nil {
		return res, fmt.Errorf("the value was written, but marking proposal %d approved failed: %w", p.ID, err)
	}
	return res, nil
}

// loadConfigFile loads the global config at configPath ("" = the default).
func loadConfigFile(configPath string) (config.Config, error) {
	resolvedPath, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return config.Config{}, fmt.Errorf("resolve config path: %w", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
	if err != nil {
		return config.Config{}, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

// currentSettingValue is the value in force for key, in the `config set`
// spelling ("" when unknown or hidden), for a proposal's prev_value.
func currentSettingValue(cfg *config.Config, key string, gov configschema.KeyGovernance) string {
	v, err := getSetting(cfg, key, gov)
	if err != nil || v.Hidden {
		return ""
	}
	return settingDisplayValue(v)
}
