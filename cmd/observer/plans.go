package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/planlimitssvc"
)

// newPlansCmd is the CLI twin of the Plans & limits page
// (docs/plans-and-limits.md): how much of each coding plan and API balance
// is left. Every verb works on this machine's database and keychain
// directly; secrets are read from stdin, never from the command line.
func newPlansCmd() *cobra.Command {
	var configPath string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "plans",
		Short: "Show how much of each coding plan and API balance is left",
		Long: "Shows your coding plan limits (5-hour, weekly, monthly) and API balances.\n" +
			"Claude and Codex limits appear on their own when you use those tools.\n" +
			"Add an account to track a balance or another plan: keys are stored in the\n" +
			"system keychain and never leave this machine.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPlansStatus(cmd, configPath, jsonOut)
		},
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the page model as JSON")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show every plan and balance (the default)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPlansStatus(cmd, configPath, jsonOut)
		},
	}
	status.Flags().BoolVar(&jsonOut, "json", false, "print the page model as JSON")
	cmd.AddCommand(status, newPlansAddCmd(&configPath), newPlansRemoveCmd(&configPath),
		newPlansRefreshCmd(&configPath), newPlansOptInCmd(&configPath), newPlansProbeCmd(&configPath),
		newPlansSourcesCmd(), newPlansUsageCmd(&configPath))
	return cmd
}

// withPlans opens the config, database and service for one CLI verb.
func withPlans(cmd *cobra.Command, configPath string, fn func(*planlimitssvc.Service) error) error {
	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	return fn(newPlansService(cfg, database, newLogger(cfg.Observer.LogLevel)))
}

func runPlansStatus(cmd *cobra.Command, configPath string, jsonOut bool) error {
	return withPlans(cmd, configPath, func(svc *planlimitssvc.Service) error {
		v, err := svc.Status(cmd.Context())
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if jsonOut {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(v)
		}
		printPlanView(out, v, time.Now())
		return nil
	})
}

// --- usage ----------------------------------------------------------------------

// newPlansUsageCmd is the CLI twin of the card's "Codex usage by day": the
// vendor's account-wide daily total, what this node captured, and what it
// did not capture, per UTC day. It reads the local database only.
func newPlansUsageCmd(configPath *string) *cobra.Command {
	var days int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "usage <account-id>",
		Short: "Show an account's daily usage beside what this machine captured",
		Long: "For an account whose source reports daily usage (the Codex app-server), shows per UTC day\n" +
			"the vendor's account-wide token total, the tokens this machine captured for that tool,\n" +
			"and the difference: usage not captured here (Codex cloud chats, other devices or\n" +
			"sessions Observer did not run on). Tokens only. Reads the local database; it does not\n" +
			"poll. Run `observer plans refresh <account-id>` first for a fresh reading.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withPlans(cmd, *configPath, func(svc *planlimitssvc.Service) error {
				v, err := svc.Usage(cmd.Context(), args[0], days)
				if err != nil {
					return plansCLIError(err)
				}
				out := cmd.OutOrStdout()
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(v)
				}
				printPlanUsage(out, v)
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&days, "days", planlimitssvc.DefaultUsageDays, "how many UTC days to show (1 to 366)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the reconciliation as JSON")
	return cmd
}

// printPlanUsage renders a UsageView as a table, newest day first.
func printPlanUsage(out io.Writer, v planlimitssvc.UsageView) {
	name := planProviderLabel(v.Provider)
	if !v.Available {
		fmt.Fprintf(out, "%s: this account's source does not report daily usage.\n", name)
		return
	}
	if v.Reconciliation == nil {
		fmt.Fprintf(out, "%s: no daily usage read yet. Run `observer plans refresh %s`.\n", name, v.AccountID)
		return
	}
	r := v.Reconciliation
	fmt.Fprintf(out, "%s usage by day, %s to %s (UTC days)\n", name, r.From, r.To)
	if len(r.Days) == 0 {
		fmt.Fprintln(out, "No usage on any day in this window.")
	} else {
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', tabwriter.AlignRight)
		fmt.Fprintln(tw, "Day\tVendor total\tCaptured here\tNot captured here\tCaptured share\t")
		for _, d := range r.Days {
			vendor := planTokens(d.VendorTokens)
			if !d.VendorReported {
				vendor = "none reported"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t\n", d.Day, vendor, planTokens(d.CapturedTokens),
				planTokens(d.UncapturedTokens), planRatio(d.Ratio))
		}
		fmt.Fprintf(tw, "Total\t%s\t%s\t%s\t%s\t\n", planTokens(r.Totals.VendorTokens), planTokens(r.Totals.CapturedTokens),
			planTokens(r.Totals.UncapturedTokens), planRatio(r.Totals.Ratio))
		_ = tw.Flush()
	}
	if v.FetchedAt != nil {
		fmt.Fprintf(out, "Vendor figures read %s.\n", v.FetchedAt.Local().Format("Mon Jan 2 15:04"))
	}
	fmt.Fprintln(out, "Not captured here: Codex cloud chats, other devices or sessions Observer did not run on.")
	fmt.Fprintln(out, "The vendor total is account-wide; captured here is this machine's "+strings.Join(v.Tools, ", ")+
		" sessions for any login. Days are UTC; the vendor does not document its day boundary.")
}

// planTokens formats a token count with thousands separators.
func planTokens(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// planRatio formats a captured share; "" when there is no vendor total.
func planRatio(r *float64) string {
	if r == nil {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", *r*100)
}

// --- add / remove / refresh / optin ---------------------------------------------

func newPlansAddCmd(configPath *string) *cobra.Command {
	var (
		source  string
		label   string
		params  []string
		secrets []string
	)
	c := &cobra.Command{
		Use:   "add <provider>",
		Short: "Add an account (secrets are read from stdin, one line each)",
		Long: "Adds an account and reads it once. Pass each secret's name with --secret;\n" +
			"its value is read from stdin, one line per --secret, in order, so keys\n" +
			"never land in shell history. See `observer plans sources` for what each\n" +
			"provider takes.\n\n" +
			"  printf '%s\\n' \"$OPENROUTER_KEY\" | observer plans add openrouter --source openrouter.api --secret key\n" +
			"  observer plans add cursor --source manual --param unit=requests --param allowance=500",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := parseKV(params)
			if err != nil {
				return err
			}
			sec, err := readSecrets(cmd.InOrStdin(), secrets)
			if err != nil {
				return err
			}
			if source == "" {
				source = defaultPlanSource(args[0])
			}
			return withPlans(cmd, *configPath, func(svc *planlimitssvc.Service) error {
				info, err := svc.AddAccount(cmd.Context(), planlimitssvc.AddRequest{
					Provider: args[0], Source: source, Label: label, Params: p, Secrets: sec,
				})
				if err != nil {
					return plansCLIError(err)
				}
				res, _ := svc.Refresh(cmd.Context(), info.ID)
				fmt.Fprintf(cmd.OutOrStdout(), "Added %s account %s.\n", planProviderLabel(info.Provider), info.ID)
				fmt.Fprintf(cmd.OutOrStdout(), "First check: %s\n", planOutcomeText(res.Outcome))
				return nil
			})
		},
	}
	c.Flags().StringVar(&source, "source", "", "how to read it (a source id from `observer plans sources`)")
	c.Flags().StringVar(&label, "label", "", "a name for the account, for example Work")
	c.Flags().StringArrayVar(&params, "param", nil, "a setting as key=value (repeatable)")
	c.Flags().StringArrayVar(&secrets, "secret", nil, "a secret's name; its value is read from stdin (repeatable)")
	return c
}

func newPlansRemoveCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <account-id>",
		Short: "Remove an account and delete its keys from the keychain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withPlans(cmd, *configPath, func(svc *planlimitssvc.Service) error {
				if err := svc.RemoveAccount(cmd.Context(), args[0]); err != nil {
					return plansCLIError(err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Removed account %s.\n", args[0])
				return nil
			})
		},
	}
}

func newPlansRefreshCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh [account-id]",
		Short: "Read one account now, or every account",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withPlans(cmd, *configPath, func(svc *planlimitssvc.Service) error {
				var results []planlimitssvc.RefreshResult
				if len(args) == 1 {
					r, err := svc.Refresh(cmd.Context(), args[0])
					if err != nil {
						return plansCLIError(err)
					}
					results = append(results, r)
				} else {
					results = svc.RefreshAll(cmd.Context())
				}
				if len(results) == 0 {
					fmt.Fprintln(cmd.OutOrStdout(), "No accounts to refresh.")
				}
				for _, r := range results {
					fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", r.AccountID, planOutcomeText(r.Outcome))
				}
				return nil
			})
		},
	}
}

func newPlansOptInCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "optin <provider> on|off",
		Short: "Turn a provider's experimental sources on or off",
		Long: "Experimental sources read another app's sign-in on this machine (read-only)\n" +
			"or use an endpoint the vendor has not documented. They can break, and the\n" +
			"vendor's terms may not allow them. Off by default, per provider.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var on bool
			switch strings.ToLower(args[1]) {
			case "on", "true", "yes":
				on = true
			case "off", "false", "no":
			default:
				return fmt.Errorf("say on or off, not %q", args[1])
			}
			return withPlans(cmd, *configPath, func(svc *planlimitssvc.Service) error {
				if err := svc.SetOptIn(cmd.Context(), args[0], on); err != nil {
					return plansCLIError(err)
				}
				state := "off"
				if on {
					state = "on"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Experimental sources for %s are %s.\n", planProviderLabel(args[0]), state)
				return nil
			})
		},
	}
}

// --- probe ------------------------------------------------------------------------

func newPlansProbeCmd(configPath *string) *cobra.Command {
	var (
		source  string
		params  []string
		secrets []string
		jsonOut bool
	)
	c := &cobra.Command{
		Use:   "probe <provider|account-id>",
		Short: "Run one live check and print what came back (stores nothing)",
		Long: "Runs one source once and prints the numbers it returned: plan, windows,\n" +
			"resets and balances. Nothing is stored and no secret is ever printed.\n" +
			"With an account id it uses that account's settings and keys; with a\n" +
			"provider it uses --source (default: the provider's first source that\n" +
			"needs no account), --param and --secret (values from stdin).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := parseKV(params)
			if err != nil {
				return err
			}
			sec, err := readSecrets(cmd.InOrStdin(), secrets)
			if err != nil {
				return err
			}
			return withPlans(cmd, *configPath, func(svc *planlimitssvc.Service) error {
				var snap planlimits.Snapshot
				var perr error
				if _, ok := planlimits.ProviderByID(args[0]); ok {
					src := source
					if src == "" {
						src = defaultPlanSource(args[0])
					}
					if src == "" {
						return fmt.Errorf("%s has no source to probe; pass --source", planProviderLabel(args[0]))
					}
					snap, perr = svc.Probe(cmd.Context(), planlimitssvc.ProbeRequest{Provider: args[0], Source: src, Params: p, Secrets: sec})
				} else {
					snap, perr = svc.ProbeAccount(cmd.Context(), args[0])
				}
				out := cmd.OutOrStdout()
				if perr != nil {
					if errors.Is(perr, planlimitssvc.ErrInvalid) || errors.Is(perr, planlimitssvc.ErrNeedsOptIn) || errors.Is(perr, planlimitssvc.ErrNotFound) {
						return plansCLIError(perr)
					}
					fmt.Fprintf(out, "Check failed: %s (%s)\n", planOutcomeText(planlimits.OutcomeCode(perr)), planlimits.OutcomeCode(perr))
					return nil
				}
				if jsonOut {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(snap)
				}
				printPlanSnapshot(out, snap, time.Now())
				return nil
			})
		},
	}
	c.Flags().StringVar(&source, "source", "", "the source id to run (see `observer plans sources`)")
	c.Flags().StringArrayVar(&params, "param", nil, "a setting as key=value (repeatable)")
	c.Flags().StringArrayVar(&secrets, "secret", nil, "a secret's name; its value is read from stdin (repeatable)")
	c.Flags().BoolVar(&jsonOut, "json", false, "print the reading as JSON")
	return c
}

// newPlansSourcesCmd lists every provider's sources and what each takes.
func newPlansSourcesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sources",
		Short: "List each provider's sources and what they need",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "PROVIDER\tSOURCE\tKIND\tNEEDS")
			for _, p := range planlimits.Providers {
				for _, s := range planlimits.SourcesFor(p.ID) {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, s.ID, planSourceKindText(s), planSourceNeeds(s))
				}
			}
			return tw.Flush()
		},
	}
}

func planSourceKindText(s planlimits.SourceDef) string {
	switch {
	case s.Passive:
		return "automatic"
	case s.Experimental():
		return "experimental"
	case s.Kind == planlimits.KindManual:
		return "typed in"
	default:
		return "official"
	}
}

func planSourceNeeds(s planlimits.SourceDef) string {
	var need []string
	for _, sec := range s.Secrets {
		need = append(need, "--secret "+sec.Key+optMark(sec.Required))
	}
	for _, p := range s.Params {
		v := "--param " + p.Key + "="
		if len(p.Choices) > 0 {
			v += strings.Join(p.Choices, "|")
		}
		need = append(need, v+optMark(p.Required))
	}
	if s.Command != "" {
		need = append(need, "runs "+s.Command)
	}
	if len(need) == 0 {
		return "nothing"
	}
	return strings.Join(need, ", ")
}

func optMark(required bool) string {
	if required {
		return ""
	}
	return " (optional)"
}

// defaultPlanSource is the provider's first source an account can use, or
// "" when it has none besides manual entry.
func defaultPlanSource(provider string) string {
	for _, s := range planlimits.SourcesFor(provider) {
		if !s.Passive && s.Kind != planlimits.KindManual && s.Provider == provider {
			return s.ID
		}
	}
	return ""
}

// --- helpers ----------------------------------------------------------------------

func parseKV(items []string) (map[string]string, error) {
	out := map[string]string{}
	for _, it := range items {
		k, v, ok := strings.Cut(it, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("--param %q: use key=value", it)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

// readSecrets reads one line from r per name, in order. Values never come
// from argv, so they never land in shell history or a process listing.
func readSecrets(r io.Reader, names []string) (map[string]string, error) {
	out := map[string]string{}
	if len(names) == 0 {
		return out, nil
	}
	sc := bufio.NewScanner(io.LimitReader(r, 64<<10))
	for _, n := range names {
		if !sc.Scan() {
			return nil, fmt.Errorf("--secret %s: no value on stdin (pipe one line per --secret)", n)
		}
		out[n] = strings.TrimSpace(sc.Text())
	}
	return out, nil
}

// plansCLIError turns a service error into a plain sentence.
func plansCLIError(err error) error {
	switch {
	case errors.Is(err, planlimitssvc.ErrNeedsOptIn):
		return errors.New("turn on experimental sources for this provider first: observer plans optin <provider> on")
	case errors.Is(err, planlimitssvc.ErrNotFound):
		return errors.New("no account with that id: see observer plans")
	}
	return errors.New(strings.TrimPrefix(err.Error(), "planlimits: "))
}

var planProviderLabels = map[string]string{
	"claude": "Claude", "chatgpt": "ChatGPT and Codex", "github_copilot": "GitHub Copilot",
	"cursor": "Cursor", "windsurf": "Windsurf", "kiro": "Kiro", "kimi_code": "Kimi Code",
	"amp": "Amp", "augment": "Augment", "openrouter": "OpenRouter", "deepseek": "DeepSeek",
	"moonshot": "Moonshot", "xai": "xAI", "other": "Other",
}

func planProviderLabel(id string) string {
	if l, ok := planProviderLabels[id]; ok {
		return l
	}
	return id
}

var planOutcomeTexts = map[string]string{
	planlimits.StatusOK:           "ok",
	planlimits.StatusThrottled:    "limit reached",
	planlimits.StatusPlanOnly:     "plan known, no usage meter",
	planlimits.StatusUnmetered:    "no metered limit",
	planlimits.StatusBilledElse:   "billed elsewhere",
	planlimits.StatusAuthNeeded:   "sign in again or replace the key",
	planlimits.StatusError:        "the check failed; the last reading stays",
	planlimits.StatusEndpointGone: "the vendor changed its API",
	planlimits.StatusStale:        "out of date",
	planlimits.StatusNotOptedIn:   "experimental sources are off for this provider",
	planlimits.StatusSkipped:      "not needed right now",
}

func planOutcomeText(code string) string {
	if t, ok := planOutcomeTexts[code]; ok {
		return t
	}
	if code == "" {
		return "no result"
	}
	return code
}

var planWindowLabels = map[string]string{
	"5h": "5-hour", "daily": "Daily", "weekly": "Weekly", "monthly": "Monthly", "cycle": "This cycle",
	"key_cap": "Key cap", "spend_limit": "Spend limit", "extra_usage": "Extra usage",
	"free_daily_requests": "Free requests today", "bonus": "Bonus credits",
	"premium": "Premium requests", "ai_credit": "AI credits",
}

func planWindowLabel(key string) string {
	if l, ok := planWindowLabels[key]; ok {
		return l
	}
	if p, rest, ok := strings.Cut(key, ":"); ok {
		head := planWindowLabels[p]
		if p == "model" {
			head = "Weekly"
		}
		if head == "" {
			head = p
		}
		return head + ", " + rest
	}
	return key
}

func planAmount(unit planlimits.Unit, v float64) string {
	switch unit {
	case planlimits.UnitUSDMicros:
		return fmt.Sprintf("USD %.2f", v/1e6)
	case planlimits.UnitCNYMicros:
		return fmt.Sprintf("CNY %.2f", v/1e6)
	case planlimits.UnitPercent:
		return fmt.Sprintf("%.0f%%", v)
	default:
		if v == math.Trunc(v) {
			return fmt.Sprintf("%.0f %s", v, unitWord(unit))
		}
		return fmt.Sprintf("%.2f %s", v, unitWord(unit))
	}
}

func unitWord(u planlimits.Unit) string {
	switch u {
	case planlimits.UnitCredits:
		return "credits"
	case planlimits.UnitAICredits:
		return "AI credits"
	case planlimits.UnitRequests:
		return "requests"
	case planlimits.UnitTokens:
		return "tokens"
	}
	return ""
}

func planWindowValue(w planlimits.Window) string {
	if w.Unit != planlimits.UnitPercent && w.Used != nil && w.Limit != nil {
		return planAmount(w.Unit, *w.Used) + " of " + planAmount(w.Unit, *w.Limit)
	}
	if w.UsedFrac != nil {
		return fmt.Sprintf("%.0f%%", *w.UsedFrac*100)
	}
	if w.Remaining != nil {
		return planAmount(w.Unit, *w.Remaining) + " left"
	}
	if w.Limit != nil {
		return planAmount(w.Unit, *w.Limit) + " cap"
	}
	return "not reported"
}

func planReset(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	d := t.Sub(now).Round(time.Minute)
	if d <= 0 {
		return "reset since this reading"
	}
	if d < 48*time.Hour {
		return "resets in " + d.String()
	}
	return "resets " + t.Local().Format("Mon Jan 2 15:04")
}

func printPlanSnapshot(out io.Writer, s planlimits.Snapshot, now time.Time) {
	fmt.Fprintf(out, "%s via %s: %s\n", planProviderLabel(s.Provider), s.Source, planOutcomeText(s.Status))
	if s.PlanLabel != "" || s.PlanCode != "" {
		fmt.Fprintf(out, "  plan: %s\n", planFirst(s.PlanLabel, s.PlanCode))
	}
	for _, w := range s.Windows {
		fmt.Fprintf(out, "  %s: %s %s\n", planWindowLabel(w.Key), planWindowValue(w), planReset(w.ResetsAt, now))
	}
	for _, b := range s.Balances {
		fmt.Fprintf(out, "  balance (%s): %s\n", b.Kind, planAmount(b.Unit, float64(b.Amount)))
	}
	for _, sp := range s.Spend {
		fmt.Fprintf(out, "  spent (%s): %s\n", sp.Period, planAmount(sp.Unit, float64(sp.Amount)))
	}
}

func planFirst(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func printPlanView(out io.Writer, v planlimitssvc.View, now time.Time) {
	if len(v.Cards) == 0 {
		fmt.Fprintln(out, "No plans yet. Claude and Codex limits appear when you use them;")
		fmt.Fprintln(out, "add an account to track a balance: observer plans add <provider>")
		return
	}
	cards := append([]planlimits.Card(nil), v.Cards...)
	sort.SliceStable(cards, func(i, j int) bool { return cards[i].Provider < cards[j].Provider })
	for _, c := range cards {
		title := planProviderLabel(c.Provider)
		if p := planFirst(c.PlanLabel, c.PlanCode); p != "" {
			title += " " + p
		}
		// The terminal is the owner's own, so the observed login still shows
		// here when there is no typed label, exactly as before Identity was
		// split out of Label (T-803 moved it out of the dashboard card title).
		if c.Label != "" {
			title += " (" + c.Label + ")"
		} else if c.Identity != "" {
			title += " (" + c.Identity + ")"
		}
		line := title
		if c.AccountID != "" {
			line += "  [" + c.AccountID + "]"
		}
		if c.Status != planlimits.StatusOK && c.Status != "" {
			line += "  " + planOutcomeText(c.Status)
		}
		if c.Experimental {
			line += "  experimental"
		}
		fmt.Fprintln(out, line)
		if c.Health == planlimits.HealthWaiting {
			fmt.Fprintln(out, "  waiting for the first reading")
		}
		for _, w := range c.Windows {
			fmt.Fprintf(out, "  %s: %s %s\n", planWindowLabel(w.Key), planWindowValue(w.Window), planReset(w.ResetsAt, now))
		}
		for _, b := range c.Balances {
			fmt.Fprintf(out, "  balance (%s): %s\n", b.Balance.Kind, planAmount(b.Unit, float64(b.Amount)))
		}
		for _, sp := range c.Spend {
			fmt.Fprintf(out, "  spent (%s): %s\n", sp.Period, planAmount(sp.Unit, float64(sp.Amount)))
		}
		if c.ObservedAt != nil {
			fmt.Fprintf(out, "  updated %s ago\n", now.Sub(*c.ObservedAt).Round(time.Minute))
		}
	}
}
