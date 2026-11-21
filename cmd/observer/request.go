package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// request.go - `observer request ...` and `observer requests`, the CLI half of
// the Requests page (request-grants design §1.2, phase G6). A developer asks
// the org for a guard exemption, a budget increase, a tool, a model or a
// feature, previews exactly what will be sent (--dry-run), and follows the
// answer. `observer org request` / `observer org requests` stay as aliases of
// the free-text ask.

// requestFlags are the flags every typed request shares.
type requestFlags struct {
	configPath     string
	duration       string
	uses           int64
	includeExcerpt bool
	dryRun         bool
}

func (f *requestFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&f.duration, "duration", "24h", "how long you need it, e.g. 8h, 3d (the org caps this per type; never permanent)")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "print exactly what would be sent, and send nothing")
}

// parseRequestDuration accepts Go durations plus a whole-day "Nd" form.
func parseRequestDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return accessgrant.DefaultDuration, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("bad duration %q", s)
	}
	return d, nil
}

// sendTypedRequest prepares, optionally previews, and sends (or queues) one
// request through the same client path the dashboard uses.
func sendTypedRequest(cmd *cobra.Command, f requestFlags, in orgcontract.AccessRequestCreate) error {
	d, err := parseRequestDuration(f.duration)
	if err != nil {
		return err
	}
	in.RequestedDurationS = int64(d / time.Second)
	if f.uses > 0 {
		in.RequestedUses = f.uses
	}
	b, err := buildOrgBundle(cmd.Context(), f.configPath)
	if err != nil {
		return err
	}
	defer b.cleanup()
	prepared, err := b.client.PrepareAccessRequest(cmd.Context(), in, f.includeExcerpt)
	if errors.Is(err, orgclient.ErrNotEnrolled) {
		return errors.New("not enrolled; requests go to an organization. Run `observer enroll <org-url> <token>` first")
	}
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if f.dryRun {
		raw, _ := json.MarshalIndent(prepared, "", "  ")
		fmt.Fprintln(out, "This is exactly what would be sent (nothing was sent):")
		fmt.Fprintln(out, string(raw))
		return nil
	}
	got, queued, err := b.client.SendOrQueueAccessRequest(cmd.Context(), prepared)
	var refused *orgclient.RequestRefusedError
	switch {
	case errors.As(err, &refused):
		return refused
	case errors.Is(err, orgclient.ErrOrgRequestCapReached):
		return errors.New("you already have the maximum number of open requests to this organization; withdraw one or wait for an answer (`observer requests`)")
	case err != nil:
		return err
	}
	if queued > 0 {
		fmt.Fprintf(out, "The organization is unreachable right now. The request is queued (queue id %d) and will be sent on the next sync.\n", queued)
		return nil
	}
	if got.Duplicate {
		fmt.Fprintf(out, "You already have this request open (#%d); nothing new was sent.\n", got.ID)
		return nil
	}
	fmt.Fprintf(out, "Request #%d sent. Your admin will see it in their Requests queue; run `observer requests` to follow it.\n", got.ID)
	return nil
}

func newRequestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Ask your organization for an exception: a guard exemption, more budget, a tool, a model or a feature",
		Long: `Asks the organization this node is enrolled with for a time-limited exception.
An admin grants it with an expiry (or declines it with a note); a granted
exception reaches this node on its next sync and ends on its own when it
expires. Every request can be previewed with --dry-run first.

The same actions are on the dashboard's Requests page.`,
	}
	cmd.AddCommand(newRequestAccessCmd(), newRequestBudgetCmd(),
		newRequestTargetCmd("tool", accessgrant.TypeToolAllow, "Ask to use a tool the organization blocks"),
		newRequestTargetCmd("model", accessgrant.TypeModelAccess, "Ask to use a model the organization does not allow"),
		newRequestTargetCmd("feature", accessgrant.TypeFeatureEnable, "Ask the organization to enable a feature for you"),
		newRequestTargetCmd("component", accessgrant.TypeComponentEnable, "Ask the organization to let a component run on this machine"),
		newRequestWithdrawCmd(), newRequestCancelQueuedCmd())
	return cmd
}

func newRequestAccessCmd() *cobra.Command {
	var (
		f         requestFlags
		eventID   int64
		ruleID    string
		sessionID string
		breadth   string
	)
	cmd := &cobra.Command{
		Use:   "access <why>",
		Short: "Ask for an exemption from a guard rule",
		Long: `Asks for an exemption from one guard rule. With --event (a guard event id from
the Security page or ` + "`observer guard events`" + `) the request is prefilled with
the rule, the exact command and the project, and --breadth exact is the
default: the exemption then covers that command again and nothing else.
With --rule alone the request is rule-wide; add --session (the session id the
guard's deny line names) to start from that session's newest event for the
rule instead, exact by default.

The command excerpt is sent only with --include-excerpt on a personal node;
on an organization-managed node it is always part of the request.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if eventID <= 0 && ruleID == "" {
				return errors.New("name the rule with --rule, or start from a guard event with --event")
			}
			b, err := buildOrgBundle(cmd.Context(), f.configPath)
			if err != nil {
				return err
			}
			in, err := resolveAccessDraft(cmd.Context(), b.store, eventID, ruleID, sessionID, breadth, cmd.Flags().Changed("breadth"))
			b.cleanup()
			if err != nil {
				return err
			}
			in.Message = args[0]
			return sendTypedRequest(cmd, f, in)
		},
	}
	f.bind(cmd)
	cmd.Flags().Int64Var(&eventID, "event", 0, "guard event id to prefill from")
	cmd.Flags().StringVar(&ruleID, "rule", "", "guard rule id, e.g. R-171")
	cmd.Flags().StringVar(&sessionID, "session", "", "with --rule: start from this session's newest event for the rule")
	cmd.Flags().StringVar(&breadth, "breadth", accessgrant.BreadthExact, "exact (this command) | class (this kind of command) | rule (anything the rule matches); default exact from an event, rule otherwise")
	cmd.Flags().Int64Var(&f.uses, "uses", 0, "how many times you need it (0 = until it expires)")
	cmd.Flags().BoolVar(&f.includeExcerpt, "include-excerpt", false, "send the command excerpt so the approver can see it")
	return cmd
}

func newRequestBudgetCmd() *cobra.Command {
	var (
		f           requestFlags
		deltaTokens int64
		deltaUSD    float64
		budgetID    string
	)
	cmd := &cobra.Command{
		Use:   "budget <why>",
		Short: "Ask for more budget for the current budget period",
		Long: `Asks for a budget increase of --tokens or --usd on top of your current cap. An
approved increase lasts at most until the end of the current budget period,
and your cap drops back on its own when it ends.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if deltaTokens <= 0 && deltaUSD <= 0 {
				return errors.New("say how much more you need with --tokens or --usd")
			}
			return sendTypedRequest(cmd, f, orgcontract.AccessRequestCreate{
				RequestType: accessgrant.TypeBudgetIncrease, Message: args[0],
				Payload: &orgcontract.AccessRequestPayload{BudgetID: budgetID, DeltaTokens: deltaTokens, DeltaUSD: deltaUSD},
			})
		},
	}
	f.bind(cmd)
	cmd.Flags().Int64Var(&deltaTokens, "tokens", 0, "additional tokens")
	cmd.Flags().Float64Var(&deltaUSD, "usd", 0, "additional dollars")
	cmd.Flags().StringVar(&budgetID, "budget-id", "", "the budget to raise, when you know it (otherwise your organization fills in yours, or the approver picks)")
	return cmd
}

func newRequestTargetCmd(name, reqType, short string) *cobra.Command {
	var f requestFlags
	cmd := &cobra.Command{
		Use:   name + " <" + name + "> <why>",
		Short: short,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return sendTypedRequest(cmd, f, orgcontract.AccessRequestCreate{
				RequestType: reqType, Message: args[1], Target: args[0],
				Payload: &orgcontract.AccessRequestPayload{Target: args[0]},
			})
		},
	}
	f.bind(cmd)
	return cmd
}

func newRequestWithdrawCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "withdraw <request-id>",
		Short: "Withdraw one of your open requests",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(strings.TrimPrefix(args[0], "#"), 10, 64)
			if err != nil || id <= 0 {
				return fmt.Errorf("bad request id %q", args[0])
			}
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			switch err := b.client.WithdrawOrgRequest(cmd.Context(), id); {
			case errors.Is(err, orgclient.ErrRequestNotFound):
				return fmt.Errorf("no open request #%d of yours", id)
			case errors.Is(err, orgclient.ErrRequestNotOpen):
				return fmt.Errorf("request #%d is no longer open", id)
			case err != nil:
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Request #%d withdrawn.\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func newRequestCancelQueuedCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "cancel <queue-id>",
		Short: "Cancel a request that is queued because the organization was unreachable",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || id <= 0 {
				return fmt.Errorf("bad queue id %q", args[0])
			}
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			ok, err := b.client.CancelQueuedAccessRequest(cmd.Context(), id)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no queued request %d", id)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Queued request %d cancelled; it was never sent.\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// newRequestsCmd lists this member's requests, the queue and the grants this
// machine holds.
func newRequestsCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "requests",
		Short: "List your requests to your organization, queued requests, and the exceptions in force on this machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			out := cmd.OutOrStdout()
			view, _, err := b.client.AccessGrantsView(cmd.Context())
			if err != nil {
				return err
			}
			printGrantsInForce(out, view, time.Now())
			if q, err := b.client.QueuedAccessRequests(cmd.Context()); err == nil && len(q) > 0 {
				fmt.Fprintln(out, "Queued (not yet sent):")
				for _, r := range q {
					fmt.Fprintf(out, "  queue %d  since %s  attempts %d %s\n", r.ID, r.CreatedAt, r.Attempts, r.LastError)
				}
				fmt.Fprintln(out)
			}
			reqs, err := b.client.ListMyOrgRequests(cmd.Context())
			if errors.Is(err, orgclient.ErrNotEnrolled) {
				return errors.New("not enrolled; run `observer enroll <org-url> <token>` first")
			}
			if err != nil {
				fmt.Fprintf(out, "Requests: the organization could not be reached (%v)\n", err)
				return nil
			}
			if len(reqs) == 0 {
				fmt.Fprintln(out, "No requests yet. Ask with `observer request access|budget|tool|model|feature`.")
				return nil
			}
			fmt.Fprintln(out, "Requests:")
			for _, r := range reqs {
				label := orgOrDefault(r.RequestType, orgOrDefault(r.Kind, "other"))
				fmt.Fprintf(out, "  #%d  %-16s  %-9s  %s\n", r.ID, label, r.Status, r.CreatedAt)
				fmt.Fprintf(out, "       %s\n", r.Message)
				if r.Grant != nil {
					fmt.Fprintf(out, "       %s\n", requestGrantLine(r.Grant, time.Now()))
				}
				if r.ResolutionNote != "" {
					fmt.Fprintf(out, "       note: %s\n", r.ResolutionNote)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// requestGrantLine is the answer line of a granted request: the grant's
// live state, not the request's decision (demo finding #27). A revoked grant
// says when and the admin's reason; one an extension replaced says which
// grant replaced it (accessgrant.ReplacedBy); an ended one says it ended.
func requestGrantLine(g *orgcontract.AccessRequestGrantSummary, now time.Time) string {
	switch g.Status {
	case accessgrant.StatusRevoked:
		if by, ok := accessgrant.ReplacedBy(g.RevokeReason); ok {
			line := fmt.Sprintf("granted as G-%d, replaced by %s", g.ID, by)
			if g.RevokedAtNs > 0 {
				line += " " + time.Unix(0, g.RevokedAtNs).UTC().Format(time.RFC3339)
			}
			return line
		}
		line := fmt.Sprintf("granted as G-%d, revoked", g.ID)
		if g.RevokedAtNs > 0 {
			line += " " + time.Unix(0, g.RevokedAtNs).UTC().Format(time.RFC3339)
		}
		if g.RevokeReason != "" {
			line += ": " + g.RevokeReason
		}
		return line
	case accessgrant.StatusExhausted:
		return fmt.Sprintf("granted as G-%d, every use spent", g.ID)
	default:
		return fmt.Sprintf("granted as G-%d (%s)", g.ID, grantWindowText(g.ExpiresAtNs, now))
	}
}

func grantWindowText(expiresNs int64, now time.Time) string {
	if expiresNs <= 0 {
		return "no expiry"
	}
	exp := time.Unix(0, expiresNs)
	if !exp.After(now) {
		return "expired " + exp.UTC().Format(time.RFC3339)
	}
	return "until " + exp.UTC().Format(time.RFC3339) + ", " + accessgrant.HumanDuration(exp.Sub(now)) + " left"
}

// printGrantsInForce renders the exceptions this machine holds, each with
// its expiry and whether the node would honour it right now.
func printGrantsInForce(out io.Writer, view store.AccessGrantsView, now time.Time) {
	if len(view.Grants) == 0 {
		fmt.Fprintln(out, "Exceptions in force on this machine: none.")
		fmt.Fprintln(out)
		return
	}
	fmt.Fprintln(out, "Exceptions in force on this machine:")
	for _, g := range view.Grants {
		what := g.Grant.Type
		if g.Grant.RuleID != "" {
			what += " " + g.Grant.RuleID
		}
		if g.Grant.Target != "" {
			what += " " + g.Grant.Target
		}
		state := "in force"
		if !g.Honoured {
			state = "not in force (" + g.Reason + ")"
		}
		fmt.Fprintf(out, "  G-%d  %s  %s  %s\n", g.Grant.ID, what, grantWindowText(g.Grant.ExpiresAtNs, now), state)
	}
	fmt.Fprintln(out)
}

// resolveAccessDraft builds `observer request access`'s guard-exemption
// draft: from a guard event (exact by default), else from a rule and an
// optional session (store.GuardRuleRequestDraft: that session's newest event
// for the rule, else rule-wide). An explicit --breadth wins and drops what
// that breadth does not carry. The deny line's own command (--rule alone)
// therefore yields a rule-wide request the local pre-check accepts.
func resolveAccessDraft(ctx context.Context, st *store.Store, eventID int64, ruleID, sessionID, breadth string, breadthSet bool) (orgcontract.AccessRequestCreate, error) {
	var in orgcontract.AccessRequestCreate
	switch {
	case eventID > 0:
		draft, ok, err := st.GuardEventRequestDraft(ctx, eventID)
		if err != nil {
			return in, err
		}
		if !ok {
			return in, fmt.Errorf("no guard event #%d on this machine", eventID)
		}
		in = draft
	case ruleID != "":
		draft, err := st.GuardRuleRequestDraft(ctx, ruleID, sessionID)
		if err != nil {
			return in, err
		}
		in = draft
	default:
		return in, errors.New("name the rule with --rule, or start from a guard event with --event")
	}
	in.RequestType = accessgrant.TypeGuardExemption
	if in.Payload == nil {
		in.Payload = &orgcontract.AccessRequestPayload{}
	}
	if ruleID != "" {
		in.Payload.RuleID = ruleID
	}
	if breadthSet {
		in.Payload.Breadth = breadth
	}
	if in.Payload.Breadth != accessgrant.BreadthExact {
		in.Payload.OperandHash = ""
	}
	if in.Payload.Breadth == accessgrant.BreadthRule {
		in.Payload.CommandClass = ""
	}
	return in, nil
}
