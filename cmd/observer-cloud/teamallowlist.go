package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// teamallowlist.go is the operator side of the team create allow-list
// (managed-SaaS plan 07 wave 17 lane portal-guardrails; cloud 0130;
// docs/security.md TEAMGATE-1): the serve switch and the
// `observer-cloud staff team-allowlist` verbs. The staff console changes the
// same list through /staff/api/team-allowlist; both write a staff_actions row
// per change (actor "operator" here).

// teamCreateAllowlistEnv is the serve switch: "on" lets only allow-listed
// accounts and verified email domains create a team org; "off" (or unset)
// leaves team creation open, capped per account. The production kit sets it
// on (deploy/saas-ovh/cloud-app, SBCI_OVH_TEAM_CREATE_ALLOWLIST) until GO-3.
const teamCreateAllowlistEnv = "SBCI_TEAM_CREATE_ALLOWLIST"

// teamCreateAllowlistFromEnv reads the switch. Any value other than on, off,
// true, false, 1, 0 or empty is an error, so a typo cannot quietly open team
// creation.
func teamCreateAllowlistFromEnv(log *slog.Logger) (bool, error) {
	on, err := parseTeamCreateAllowlist(os.Getenv(teamCreateAllowlistEnv))
	if err != nil {
		return false, err
	}
	if on {
		log.Info("observer-cloud: team org creation is by allow-list (" + teamCreateAllowlistEnv + "=on)")
	} else {
		log.Info("observer-cloud: team org creation is open to every account, capped per account (" + teamCreateAllowlistEnv + " off)")
	}
	return on, nil
}

func parseTeamCreateAllowlist(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "true", "1":
		return true, nil
	case "", "off", "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("%s=%q: want on or off", teamCreateAllowlistEnv, raw)
	}
}

// newStaffTeamAllowlistCmd is `observer-cloud staff team-allowlist`.
func newStaffTeamAllowlistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "team-allowlist",
		Short: "who may create a team org while " + teamCreateAllowlistEnv + " is on (until GO-3)",
		Long: "While " + teamCreateAllowlistEnv + "=on, only an account on this list, or one whose verified email is at a\n" +
			"listed domain, may create a team org from the console. Personal orgs are never checked. Every\n" +
			"change is kept with its reason in the staff action log. The staff console changes the same list.",
	}
	cmd.AddCommand(newTeamAllowlistListCmd(), newTeamAllowlistAddCmd(), newTeamAllowlistRemoveCmd())
	return cmd
}

// teamAllowlistOps is the store slice the verbs use.
type teamAllowlistOps interface {
	ListTeamAllowlist(ctx context.Context, includeRemoved bool) ([]store.TeamAllowlistEntry, error)
	AddTeamAllowlistEntry(ctx context.Context, e staffauth.AllowlistEntry, c store.TeamAllowlistChange) (store.TeamAllowlistEntry, error)
	RemoveTeamAllowlistEntry(ctx context.Context, entryID string, c store.TeamAllowlistChange) (store.TeamAllowlistEntry, error)
}

func withTeamAllowlistStore(cmd *cobra.Command, fn func(ctx context.Context, s teamAllowlistOps) error) error {
	ctx := cmd.Context()
	s, err := openOperatorStaffStore(ctx)
	if err != nil {
		return err
	}
	defer s.Pool().Close()
	return fn(ctx, s)
}

func newTeamAllowlistListCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "list the active entries (--all adds the removed ones)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withTeamAllowlistStore(cmd, func(ctx context.Context, s teamAllowlistOps) error {
				return runTeamAllowlistList(ctx, s, all, cmd.OutOrStdout())
			})
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "include removed entries")
	return cmd
}

func runTeamAllowlistList(ctx context.Context, s teamAllowlistOps, all bool, out io.Writer) error {
	entries, err := s.ListTeamAllowlist(ctx, all)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		_, err := fmt.Fprintln(out, "the team allow-list is empty")
		return err
	}
	for _, e := range entries {
		state := "active"
		if !e.Active() {
			state = "removed " + e.RemovedAt.UTC().Format(time.RFC3339) + " by " + e.RemovedBy
		}
		if _, err := fmt.Fprintf(out, "%s  %-12s %-40s added %s by %s  %s\n", e.EntryID, e.Kind, e.Value,
			e.AddedAt.UTC().Format(time.RFC3339), e.AddedBy, state); err != nil {
			return err
		}
	}
	return nil
}

type teamAllowlistAddFlags struct {
	account, domain, reason string
}

func newTeamAllowlistAddCmd() *cobra.Command {
	var f teamAllowlistAddFlags
	cmd := &cobra.Command{
		Use:   "add",
		Short: "allow one account (--account ID) or a verified email domain (--domain example.com)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withTeamAllowlistStore(cmd, func(ctx context.Context, s teamAllowlistOps) error {
				return runTeamAllowlistAdd(ctx, s, f, time.Now(), cmd.OutOrStdout())
			})
		},
	}
	cmd.Flags().StringVar(&f.account, "account", "", "an account id (the refusal shows it to the person as their account reference)")
	cmd.Flags().StringVar(&f.domain, "domain", "", "an email domain; matches a VERIFIED email at exactly this domain")
	cmd.Flags().StringVar(&f.reason, "reason", "", "why (required; kept in the staff action log)")
	return cmd
}

func runTeamAllowlistAdd(ctx context.Context, s teamAllowlistOps, f teamAllowlistAddFlags, now time.Time, out io.Writer) error {
	var kind, value string
	switch {
	case (f.account == "") == (f.domain == ""):
		return errors.New("give exactly one of --account or --domain")
	case f.account != "":
		kind, value = string(staffauth.AllowlistAccount), f.account
	default:
		kind, value = string(staffauth.AllowlistEmailDomain), f.domain
	}
	entry, err := staffauth.ValidateAllowlistEntry(kind, value)
	if err != nil {
		return err
	}
	got, err := s.AddTeamAllowlistEntry(ctx, entry, store.TeamAllowlistChange{Reason: f.reason, Now: now})
	if errors.Is(err, store.ErrTeamAllowlistExists) {
		return fmt.Errorf("%s %s is already on the team allow-list", entry.Kind, entry.Value)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "added %s %s (entry %s)\n", got.Kind, got.Value, got.EntryID)
	return err
}

func newTeamAllowlistRemoveCmd() *cobra.Command {
	var entryID, reason string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "remove an entry (an account that already holds a team org keeps it)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withTeamAllowlistStore(cmd, func(ctx context.Context, s teamAllowlistOps) error {
				return runTeamAllowlistRemove(ctx, s, entryID, reason, time.Now(), cmd.OutOrStdout())
			})
		},
	}
	cmd.Flags().StringVar(&entryID, "entry", "", "the entry id (from list)")
	cmd.Flags().StringVar(&reason, "reason", "", "why (required; kept in the staff action log)")
	return cmd
}

func runTeamAllowlistRemove(ctx context.Context, s teamAllowlistOps, entryID, reason string, now time.Time, out io.Writer) error {
	if strings.TrimSpace(entryID) == "" {
		return errors.New("--entry is required")
	}
	got, err := s.RemoveTeamAllowlistEntry(ctx, strings.TrimSpace(entryID), store.TeamAllowlistChange{Reason: reason, Now: now})
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no active entry %s", entryID)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "removed %s %s (entry %s)\n", got.Kind, got.Value, got.EntryID)
	return err
}
