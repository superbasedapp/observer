package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
)

// The vendor user of a member-scoped account (CLOUDAGENTS-6,
// docs/cloud-agents.md "Devin", "OpenHands", "Warp"): a Devin key lists every
// member of its organization, an OpenHands key every conversation it can see
// and a Warp key its teams' runs, and none of them names the key's owner, so
// the developer picks their own vendor user from the users the list reports.
// `users` prints the picker; `choose-user` records the pick (by its number
// in that list, or the user id it printed), never free text the CLI cannot
// check. Both commands work for any connector whose catalog row says it
// chooses a user.

func newCloudAgentsUsersCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "users <account-id>",
		Short: "List the users an account whose key sees other people's sessions (devin, openhands-cloud, warp-cloud) can pull for",
		Long: "Reads one page of the account's sessions and prints the users it names,\n" +
			"numbered, with their display names where the vendor gives one (Warp: on\n" +
			"the list itself; Devin: one page of messages per user; OpenHands: ids\n" +
			"only). Record yours with `observer cloud-agents choose-user <account-id> <number>`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseAccountID(args[0])
			if err != nil {
				return err
			}
			return withCloudAgents(cmd, *configPath, func(svc *cloudagentssvc.Service) error {
				uc, err := svc.UserCandidates(cmd.Context(), id)
				if err != nil {
					return err
				}
				printUserCandidates(cmd.OutOrStdout(), uc)
				return userCandidatesErr(uc)
			})
		},
	}
}

func newCloudAgentsChooseUserCmd(configPath *string) *cobra.Command {
	var noSync bool
	c := &cobra.Command{
		Use:   "choose-user <account-id> [number|user-id]",
		Short: "Name your own user on an account whose key sees other people's sessions (devin, openhands-cloud, warp-cloud); only its sessions are pulled",
		Long: "Without a choice, lists the users (`users`) and asks for a number on a\n" +
			"terminal. The next pass pulls only that user's sessions and removes the\n" +
			"sessions of this account other members or service users started.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseAccountID(args[0])
			if err != nil {
				return err
			}
			pick := ""
			if len(args) == 2 {
				pick = strings.TrimSpace(args[1])
			}
			return withCloudAgents(cmd, *configPath, func(svc *cloudagentssvc.Service) error {
				out := cmd.OutOrStdout()
				chosen, err := chooseVendorUser(cmd, svc, id, pick)
				if err != nil || chosen == "" {
					return err
				}
				if noSync {
					return nil
				}
				res, err := svc.SyncAccount(cmd.Context(), id)
				if err == nil || cloudagentssvc.IsCollectionError(err) {
					printSyncResult(out, res)
				}
				return syncErr(err)
			})
		},
	}
	c.Flags().BoolVar(&noSync, "no-sync", false, "record the choice only; the daemon pulls on its next tick")
	return c
}

func parseAccountID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cloud-agents: account id %q is not a number (see `observer cloud-agents status`)", s)
	}
	return id, nil
}

// chooseVendorUser records pick (a user id, or a number from the listed
// users) or, with none, lists the users and asks for a number on a
// terminal. It returns the chosen id, "" when nothing was chosen (the list
// was printed with the command to run).
func chooseVendorUser(cmd *cobra.Command, svc *cloudagentssvc.Service, id int64, pick string) (string, error) {
	out := cmd.OutOrStdout()
	userID := pick
	if pick == "" || isListNumber(pick) {
		uc, err := svc.UserCandidates(cmd.Context(), id)
		if err != nil {
			return "", err
		}
		if pick == "" {
			printUserCandidates(out, uc)
		}
		if err := userCandidatesErr(uc); err != nil {
			return "", err
		}
		if len(uc.Candidates) == 0 {
			return "", nil
		}
		if pick == "" {
			v, err := cloudAgentsPick(cmd.InOrStdin(), cmd.ErrOrStderr(), userChoices(uc))
			if err != nil {
				_, _ = fmt.Fprintf(out, "Record yours with `observer cloud-agents choose-user %d <number>`.\n", id)
				return "", nil
			}
			userID = v
		} else {
			n, _ := strconv.Atoi(pick)
			if n < 1 || n > len(uc.Candidates) {
				return "", fmt.Errorf("cloud-agents: %d is not one of the %d listed users", n, len(uc.Candidates))
			}
			userID = uc.Candidates[n-1].UserID
		}
	}
	av, err := svc.ChooseVendorUser(cmd.Context(), id, userID)
	if err != nil {
		return "", err
	}
	_, _ = fmt.Fprintf(out, "account %d now pulls only %s's sessions", av.ID, terminalSafe(av.VendorUser))
	if av.PurgePending {
		_, _ = fmt.Fprint(out, "; the next pass removes the sessions other members or service users started")
	}
	_, _ = fmt.Fprintln(out)
	return av.VendorUser, nil
}

// isListNumber reports whether a choice is a number from the listed users
// (a user id is never all digits).
func isListNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// userChoices turns the candidates into a picker parameter, so the terminal
// pick is the same numbered list as every other picker.
func userChoices(uc cloudagentssvc.UserCandidates) cloudagents.ParamSpec {
	p := cloudagents.ParamSpec{Name: "vendor_user", Label: "Your " + uc.UserLabel}
	for _, c := range uc.Candidates {
		p.Choices = append(p.Choices, cloudagents.ParamChoice{Value: c.UserID, Label: candidateLabel(c)})
	}
	return p
}

// candidateLabel is a candidate's display: its username (sanitized) and its
// session count.
func candidateLabel(c cloudagents.VendorUserCandidate) string {
	name := "name not read"
	if c.Username != "" {
		name = terminalSafe(c.Username)
	}
	return fmt.Sprintf("%s, %d session(s)", name, c.Sessions)
}

func printUserCandidates(w io.Writer, uc cloudagentssvc.UserCandidates) {
	if uc.ErrorClass != "" {
		_, _ = fmt.Fprintf(w, "account %d (%s): the users could not be listed (%s)\n", uc.AccountID, uc.Connector, uc.ErrorClass)
		if hint := classHint(uc.ErrorClass, uc.Connector); hint != "" {
			_, _ = fmt.Fprintln(w, "  "+hint)
		}
		return
	}
	if len(uc.Candidates) == 0 {
		_, _ = fmt.Fprintf(w, "account %d (%s): no session on the first page names a person. Start a session as yourself with this vendor, then run this again.\n", uc.AccountID, uc.Connector)
	} else {
		_, _ = fmt.Fprintf(w, "%ss with sessions this key can see (account %d):\n", uc.UserLabel, uc.AccountID)
		for i, c := range uc.Candidates {
			mark := ""
			if c.UserID == uc.Chosen {
				mark = "  (chosen)"
			}
			_, _ = fmt.Fprintf(w, "  %d) %s  %s%s\n", i+1, terminalSafe(c.UserID), candidateLabel(c), mark)
		}
	}
	if uc.ServiceUserSessions > 0 {
		_, _ = fmt.Fprintf(w, "  %d session(s) started by a service user or service account: never pulled\n", uc.ServiceUserSessions)
	}
	if uc.NoUserSessions > 0 {
		_, _ = fmt.Fprintf(w, "  %d session(s) naming no person: never pulled\n", uc.NoUserSessions)
	}
	if uc.More {
		_, _ = fmt.Fprintln(w, "  (first page only: a user with no recent session is not listed)")
	}
	if len(uc.Candidates) > 0 {
		_, _ = fmt.Fprintf(w, "Record yours: observer cloud-agents choose-user %d <number>\n", uc.AccountID)
	}
}

func userCandidatesErr(uc cloudagentssvc.UserCandidates) error {
	if uc.ErrorClass == "" {
		return nil
	}
	return errors.New("cloud-agents: listing users failed (" + string(uc.ErrorClass) + ")")
}

// printVendorUser is the account section's user line.
func printVendorUser(w io.Writer, a cloudagentssvc.AccountView, label string) {
	switch a.UserState {
	case cloudagents.VendorUserNotChosen:
		_, _ = fmt.Fprintf(w, "  %-10s not chosen: nothing is pulled. Pick your %s: observer cloud-agents choose-user %d\n", "user", label, a.ID)
	case cloudagents.VendorUserChosen:
		line := terminalSafe(a.VendorUser) + " (only this " + label + "'s sessions are pulled)"
		if a.PurgePending {
			line += "; the next pass removes the sessions other members started"
		}
		_, _ = fmt.Fprintf(w, "  %-10s %s\n", "user", line)
	}
}
