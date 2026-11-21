package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// sessionHoldScope is said by every hold command: the hold is this node's
// own, so the developer never mistakes it for an org-side save.
const sessionHoldScope = "This hold is local to this machine: node retention ([observer.retention]) keeps the session.\n" +
	"It does not save anything on an org server, whose retention is separate."

// newSessionsCmd is `observer sessions`, the per-session management group
// (managed-SaaS plan 07 M8.8: `observer sessions hold <id>`). Holds live in
// local_session_holds (agent migration 251), written only through
// internal/store/sessionholds.go and honoured by every node retention pass.
func newSessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Manage sessions on this machine (hold one so retention keeps it)",
		Long: "Per-session management.\n\n" +
			"  observer sessions hold <id>     keep a session past node retention\n" +
			"  observer sessions release <id>  remove a hold (the next retention pass decides)\n" +
			"  observer sessions holds         list the held sessions\n\n" +
			"A session id may be abbreviated to any unique prefix.\n\n" + sessionHoldScope,
	}
	cmd.AddCommand(newSessionsHoldCmd(), newSessionsReleaseCmd(), newSessionsHoldsCmd())
	return cmd
}

func newSessionsHoldCmd() *cobra.Command {
	var (
		configPath string
		note       string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "hold <session-id-prefix>",
		Short: "Keep a session past this machine's retention",
		Long:  "Places a hold on one session so node retention never prunes it.\n\n" + sessionHoldScope,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			id, err := resolveSessionPrefix(cmd.Context(), st, args[0])
			if err != nil {
				return err
			}
			created, err := st.HoldSession(cmd.Context(), id, note, time.Now().UTC())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				body, _ := json.MarshalIndent(map[string]any{"session_id": id, "held": true, "created": created, "scope": "node"}, "", "  ")
				fmt.Fprintln(out, string(body))
				return nil
			}
			if created {
				fmt.Fprintf(out, "held %s\n", id)
			} else {
				fmt.Fprintf(out, "%s was already held\n", id)
			}
			fmt.Fprintln(out, sessionHoldScope)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&note, "note", "", "Why the session is held (max 500 characters)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	return cmd
}

func newSessionsReleaseCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "release <session-id-prefix>",
		Short: "Remove a session's hold; the next retention pass decides",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			// A hold can outlive its session's rows (a component purge removes
			// them), so a full id that matches no session still releases.
			id, err := resolveSessionPrefix(cmd.Context(), st, args[0])
			if errors.Is(err, store.ErrSessionNotFound) {
				id, err = args[0], nil
			}
			if err != nil {
				return err
			}
			released, err := st.ReleaseSessionHold(cmd.Context(), id)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				body, _ := json.MarshalIndent(map[string]any{"session_id": id, "released": released}, "", "  ")
				fmt.Fprintln(out, string(body))
				return nil
			}
			if !released {
				return fmt.Errorf("%s is not held", id)
			}
			fmt.Fprintf(out, "released %s; node retention may prune it on its next pass\n", id)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	return cmd
}

func newSessionsHoldsCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "holds",
		Short: "List the sessions held on this machine",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			holds, err := store.New(database).ListSessionHolds(cmd.Context())
			if err != nil {
				return err
			}
			if holds == nil {
				holds = []store.SessionHold{}
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				body, _ := json.MarshalIndent(holds, "", "  ")
				fmt.Fprintln(out, string(body))
				return nil
			}
			if len(holds) == 0 {
				fmt.Fprintln(out, "no held sessions")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "SESSION\tHELD AT\tNOTE")
			for _, h := range holds {
				id := h.SessionID
				if !h.Exists {
					id += " (no rows left)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", id, h.HeldAt.Format(time.RFC3339), h.Note)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	return cmd
}
