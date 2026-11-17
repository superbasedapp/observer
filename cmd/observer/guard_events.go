package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer guard events` lists this node's recent guard verdicts
// (control-coverage audit CG-18). A verdict tied to a session is shown on that
// session's Messages tab, which stays visible on every node. A session-less
// one (an org bundle rejected by R-205, a posture change, a disabled hook, an
// invalid user policy) is shown only on the Security page, which is hidden by
// default on a managed node, and `observer guard status` prints counts only.
// --session-less is that list. It reads the node's own audit log, read-only.

// guardEventsReasonMax bounds the reason column in the table form; --json
// carries the whole reason.
const guardEventsReasonMax = 160

func newGuardEventsCmd() *cobra.Command {
	var (
		configPath  string
		since       string
		limit       int
		sessionLess bool
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "events",
		Short: "List recent guard verdicts (--session-less: the ones no session view shows)",
		Long: "Lists this node's recent guard verdicts, newest first, from the local audit log.\n" +
			"--session-less keeps only verdicts that carry no session id (an org policy\n" +
			"bundle that was rejected, a posture change, a disabled hook, an invalid user\n" +
			"policy): a session's own verdicts are on its Messages tab in the dashboard.",
		Args: cobra.NoArgs,
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
			s := store.New(database)
			var rows []store.GuardEventRow
			if sessionLess {
				rows, err = s.LoadRecentSessionlessGuardEvents(cmd.Context(), sinceTime, limit)
			} else {
				rows, err = s.LoadRecentGuardEvents(cmd.Context(), sinceTime, limit)
			}
			if err != nil {
				return err
			}
			if jsonOut {
				return writeGuardEventsJSON(cmd.OutOrStdout(), rows)
			}
			writeGuardEventsTable(cmd.OutOrStdout(), rows, sessionLess)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&since, "since", "", "only show events newer than this duration ago (e.g. 24h, 30m)")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum rows to show (newest first)")
	cmd.Flags().BoolVar(&sessionLess, "session-less", false, "only verdicts that carry no session id")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

// guardEventView is one listed verdict: what the developer needs to read it,
// never the chain links or the target hash.
type guardEventView struct {
	Time         string `json:"time"`
	SessionID    string `json:"session_id,omitempty"`
	Tool         string `json:"tool,omitempty"`
	Kind         string `json:"event_kind,omitempty"`
	RuleID       string `json:"rule_id"`
	Decision     string `json:"decision"`
	Enforced     bool   `json:"enforced"`
	DegradedFrom string `json:"degraded_from,omitempty"`
	Source       string `json:"source,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

func guardEventViews(rows []store.GuardEventRow) []guardEventView {
	out := make([]guardEventView, 0, len(rows))
	for _, r := range rows {
		out = append(out, guardEventView{
			Time: r.TS.UTC().Format(time.RFC3339), SessionID: r.SessionID, Tool: r.Tool,
			Kind: r.EventKind, RuleID: r.RuleID, Decision: r.Decision, Enforced: r.Enforced,
			DegradedFrom: r.DegradedFrom, Source: r.Source, Reason: r.Reason,
		})
	}
	return out
}

func writeGuardEventsJSON(w io.Writer, rows []store.GuardEventRow) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"events": guardEventViews(rows)})
}

func writeGuardEventsTable(w io.Writer, rows []store.GuardEventRow, sessionLess bool) {
	if len(rows) == 0 {
		if sessionLess {
			fmt.Fprintln(w, "(no session-less guard verdicts in range)")
		} else {
			fmt.Fprintln(w, "(no guard verdicts in range)")
		}
		return
	}
	fmt.Fprintf(w, "%-20s %-12s %-14s %-7s %-8s %-4s %-6s %s\n", "TIME", "TOOL", "KIND", "RULE", "DECISION", "ENF", "SOURCE", "REASON")
	for _, v := range guardEventViews(rows) {
		enf := "no"
		if v.Enforced {
			enf = "yes"
		}
		fmt.Fprintf(w, "%-20s %-12s %-14s %-7s %-8s %-4s %-6s %s\n",
			v.Time, dashIfEmpty(v.Tool), dashIfEmpty(v.Kind), v.RuleID, v.Decision, enf, dashIfEmpty(v.Source),
			oneLine(v.Reason, guardEventsReasonMax))
	}
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// oneLine flattens s to one line and cuts it to max runes.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
