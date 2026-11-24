package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/mcp/audit"
)

// newMCPAuditCmd wires `observer mcp-audit`, the operator-facing read
// surface on top of the mcp_audit table (V7-14).
//
// Subcommands:
//   - list        — table of rows for one session / window
//   - stats       — aggregate counts + by-tool breakdown
//   - top-paths   — most-requested paths (capacity planning)
//   - denied      — only response_ok=0 rows
//   - purge       — manual deletion older than a duration
//
// Each read subcommand supports `--json` for machine consumption.
func newMCPAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp-audit",
		Short: "Read and prune the mcp_audit table (the MCP retrieval tools' call log)",
		Long: "Inspect the MCP audit log. Every retrieval-tool call (get_file,\n" +
			"get_symbols, get_relations, retrieve_stashed) writes one row when\n" +
			"the audit writer is enabled - operators consult this surface to\n" +
			"answer 'why was X denied?', 'which file is the agent re-reading?',\n" +
			"or 'how many sessions hit the cap last hour?'.",
	}
	cmd.AddCommand(newMCPAuditListCmd())
	cmd.AddCommand(newMCPAuditStatsCmd())
	cmd.AddCommand(newMCPAuditTopPathsCmd())
	cmd.AddCommand(newMCPAuditDeniedCmd())
	cmd.AddCommand(newMCPAuditPurgeCmd())
	return cmd
}

func newMCPAuditListCmd() *cobra.Command {
	var (
		configPath string
		sessionID  string
		tool       string
		sinceStr   string
		limit      int
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recent mcp_audit rows (newest first)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			since, err := parseSinceFlag(sinceStr)
			if err != nil {
				return err
			}
			rows, err := audit.List(cmd.Context(), database, audit.ListOptions{
				SessionID: sessionID,
				Tool:      tool,
				Since:     since,
				Limit:     limit,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), rows)
			}
			printListRows(cmd.OutOrStdout(), rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "Restrict to one session_id")
	cmd.Flags().StringVar(&tool, "tool", "", "Restrict to one tool_name (e.g. get_file)")
	cmd.Flags().StringVar(&sinceStr, "since", "24h", "Time window (e.g. 30m, 24h, 7d - empty = all time)")
	cmd.Flags().IntVar(&limit, "limit", 50, "Cap returned rows")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of table")
	return cmd
}

func newMCPAuditStatsCmd() *cobra.Command {
	var (
		configPath string
		sinceStr   string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Aggregate counts: total / ok / denied / truncated / by-tool",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			since, err := parseSinceFlag(sinceStr)
			if err != nil {
				return err
			}
			stats, err := audit.StatsSummary(cmd.Context(), database, since)
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), stats)
			}
			printStats(cmd.OutOrStdout(), stats)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sinceStr, "since", "24h", "Time window (empty = all time)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of text")
	return cmd
}

func newMCPAuditTopPathsCmd() *cobra.Command {
	var (
		configPath string
		sinceStr   string
		limit      int
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "top-paths",
		Short: "Most-requested paths in the window (capacity planning / re-read detection)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			since, err := parseSinceFlag(sinceStr)
			if err != nil {
				return err
			}
			paths, err := audit.TopPaths(cmd.Context(), database, since, limit)
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), paths)
			}
			printTopPaths(cmd.OutOrStdout(), paths)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sinceStr, "since", "24h", "Time window (empty = all time)")
	cmd.Flags().IntVar(&limit, "limit", 20, "Cap returned paths")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of table")
	return cmd
}

func newMCPAuditDeniedCmd() *cobra.Command {
	var (
		configPath string
		sinceStr   string
		limit      int
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "denied",
		Short: "Recent denied rows (response_ok=0)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			since, err := parseSinceFlag(sinceStr)
			if err != nil {
				return err
			}
			rows, err := audit.List(cmd.Context(), database, audit.ListOptions{
				Since:      since,
				Limit:      limit,
				OnlyDenied: true,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), rows)
			}
			printListRows(cmd.OutOrStdout(), rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sinceStr, "since", "24h", "Time window")
	cmd.Flags().IntVar(&limit, "limit", 50, "Cap returned rows")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newMCPAuditPurgeCmd() *cobra.Command {
	var (
		configPath   string
		olderThanStr string
		yes          bool
	)
	cmd := &cobra.Command{
		Use:   "purge",
		Short: "Delete rows older than --older-than (destructive)",
		RunE: func(cmd *cobra.Command, args []string) error {
			olderThan, err := time.ParseDuration(olderThanStr)
			if err != nil {
				return fmt.Errorf("--older-than: %w (use e.g. 720h for 30d)", err)
			}
			if olderThan <= 0 {
				return fmt.Errorf("--older-than must be > 0")
			}
			if !yes {
				return fmt.Errorf("destructive operation - re-run with --yes to confirm")
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			n, err := audit.Purge(cmd.Context(), database, olderThan)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted %d row(s) older than %s\n", n, olderThan)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&olderThanStr, "older-than", "", "Required. e.g. 720h (30d), 168h (7d)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm the destructive operation")
	_ = cmd.MarkFlagRequired("older-than")
	return cmd
}

// parseSinceFlag accepts a duration string OR empty (= "all time", 0).
// Negative values reject.
func parseSinceFlag(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("--since: %w (use e.g. 30m, 24h, 168h)", err)
	}
	if d < 0 {
		return 0, fmt.Errorf("--since: negative duration")
	}
	return d, nil
}

func writeJSON(w io.Writer, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(body))
	return err
}

func printListRows(w io.Writer, rows []audit.ListRow) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no rows)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TS\tTOOL\tSESSION\tOK\tBYTES\tPATH\tREASON")
	for _, r := range rows {
		ok := "y"
		if !r.ResponseOK {
			ok = "N"
		}
		path := r.PathRequested
		if path == "" {
			path = "-"
		}
		reason := r.Reason
		if r.ResponseOK {
			reason = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			r.Ts.Format("2006-01-02 15:04:05"),
			r.Tool, truncOrDash(r.SessionID, 16), ok,
			r.ResponseBytes, truncOrDash(path, 50), truncOrDash(reason, 40))
	}
	_ = tw.Flush()
}

func printStats(w io.Writer, s audit.Stats) {
	window := "all time"
	if s.Since > 0 {
		window = s.Since.String()
	}
	fmt.Fprintf(w, "window: %s\n", window)
	fmt.Fprintf(w, "total:     %d\n", s.Total)
	fmt.Fprintf(w, "ok:        %d\n", s.OK)
	fmt.Fprintf(w, "denied:    %d\n", s.Denied)
	fmt.Fprintf(w, "truncated: %d\n", s.Truncated)
	if len(s.ByTool) == 0 {
		return
	}
	fmt.Fprintln(w, "\nby tool:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tCALLS")
	// Stable order — sort by call count desc, then name.
	for _, name := range sortByToolCount(s.ByTool) {
		fmt.Fprintf(tw, "%s\t%d\n", name, s.ByTool[name])
	}
	_ = tw.Flush()
}

func printTopPaths(w io.Writer, paths []audit.TopPath) {
	if len(paths) == 0 {
		fmt.Fprintln(w, "(no rows)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tCALLS\tOK\tDENIED\tBYTES")
	for _, p := range paths {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n",
			truncOrDash(p.Path, 70),
			p.Calls, p.OKCalls, p.DeniedCalls, p.TotalBytes)
	}
	_ = tw.Flush()
}

func sortByToolCount(m map[string]int) []string {
	type pair struct {
		k string
		v int
	}
	pairs := make([]pair, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, pair{k, v})
	}
	// Simple insertion sort — N is at most ~5 tools.
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0; j-- {
			if pairs[j].v > pairs[j-1].v ||
				(pairs[j].v == pairs[j-1].v && pairs[j].k < pairs[j-1].k) {
				pairs[j], pairs[j-1] = pairs[j-1], pairs[j]
			} else {
				break
			}
		}
	}
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k
	}
	return out
}

func truncOrDash(s string, n int) string {
	if s == "" {
		return "-"
	}
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
