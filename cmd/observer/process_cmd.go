//go:build !sbo_omit_processobs

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/processobs/linuxebpf"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newProcessCmd is the `observer process` command group — the operator
// surface for the Process Observability feature
// (docs/process-observability.md §13.2).
func newProcessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "process",
		Short: "Inspect captured OS process activity (process observability)",
		Long: "Surfaces the OS-level process trees captured for AI sessions when\n" +
			"[observer.process] is enabled: which processes a session spawned, what\n" +
			"command (action) spawned them, and their runtime outcome.",
	}
	cmd.AddCommand(newProcessStatusCmd(), newProcessTreeCmd(), newProcessListCmd(), newProcessFindingsCmd(), newProcessNetworkCmd(), newProcessPruneCmd(), newProcessStatsCmd(), newProcessCompactCmd())
	return cmd
}

func newProcessStatusCmd() *cobra.Command {
	var configPath string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show process-capture posture and persisted-row tallies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			stats, err := st.ProcessStats(cmd.Context())
			if err != nil {
				return err
			}
			longRunning, _ := st.LongRunningChildRuns(cmd.Context(), 0)
			recentFindings, _ := st.RecentProcessFindings(cmd.Context(), 0)
			pc := cfg.Observer.Process
			// Whether the real-time eBPF backend would actually be used: relevant
			// only for the eBPF-capable backend settings, and gated on this
			// process being able to load BPF (probed). The daemon's capability may
			// differ if it was launched with different privileges.
			ebpfRelevant := pc.Enabled && (pc.Backend == "auto" || pc.Backend == "linux_ebpf")
			ebpfAvail := ebpfRelevant && linuxebpf.Available(nil)
			if jsonOut {
				payload := map[string]any{
					"enabled": pc.Enabled, "backend": pc.Backend,
					"retention_days": pc.RetentionDays,
					"total":          stats.Total, "attributed": stats.Attributed,
					"unattributed": stats.Unattributed, "derived": stats.Derived,
					"by_tool":               stats.ByTool,
					"long_running_children": len(longRunning),
					"recent_findings":       len(recentFindings),
				}
				if ebpfRelevant {
					payload["ebpf_available"] = ebpfAvail
				}
				return writeJSON(cmd.OutOrStdout(), payload)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "process observability: enabled=%v backend=%s retention=%dd\n", pc.Enabled, pc.Backend, pc.RetentionDays)
			if !pc.Enabled {
				fmt.Fprintln(out, "  (opt-in - set [observer.process] enabled = true and restart to capture)")
			}
			if ebpfRelevant {
				if ebpfAvail {
					fmt.Fprintln(out, "  eBPF capture: available - real-time fork/exec/exit (probed in this process)")
				} else {
					fmt.Fprintln(out, "  eBPF capture: unavailable here - using poll (misses sub-poll-interval commands).")
					fmt.Fprintln(out, "    Grant the daemon CAP_BPF+CAP_PERFMON to enable real-time capture:")
					fmt.Fprintln(out, "      sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep <observer-binary>   (binary must be on ext4, not DrvFs/9p)")
				}
			}
			fmt.Fprintf(out, "  process_runs: %d total · %d attributed · %d unattributed\n", stats.Total, stats.Attributed, stats.Unattributed)
			if stats.Derived > 0 {
				fmt.Fprintf(out, "    of which %d derived from tool exec record (fast commands the poll backend missed; no OS metrics)\n", stats.Derived)
			}
			for _, tool := range sortedKeys(stats.ByTool) {
				fmt.Fprintf(out, "    %-14s %d\n", tool, stats.ByTool[tool])
			}
			if len(longRunning) > 0 {
				fmt.Fprintf(out, "  ⚠ %d long-running children still alive after their session ended (process list --long-running)\n", len(longRunning))
			}
			if len(recentFindings) > 0 {
				fmt.Fprintf(out, "  ⚠ %d process findings in the last 24h (process findings)\n", len(recentFindings))
			}
			fmt.Fprintln(out, "  (live backend health is on the daemon /metrics endpoint)")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newProcessTreeCmd() *cobra.Command {
	var configPath, sessionID string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "tree",
		Short: "Show the process tree captured for a session (with the spawning command)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sessionID == "" {
				return fmt.Errorf("--session is required")
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			// Refresh attribution lazily before the render (best-effort, never
			// blocks). Cross-OS first (§5.5: join the Windows bridge subtree to
			// this session), then the §9.2.4 action links on the attributed rows.
			_, _ = st.CorrelateCrossOS(cmd.Context(), sessionID)
			_, _ = st.CorrelateProcessActions(cmd.Context(), sessionID)

			runs, err := st.ProcessRunsForSession(cmd.Context(), sessionID)
			if err != nil {
				return err
			}
			cmds, _ := st.ActionCommandsForSession(cmd.Context(), sessionID)
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), runs)
			}
			renderProcessTree(cmd.OutOrStdout(), sessionID, runs, cmds)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session id (required)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newProcessListCmd() *cobra.Command {
	var configPath, sessionID string
	var since time.Duration
	var jsonOut, longRunning bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List process runs for a session (flat)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sessionID == "" && !longRunning {
				return fmt.Errorf("--session is required (or use --long-running)")
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			var runs []store.ProcessRunRow
			if longRunning {
				runs, err = st.LongRunningChildRuns(cmd.Context(), 0)
			} else {
				runs, err = st.ProcessRunsForSession(cmd.Context(), sessionID)
			}
			if err != nil {
				return err
			}
			if since > 0 {
				cutoff := time.Now().Add(-since)
				filtered := runs[:0]
				for _, r := range runs {
					if r.StartedAt.After(cutoff) {
						filtered = append(filtered, r)
					}
				}
				runs = filtered
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), runs)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%-7s %-18s %-22s %-9s %s\n", "PID", "EXE", "ATTRIBUTION", "RUNTIME", "STARTED")
			for _, r := range runs {
				fmt.Fprintf(out, "%-7d %-18s %-22s %-9s %s\n",
					r.PID, truncate(r.ExeBasename, 18), attribLabel(r), runtimeLabel(r),
					r.StartedAt.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session id (required unless --long-running)")
	cmd.Flags().DurationVar(&since, "since", 0, "Only runs started within this window (e.g. 24h)")
	cmd.Flags().BoolVar(&longRunning, "long-running", false, "List children still alive after their session ended (all sessions)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newProcessFindingsCmd() *cobra.Command {
	var configPath, sessionID string
	var since time.Duration
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Show observe-only process findings (privileged exec, exec-from-tmp)",
		Long: "Derives the §14 observe-only findings from the captured process\n" +
			"envelope: privilege elevations (effective root from a non-root uid) and\n" +
			"executables run from scratch locations (tmp/cache/downloads). Findings\n" +
			"never block - they are audit evidence for the operator. With --session\n" +
			"they cover one session; without it, a recent cross-session rollup.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			var findings []store.ProcessFindingRow
			if sessionID != "" {
				findings, err = st.ProcessFindingsForSession(cmd.Context(), sessionID)
			} else {
				findings, err = st.RecentProcessFindings(cmd.Context(), since)
			}
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), findings)
			}
			out := cmd.OutOrStdout()
			if len(findings) == 0 {
				fmt.Fprintln(out, "no process findings")
				return nil
			}
			fmt.Fprintf(out, "%-9s %-22s %-16s %s\n", "SEVERITY", "RULE", "PROCESS", "DETAIL")
			for _, f := range findings {
				proc := f.ExeBasename
				if proc == "" {
					proc = truncate(f.ProcessKey, 8)
				}
				fmt.Fprintf(out, "%-9s %-22s %-16s %s\n",
					f.Severity, strings.TrimPrefix(f.RuleID, "process."), truncate(proc, 16), f.Detail)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session id (omit for a recent cross-session rollup)")
	cmd.Flags().DurationVar(&since, "since", 24*time.Hour, "Rollup window when --session is omitted")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newProcessNetworkCmd() *cobra.Command {
	var configPath, sessionID string
	var limit int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "network",
		Short: "List process-network egress events for a session",
		Long: "Lists network_connect events attributed to a session. The list is\n" +
			"metadata-only; use `observer process network show <event-id>` to view\n" +
			"the capped request/response body when a plaintext capture source (for\n" +
			"example the Observer proxy) stored one.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sessionID == "" {
				return fmt.Errorf("--session is required")
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			rows, err := store.New(database).NetworkEventsForSession(cmd.Context(), sessionID, limit)
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), rows)
			}
			out := cmd.OutOrStdout()
			if len(rows) == 0 {
				fmt.Fprintf(out, "session %s: no network events captured\n", sessionID)
				return nil
			}
			fmt.Fprintf(out, "%-7s %-20s %-7s %-32s %-6s %s\n", "ID", "TIME", "BODY", "TARGET", "STATUS", "PROCESS")
			for _, r := range rows {
				body := "no"
				if r.HasBody {
					body = "yes"
				}
				proc := r.ExeBasename
				if proc == "" && strings.HasPrefix(r.ProcessKey, "proxy:") {
					proc = "proxy"
				}
				status := ""
				if r.DetailsJSON != "" {
					status = detailStatus(r.DetailsJSON)
				}
				fmt.Fprintf(out, "%-7d %-20s %-7s %-32s %-6s %s\n",
					r.ID, truncate(r.Timestamp, 20), body, truncate(r.Target, 32), truncate(status, 6), proc)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "Session id (required)")
	cmd.Flags().IntVar(&limit, "limit", 100, "Maximum events to list")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	cmd.AddCommand(newProcessNetworkShowCmd())
	return cmd
}

func newProcessNetworkShowCmd() *cobra.Command {
	var configPath string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "show <event-id>",
		Short: "Show one network event, including captured request/response excerpts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil || id <= 0 {
				return fmt.Errorf("event-id must be a positive integer")
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			row, err := store.New(database).NetworkEventDetail(cmd.Context(), id)
			if err != nil {
				return err
			}
			if jsonOut {
				return writeJSON(cmd.OutOrStdout(), row)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "network event %d\n", row.ID)
			fmt.Fprintf(out, "  time:    %s\n", row.Timestamp)
			fmt.Fprintf(out, "  session: %s\n", row.SessionID)
			fmt.Fprintf(out, "  target:  %s\n", row.Target)
			if row.ExeBasename != "" || row.PID != 0 {
				fmt.Fprintf(out, "  process: %s pid=%d\n", row.ExeBasename, row.PID)
			}
			if row.Body == nil {
				fmt.Fprintln(out, "  body:    not captured")
				return nil
			}
			b := row.Body
			fmt.Fprintf(out, "  source:  %s request_id=%s status=%d duration=%s\n",
				b.CaptureSource, b.RequestID, b.StatusCode, fmtMillis(b.DurationMs))
			fmt.Fprintf(out, "\nrequest (%d bytes sha256=%s truncated=%v)\n", b.RequestBodyBytes, b.RequestBodySHA256, b.RequestBodyTruncated)
			if b.RequestBody != "" {
				fmt.Fprintln(out, b.RequestBody)
			} else {
				fmt.Fprintln(out, "(request body unavailable)")
			}
			fmt.Fprintf(out, "\nresponse (%d bytes sha256=%s truncated=%v content_type=%s)\n",
				b.ResponseBodyBytes, b.ResponseBodySHA256, b.ResponseBodyTruncated, b.ResponseContentType)
			switch {
			case b.ResponseBody != "":
				fmt.Fprintln(out, b.ResponseBody)
			case b.BodyUnavailableReason != "":
				fmt.Fprintf(out, "(response body unavailable: %s)\n", b.BodyUnavailableReason)
			default:
				fmt.Fprintln(out, "(response body unavailable)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func newProcessPruneCmd() *cobra.Command {
	var configPath string
	var days int
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete process_runs / process_events older than the retention horizon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			horizon := days
			if horizon <= 0 {
				horizon = cfg.Observer.Process.RetentionDays
			}
			n, err := store.New(database).PruneProcessRows(cmd.Context(), horizon)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "pruned %d process rows older than %d days\n", n, horizon)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().IntVar(&days, "days", 0, "Retention horizon in days (0 = use [observer.process].retention_days)")
	return cmd
}

// renderProcessTree prints the parent/child process tree for a session, each
// node labeled with its executable, attribution confidence, runtime outcome,
// and — when the §9.2.4 correlation linked it — the command (action) that
// spawned it.
func renderProcessTree(w io.Writer, sessionID string, runs []store.ProcessRunRow, cmds map[int64]string) {
	if len(runs) == 0 {
		fmt.Fprintf(w, "session %s: no process runs captured\n", sessionID)
		return
	}
	byKey := make(map[string]store.ProcessRunRow, len(runs))
	childrenOf := make(map[string][]string)
	for _, r := range runs {
		byKey[r.ProcessKey] = r
	}
	var roots []string
	for _, r := range runs {
		if r.ParentProcessKey == "" {
			roots = append(roots, r.ProcessKey)
			continue
		}
		if _, ok := byKey[r.ParentProcessKey]; ok {
			childrenOf[r.ParentProcessKey] = append(childrenOf[r.ParentProcessKey], r.ProcessKey)
		} else {
			roots = append(roots, r.ProcessKey) // parent not captured → treat as a root
		}
	}
	startedLess := func(a, b string) bool {
		ra, rb := byKey[a], byKey[b]
		if !ra.StartedAt.Equal(rb.StartedAt) {
			return ra.StartedAt.Before(rb.StartedAt)
		}
		return ra.PID < rb.PID
	}
	sort.SliceStable(roots, func(i, j int) bool { return startedLess(roots[i], roots[j]) })
	for k := range childrenOf {
		ch := childrenOf[k]
		sort.SliceStable(ch, func(i, j int) bool { return startedLess(ch[i], ch[j]) })
		childrenOf[k] = ch
	}

	fmt.Fprintf(w, "session %s - %d process runs\n", sessionID, len(runs))
	for i, root := range roots {
		renderNode(w, root, "", i == len(roots)-1, byKey, childrenOf, cmds)
	}
}

func renderNode(w io.Writer, key, prefix string, last bool, byKey map[string]store.ProcessRunRow, childrenOf map[string][]string, cmds map[int64]string) {
	r := byKey[key]
	branch := "├─ "
	childPrefix := prefix + "│  "
	if last {
		branch = "└─ "
		childPrefix = prefix + "   "
	}
	fmt.Fprintf(w, "%s%s%s\n", prefix, branch, nodeLabel(r, cmds))
	ch := childrenOf[key]
	for i, c := range ch {
		renderNode(w, c, childPrefix, i == len(ch)-1, byKey, childrenOf, cmds)
	}
}

func nodeLabel(r store.ProcessRunRow, cmds map[int64]string) string {
	exe := r.ExeBasename
	if exe == "" {
		exe = "?"
	}
	label := fmt.Sprintf("%s (pid %d) · %s · %s", exe, r.PID, attribLabel(r), runtimeLabel(r))
	if r.ActionID != nil {
		cmd := cmds[*r.ActionID]
		if cmd == "" {
			cmd = fmt.Sprintf("action %d", *r.ActionID)
		}
		turn := ""
		if r.TurnIndex != nil {
			turn = fmt.Sprintf(" (turn %d)", *r.TurnIndex)
		}
		label += fmt.Sprintf("  ↳ %s%s", truncate(cmd, 48), turn)
	}
	return label
}

func attribLabel(r store.ProcessRunRow) string {
	if r.AttributionSource == "" || r.AttributionSource == "none" {
		return "unattributed"
	}
	if r.AttributionConfidence == "" || r.AttributionConfidence == "none" {
		return r.AttributionSource
	}
	return r.AttributionSource + "/" + r.AttributionConfidence
}

func runtimeLabel(r store.ProcessRunRow) string {
	if !r.Exited {
		return "running"
	}
	if r.ExitSignal > 0 {
		return fmt.Sprintf("sig %d (%s)", r.ExitSignal, fmtMillis(r.DurationMs))
	}
	return fmt.Sprintf("exit %d (%s)", r.ExitCode, fmtMillis(r.DurationMs))
}

func fmtMillis(ms int64) string {
	switch {
	case ms <= 0:
		return "0ms"
	case ms < 1000:
		return fmt.Sprintf("%dms", ms)
	case ms < 60_000:
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	default:
		return fmt.Sprintf("%.1fm", float64(ms)/60_000)
	}
}

func detailStatus(detailsJSON string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(detailsJSON), &m); err != nil {
		return ""
	}
	if v, ok := m["status_code"].(float64); ok && v > 0 {
		return strconv.Itoa(int(v))
	}
	if v, ok := m["network_status"].(string); ok {
		return v
	}
	return ""
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
