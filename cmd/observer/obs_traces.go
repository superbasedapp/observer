package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// obs_traces.go is `observer obs traces list|show|tail` (Plane A lane B5,
// plan W2-5, finding F15): the machine's app traces from the terminal, over
// the same node-local obs store the Your apps pages read. Like the other obs
// CLIs it reaches the store only through the build-tagged wrappers in
// obs_wire_traces.go (stub: obs_wire_traces_stub.go), so this file imports
// no internal/obs package (tests/invariant/obs_boundary_test.go). tail polls
// the local database; it opens no network lane.

// obsTraceQuery is the list filter (the store's TraceFilter, cmd-side).
type obsTraceQuery struct {
	Since       time.Time
	SessionID   string
	EndUser     string
	Service     string
	Environment string
	Status      string
	Search      string
	Limit       int
	Offset      int
}

// obsTraceLine is one trace in a list (a plain copy of the store row).
type obsTraceLine struct {
	TraceID     string   `json:"trace_id"`
	RootName    string   `json:"root_name"`
	Source      string   `json:"source"`
	SessionID   string   `json:"session_id,omitempty"`
	Status      string   `json:"status"`
	StartedAt   string   `json:"started_at"`
	DurationMS  int64    `json:"duration_ms"`
	SpanCount   int64    `json:"span_count"`
	ErrorCount  int64    `json:"error_count"`
	TotalTokens int64    `json:"total_tokens"`
	CostUSD     *float64 `json:"cost_usd"` // null when nothing in the trace is priced (L-06)
	Model       string   `json:"model,omitempty"`
	EndUser     string   `json:"end_user,omitempty"`
	Service     string   `json:"service,omitempty"`
	Environment string   `json:"environment,omitempty"`
	Release     string   `json:"release,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// obsSpanLine is one span of a shown trace.
type obsSpanLine struct {
	SpanID       string   `json:"span_id"`
	ParentSpanID string   `json:"parent_span_id,omitempty"`
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	StartedAt    string   `json:"started_at"`
	DurationMS   int64    `json:"duration_ms"`
	Model        string   `json:"model,omitempty"`
	InputTokens  *int64   `json:"input_tokens,omitempty"`
	OutputTokens *int64   `json:"output_tokens,omitempty"`
	CostUSD      *float64 `json:"cost_usd,omitempty"`
	CostSource   string   `json:"cost_source,omitempty"`
	ErrorType    string   `json:"error_type,omitempty"`
}

// obsContentLine is one stored body (prompt, response, tool I/O).
type obsContentLine struct {
	SpanID      string `json:"span_id"`
	Kind        string `json:"kind"`
	Content     string `json:"content"`
	ContentHash string `json:"content_hash"`
}

// obsTraceShown is `show`'s payload.
type obsTraceShown struct {
	Trace   obsTraceLine     `json:"trace"`
	Spans   []obsSpanLine    `json:"spans"`
	Content []obsContentLine `json:"content,omitempty"`
}

func newObsTracesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "traces",
		Short: "Your apps' traces on this machine: list, show one, or tail new ones",
		Long: "Read the traces your LLM apps sent to this machine (the superbased SDK, or\n" +
			"any OpenTelemetry exporter pointed at the local receiver). The same data\n" +
			"as the dashboard's Your apps > Traces page. Requires [observability]\n" +
			"enabled = true; nothing here leaves the machine.",
	}
	cmd.AddCommand(newObsTracesListCmd(), newObsTracesShowCmd(), newObsTracesTailCmd())
	return cmd
}

// traceQueryFlags binds the shared list filters to cmd.
func traceQueryFlags(cmd *cobra.Command, q *obsTraceQuery, days *int) {
	cmd.Flags().IntVar(days, "days", 0, "only traces started in the last N days (0 = all)")
	cmd.Flags().StringVar(&q.SessionID, "session", "", "only this session id")
	cmd.Flags().StringVar(&q.EndUser, "end-user", "", "only this end user")
	cmd.Flags().StringVar(&q.Service, "service", "", "only this service")
	cmd.Flags().StringVar(&q.Environment, "environment", "", "only this environment")
	cmd.Flags().StringVar(&q.Status, "status", "", "error (an error status or span) or ok")
	cmd.Flags().StringVar(&q.Search, "search", "", "substring of the trace id or root span name")
}

// sinceDays turns --days into a window start (midnight UTC, the dashboard's rule).
func sinceDays(now time.Time, days int) time.Time {
	if days <= 0 {
		return time.Time{}
	}
	return now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
}

// validTraceStatus refuses an unknown --status loudly (the HTTP route ignores one).
func validTraceStatus(s string) error {
	switch s {
	case "", "error", "ok":
		return nil
	}
	return fmt.Errorf("--status %q: want error or ok", s)
}

func newObsTracesListCmd() *cobra.Command {
	var (
		configPath string
		q          obsTraceQuery
		days       int
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List traces, newest first",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validTraceStatus(q.Status); err != nil {
				return err
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireAppObs(cfg.Observability.Enabled); err != nil {
				return err
			}
			q.Since = sinceDays(time.Now(), days)
			rows, total, err := obsTracesListCLI(cmd.Context(), database, q)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return traceJSON(out, map[string]any{"traces": rows, "total": total})
			}
			printTraceTable(out, rows)
			fmt.Fprintf(out, "\n%d of %d traces\n", len(rows), total)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	traceQueryFlags(cmd, &q, &days)
	cmd.Flags().IntVar(&q.Limit, "limit", 50, "max traces (1-500)")
	cmd.Flags().IntVar(&q.Offset, "offset", 0, "skip this many")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func newObsTracesShowCmd() *cobra.Command {
	var (
		configPath string
		asJSON     bool
		content    bool
	)
	cmd := &cobra.Command{
		Use:   "show <trace-id>",
		Short: "Show one trace: its spans as a tree, and with --content the stored bodies",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireAppObs(cfg.Observability.Enabled); err != nil {
				return err
			}
			d, found, err := obsTraceShowCLI(cmd.Context(), database, args[0])
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("no trace %q on this machine", args[0])
			}
			if !content {
				d.Content = nil
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return traceJSON(out, d)
			}
			printTraceShown(out, d)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	cmd.Flags().BoolVar(&content, "content", false, "also print the stored prompt, response and tool bodies")
	return cmd
}

func newObsTracesTailCmd() *cobra.Command {
	var (
		configPath string
		q          obsTraceQuery
		days       int
		interval   time.Duration
		maxPolls   int
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Print new traces as they arrive (polls this machine's database; Ctrl-C stops)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validTraceStatus(q.Status); err != nil {
				return err
			}
			if interval < 200*time.Millisecond {
				return fmt.Errorf("--interval %s: at least 200ms", interval)
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if err := requireAppObs(cfg.Observability.Enabled); err != nil {
				return err
			}
			// Start from now (minus --days when given): tail shows what arrives.
			q.Since = time.Now().UTC()
			if days > 0 {
				q.Since = sinceDays(time.Now(), days)
			}
			q.Limit = 500
			t := traceTail{seen: map[string]bool{}}
			out := cmd.OutOrStdout()
			if !asJSON {
				fmt.Fprintln(out, "waiting for traces (Ctrl-C stops)...")
			}
			for poll := 0; maxPolls <= 0 || poll < maxPolls; poll++ {
				if poll > 0 {
					select {
					case <-cmd.Context().Done():
						return nil
					case <-time.After(interval):
					}
				}
				rows, _, err := obsTracesListCLI(cmd.Context(), database, q)
				if err != nil {
					return err
				}
				for _, r := range t.fresh(rows) {
					if asJSON {
						if err := traceJSONLine(out, r); err != nil {
							return err
						}
						continue
					}
					fmt.Fprintln(out, traceLineText(r))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	traceQueryFlags(cmd, &q, &days)
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "how often to read the database")
	cmd.Flags().IntVar(&maxPolls, "max-polls", 0, "stop after N reads (0 = until Ctrl-C)")
	_ = cmd.Flags().MarkHidden("max-polls")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print one JSON object per line")
	return cmd
}

// traceTail remembers which traces it has printed, so a trace is printed
// once even though every poll re-reads the window.
type traceTail struct{ seen map[string]bool }

// fresh returns the unseen rows, oldest first, and marks them seen.
func (t *traceTail) fresh(rows []obsTraceLine) []obsTraceLine {
	var out []obsTraceLine
	for i := len(rows) - 1; i >= 0; i-- { // rows arrive newest first
		if t.seen[rows[i].TraceID] {
			continue
		}
		t.seen[rows[i].TraceID] = true
		out = append(out, rows[i])
	}
	return out
}

// requireAppObs refuses when app observability is off on this machine.
func requireAppObs(enabled bool) error {
	if !enabled {
		return fmt.Errorf("app observability is off on this machine: set [observability] enabled = true (or turn it on from the dashboard's Overview), then restart the daemon")
	}
	return nil
}

func traceJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func traceJSONLine(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

// traceLineText is one trace on one line (list and tail).
func traceLineText(r obsTraceLine) string {
	name := r.RootName
	if name == "" {
		name = "(unnamed)"
	}
	status := r.Status
	if r.ErrorCount > 0 && status != "error" {
		status = fmt.Sprintf("%s+%derr", status, r.ErrorCount)
	}
	who := r.EndUser
	if who == "" {
		who = "-"
	}
	svc := r.Service
	if svc == "" {
		svc = "-"
	}
	return fmt.Sprintf("%-20s %-32s %-34s %-9s %-16s %-14s %6d %8s %9s %s",
		traceTime(r.StartedAt), r.TraceID, traceClip(name, 34), status, traceClip(who, 16), traceClip(svc, 14),
		r.SpanCount, traceTokens(r.TotalTokens), traceTotalCost(r.CostUSD), traceDur(r.DurationMS))
}

func printTraceTable(w io.Writer, rows []obsTraceLine) {
	fmt.Fprintf(w, "%-20s %-32s %-34s %-9s %-16s %-14s %6s %8s %9s %s\n",
		"STARTED", "TRACE", "NAME", "STATUS", "END USER", "SERVICE", "SPANS", "TOKENS", "COST", "DURATION")
	for _, r := range rows {
		fmt.Fprintln(w, traceLineText(r))
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "(no traces)")
	}
}

func printTraceShown(w io.Writer, d obsTraceShown) {
	t := d.Trace
	fmt.Fprintf(w, "trace:     %s\n", t.TraceID)
	fmt.Fprintf(w, "name:      %s\n", t.RootName)
	fmt.Fprintf(w, "status:    %s (%d error spans)\n", t.Status, t.ErrorCount)
	fmt.Fprintf(w, "started:   %s  duration %s\n", t.StartedAt, traceDur(t.DurationMS))
	fmt.Fprintf(w, "tokens:    %s  cost %s\n", traceTokens(t.TotalTokens), traceTotalCost(t.CostUSD))
	for _, kv := range [][2]string{
		{"source", t.Source},
		{"session", t.SessionID},
		{"end user", t.EndUser},
		{"service", t.Service},
		{"env", t.Environment},
		{"release", t.Release},
		{"tags", strings.Join(t.Tags, ", ")},
	} {
		if kv[1] != "" {
			fmt.Fprintf(w, "%-10s %s\n", kv[0]+":", kv[1])
		}
	}
	fmt.Fprintf(w, "\nspans (%d):\n", len(d.Spans))
	for _, s := range spanTreeOrder(d.Spans) {
		line := fmt.Sprintf("%s%-9s %s", strings.Repeat("  ", s.depth+1), s.span.Kind, s.span.Name)
		meta := []string{s.span.Status, traceDur(s.span.DurationMS)}
		if s.span.Model != "" {
			meta = append(meta, s.span.Model)
		}
		if s.span.InputTokens != nil || s.span.OutputTokens != nil {
			meta = append(meta, fmt.Sprintf("%d in / %d out", traceDeref(s.span.InputTokens), traceDeref(s.span.OutputTokens)))
		}
		if s.span.CostUSD != nil {
			c := traceCost(*s.span.CostUSD)
			if s.span.CostSource != "" {
				c += " (" + s.span.CostSource + ")"
			}
			meta = append(meta, c)
		}
		if s.span.ErrorType != "" {
			meta = append(meta, "error "+s.span.ErrorType)
		}
		fmt.Fprintf(w, "%s  [%s]\n", line, strings.Join(meta, ", "))
	}
	if len(d.Content) > 0 {
		fmt.Fprintf(w, "\ncontent (%d):\n", len(d.Content))
		for _, c := range d.Content {
			body := c.Content
			if body == "" {
				body = "(not stored; hash " + c.ContentHash + ")"
			}
			fmt.Fprintf(w, "--- %s %s\n%s\n", c.SpanID, c.Kind, body)
		}
	}
}

type spanAt struct {
	span  obsSpanLine
	depth int
}

// spanTreeOrder lists spans depth-first under their parents (start order
// among siblings, the store's order); an orphan whose parent is not in the
// trace is a root.
func spanTreeOrder(spans []obsSpanLine) []spanAt {
	ids := map[string]bool{}
	for _, s := range spans {
		ids[s.SpanID] = true
	}
	children := map[string][]obsSpanLine{}
	var roots []obsSpanLine
	for _, s := range spans {
		if s.ParentSpanID == "" || !ids[s.ParentSpanID] {
			roots = append(roots, s)
			continue
		}
		children[s.ParentSpanID] = append(children[s.ParentSpanID], s)
	}
	var out []spanAt
	seen := map[string]bool{}
	var walk func(s obsSpanLine, depth int)
	walk = func(s obsSpanLine, depth int) {
		if seen[s.SpanID] {
			return
		}
		seen[s.SpanID] = true
		out = append(out, spanAt{span: s, depth: depth})
		for _, c := range children[s.SpanID] {
			walk(c, depth+1)
		}
	}
	for _, r := range roots {
		walk(r, 0)
	}
	for _, s := range spans { // a cycle leaves spans unreached: list them flat
		if !seen[s.SpanID] {
			out = append(out, spanAt{span: s})
		}
	}
	return out
}

func traceDeref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func traceClip(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func traceTime(rfc string) string {
	t, err := time.Parse(time.RFC3339Nano, rfc)
	if err != nil {
		return rfc
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func traceTokens(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprintf("%d", n)
}

// traceCost prints a Plane A trace's recorded model cost.
// traceTotalCost renders a trace total: "unpriced" when no span of the trace
// is priced (L-06), never "$0".
func traceTotalCost(usd *float64) string {
	if usd == nil {
		return "unpriced"
	}
	return traceCost(*usd)
}

func traceCost(usd float64) string {
	// no-bare-usd:allow (Plane A app traces: a hosted app's recorded model spend, not the developer's coding spend)
	if usd == 0 {
		return "$0"
	}
	if usd < 0.01 {
		return fmt.Sprintf("$%.4f", usd)
	}
	return fmt.Sprintf("$%.2f", usd)
}

func traceDur(ms int64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dms", ms)
}
