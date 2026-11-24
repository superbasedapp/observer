package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guard/export"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Guard export + evidence-pack surfaces (guard spec §11.4 / §14.4,
// G16). This file is the I/O half of internal/guard/export: it reads
// guard_events / guard_policy_state / guard_approvals through the
// existing store seams, maps rows onto the pure package's types at
// the boundary, and writes files or stdout. Export is file/pull only
// — the §11.4 no-network invariant; the only network path for guard
// events is the doubly-gated OTel feed (guardotel.go).

// exportPageSize bounds one tail-read page so a full-history export
// streams with constant memory instead of materializing the table.
const exportPageSize = 1000

// exportEventFromRow maps a store guard_events row onto the export
// package's Event at the boundary (the PersistGuardVerdicts
// translate-at-the-seam discipline, in the read direction).
func exportEventFromRow(r store.GuardEventRow) export.Event {
	return export.Event{
		ID: r.ID, TS: r.TS, SessionID: r.SessionID,
		ActionID: r.ActionID, APITurnID: r.APITurnID,
		Tool: r.Tool, EventKind: r.EventKind, RuleID: r.RuleID,
		Category: r.Category, Severity: r.Severity, Decision: r.Decision,
		DegradedFrom: r.DegradedFrom, Enforced: r.Enforced, Source: r.Source,
		Reason: r.Reason, TargetHash: r.TargetHash, TargetExcerpt: r.TargetExcerpt,
		TaintOrigin: r.TaintOrigin, ChainPrev: r.ChainPrev, ChainHash: r.ChainHash,
	}
}

// newGuardExportCmd implements `observer guard export` (spec §11.4):
// stream guard_events as JSONL or CEF to stdout or --out, filtered by
// window and severity.
func newGuardExportCmd() *cobra.Command {
	var (
		configPath  string
		format      string
		sinceStr    string
		periodStr   string
		minSeverity string
		outPath     string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export guard audit events as JSONL or CEF (SIEM ingestion)",
		Long: "Streams guard_events in chain (insert) order. File-based and\n" +
			"pull-based by design - this command never makes a network call\n" +
			"(spec §11.4); ship the output to your SIEM with its own collector.\n\n" +
			"  observer guard export --format jsonl --since 168h\n" +
			"  observer guard export --format cef --period 2026-05 --out may.cef\n\n" +
			"--since takes a duration window ending now (empty = all history);\n" +
			"--period takes a calendar month (2026-05), day (2026-05-01), or\n" +
			"duration, for auditor-shaped windows. The two are exclusive.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format = strings.ToLower(strings.TrimSpace(format))
			if format != "jsonl" && format != "cef" {
				return fmt.Errorf("--format must be jsonl or cef, got %q", format)
			}
			filter, err := buildExportFilter(sinceStr, periodStr, minSeverity)
			if err != nil {
				return err
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			database, err := db.Open(cmd.Context(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()

			out := cmd.OutOrStdout()
			if outPath != "" {
				// 0600: audit rows carry bounded command/path excerpts.
				f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
				if err != nil {
					return fmt.Errorf("open --out file: %w", err)
				}
				defer f.Close()
				out = f
			}

			n, err := streamGuardEvents(cmd.Context(), store.New(database), out, format, filter)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "exported %d event(s) as %s\n", n, format)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&format, "format", "jsonl", "output format: jsonl or cef")
	cmd.Flags().StringVar(&sinceStr, "since", "", "duration window ending now (e.g. 168h; empty = all history)")
	cmd.Flags().StringVar(&periodStr, "period", "", "calendar window: YYYY-MM month, YYYY-MM-DD day, or a duration")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "minimum severity ("+strings.Join(export.SeverityLabels(), "|")+")")
	cmd.Flags().StringVar(&outPath, "out", "", "write to this file instead of stdout (created 0600)")
	return cmd
}

// buildExportFilter assembles the §11.4 window/severity filter from
// the flag forms. --since and --period are exclusive: a tail window
// and a calendar window over the same export would silently intersect.
func buildExportFilter(sinceStr, periodStr, minSeverity string) (export.Filter, error) {
	var f export.Filter
	if minSeverity != "" {
		labels := export.SeverityLabels()
		valid := false
		for _, l := range labels {
			if l == minSeverity {
				valid = true
				break
			}
		}
		if !valid {
			return f, fmt.Errorf("--min-severity must be one of %s, got %q", strings.Join(labels, "|"), minSeverity)
		}
		f.MinSeverity = minSeverity
	}
	if sinceStr != "" && periodStr != "" {
		return f, fmt.Errorf("--since and --period are exclusive - pick one window form")
	}
	if sinceStr != "" {
		d, err := parseSinceFlag(sinceStr)
		if err != nil {
			return f, err
		}
		if d > 0 {
			f.Since = time.Now().UTC().Add(-d)
		}
	}
	if periodStr != "" {
		p, err := export.ParsePeriod(periodStr, time.Now().UTC())
		if err != nil {
			return f, err
		}
		f.Since, f.Until = p.Start, p.End
	}
	return f, nil
}

// streamGuardEvents pages the guard_events tail in chain order,
// applies the filter, and writes one formatted line per event.
// Returns the count written.
func streamGuardEvents(ctx context.Context, st *store.Store, out io.Writer, format string, filter export.Filter) (int, error) {
	var cursor int64
	written := 0
	for {
		rows, err := st.GuardEventsAfter(ctx, cursor, exportPageSize)
		if err != nil {
			return written, fmt.Errorf("read events: %w", err)
		}
		if len(rows) == 0 {
			return written, nil
		}
		for _, r := range rows {
			cursor = r.ID
			ev := exportEventFromRow(r)
			if !filter.Match(ev) {
				continue
			}
			var line []byte
			if format == "cef" {
				line = []byte(export.CEFLine(ev, version))
			} else {
				line, err = export.JSONLLine(ev)
				if err != nil {
					return written, err
				}
			}
			if _, err := out.Write(append(line, '\n')); err != nil {
				return written, fmt.Errorf("write: %w", err)
			}
			written++
		}
	}
}

// newGuardReportCmd implements `observer guard report --period`
// (spec §14.4): the compliance evidence pack — effective policy at
// the period boundaries, the policy-change log, verdict statistics,
// the audit-chain verification result, the §6.5 coverage matrix and
// the active-approval exception register, composed from the existing
// store/guard accessors. Text by default, --json for machines.
func newGuardReportCmd() *cobra.Command {
	var (
		configPath string
		periodStr  string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render the §14.4 compliance evidence pack for a period",
		Long: "Assembles the audit evidence an assessor asks for (SOC 2 CC-series,\n" +
			"NIST 800-53 AU-2/AU-3/AU-9/AC-6): effective policy at period\n" +
			"start/end,\n" +
			"policy-change log, verdict statistics, audit-chain verification,\n" +
			"coverage matrix, and the active-approval exception register.\n\n" +
			"A broken audit chain is REPORTED, not an error - the evidence pack\n" +
			"documents reality; use `observer guard verify-audit` for a gating\n" +
			"exit code.\n\n" +
			"--period accepts a duration (720h), a month (2026-05), or a day\n" +
			"(2026-05-01).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			now := time.Now().UTC()
			period, err := export.ParsePeriod(periodStr, now)
			if err != nil {
				return err
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			database, err := db.Open(cmd.Context(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer database.Close()
			st := store.New(database)

			input, err := buildReportInput(cmd.Context(), st, cfg, period, now)
			if err != nil {
				return err
			}
			report := export.BuildReport(input)

			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			_, err = io.WriteString(out, export.RenderText(report))
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&periodStr, "period", "720h", "reporting window: duration, YYYY-MM month, or YYYY-MM-DD day")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the evidence pack as JSON")
	return cmd
}

// buildReportInput composes the evidence pack's inputs from the
// existing accessors — nothing here re-derives what the store and the
// conformance matrix already answer (the G16 compose-don't-re-derive
// rule).
func buildReportInput(ctx context.Context, st *store.Store, cfg config.Config, period export.Period, now time.Time) (export.ReportInput, error) {
	policyLog, err := st.LoadGuardPolicyStates(ctx)
	if err != nil {
		return export.ReportInput{}, err
	}
	stats, err := st.SummarizeGuardEventsBetween(ctx, period.Start, period.End)
	if err != nil {
		return export.ReportInput{}, err
	}
	chain, err := st.VerifyGuardChain(ctx)
	if err != nil {
		return export.ReportInput{}, fmt.Errorf("verify chain: %w", err)
	}
	approvals, err := st.ActiveGuardApprovals(ctx, "", now)
	if err != nil {
		return export.ReportInput{}, err
	}

	in := export.ReportInput{
		GeneratedAt:     now,
		Period:          period,
		GuardEnabled:    cfg.Guard.Enabled,
		Mode:            cfg.Guard.Mode,
		ObserverVersion: version,
		Stats: export.VerdictStats{
			Total: stats.Total, Enforced: stats.Enforced,
			ByDecision: stats.ByDecision, BySeverity: stats.BySeverity, ByCategory: stats.ByCategory,
		},
		Chain: export.ChainResult{
			Checked: chain.Checked, OK: chain.OK,
			FirstDivergenceID: chain.FirstDivergenceID, Detail: chain.Detail,
		},
	}
	for _, p := range policyLog {
		in.PolicyLog = append(in.PolicyLog, export.PolicyStateEntry{
			Layer: p.Layer, Path: p.Path, Version: p.Version,
			ContentHash: p.ContentHash, Signature: p.Signature, LoadedAt: p.LoadedAt,
		})
	}
	for _, c := range guard.ConformanceMatrix() {
		in.Coverage = append(in.Coverage, export.CoverageRow{
			Client: c.Client, Channel: c.Channel,
			PreExecution: c.Caps.PreExecution, CanBlock: c.Caps.CanBlock, CanAsk: c.Caps.CanAsk,
			Notes: c.Notes,
		})
	}
	for _, a := range approvals {
		in.ActiveApprovals = append(in.ActiveApprovals, export.ApprovalEntry{
			ID: a.ID, TS: a.TS, RuleID: a.RuleID, Scope: a.Scope,
			SessionID: a.SessionID, ProjectRootHash: a.ProjectRootHash,
			GrantedBy: a.GrantedBy, ExpiresAt: a.ExpiresAt,
		})
	}
	return in, nil
}
