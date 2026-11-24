//go:build !sbo_omit_proxy_routing

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer routing export` (§R19.5): the node-side audit export —
// every decision row in the window as CSV or JSON, for finance /
// compliance workflows. The org-side rollup export lives on the org
// server (GET /api/org/routing-summaries/export); the two together
// are the §R19.5 surface. Decision rows carry models / hashes / enum
// codes / dollars only — exporting them changes nothing about what
// they contain.

func newRoutingExportCmd() *cobra.Command {
	var (
		configPath string
		window     string
		format     string
		outPath    string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the decision log as CSV or JSON (audit export)",
		RunE: func(cmd *cobra.Command, args []string) error {
			days, err := parseWindowDays(window)
			if err != nil {
				return err
			}
			if format != "csv" && format != "json" {
				return fmt.Errorf("--format must be csv or json")
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			s := store.New(database)
			rows, err := s.SelectRouterDecisions(cmd.Context(), time.Now().AddDate(0, 0, -days), 0)
			if err != nil {
				return err
			}

			var out io.Writer = cmd.OutOrStdout()
			if outPath != "" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				out = f
			}
			if format == "json" {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rows); err != nil {
					return err
				}
			} else if err := writeDecisionCSV(out, rows); err != nil {
				return err
			}
			if outPath != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "exported %d decisions to %s\n", len(rows), outPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&window, "window", "90d", "Lookback window (e.g. 90d)")
	cmd.Flags().StringVar(&format, "format", "csv", "csv | json")
	cmd.Flags().StringVar(&outPath, "out", "", "Output file (default stdout)")
	return cmd
}

// writeDecisionCSV emits the audit CSV: one decision per line, RFC
// 4180 via encoding/csv.
func writeDecisionCSV(w io.Writer, rows []store.RouterDecisionDetail) error {
	cw := csv.NewWriter(w)
	header := []string{
		"id", "timestamp", "session_id", "api_turn_id", "mode", "channel",
		"turn_kind", "original_model", "selected_model", "applied",
		"reason_codes", "policy_name", "policy_hash",
		"est_savings_usd", "cache_forfeit_usd", "estimate_version",
		"project_root", "tool",
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, d := range rows {
		turnID := ""
		if d.APITurnID != nil {
			turnID = strconv.FormatInt(*d.APITurnID, 10)
		}
		rec := []string{
			strconv.FormatInt(d.ID, 10),
			d.Timestamp.UTC().Format(time.RFC3339),
			d.SessionID, turnID, d.Mode, d.Channel,
			d.TurnKind, d.OriginalModel, d.SelectedModel,
			strconv.FormatBool(d.Applied),
			strings.Join(d.ReasonCodes, "|"),
			d.PolicyName, d.PolicyHash,
			strconv.FormatFloat(d.EstSavingsUSD, 'f', 6, 64),
			strconv.FormatFloat(d.CacheForfeitUSD, 'f', 6, 64),
			d.EstimateVersion,
			d.ProjectRoot, d.Tool,
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
