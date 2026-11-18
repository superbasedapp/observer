package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgintel"
)

// intelactions_cli.go is `observer intel results | preview | enrich | ledger`:
// the CLI twins of the dashboard's per-session org-plane actions, over the
// SAME functions (intelactions.go).

func writeIntelJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newIntelResultsCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "results <session-id>",
		Short: "Show one session's org enrichment: what you can do, its latest submission and the result",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			v, err := orgIntelSessionState(cmd.Context(), b, args[0], configPath)
			if err != nil {
				return err
			}
			results, err := b.store.OrgIntelResultsForSession(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if asJSON {
				payload := map[string]any{"session": v}
				if len(results) > 0 {
					payload["result"] = results[0]
				}
				return writeIntelJSON(cmd.OutOrStdout(), payload)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Session:        %s\n", v.SessionID)
			fmt.Fprintf(out, "Captured for:   %s\n", v.Authority)
			if v.Actions.ReasonText != "" {
				fmt.Fprintf(out, "Actions:        %s\n", v.Actions.ReasonText)
			} else {
				fmt.Fprintf(out, "Actions:        preview, enrich%s\n", map[bool]string{true: " (after a preview)", false: ""}[v.Actions.NeedsPreview])
			}
			if v.Latest != nil {
				fmt.Fprintf(out, "Latest:         %s, %s, level %s (%s)\n", v.Latest.State, v.Latest.Trigger, v.Latest.EvidenceLevel, v.Latest.UpdatedAt)
				if v.Latest.Reason != "" {
					fmt.Fprintf(out, "                reason: %s\n", v.Latest.Reason)
				}
			} else {
				fmt.Fprintln(out, "Latest:         nothing submitted from this machine")
			}
			if len(results) == 0 {
				fmt.Fprintln(out, "Result:         not yet enriched")
				return nil
			}
			r := results[0]
			fmt.Fprintf(out, "Result:         %s\n", r.Title)
			if r.Description != "" {
				fmt.Fprintf(out, "                %s\n", r.Description)
			}
			fmt.Fprintf(out, "                confidence %s, fetched %s\n", r.Confidence, r.FetchedAt.UTC().Format("2006-01-02 15:04 UTC"))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print as JSON")
	return cmd
}

func printIntelPreview(out io.Writer, p dashapi.OrgIntelPreview) {
	fmt.Fprintln(out, p.Bytes)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Organization:   %s\n", p.OrgName)
	fmt.Fprintf(out, "Level:          %s (purpose %s)\n", p.EvidenceLevel, p.Purpose)
	fmt.Fprintf(out, "Size:           %d bytes, %d actions, %d excerpts\n", p.SizeBytes, p.Actions, p.Excerpts)
	fmt.Fprintf(out, "Content digest: %s\n", p.EvidenceDigest)
	fmt.Fprintf(out, "Upload digest:  %s\n", p.UploadDigest)
}

func newIntelPreviewCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "preview <session-id>",
		Short: "Print the exact evidence an org enrichment of this session would send (nothing is sent)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			built, s, err := previewOrgIntelSession(cmd.Context(), b, args[0])
			if err != nil {
				return err
			}
			p := orgIntelPreviewView(args[0], built, s)
			if asJSON {
				return writeIntelJSON(cmd.OutOrStdout(), p)
			}
			printIntelPreview(cmd.OutOrStdout(), p)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print as JSON")
	return cmd
}

func newIntelEnrichCmd() *cobra.Command {
	var configPath, digest string
	var yes, asJSON bool
	cmd := &cobra.Command{
		Use:   "enrich <session-id>",
		Short: "Send this session's evidence to your organization for enrichment (shows the exact bytes first)",
		Long: `Builds the session's org-plane evidence, prints the exact bytes and asks before
sending them to your organization's server. --digest sends only if the bytes
still match a preview you ran (observer intel preview); --yes sends the bytes
printed here without asking. On a managed machine nothing is asked.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			b, err := buildOrgBundle(ctx, configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			shown := digest
			if shown == "" {
				built, s, perr := previewOrgIntelSession(ctx, b, args[0])
				if perr != nil {
					return perr
				}
				if !s.plan.Enrich {
					return orgIntelConflict{err: errors.New(orgintel.ActionReasonText(s.plan.Reason))}
				}
				if s.plan.NeedsPreview {
					if !asJSON {
						printIntelPreview(cmd.OutOrStdout(), orgIntelPreviewView(args[0], built, s))
					}
					if !yes {
						if !isInteractiveTerminal(cmd) {
							return errors.New("not a terminal: re-run with --yes to send the bytes printed above, or with --digest from `observer intel preview`")
						}
						ok, aerr := promptYesNo(cmd, "Send exactly these bytes to your organization? [y/N] ")
						if aerr != nil {
							return aerr
						}
						if !ok {
							fmt.Fprintln(cmd.OutOrStdout(), "Not sent. Nothing was queued.")
							return nil
						}
					}
					shown = built.Result.Digests.Upload
				}
			}
			res, err := enrichOrgIntelSession(ctx, b, args[0], shown)
			if err != nil {
				return err
			}
			if asJSON {
				return writeIntelJSON(cmd.OutOrStdout(), res)
			}
			fmt.Fprintln(cmd.OutOrStdout(), res.Message)
			fmt.Fprintf(cmd.OutOrStdout(), "Submission %d: %s, level %s, upload digest %s\n",
				res.Submission.ID, res.Submission.State, res.Submission.EvidenceLevel, res.Submission.UploadDigest)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&digest, "digest", "", "Send only if the evidence still has this upload digest (from `observer intel preview`)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Send the bytes printed without prompting")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the result as JSON")
	return cmd
}

func newIntelLedgerCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ledger [submission-id]",
		Short: "List every org enrichment submission from this machine (or show one with its exact bytes)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var id int64
			if len(args) == 1 {
				n, perr := strconv.ParseInt(args[0], 10, 64)
				if perr != nil || n <= 0 {
					return fmt.Errorf("submission id must be a positive integer, got %q", args[0])
				}
				id = n
			}
			b, err := buildOrgBundle(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer b.cleanup()
			l, err := orgIntelLedger(cmd.Context(), b, id)
			if err != nil {
				return err
			}
			if asJSON {
				return writeIntelJSON(cmd.OutOrStdout(), l)
			}
			out := cmd.OutOrStdout()
			if len(l.Rows) == 0 {
				fmt.Fprintln(out, "No org enrichment submissions from this machine.")
				return nil
			}
			for _, r := range l.Rows {
				fmt.Fprintf(out, "%d  %s  %-16s %-10s %-10s %s  %s\n", r.ID, r.CreatedAt, r.State, r.Trigger, r.EvidenceLevel, r.SessionID, r.UploadDigest)
				if r.Reason != "" {
					fmt.Fprintf(out, "    reason: %s\n", r.Reason)
				}
			}
			if id > 0 {
				r := l.Rows[0]
				if r.BytesHeld {
					fmt.Fprintln(out)
					fmt.Fprintln(out, r.Bytes)
				} else {
					fmt.Fprintln(out, "The bytes were sent and are not kept on this machine; the digests above identify them.")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print as JSON")
	return cmd
}
