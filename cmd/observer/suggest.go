package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/suggest"
)

// newSuggestCmd wires `observer suggest` — compose derived patterns and
// learn rules into CLAUDE.md / AGENTS.md / .cursorrules (spec §15).
func newSuggestCmd() *cobra.Command {
	var (
		configPath  string
		projectRoot string
		days        int
		targets     string
		outputDir   string
		apply       bool
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "suggest",
		Short: "Compose derived patterns + correction rules into instruction files",
		Long: "Pulls hot files, common commands, edit→test pairs, onboarding reads,\n" +
			"and learn-derived correction rules from the DB, renders them into an\n" +
			"instruction-file body, and (with --apply) writes them to a managed\n" +
			"block in CLAUDE.md / AGENTS.md / .cursorrules. Preserves content\n" +
			"outside the markers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if projectRoot == "" {
				return errors.New("--project is required (the project to summarize)")
			}
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			in, err := suggest.Load(cmd.Context(), database, suggest.Options{
				ProjectRoot: projectRoot,
				Days:        days,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				body, _ := json.MarshalIndent(in, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(),
					"project: %s\nhot_files=%d common_commands=%d edit_test_pairs=%d co_change=%d onboarding=%d rules=%d\n",
					projectRoot,
					len(in.HotFiles), len(in.CommonCommands), len(in.EditTestPairs),
					len(in.CoChangePairs), len(in.OnboardingReads), len(in.Rules))
			}

			ts, err := resolveRuleTargets(targets, outputDir, projectRoot,
				suggest.RenderMarkdown, suggest.RenderCursorRules, "")
			if err != nil {
				return err
			}
			if !apply {
				fmt.Fprintf(cmd.OutOrStdout(),
					"\ndry-run: pass --apply to write into %s\n", joinTargetPaths(ts))
				return nil
			}
			now := time.Now()
			for _, t := range ts {
				body := t.render(in, now)
				changed, err := suggest.Apply(t.path, body)
				if err != nil {
					return err
				}
				status := "unchanged"
				if changed {
					status = "updated"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", t.path, status)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&projectRoot, "project", "", "Project root to summarize (required)")
	cmd.Flags().IntVar(&days, "days", 60, "Restrict learn rules to failures in the last N days")
	cmd.Flags().StringVar(&targets, "target", "claude", "Targets: claude, agents, cursor, all (comma-separated)")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Override directory for instruction files (defaults to project root)")
	cmd.Flags().BoolVar(&apply, "apply", false, "Write files (default is dry-run)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the composed input as JSON")
	return cmd
}
