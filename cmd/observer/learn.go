package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/learn"
)

// newLearnCmd wires `observer learn` — derive correction rules from paired
// failures → successes and optionally write them to CLAUDE.md / AGENTS.md /
// .cursorrules (spec §15.3).
func newLearnCmd() *cobra.Command {
	var (
		configPath  string
		projectRoot string
		days        int
		minFailures int
		apply       bool
		targetsRaw  string
		outputDir   string
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "learn",
		Short: "Derive correction rules from failure→recovery pairs",
		Long: "Scans failure_context, pairs each failure with the next success of the\n" +
			"same command in the same session, and collects the file edits between\n" +
			"them. Rule-based, zero LLM cost.\n\n" +
			"Without --apply the command only prints the derived rules (dry run).\n" +
			"With --apply it rewrites a managed block in the target instruction file\n" +
			"(CLAUDE.md / AGENTS.md / .cursorrules). Content outside the managed\n" +
			"markers is preserved.",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			rules, err := learn.New(database).Derive(cmd.Context(), learn.Options{
				ProjectRoot: projectRoot,
				Days:        days,
				MinFailures: minFailures,
			})
			if err != nil {
				return err
			}

			if jsonOut {
				body, _ := json.MarshalIndent(rules, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
			} else {
				printLearnRules(cmd.OutOrStdout(), rules)
			}

			targets, err := resolveRuleTargets(targetsRaw, outputDir, projectRoot,
				learn.RenderMarkdown, learn.RenderCursorRules, " (want claude, agents, cursor, all)")
			if err != nil {
				return err
			}
			if !apply {
				if len(rules) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(),
						"\ndry-run: pass --apply to write %d rule(s) into %s\n",
						len(rules), joinTargetPaths(targets))
				}
				return nil
			}
			if len(targets) == 0 {
				return errors.New("--apply requires --target (claude|agents|cursor|all) or --output-dir")
			}
			now := time.Now()
			changedAny := false
			for _, t := range targets {
				body := t.render(rules, now)
				changed, err := learn.Apply(t.path, body)
				if err != nil {
					return err
				}
				changedAny = changedAny || changed
				status := "unchanged"
				if changed {
					status = "updated"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", t.path, status)
			}
			if !changedAny {
				fmt.Fprintln(cmd.OutOrStdout(), "no changes - existing managed block(s) already match")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&projectRoot, "project", "", "Restrict to one project root (required for --apply unless --output-dir is set)")
	cmd.Flags().IntVar(&days, "days", 60, "Restrict to failures in the last N days (0 disables)")
	cmd.Flags().IntVar(&minFailures, "min-failures", 2, "Minimum failure count before a pattern becomes a rule")
	cmd.Flags().BoolVar(&apply, "apply", false, "Write rules into instruction files (default is dry-run)")
	cmd.Flags().StringVar(&targetsRaw, "target", "claude", "Comma-separated targets: claude, agents, cursor, all")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Override directory for instruction files (defaults to --project root, CWD otherwise)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit rules as JSON")
	return cmd
}

// ruleTarget pairs an output path with the renderer to use on it. R is what
// the renderer takes: learn's rules or suggest's composed input.
type ruleTarget[R any] struct {
	path   string
	render func(R, time.Time) string
}

// resolveRuleTargets turns learn's and suggest's --target and --output-dir
// into the instruction files to write: claude is CLAUDE.md, agents is
// AGENTS.md (both rendered by markdown), cursor is .cursorrules (rendered by
// cursor), and all is the three. The directory is --output-dir, else the
// project root, else the working directory. An unknown target is an error
// whose text ends with unknownHint.
func resolveRuleTargets[R any](raw, outputDir, projectRoot string, markdown, cursor func(R, time.Time) string, unknownHint string) ([]ruleTarget[R], error) {
	dir := outputDir
	if dir == "" {
		dir = projectRoot
	}
	if dir == "" {
		if cwd, err := os.Getwd(); err == nil {
			dir = cwd
		}
	}
	parts := splitCSV(raw)
	if len(parts) == 0 {
		parts = []string{"claude"}
	}
	if contains(parts, "all") {
		parts = []string{"claude", "agents", "cursor"}
	}
	var out []ruleTarget[R]
	for _, p := range parts {
		switch strings.ToLower(p) {
		case "claude":
			out = append(out, ruleTarget[R]{
				path:   filepath.Join(dir, "CLAUDE.md"),
				render: markdown,
			})
		case "agents":
			out = append(out, ruleTarget[R]{
				path:   filepath.Join(dir, "AGENTS.md"),
				render: markdown,
			})
		case "cursor":
			out = append(out, ruleTarget[R]{
				path:   filepath.Join(dir, ".cursorrules"),
				render: cursor,
			})
		default:
			return nil, fmt.Errorf("unknown --target %q%s", p, unknownHint)
		}
	}
	return out, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// joinTargetPaths lists the targets' paths, comma separated.
func joinTargetPaths[R any](targets []ruleTarget[R]) string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.path)
	}
	return strings.Join(out, ", ")
}

func printLearnRules(w interface{ Write([]byte) (int, error) }, rules []learn.Rule) {
	if len(rules) == 0 {
		fmt.Fprintln(w, "no recovery patterns observed yet")
		return
	}
	fmt.Fprintf(w, "%d correction rule(s):\n", len(rules))
	for _, r := range rules {
		fmt.Fprintf(w, "- %s (%s): %d failures → %d recovered; edits: %s\n",
			truncate(r.CommandSummary, 60),
			defaultStr(r.ErrorCategory, "?"),
			r.FailureCount, r.RecoveryCount,
			strings.Join(r.EditedFiles, ", "))
	}
}

func defaultStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
