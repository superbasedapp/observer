package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	adapterdefaults "github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/config/migrate"
)

// newConfigCmd is the `observer config` group (P3.3): a generic
// dotted-key setter over the global config.toml and repo-local
// project override files. Same write owner as the dashboard
// (config.WriteToml's .bak + atomic-rename path); global writes poke
// a running daemon so hot-reloadable consumers (the compression
// profile router) re-read immediately, and project-file writes apply
// to new sessions automatically via the daemon's mtime cache.
func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Read and edit observer configuration from the command line",
	}
	cmd.AddCommand(newConfigSetCmd())
	cmd.AddCommand(newConfigMigrateCmd())
	cmd.AddCommand(newConfigAdoptDefaultsCmd())
	return cmd
}

// newConfigMigrateCmd exposes the config auto-migration rail
// (internal/config/migrate) as an explicit command. It renames
// deprecated keys (e.g. the decommissioned [compression.code_graph] /
// [intelligence.code_graph] blocks) onto their new [codeintel] homes
// in place, preserving comments and untouched sections, and stamps a
// [observer] config_version. The same migration runs automatically on
// `observer start`; this command is for manual/CI runs and dry-runs.
func newConfigMigrateCmd() *cobra.Command {
	var (
		configPath string
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Rewrite config.toml to the current schema (rename deprecated keys, preserving comments)",
		Long: "Surgically renames deprecated config keys to their current names\n" +
			"(preserving your values, comments, and every untouched line), drops\n" +
			"keys that no longer exist, and stamps [observer] config_version.\n\n" +
			"A backup is written to config.toml.bak before any change. Pristine or\n" +
			"already-current files are left untouched. This same migration runs\n" +
			"automatically on `observer start`.\n\n" +
			"  observer config migrate            # migrate the global config.toml\n" +
			"  observer config migrate --dry-run  # show what would change, write nothing",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			out := cmd.OutOrStdout()

			if dryRun {
				body, err := os.ReadFile(resolvedPath)
				if os.IsNotExist(err) {
					fmt.Fprintf(out, "no config file at %s — nothing to migrate\n", resolvedPath)
					return nil
				}
				if err != nil {
					return fmt.Errorf("read %s: %w", resolvedPath, err)
				}
				res, err := migrate.Apply(string(body))
				if err != nil {
					return err
				}
				printMigrateReport(out, resolvedPath, res, true)
				return nil
			}

			res, err := config.MigrateFile(resolvedPath)
			if err != nil {
				return err
			}
			printMigrateReport(out, resolvedPath, res, false)
			if res.Migrated {
				if pokeReload() {
					fmt.Fprintln(out, "daemon reloaded — new settings apply to new sessions now")
				} else {
					fmt.Fprintln(out, "no running daemon detected — applies on next start")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would change without writing")
	return cmd
}

// printMigrateReport renders a migrate.Result to the user.
func printMigrateReport(out io.Writer, path string, res migrate.Result, dry bool) {
	switch {
	case res.Skipped:
		fmt.Fprintf(out, "skipped %s: %s\n", path, res.SkipReason)
		return
	case !res.Migrated:
		fmt.Fprintf(out, "%s is already up to date (config_version %d) — no changes\n", path, res.FromVersion)
		return
	}
	verb := "migrated"
	if dry {
		verb = "would migrate"
	}
	fmt.Fprintf(out, "%s %s (config_version %d → %d):\n", verb, path, res.FromVersion, res.ToVersion)
	for _, c := range res.Changes {
		switch c.Kind {
		case "rename":
			fmt.Fprintf(out, "  • %s → %s (%s)\n", c.From, c.To, c.Note)
		case "remove":
			fmt.Fprintf(out, "  • %s removed (%s)\n", c.From, c.Note)
		case "stamp":
			fmt.Fprintf(out, "  • %s\n", c.Note)
		}
	}
	if !dry {
		fmt.Fprintf(out, "backup written to %s.bak\n", path)
	}
}

// newConfigAdoptDefaultsCmd exposes the Invariant #51 drift-hardening
// fix (internal/config.AdoptEnabledAdapters) as an explicit command.
// Config.Default() only seeds [observer.watch] enabled_adapters when
// the key is absent from config.toml — an operator with an explicit
// list carried over from a prior release silently never picks up
// newly-registered default adapters, and their sessions from those
// tools go uncaptured. This command appends exactly the missing names
// to the operator's existing array, preserving order, formatting, and
// comments.
//
// Unlike `config migrate`, dry-run is the DEFAULT here rather than
// opt-in: this command edits a list the operator wrote by hand, so it
// only touches disk when explicitly told to via --write.
func newConfigAdoptDefaultsCmd() *cobra.Command {
	var (
		configPath string
		write      bool
	)
	cmd := &cobra.Command{
		Use:   "adopt-defaults",
		Short: "Add newly-registered default adapters to an explicit enabled_adapters list",
		Long: "Config.Default() only seeds [observer.watch] enabled_adapters when the\n" +
			"key is absent from config.toml. If your config.toml carries an\n" +
			"explicit list from a prior release, newly-added default adapters\n" +
			"never run — sessions from those tools go uncaptured until you add\n" +
			"them by hand. This command does that for you: it appends only the\n" +
			"missing names, leaving your existing order, formatting, and comments\n" +
			"untouched.\n\n" +
			"  observer config adopt-defaults          # preview only, writes nothing\n" +
			"  observer config adopt-defaults --write  # apply the append\n\n" +
			"A backup is written to config.toml.bak before any change. A file with\n" +
			"no explicit enabled_adapters key, or one that already lists every\n" +
			"default, is reported as-is with nothing written.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			out := cmd.OutOrStdout()

			defs := adapterdefaults.Adapters()
			names := make([]string, len(defs))
			for i, a := range defs {
				names[i] = a.Name()
			}

			body, readErr := os.ReadFile(resolvedPath)
			fileExists := !os.IsNotExist(readErr)
			if readErr != nil && fileExists {
				return fmt.Errorf("read %s: %w", resolvedPath, readErr)
			}
			if !fileExists {
				fmt.Fprintf(out, "no config file at %s — nothing to adopt\n", resolvedPath)
				return nil
			}

			if !write {
				_, res, err := config.AdoptEnabledAdapters(string(body), names)
				if err != nil {
					return err
				}
				printAdoptReport(out, resolvedPath, res, true)
				return nil
			}

			res, err := config.AdoptEnabledAdaptersFile(resolvedPath, names)
			if err != nil {
				return err
			}
			printAdoptReport(out, resolvedPath, res, false)
			if res.Changed && !res.Skipped {
				if pokeReload() {
					fmt.Fprintln(out, "daemon reloaded — new settings apply to new sessions now")
				} else {
					fmt.Fprintln(out, "no running daemon detected — applies on next start")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&write, "write", false, "Apply the append (default: preview only, writes nothing)")
	return cmd
}

// printAdoptReport renders an config.AdoptResult to the user, mirroring
// printMigrateReport's style and honesty-first posture: every branch
// describes exactly what is true of the file, never implies a change
// that didn't happen.
func printAdoptReport(out io.Writer, path string, res config.AdoptResult, dry bool) {
	switch {
	case !res.HadExplicitList:
		fmt.Fprintf(out, "%s has no explicit enabled_adapters list — nothing to adopt (every default adapter already applies)\n", path)
		return
	case res.Skipped:
		fmt.Fprintf(out, "skipped %s: %s\n", path, res.SkipReason)
		return
	case !res.Changed:
		fmt.Fprintf(out, "%s already lists every default adapter (%d) — no changes\n", path, len(res.Existing))
		return
	}
	verb := "added"
	if dry {
		verb = "would add"
	}
	fmt.Fprintf(out, "%s %d missing default adapter(s) to %s:\n", verb, len(res.Missing), path)
	for _, m := range res.Missing {
		fmt.Fprintf(out, "  • %s\n", m)
	}
	if dry {
		fmt.Fprintln(out, "re-run with --write to apply")
		return
	}
	fmt.Fprintf(out, "backup written to %s.bak\n", path)
}

func newConfigSetCmd() *cobra.Command {
	var (
		configPath  string
		projectRoot string
	)
	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set one config key (dotted TOML path) in config.toml or a project override file",
		Long: "Sets a dotted TOML key, e.g.:\n" +
			"  observer config set compression.conversation.target_ratio 0.7\n" +
			"  observer config set profiles.by_provider.openai codex-variant\n" +
			"  observer config set profiles.by_tool.cline codex-safe\n" +
			"  observer config set --project /path/to/repo compression.conversation.enabled false\n\n" +
			"Without --project the key lands in the global config.toml (the same\n" +
			"atomic write+backup path dashboard saves use) and a running daemon is\n" +
			"poked so profile/assignment changes apply to NEW sessions immediately.\n" +
			"With --project the key lands in <root>/.observer/config.toml — the\n" +
			"repo-local override file, which accepts ONLY profiles.* and\n" +
			"compression.* keys (it is world-authored; daemon-level keys are\n" +
			"refused). Project-file edits need no poke: the daemon notices the\n" +
			"file change on the next session.\n\n" +
			"List values are comma-separated; booleans true/false.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]

			if projectRoot != "" {
				if err := config.UpdateProjectOverlay(projectRoot, key, value); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "set %s = %s in %s/%s\n",
					key, value, projectRoot, config.ProjectOverlayFilename)
				fmt.Fprintln(cmd.OutOrStdout(), "applies to this project's NEW sessions automatically (no restart)")
				return nil
			}

			resolvedPath, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := config.SetConfigKey(&cfg, key, value); err != nil {
				return err
			}
			// Validate the resulting config before persisting — a value
			// that parses but violates an invariant (port range, mode
			// names) must not land on disk.
			if err := config.Validate(cfg); err != nil {
				return fmt.Errorf("refusing to save: %w", err)
			}
			if err := config.WriteToml(resolvedPath, cfg); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "set %s = %s (saved to %s)\n", key, value, resolvedPath)
			if pokeReload() {
				fmt.Fprintln(cmd.OutOrStdout(), "daemon reloaded — hot-reloadable settings apply to new sessions now")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "no running daemon detected on the dashboard port — applies on next start (or dashboard save)")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&projectRoot, "project", "", "Write to <root>/.observer/config.toml instead of the global config (profiles.* and compression.* keys only)")
	return cmd
}
