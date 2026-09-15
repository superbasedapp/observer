package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/index"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
	"github.com/marmutapp/superbased-observer/internal/codeintel/surface"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newIndexCmd is the explicit code-intelligence indexing surface
// (docs/codeintel/project-lifecycle.md §5b.2). `observer index <path>`
// is consent-given by definition, so it bypasses the auto_index_limit
// gate. Subcommands: status, delete.
func newIndexCmd() *cobra.Command {
	var (
		configPath string
		all        bool
		rescan     bool
	)
	cmd := &cobra.Command{
		Use:   "index [path]",
		Short: "Index a project's source tree for code intelligence",
		Long: "Walks a project's source tree, extracts symbols + spans, and persists\n" +
			"them to the local code-intelligence index. Read-only on your repo. An\n" +
			"explicit `observer index <path>` is treated as consent, so it indexes\n" +
			"even a large project the auto-indexer would have gated.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			if !cfg.CodeIntel.Enabled {
				fmt.Fprintln(cmd.OutOrStdout(), "codeintel is disabled ([codeintel].enabled=false)")
				return nil
			}
			ix := index.New(codeIntelIndexOptions(cfg, st))

			projects, err := indexTargets(cmd, st, args, all)
			if err != nil {
				return err
			}
			for _, project := range projects {
				if index.IsIgnored(project, cfg.CodeIntel.IgnorePaths) {
					fmt.Fprintf(cmd.OutOrStdout(),
						"note: %s is in [codeintel].ignore_paths — indexing anyway because this is an explicit request; remove it there to stop auto-index.\n",
						project)
				}
				if rescan {
					if err := st.CodeIntelDeleteProject(cmd.Context(), project); err != nil {
						return err
					}
				}
				rep, err := ix.IndexProject(cmd.Context(), project, true)
				if err != nil {
					return fmt.Errorf("index %q: %w", project, err)
				}
				printIndexReport(cmd, rep)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&all, "all", false, "Index every project already known to the index")
	cmd.Flags().BoolVar(&rescan, "rescan", false, "Delete the project's index first, then re-index from scratch")

	cmd.AddCommand(newIndexStatusCmd())
	cmd.AddCommand(newIndexDeleteCmd())
	cmd.AddCommand(newIndexIgnoreCmd())
	return cmd
}

// newIndexIgnoreCmd is `observer index ignore <path>`: the one-command way
// to un-index a folder AND keep it out. It removes the code-intelligence
// index for the path and every project nested under it, then prints the
// exact [codeintel].ignore_paths line to add so `observer start` never
// re-adopts it. It deliberately does NOT edit config.toml itself — the
// sanctioned writer round-trips the file and would drop your comments —
// so it shows the line to paste instead.
func newIndexIgnoreCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "ignore <path>",
		Short: "Un-index a folder and show how to keep it out for good",
		Long: "Removes the code-intelligence index for <path> and everything nested\n" +
			"under it, then prints the `[codeintel].ignore_paths` line to add so\n" +
			"`observer start` never re-indexes it. Paste the shown line into\n" +
			"~/.observer/config.toml (this command does not edit it for you, to\n" +
			"avoid rewriting your file).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			root := resolveProjectRoot(args[0])
			w := cmd.OutOrStdout()

			deleted, err := st.CodeIntelDeleteProjectsUnder(cmd.Context(), root)
			if err != nil {
				return err
			}
			if len(deleted) == 0 {
				fmt.Fprintf(w, "no indexed projects at or under %s\n", root)
			} else {
				for _, p := range deleted {
					fmt.Fprintf(w, "deleted index for %s\n", p)
				}
				fmt.Fprintf(w, "removed %d project(s) under %s\n", len(deleted), root)
			}

			if index.IsIgnored(root, cfg.CodeIntel.IgnorePaths) {
				fmt.Fprintf(w, "\n%s is already covered by [codeintel].ignore_paths — nothing to add.\n", root)
				return nil
			}
			paths := make([]string, 0, len(cfg.CodeIntel.IgnorePaths)+1)
			paths = append(paths, cfg.CodeIntel.IgnorePaths...)
			paths = append(paths, root)
			fmt.Fprintf(w, "\nto keep it out, add this under [codeintel] in %s:\n    ignore_paths = %s\n",
				configPathOrDefault(configPath), tomlStringList(paths))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// configPathOrDefault names the config file for display, falling back to
// the default location when no --config was given.
func configPathOrDefault(p string) string {
	if p != "" {
		return p
	}
	return "~/.observer/config.toml"
}

// tomlStringList renders paths as a TOML array literal (["a", "b"]) for
// the copy-paste hint. %q escaping is compatible with TOML basic strings.
func tomlStringList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// indexTargets resolves which project roots to index: --all uses every
// known project; otherwise the path arg (or cwd) resolved to its git
// root.
func indexTargets(cmd *cobra.Command, st *store.Store, args []string, all bool) ([]string, error) {
	if all {
		return st.CodeIntelListProjects(cmd.Context())
	}
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	root := resolveProjectRoot(dir)
	return []string{root}, nil
}

// resolveProjectRoot maps a directory to its git root (the project
// identity sessions/turns already carry), falling back to the absolute
// directory for non-git trees.
func resolveProjectRoot(dir string) string {
	if root, ok := git.FindRoot(dir); ok {
		return root
	}
	if abs, err := absPath(dir); err == nil {
		return abs
	}
	return dir
}

func newIndexStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show per-project index state (indexed / stale / pending / needs_consent)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			projects, err := st.CodeIntelListProjects(cmd.Context())
			if err != nil {
				return err
			}
			// Corpus archival P2.3: an archived project has ZERO rows in
			// codeintel_files, so it vanishes from the list above entirely —
			// and if every project is archived, the message below would tell
			// an operator to index repositories that are already indexed and
			// sitting in cold storage. The marker table is the only thing that
			// can say otherwise, and it costs one indexed read.
			archived, aerr := st.CodeIntelArchivedProjects(cmd.Context(), 0)
			if aerr != nil {
				return aerr
			}
			if len(projects) == 0 && len(archived) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no indexed projects — run `observer index <path>`")
				return nil
			}
			if len(projects) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(),
					"no HOT indexed projects — every indexed project is in cold storage")
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "PROJECT\tINDEXED\tSTALE\tPENDING\tNEEDS_CONSENT\tFAILED")
			for _, p := range projects {
				counts, err := st.CodeIntelProjectStatus(cmd.Context(), p)
				if err != nil {
					return err
				}
				fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\n", p,
					counts["indexed"], counts["stale"], counts["pending"],
					counts["needs_consent"], counts["failed"])
			}
			for _, m := range archived {
				when := "unknown"
				if m.LastIndexedAt > 0 {
					when = time.Unix(m.LastIndexedAt, 0).UTC().Format("2006-01-02")
				}
				fmt.Fprintf(tw, "%s\tarchived\t-\t-\t-\t-\t(last indexed %s, %d rows in cold storage)\n",
					m.Project, when, m.RowsArchived)
			}
			if len(archived) > 0 {
				fmt.Fprintln(tw, "\nrestore an archived project with `observer archive rehydrate <path>`")
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

func newIndexDeleteCmd() *cobra.Command {
	var (
		configPath string
		recursive  bool
	)
	cmd := &cobra.Command{
		Use:   "delete <project-root>",
		Short: "Remove a project's code-intelligence index",
		Long: "Removes the code-intelligence index for a project root.\n\n" +
			"With --recursive, also removes every indexed project nested under\n" +
			"that path — the one-command way to un-index a whole tree you never\n" +
			"meant to index (a folder can hold several nested project keys). Run\n" +
			"`observer index status` first to see what is currently indexed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			project := resolveProjectRoot(args[0])

			if recursive {
				deleted, err := st.CodeIntelDeleteProjectsUnder(cmd.Context(), project)
				if err != nil {
					return err
				}
				if len(deleted) == 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "no indexed projects at or under %s\n", project)
					return nil
				}
				for _, p := range deleted {
					fmt.Fprintf(cmd.OutOrStdout(), "deleted index for %s\n", p)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "removed %d project(s) under %s\n", len(deleted), project)
				return nil
			}

			if err := st.CodeIntelDeleteProject(cmd.Context(), project); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted index for %s\n", project)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Also delete every indexed project nested under <project-root>")
	return cmd
}

// newCodeIntelCmd is the `observer codeintel` group — transparency +
// inspection surfaces (docs/codeintel/configuration.md §11.3).
func newCodeIntelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "codeintel",
		Short: "Inspect and query the code-intelligence index",
	}
	cmd.AddCommand(newCodeIntelExplainCmd())
	cmd.AddCommand(newCodeIntelSearchCmd())
	cmd.AddCommand(newCodeIntelRelationCmd(
		"related <file> <symbol>",
		"Semantically related symbols (embedding cosine)",
		func(svc *surface.Service, c *cobra.Command, id, limit int64) ([]codeintel.SymbolMatch, error) {
			return svc.SemanticNeighbors(c.Context(), id, int(limit))
		},
	))
	cmd.AddCommand(newCodeIntelRelationCmd(
		"similar <file> <symbol>",
		"Near-clone candidates for a symbol (MinHash/LSH)",
		func(svc *surface.Service, c *cobra.Command, id, limit int64) ([]codeintel.SymbolMatch, error) {
			return svc.Similar(c.Context(), id, int(limit))
		},
	))
	cmd.AddCommand(newCodeIntelArchitectureCmd())
	cmd.AddCommand(newCodeIntelDeadCodeCmd())
	cmd.AddCommand(newCodeIntelImpactCmd())
	cmd.AddCommand(newCodeIntelQueryCmd())
	cmd.AddCommand(newCodeIntelSurfacesCmd())
	return cmd
}

// newCodeIntelExplainCmd shows the symbols + spans the index found for a
// file and, as a DRY RUN, exactly what aggressive compression WOULD
// collapse — changing nothing. The developer previews before enabling.
func newCodeIntelExplainCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "explain <file>",
		Short: "Show indexed symbols + spans for a file (and what aggressive compression would collapse)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			abs, err := absPath(args[0])
			if err != nil {
				return err
			}
			eng := codeintel.NewEngine(st)
			syms, err := eng.SymbolsInFile(cmd.Context(), abs)
			if err != nil {
				return err
			}

			lang, langOK := parse.LanguageForPath(abs)
			capab := index.DefaultRegistry().Capability(lang)

			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s\n", abs)
			if !langOK {
				fmt.Fprintln(w, "  (unsupported file extension — not indexed)")
				return nil
			}
			fmt.Fprintf(w, "  language %s · exact-spans %v · collapsible %v\n\n", lang, capab.ExactSpans, capab.CanCollapse())
			if len(syms) == 0 {
				fmt.Fprintln(w, "  no symbols indexed — run `observer index` on this project first")
				return nil
			}
			tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "KIND\tNAME\tLINES\tWOULD-COLLAPSE")
			for _, s := range syms {
				var lines string
				collapse := "no"
				if s.EndLine >= s.StartLine && s.EndLine > 0 {
					lines = fmt.Sprintf("%d-%d", s.StartLine, s.EndLine)
					// Dry run: only an exact-span backend may collapse
					// (ADR-0005); the actual size gate lands with Phase 2.
					if capab.CanCollapse() {
						collapse = "yes"
					}
				} else {
					lines = fmt.Sprintf("%d-?", s.StartLine)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Kind, s.Name, lines, collapse)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// runCodeIntelOnStart indexes known projects when `observer start`
// boots, gated by [codeintel].enabled + index.on_start + auto mode. It
// is best-effort and NEVER blocks/aborts the daemon: any error is logged
// and swallowed (ADR-0002 — index time only, off the proxy hot path).
// New projects over auto_index_limit are consent-gated (force=false).
//
// T2.4 (2026-08-26 disk/compute remediation plan, P2-H): the whole loop
// is bounded by an aggregate wall-clock deadline
// ([codeintel.index].on_start_timeout_minutes, default 10) so a huge
// discovered project set (historically 384K files across a Windows home
// directory's worth of roots) can't run unbounded on every boot — any
// projects not reached by the deadline are simply left for next start or
// an explicit `observer index`. This is orthogonal to (and doesn't
// weaken) the existing per-project isAutoIndexBlocked home/drive-root
// gate inside index.IndexProject, nor the per-project auto_index_limit
// consent gate below.
//
// T2.3 (P1-F): guarded by the "codeintel-index" dblease so only one
// observer process on this machine runs this pass per boot.
func runCodeIntelOnStart(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	if !cfg.CodeIntel.Enabled || !cfg.CodeIntel.Index.OnStart || cfg.CodeIntel.Index.Mode == "manual" {
		return
	}
	logger := newLogger(cfg.Observer.LogLevel)

	release, proceed := acquireMaintenanceLease(cfg, "codeintel-index", logger)
	defer release()
	if !proceed {
		return
	}

	if minutes := cfg.CodeIntel.Index.OnStartTimeoutMinutes; minutes > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(minutes)*time.Minute)
		defer cancel()
	}

	st := store.New(database)

	// Union of already-indexed projects and every project Observer knows
	// about from ingest, so a freshly-observed repo gets picked up.
	seen := map[string]struct{}{}
	var projects []string
	known, _ := st.CodeIntelListProjects(ctx)
	roots, _ := st.ProjectRoots(ctx)
	for _, p := range slices.Concat(known, roots) {
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		projects = append(projects, p)
	}
	if len(projects) == 0 {
		return
	}

	ix := index.New(codeIntelIndexOptions(cfg, st))
	for _, project := range projects {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				logger.Info("codeintel: index-on-start aggregate deadline reached — remaining projects deferred to next start",
					"timeout_minutes", cfg.CodeIntel.Index.OnStartTimeoutMinutes)
			}
			return
		}
		rep, err := ix.IndexProject(ctx, project, false)
		if err != nil {
			logger.Warn("codeintel: index-on-start failed", "project", project, "err", err)
			continue
		}
		if rep.NeedsConsent {
			logger.Info("codeintel: project awaiting consent (exceeds auto_index_limit)",
				"project", project, "files", rep.Scanned, "limit", cfg.CodeIntel.AutoIndexLimit)
			continue
		}
		if rep.Indexed > 0 {
			logger.Info("codeintel: indexed on start",
				"project", project, "indexed", rep.Indexed, "unchanged", rep.Unchanged)
		}
	}
}

// aggressiveExtsFor expands the [codeintel.compression].aggressive_languages
// list into the concrete set of file extensions the proxy's collapse hook
// checks. Unknown language names contribute nothing (no extensions).
func aggressiveExtsFor(langs []string) map[string]bool {
	out := map[string]bool{}
	for _, l := range langs {
		for _, ext := range parse.Extensions(codeintel.Language(l)) {
			out[ext] = true
		}
	}
	return out
}

// codeIntelIndexOptions maps [codeintel] config onto the indexer's
// Options at the boundary (the index package never imports config).
func codeIntelIndexOptions(cfg config.Config, st *store.Store) index.Options {
	langs := make([]codeintel.Language, 0, len(cfg.CodeIntel.Languages))
	for _, l := range cfg.CodeIntel.Languages {
		langs = append(langs, codeintel.Language(l))
	}
	return index.Options{
		Store:          st,
		Registry:       index.DefaultRegistry(),
		Languages:      langs,
		MaxFileBytes:   cfg.CodeIntel.MaxFileBytes,
		AutoIndexLimit: cfg.CodeIntel.AutoIndexLimit,
		IgnoreRoots:    cfg.CodeIntel.IgnorePaths,
	}
}

func printIndexReport(cmd *cobra.Command, rep index.Report) {
	w := cmd.OutOrStdout()
	if rep.Ignored {
		fmt.Fprintf(w, "%s\n  skipped — in [codeintel].ignore_paths\n", rep.Project)
		return
	}
	if rep.NeedsConsent {
		fmt.Fprintf(w, "%s\n  %d files exceed auto_index_limit — run `observer index %s` to consent (already done if you see this from an explicit run).\n",
			rep.Project, rep.Scanned, rep.Project)
		return
	}
	derived := "rebuilt"
	if rep.DerivedSkipped {
		derived = "unchanged (skipped)"
	}
	fmt.Fprintf(w, "%s\n  scanned %d · indexed %d · unchanged %d · skipped %d · failed %d\n  search index: %s\n",
		rep.Project, rep.Scanned, rep.Indexed, rep.Unchanged, rep.Skipped, rep.Failed, derived)
}

// absPath resolves p to an absolute path (cwd-relative when p is
// relative or empty).
func absPath(p string) (string, error) {
	if p == "" {
		p = "."
	}
	return filepath.Abs(p)
}
