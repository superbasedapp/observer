//go:build !sbo_omit_codeintel

package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/surface"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// openCodeIntel builds the Tier-C surface service AND the native engine
// over a SINGLE DB handle for a CLI command, returning them plus a
// cleanup closure. (Both share the one connection — the engine is used
// for symbol resolution, the service for the surfaces.)
//
// With code intelligence off (the default since D-307) the read surfaces
// still answer from whatever index is on disk (one built while it was on,
// until retention prunes it), so they keep working for inspection; a
// one-line note on stderr says the index is no longer maintained, so an
// empty or stale answer is never mistaken for "no such symbol".
func openCodeIntel(cmd *cobra.Command, configPath string) (*surface.Service, codeintel.Provider, func(), error) {
	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return nil, nil, nil, err
	}
	if !cfg.CodeIntel.Enabled {
		fmt.Fprintln(cmd.ErrOrStderr(), "note: "+codeintel.DisabledNote+"; answering from any index left on disk, which is not being updated")
	}
	eng := codeintel.NewEngine(store.New(database))
	return surface.New(eng), eng, cleanup, nil
}

// printSymbols renders a SymbolMatch slice as a table.
func printSymbols(cmd *cobra.Command, syms []codeintel.SymbolMatch) {
	if len(syms) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no results")
		return
	}
	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tNAME\tFQN\tFILE\tLINE")
	for _, s := range syms {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", s.Kind, s.Name, s.FQN, s.File, s.StartLine)
	}
	_ = tw.Flush()
}

func newCodeIntelSearchCmd() *cobra.Command {
	var (
		configPath string
		limit      int
		allProj    bool
	)
	cmd := &cobra.Command{
		Use:   "search <query> [path]",
		Short: "Full-text symbol search (name/fqn/signature, camelCase + snake_case aware)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, _, cleanup, err := openCodeIntel(cmd, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			project := ""
			if !allProj {
				dir := "."
				if len(args) == 2 {
					dir = args[1]
				}
				project = resolveProjectRoot(dir)
			}
			syms, err := svc.Search(cmd.Context(), project, args[0], limit)
			if err != nil {
				return err
			}
			printSymbols(cmd, syms)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().IntVar(&limit, "limit", 20, "Max results")
	cmd.Flags().BoolVar(&allProj, "all-projects", false, "Search across every indexed project")
	return cmd
}

// relationFn resolves the related symbols for an anchor node id.
type relationFn func(svc *surface.Service, cmd *cobra.Command, nodeID, limit int64) ([]codeintel.SymbolMatch, error)

func newCodeIntelRelationCmd(use, short string, rel relationFn) *cobra.Command {
	var (
		configPath string
		limit      int
	)
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, eng, cleanup, err := openCodeIntel(cmd, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			abs, err := absPath(args[0])
			if err != nil {
				return err
			}
			matches, err := eng.FindSymbols(cmd.Context(), abs, args[1], "", "")
			if err != nil || len(matches) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "symbol %q not found in %s - index the project first?\n", args[1], abs)
				return nil
			}
			out, err := rel(svc, cmd, matches[0].ID, int64(limit))
			if err != nil {
				return err
			}
			printSymbols(cmd, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().IntVar(&limit, "limit", 10, "Max results")
	return cmd
}

func newCodeIntelArchitectureCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "architecture [path]",
		Short: "Directory-level overview + Louvain communities for a project",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, _, cleanup, err := openCodeIntel(cmd, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			arch, err := svc.Architecture(cmd.Context(), projectArg(args))
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%s\n  symbols %d · resolved CALLS edges %d · communities %d\n\n",
				arch.Project, arch.TotalNodes, arch.TotalEdges, len(arch.Communities))
			tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "DIR\tSYMBOLS\tINTERNAL\tOUTBOUND\tINBOUND")
			for _, d := range arch.Dirs {
				fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n", d.Dir, d.Symbols, d.Internal, d.Outbound, d.Inbound)
			}
			_ = tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

func newCodeIntelDeadCodeCmd() *cobra.Command {
	var (
		configPath string
		includeExp bool
	)
	cmd := &cobra.Command{
		Use:   "deadcode [path]",
		Short: "Functions/methods with no inbound calls (heuristic - name-matched graph)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, _, cleanup, err := openCodeIntel(cmd, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			dead, err := svc.DeadCode(cmd.Context(), projectArg(args), !includeExp)
			if err != nil {
				return err
			}
			if len(dead) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no dead-code candidates")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "KIND\tNAME\tFILE\tLINE\tWHY")
			for _, d := range dead {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", d.Kind, d.Name, d.File, d.StartLine, d.Reason)
			}
			_ = tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&includeExp, "include-exported", false, "Also flag exported symbols (likely public API / external entrypoints)")
	return cmd
}

func newCodeIntelImpactCmd() *cobra.Command {
	var (
		configPath string
		path       string
	)
	cmd := &cobra.Command{
		Use:   "impact <symbol> [symbol...]",
		Short: "Symbols transitively affected by changing the given symbol(s)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, _, cleanup, err := openCodeIntel(cmd, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			out, err := svc.Impact(cmd.Context(), resolveProjectRoot(pathOrDot(path)), args)
			if err != nil {
				return err
			}
			printSymbols(cmd, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&path, "path", ".", "A path inside the target project (resolves its git root)")
	return cmd
}

func newCodeIntelQueryCmd() *cobra.Command {
	var (
		configPath string
		path       string
	)
	cmd := &cobra.Command{
		Use:   "query <cypher>",
		Short: "Run a read-only Cypher-subset query over the symbol graph",
		Long: "Supported subset:\n" +
			"  MATCH (a)-[:CALLS]->(b) WHERE a.name = \"Run\" RETURN b.name, b.file LIMIT 10",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, _, cleanup, err := openCodeIntel(cmd, configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			rs, err := svc.Query(cmd.Context(), resolveProjectRoot(pathOrDot(path)), args[0])
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			if len(rs.Columns) > 0 {
				fmt.Fprintln(tw, joinTab(rs.Columns))
			}
			for _, row := range rs.Rows {
				fmt.Fprintln(tw, joinTab(row))
			}
			_ = tw.Flush()
			fmt.Fprintf(cmd.OutOrStdout(), "(%d rows)\n", len(rs.Rows))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&path, "path", ".", "A path inside the target project (resolves its git root)")
	return cmd
}

func newCodeIntelSurfacesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "surfaces",
		Short: "List the code-intelligence query surfaces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "SURFACE\tDESCRIPTION")
			for _, s := range surface.Catalog() {
				fmt.Fprintf(tw, "%s\t%s\n", s.Name, s.Description)
			}
			return tw.Flush()
		},
	}
	return cmd
}

// projectArg resolves an optional trailing path arg (default cwd) to a
// project root.
func projectArg(args []string) string {
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	return resolveProjectRoot(dir)
}

func pathOrDot(p string) string {
	if p == "" {
		return "."
	}
	return p
}

func joinTab(cells []string) string {
	out := ""
	for i, c := range cells {
		if i > 0 {
			out += "\t"
		}
		out += c
	}
	return out
}
