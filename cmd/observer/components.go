package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// components.go is `observer components`: the read-only view of the
// modular-packaging component catalog (docs/components.md, plan phase P0,
// lane MP-CAT). It reads only the pure internal/components catalog and
// this binary's own compiled-set registry: no config, no database, no
// network. Nothing here switches a component on or off; the add, remove
// and purge verbs arrive with phase P1 (lane MP-GATE).

// componentsUnknownExit is the exit code for an id the catalog does not
// know, distinct from a usage error.
const componentsUnknownExit = 3

func newComponentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "components",
		Short: "Show the component catalog: what this build contains and what each component adds",
		Long: "Lists the named components of superbased Observer (features, adapters,\n" +
			"integrations that write other tools' config, org server modules, and the\n" +
			"artifacts installed outside the binary), whether this binary was built\n" +
			"with each one, and what each adds to a machine: listeners, outbound\n" +
			"hosts, files and other tools' config it writes, processes it runs.\n\n" +
			"`status` shows what runs on this machine; `select`, `add` and `remove`\n" +
			"change it (written to the [components] block of config.toml), `teardown`\n" +
			"undoes what an inactive component wrote into other tools' config, and\n" +
			"`purge` deletes its data. A prebuilt distro build (minimal, developer,\n" +
			"managed) compiles in only its own set.\n" +
			"The same data is in docs/components.md and at GET /api/components.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newComponentsListCmd(), newComponentsShowCmd(), newComponentsArtifactsCmd())
	return cmd
}

func newComponentsListCmd() *cobra.Command {
	var (
		jsonOut bool
		all     bool
		class   string
		distro  string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List components with their class, level and whether this build has them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep := components.BuildReport(components.BinaryNode, all)
			if class != "" {
				if !components.Class(class).Valid() {
					return fmt.Errorf("unknown class %q (one of %s)", class, joinClasses())
				}
				rep.Components = filterViews(rep.Components, func(v components.ComponentView) bool { return string(v.Class) == class })
			}
			if distro != "" {
				d := components.Distro(distro)
				if !d.Valid() {
					return fmt.Errorf("unknown distro %q (one of minimal, developer, managed, full)", distro)
				}
				rep.Components = filterViews(rep.Components, func(v components.ComponentView) bool {
					return v.Distros != nil && v.Distros[d].Compiled()
				})
			}
			if jsonOut {
				return writeComponentsJSON(cmd.OutOrStdout(), rep)
			}
			renderComponentsList(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the catalog report as JSON (the GET /api/components shape)")
	cmd.Flags().BoolVar(&all, "all", false, "Include the org server components (never compiled into this binary)")
	cmd.Flags().StringVar(&class, "class", "", "Only one class: core, feature, adapter, integration or server")
	cmd.Flags().StringVar(&distro, "distro", "", "Only the components a prebuilt distro compiles in: minimal, developer, managed or full")
	return cmd
}

func newComponentsShowCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:           "show <id>",
		SilenceErrors: true,
		Short:         "Show one component: what it adds, what it needs, and where it is going",
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			c, ok := components.Get(id)
			if !ok {
				if a, found := findArtifact(id); found {
					if jsonOut {
						return writeComponentsJSON(cmd.OutOrStdout(), a)
					}
					renderArtifact(cmd.OutOrStdout(), a)
					return nil
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "%s is not a known component. `observer components list --all` lists every id.\n", id)
				return exitErr(componentsUnknownExit)
			}
			compiled := false
			if c.Binary == components.BinaryNode {
				for _, x := range components.Compiled(components.BinaryNode) {
					if x == c.ID {
						compiled = true
					}
				}
			}
			v := components.ViewOf(c, compiled)
			if jsonOut {
				return writeComponentsJSON(cmd.OutOrStdout(), v)
			}
			renderComponent(cmd.OutOrStdout(), v)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the component as JSON")
	return cmd
}

func writeComponentsJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("components: %w", err)
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

func filterViews(vs []components.ComponentView, keep func(components.ComponentView) bool) []components.ComponentView {
	out := []components.ComponentView{}
	for _, v := range vs {
		if keep(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinClasses() string {
	var s []string
	for _, c := range components.Classes() {
		s = append(s, string(c))
	}
	return strings.Join(s, ", ")
}

func findArtifact(id string) (components.ArtifactView, bool) {
	for _, a := range components.BuildReport(components.BinaryNode, false).Artifacts {
		if a.ID == id {
			return a, true
		}
	}
	return components.ArtifactView{}, false
}

// inBuild is the honest one-word build state of a row in THIS binary.
func inBuild(v components.ComponentView) string {
	switch {
	case v.Binary != components.BinaryNode:
		return "server"
	case v.Compiled:
		return "yes"
	default:
		return "no"
	}
}

func renderComponentsList(w io.Writer, rep components.Report) {
	fmt.Fprintf(w, "Catalog v%d. This binary: %s distro, %d components compiled in (digest %s).\n",
		rep.CatalogVersion, rep.Distro, rep.CompiledCount, shortDigest(rep.ComponentsDigest))
	fmt.Fprintln(w, rep.Note)
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tCLASS\tIN BUILD\tLEVELS NOW\tTARGET\tTITLE")
	views := append([]components.ComponentView(nil), rep.Components...)
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].Class != views[j].Class {
			return classRank(views[i].Class) < classRank(views[j].Class)
		}
		return views[i].ID < views[j].ID
	})
	for _, v := range views {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", v.ID, v.Class, inBuild(v), levelList(v.Levels.Implemented),
			targetText(v.Levels), v.Title)
	}
	_ = tw.Flush()
	if len(rep.Artifacts) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Installed outside this binary (Observer does not control their lifecycle):")
		for _, a := range rep.Artifacts {
			fmt.Fprintf(w, "  %s  %s (requires %s)\n", a.ID, a.Title, strings.Join(a.Requires, ", "))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Details: observer components show <id>.")
}

func renderComponent(w io.Writer, v components.ComponentView) {
	fmt.Fprintf(w, "%s: %s\n", v.ID, v.Title)
	fmt.Fprintf(w, "  %s\n\n", v.About)
	fmt.Fprintf(w, "  Class:        %s (binary %s, %s)\n", v.Class, v.Binary, v.Stability)
	fmt.Fprintf(w, "  In this build: %s\n", inBuild(v))
	fmt.Fprintf(w, "  Levels now:   %s\n", levelList(v.Levels.Implemented))
	fmt.Fprintf(w, "  Target:       %s\n", targetText(v.Levels))
	if v.BuildTag != "" {
		fmt.Fprintf(w, "  Build tag:    %s\n", v.BuildTag)
	}
	if len(v.Distros) > 0 {
		var cells []string
		for _, d := range components.Distros() {
			cells = append(cells, fmt.Sprintf("%s=%s", d, v.Distros[d]))
		}
		fmt.Fprintf(w, "  Distros:      %s\n", strings.Join(cells, " "))
	}
	if len(v.Images) > 0 {
		fmt.Fprintf(w, "  Images:       full=%s core=%s\n", v.Images[components.ImageFull], v.Images[components.ImageCore])
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  What it adds:")
	if surfaceEmpty(v.Surface) {
		fmt.Fprintln(w, "    no listener, no outbound host, no file or other tool's config written, no process run")
	}
	for _, l := range v.Surface.Listeners {
		fmt.Fprintf(w, "    listens   %s %s (auth: %s; %s)\n", l.Proto, l.Addr, l.Auth, l.Trigger)
	}
	for _, e := range v.Surface.Egress {
		fmt.Fprintf(w, "    calls     %s: %s (%s; %s)\n", e.Host, e.Purpose, e.Gate, e.Trigger)
	}
	printLines(w, "writes   ", v.Surface.FilesWritten)
	printLines(w, "edits    ", v.Surface.VendorConfigs)
	printLines(w, "OS       ", v.Surface.OSIntegration)
	printLines(w, "runs     ", v.Surface.Processes)
	printLines(w, "secrets  ", v.Surface.Credentials)
	fmt.Fprintln(w)
	printField(w, "Requires", v.Requires)
	printField(w, "Needs code of", v.RequiresCompiled)
	printField(w, "Compiled with", v.Bundles)
	printField(w, "Recommends", v.Recommends)
	printField(w, "Modules", v.DirectModules)
	printField(w, "Packages", v.Packages)
	printField(w, "Code hosted in", v.HostedIn)
	printField(w, "Tables", v.Tables)
	printField(w, "Routes", v.Routes)
	printField(w, "CLI verbs", v.Verbs)
	printField(w, "Config", v.ConfigKeys)
	printField(w, "Ledger", v.Ledger)
	for _, t := range v.Teardown {
		fmt.Fprintf(w, "  Teardown:     %s (%s)\n", t.What, t.Owner)
	}
	for _, m := range v.Migrations {
		fmt.Fprintf(w, "  Migration:    %s (%s) %s\n", m.File, m.Class, m.Note)
	}
	if v.Note != "" {
		fmt.Fprintf(w, "  Note:         %s\n", v.Note)
	}
}

func renderArtifact(w io.Writer, a components.ArtifactView) {
	fmt.Fprintf(w, "%s: %s\n  %s\n\n", a.ID, a.Title, a.About)
	fmt.Fprintf(w, "  Kind:      %s\n  Platforms: %s\n  Source:    %s\n  Signer:    %s\n  Protocol:  %s\n  States:    %s\n  Requires:  %s\n",
		a.Kind, strings.Join(a.Platforms, ", "), a.Source, a.Signer, a.Protocol, strings.Join(a.States, ", "), strings.Join(a.Requires, ", "))
}

func surfaceEmpty(s components.SurfaceView) bool {
	return len(s.Listeners) == 0 && len(s.Egress) == 0 && len(s.FilesWritten) == 0 && len(s.VendorConfigs) == 0 &&
		len(s.OSIntegration) == 0 && len(s.Processes) == 0 && len(s.Credentials) == 0
}

func printLines(w io.Writer, label string, xs []string) {
	for _, x := range xs {
		fmt.Fprintf(w, "    %s %s\n", label, x)
	}
}

func printField(w io.Writer, label string, xs []string) {
	if len(xs) == 0 {
		return
	}
	fmt.Fprintf(w, "  %-13s %s\n", label+":", strings.Join(xs, ", "))
}

func levelList(ls []components.Level) string {
	if len(ls) == 0 {
		return "none"
	}
	s := make([]string, len(ls))
	for i, l := range ls {
		s[i] = string(l)
	}
	return strings.Join(s, ",")
}

func targetText(l components.LevelsView) string {
	s := levelList(l.Target)
	if l.Phase != "" {
		s += " (" + l.Phase + ")"
	}
	return s
}

func classRank(c components.Class) int {
	for i, k := range components.Classes() {
		if c == k {
			return i
		}
	}
	return len(components.Classes())
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
