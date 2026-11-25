package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/applane"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// apps_lane.go is `observer apps lane add|list|remove`: the local app lane
// (hosted AI gateway plan L7, ruling L-172). A lane is an /up/<id> route on
// the daemon's proxy that an app built on this machine points its model
// client at, so its calls are priced exactly, held to the machine's and the
// org's app budgets, limited to the lane's model allow-list and checked by
// AI Apps admission. The lane is off until the user adds one (decision 8 of
// L-174) and loopback only. Enforcement is cooperative: the app holds the
// real provider key and could call the provider directly.
//
// The verbs write [proxy.upstreams] (and [proxy.app_lanes] models) through
// config.EditAppLanes, the writer the dashboard's /api/apps/lanes shares.

func newAppsLaneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lane",
		Short: "Local app lanes: route an app's model calls through this machine (add, list, remove)",
		Long: "A local app lane is http://127.0.0.1:<proxy port>/up/<id>: point an app's model\n" +
			"client there and its calls are priced exactly, held to your app budgets,\n" +
			"limited to the lane's model list and checked by AI Apps admission.\n\n" +
			"  observer apps lane add openai              a lane to api.openai.com\n" +
			"  observer apps lane add my-llm --upstream http://127.0.0.1:11434\n" +
			"  observer apps lane add openai --models gpt-5-nano,gpt-5-mini\n" +
			"  observer apps lane list\n" +
			"  observer apps lane remove openai\n\n" +
			"The app keeps its own provider key, so the lane enforces only the calls\n" +
			"sent through it. A running daemon serves a new lane after its next start.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newAppsLaneAddCmd(), newAppsLaneListCmd(), newAppsLaneRemoveCmd())
	return cmd
}

// appsLaneAddOptions are `apps lane add`'s flags.
type appsLaneAddOptions struct {
	configPath string
	upstream   string
	models     string
}

func newAppsLaneAddCmd() *cobra.Command {
	var o appsLaneAddOptions
	c := &cobra.Command{
		Use:   "add <id>",
		Short: "Add a local app lane and print the base URL to give your model client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lane, err := addAppLane(o.configPath, args[0], o.upstream, splitModels(o.models))
			if err != nil {
				return err
			}
			printAppLaneAdded(cmd.OutOrStdout(), lane)
			return nil
		},
	}
	c.Flags().StringVar(&o.configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	c.Flags().StringVar(&o.upstream, "upstream", "", "Upstream host root without /v1 (default for openai, anthropic, openrouter, gemini)")
	c.Flags().StringVar(&o.models, "models", "", "Comma-separated model allow-list for this lane ('*' globs; empty keeps every model allowed)")
	return c
}

func newAppsLaneListCmd() *cobra.Command {
	var configPath string
	c := &cobra.Command{
		Use:   "list",
		Short: "List the local app lanes and their client base URLs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return err
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
			if err != nil {
				return err
			}
			printAppLanes(cmd.OutOrStdout(), cfg)
			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return c
}

func newAppsLaneRemoveCmd() *cobra.Command {
	var configPath string
	c := &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove a local app lane (and its model list)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := removeAppLane(configPath, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed app lane %q. A running daemon stops serving it after its next start.\n", args[0])
			return nil
		},
	}
	c.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return c
}

// addAppLane writes one lane through the shared rules (applane.ValidateAdd /
// Add.Apply, the dashboard's POST /api/apps/lanes uses the same): upstream
// defaults for a well-known id; models, when given, become the lane's
// allow-list. It returns the lane as listed.
func addAppLane(configPath, id, upstream string, models []string) (applane.Lane, error) {
	add, err := applane.ValidateAdd(id, upstream, models)
	if err != nil {
		return applane.Lane{}, err
	}
	cfg, err := config.EditAppLanes(configPath, func(p *config.ProxyConfig) error {
		return add.Apply(p.Upstreams, p.AgentUpstreams, &p.AppLanes.Models)
	})
	if err != nil {
		return applane.Lane{}, err
	}
	return appLaneOf(cfg, add.ID), nil
}

// removeAppLane deletes one lane and its own model list.
func removeAppLane(configPath, id string) error {
	_, err := config.EditAppLanes(configPath, func(p *config.ProxyConfig) error {
		return applane.Remove(id, p.Upstreams, p.AutoDefaultLane, p.AppLanes.Models)
	})
	return err
}

// appLaneOf returns one lane of cfg as listed.
func appLaneOf(cfg config.Config, id string) applane.Lane {
	for _, l := range applane.List(cfg.Proxy.Upstreams, cfg.Proxy.AppLanes.Models, cfg.Proxy.Port) {
		if l.ID == id {
			return l
		}
	}
	return applane.Lane{ID: id}
}

func splitModels(s string) []string {
	var out []string
	for _, m := range strings.Split(s, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

func printAppLaneAdded(w io.Writer, l applane.Lane) {
	fmt.Fprintf(w, "Added app lane %q -> %s\n\n", l.ID, l.Upstream)
	fmt.Fprintf(w, "Point your %s client at:\n  %s\n\n", l.Kind, l.ClientBaseURL)
	if len(l.Models) > 0 {
		fmt.Fprintf(w, "Models allowed: %s\n", strings.Join(l.Models, ", "))
	}
	fmt.Fprintln(w, "Send X-Superbased-User and X-Superbased-Service (the superbased SDK helpers do)")
	fmt.Fprintln(w, "so your app budgets bind per user and per service.")
	fmt.Fprintln(w, "The app keeps its provider key: the lane enforces only the calls sent through it.")
	fmt.Fprintln(w, "A running daemon serves the lane after its next start (scripts/restart-daemon.sh).")
}

func printAppLanes(w io.Writer, cfg config.Config) {
	lanes := applane.List(cfg.Proxy.Upstreams, cfg.Proxy.AppLanes.Models, cfg.Proxy.Port)
	if len(lanes) == 0 {
		fmt.Fprintln(w, "No app lanes. Add one with: observer apps lane add openai")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tCLIENT BASE URL\tUPSTREAM\tMODELS")
	for _, l := range lanes {
		models := "(any)"
		if len(l.Models) > 0 {
			models = strings.Join(l.Models, ",")
			if l.ModelsFrom == applane.AllLanesKey {
				models += " (from *)"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", l.ID, l.Kind, l.ClientBaseURL, l.Upstream, models)
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\nBudget: %s ([proxy.app_lanes] budget)\n", cfg.Proxy.AppLanes.BudgetMode())
	if applane.CapSpendSource(cfg.Observability.Enabled) == applane.CapSpendProcess {
		fmt.Fprintf(w, "Caps are per daemon process: %s.\n", applane.CapSpendProcessNote)
	}
}
