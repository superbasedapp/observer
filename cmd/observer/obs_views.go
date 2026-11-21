package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/explorerview"
)

// obs_views.go is `observer obs views list|save|delete`, the CLI path to the
// machine's saved explorer views (Plane A W5-4, lane C9; the dashboard's
// /api/obs/explorer/views). It imports no internal/obs package: the store
// calls go through obsViewsCLI (obs_wire_traces.go, stubbed without obs).
// The live tail's CLI is `observer obs traces tail`.
func newObsViewsCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "views",
		Short: "List, save and delete the machine's saved explorer views",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml")
	run := func(c *cobra.Command, op, id string, v explorerview.View) error {
		cfg, database, cleanup, err := loadConfigAndDB(c.Context(), configPath)
		if err != nil {
			return err
		}
		defer cleanup()
		if err := requireAppObs(cfg.Observability.Enabled); err != nil {
			return err
		}
		out, err := obsViewsCLI(c.Context(), database, op, id, v)
		if err != nil {
			return err
		}
		if out == nil {
			fmt.Fprintln(c.OutOrStdout(), "view deleted")
			return nil
		}
		return traceJSON(c.OutOrStdout(), out)
	}
	var id string
	save := &cobra.Command{
		Use:   "save",
		Short: `Save a view from JSON on stdin: {"name", "page", "filters": {...}, "group_by", "columns": [...]}; --id replaces one`,
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			v, err := readViewJSON(c.InOrStdin())
			if err != nil {
				return err
			}
			return run(c, "save", id, v)
		},
	}
	save.Flags().StringVar(&id, "id", "", "replace this view instead of creating one")
	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "Print the saved views as JSON", Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return run(c, "list", "", explorerview.View{}) },
	}, save, &cobra.Command{
		Use: "delete <id>", Short: "Delete a saved view", Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return run(c, "delete", args[0], explorerview.View{}) },
	})
	return cmd
}

// readViewJSON decodes and validates one view (a machine view is private).
func readViewJSON(r io.Reader) (explorerview.View, error) {
	var v explorerview.View
	if err := json.NewDecoder(io.LimitReader(r, 64<<10)).Decode(&v); err != nil {
		return v, fmt.Errorf("views save: the input is not a view: %w", err)
	}
	v = explorerview.Normalize(v)
	if err := explorerview.Validate(v, false); err != nil {
		return v, err
	}
	return v, nil
}
