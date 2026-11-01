package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// backfill_loc_rekey.go is `observer backfill --loc-rekey` (SHR-8, lane
// SHR-FOLLOWUPS): the opt-in pass that moves file_changes rows of edits
// made inside a linked worktree from the project-root key an earlier build
// stored to the checkout-relative key (store.RekeyWorktreeFileChanges), so
// they join their commits on the Projects page. New edits are keyed that
// way at ingest; this pass is only for rows written before the upgrade.
// DRY RUN unless --apply; --loc-since narrows it; one transaction per row;
// nothing is deleted; no loc.Version bump.
//
// It rides the backfill command through one call in backfill.go
// (addLOCRekeyFlag), wrapping its RunE: the pass runs first, then the
// command's own passes run only when another dimension flag was given.

// locRekeyCompanionFlags are the flags the pass reads besides its own;
// given with --loc-rekey alone they ask for no other pass.
var locRekeyCompanionFlags = map[string]bool{"loc-rekey": true, "apply": true, "loc-since": true, "json": true, "config": true}

// addLOCRekeyFlag registers --loc-rekey on the backfill command and wraps
// its RunE.
func addLOCRekeyFlag(cmd *cobra.Command) {
	var rekey bool
	cmd.Flags().BoolVar(&rekey, "loc-rekey", false, "Re-key the lines-of-code rows of edits made inside a linked git worktree (in-tree or out-of-tree) from the main repository's root to the worktree's own top level, so each joins the commit that carried it on the Projects page. Edits outside a linked worktree are never touched, and new edits are keyed this way at ingest; this pass is for rows written before the upgrade, and needs the worktree still on disk. Per-table counts (file_changes): rekeyed, already keyed, clashes (both keys held; nothing is deleted) and not yet counted (run --loc). Honours --loc-since. One transaction per row; no classifier-version bump. DRY-RUN BY DEFAULT; pass --apply to write. NOT part of --all. Idempotent.")
	inner := cmd.RunE
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if !rekey {
			return inner(c, args)
		}
		if f := c.Flags().Lookup("dry-run"); f != nil && f.Changed {
			return errors.New("--loc-rekey is a dry run unless --apply; it does not take --dry-run")
		}
		if err := runLOCRekey(c); err != nil {
			return err
		}
		other := false
		c.Flags().Visit(func(f *pflag.Flag) { other = other || !locRekeyCompanionFlags[f.Name] })
		if !other {
			return nil
		}
		return inner(c, args)
	}
}

// runLOCRekey runs the pass and prints its report.
func runLOCRekey(c *cobra.Command) error {
	flag := func(name string) string {
		if f := c.Flags().Lookup(name); f != nil {
			return f.Value.String()
		}
		return ""
	}
	since, err := parseLOCSince(flag("loc-since"))
	if err != nil {
		return err
	}
	apply := flag("apply") == "true"
	_, database, cleanup, err := loadConfigAndDB(c.Context(), flag("config"))
	if err != nil {
		return err
	}
	defer cleanup()
	res, err := store.New(database).RekeyWorktreeFileChanges(c.Context(), store.RekeyLOCOptions{Since: since, Apply: apply})
	if err != nil {
		return fmt.Errorf("backfill --loc-rekey: %w", err)
	}
	out := c.OutOrStdout()
	if flag("json") == "true" {
		body, _ := json.MarshalIndent(struct {
			LOCRekey store.RekeyLOCResult `json:"loc_rekey"`
			Apply    bool                 `json:"apply"`
		}{res, apply}, "", "  ")
		fmt.Fprintln(out, string(body))
		return nil
	}
	mode := "dry run (pass --apply to write)"
	if apply {
		mode = "applied"
	}
	fmt.Fprintf(out, "loc-rekey (%s): %d edit actions read, %d sessions with edits inside a linked worktree\n", mode, res.ActionsScanned, res.Sessions)
	for _, table := range []string{"file_changes"} {
		t := res.Tables[table]
		fmt.Fprintf(out, "  %s: %d rekeyed, %d already keyed, %d clashes (both keys kept), %d not yet counted (run --loc)\n",
			table, t.Rekeyed, t.AlreadyKeyed, t.Clashes, t.NotCounted)
	}
	return nil
}
