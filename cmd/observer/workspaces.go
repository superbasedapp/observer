//go:build !sbo_omit_terminals

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// workspaces.go is the cmd-owned CLI over the B9 managed-workspace tree (plan
// §4/§9 U8-adjacent, but cmd-owned): `observer workspaces ls` lists the
// prepared workspaces (id + source + origin from each meta.json), and
// `observer workspaces rm <id>` removes one. It reads/removes the SAME
// <observerDir>/workspaces/<id>/ dirs the sandbox runtime mints and B7 reads —
// no DB, just the managed tree + meta.json. Removal is guarded through
// workspace.ValidateManagedWorkspace so it can only ever delete strictly under
// the daemon's own managed root.

// defaultWorkspacesDir resolves the managed-workspaces root: the explicit
// [terminal.sandbox].workspaces_dir when set, else <observerDir>/workspaces.
// The one owner of that default, shared by the sandbox runtime and the
// `observer workspaces` CLI (no symlink resolution here; callers canonicalize
// when they need to). It lives here, not in terminal_sandbox.go, so a build
// without terminals.sandbox keeps the same default.
func defaultWorkspacesDir(cfg config.TerminalSandboxConfig, observerDir string) string {
	if d := strings.TrimSpace(cfg.WorkspacesDir); d != "" {
		return d
	}
	return filepath.Join(observerDir, "workspaces")
}

// newWorkspacesCmd builds the `observer workspaces` command group.
func newWorkspacesCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "workspaces",
		Short: "List and remove B9 sandboxed-terminal managed workspaces",
		Long: "Manage the prepared workspace copies B9 sandboxed terminals create\n" +
			"under <observer dir>/workspaces (full repo clones, not small).\n" +
			"Each workspace is <root>/<id>/<repoLeaf> with a sibling meta.json.",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml (default ~/.observer/config.toml)")

	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List managed sandbox workspaces",
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := workspacesRoot(configPath)
			if err != nil {
				return err
			}
			return listWorkspaces(cmd, root)
		},
	}

	rmCmd := &cobra.Command{
		Use:   "rm <id>",
		Short: "Remove a managed sandbox workspace by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := workspacesRoot(configPath)
			if err != nil {
				return err
			}
			return removeWorkspace(cmd, root, args[0])
		},
	}

	cmd.AddCommand(lsCmd, rmCmd)
	return cmd
}

// workspacesRoot resolves the managed-workspaces directory from config, the
// same default the sandbox runtime uses.
func workspacesRoot(configPath string) (string, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return "", fmt.Errorf("workspaces: load config: %w", err)
	}
	return defaultWorkspacesDir(cfg.Terminal.Sandbox, filepath.Dir(cfg.Observer.DBPath)), nil
}

// listWorkspaces prints one row per <root>/<id> directory that carries a
// meta.json. An absent root (nothing prepared yet) is not an error.
func listWorkspaces(cmd *cobra.Command, root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(cmd.OutOrStdout(), "no managed workspaces")
			return nil
		}
		return fmt.Errorf("workspaces: read %s: %w", root, err)
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)

	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSOURCE\tBRANCH\tCREATED\tORIGIN")
	shown := 0
	var kept []string
	for _, id := range ids {
		meta, ok := readWorkspaceMeta(filepath.Join(root, id))
		if !ok {
			continue
		}
		branch := meta.Branch
		if branch == "" {
			branch = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			id, meta.Source, branch, meta.CreatedAt.Format("2006-01-02 15:04"), meta.Origin)
		shown++
		if meta.Kept != "" {
			kept = append(kept, id+" was kept: "+meta.Kept)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	// Why the end of a worktree run kept a workspace (meta.json's kept).
	for _, k := range kept {
		fmt.Fprintln(cmd.OutOrStdout(), k)
	}
	// A clone-remote run's returned commits wait in its return repository
	// until fetched; the daemon removes it once its run ended with nothing
	// returned, or past the retention bound (lane LEFT-SBX).
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), workspace.ReturnRepoSuffix)
		if !ok || !e.IsDir() {
			continue
		}
		repo := filepath.Join(root, e.Name())
		fmt.Fprintf(cmd.OutOrStdout(), "%s returned its commits into %s; bring them into your checkout with: %s\n",
			id, repo, workspace.ReturnFetchCommand(repo, workspace.ReturnRefPrefix+id))
	}
	if shown == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no managed workspaces")
	}
	return nil
}

// readWorkspaceMeta reads <dir>/meta.json into a workspace.Meta. ok=false when
// the file is absent or unparseable (a partially-created or foreign dir).
func readWorkspaceMeta(dir string) (workspace.Meta, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return workspace.Meta{}, false
	}
	var m workspace.Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return workspace.Meta{}, false
	}
	return m, true
}

// removeWorkspace deletes <root>/<id>, guarded so it can only ever remove a
// directory strictly under the managed root. The id must be a single clean path
// segment; the resolved target is re-checked with ValidateManagedWorkspace
// before any deletion, so a "../" or absolute id can never escape the tree.
func removeWorkspace(cmd *cobra.Command, root, id string) error {
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
		return fmt.Errorf("workspaces: invalid workspace id %q", id)
	}
	target := filepath.Join(root, id)
	if err := workspace.ValidateManagedWorkspace(target, root); err != nil {
		return fmt.Errorf("workspaces: refusing to remove %q: %w", target, err)
	}
	if _, err := os.Stat(target); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("workspaces: no workspace with id %q", id)
		}
		return fmt.Errorf("workspaces: stat %s: %w", target, err)
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("workspaces: remove %s: %w", target, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "removed workspace %s\n", id)
	return nil
}
