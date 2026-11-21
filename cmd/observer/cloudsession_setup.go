package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
)

// cloudsession_setup.go is `observer cloud-session setup` (lane CA-C2): what
// the committed setup script runs after installing observer when init was
// given --mcp. It builds, during the vendor's setup step, what the committed
// MCP server reads, so it lands in the vendor snapshot instead of being built
// on the session's first MCP call: the database (schema migrated) and, only
// with --codeintel, the repository's code-intelligence index. Code
// intelligence stays off otherwise (D-307). It makes no network call.

// sandboxMCPConfigBody is the config the MCP server reads with --codeintel:
// code intelligence on, every other setting the default (partial merge).
const sandboxMCPConfigBody = "# Written by `observer cloud-session setup --codeintel` (Rail S, lane CA-C2).\n" +
	"# Read only by the repository's MCP server entry; hooks and flush keep the defaults.\n" +
	"[codeintel]\nenabled = true\n"

func newCloudSessionSetupCmd() *cobra.Command {
	var (
		configPath, repo string
		mcp, codeIntel   bool
	)
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Build the database (and optionally the code index) the committed MCP server reads, during the vendor's setup step",
		Long: "Run by the setup script `observer cloud-session init --mcp` commits, after it\n" +
			"installs observer. It opens the local database (migrating the schema) and,\n" +
			"with --codeintel, indexes the repository for code intelligence and writes the\n" +
			"small config the MCP server reads (" + cloudsession.SandboxMCPConfig + " under\n" +
			"the home directory). Nothing leaves the machine.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCloudSessionSetup(cmd.Context(), cmd.OutOrStdout(), configPath, repo, mcp, codeIntel)
		},
	}
	cmd.Flags().BoolVar(&mcp, "mcp", false, "build what the MCP server reads (the database)")
	cmd.Flags().BoolVar(&codeIntel, "codeintel", false, "also index the repository for code intelligence and turn it on for the MCP server (needs --mcp)")
	cmd.Flags().StringVar(&repo, "repo", "", "repository to index (default: the git repository of the working directory)")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml")
	return cmd
}

// runCloudSessionSetup is the setup step.
func runCloudSessionSetup(ctx context.Context, out io.Writer, configPath, repo string, mcp, codeIntel bool) error {
	if codeIntel && !mcp {
		return errors.New("--codeintel builds the index the MCP server reads; it needs --mcp")
	}
	if !mcp {
		fmt.Fprintln(out, "cloud-session setup: nothing to set up (pass --mcp)")
		return nil
	}
	cfg, _, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return err
	}
	cleanup()
	fmt.Fprintf(out, "cloud-session setup: database ready at %s\n", cfg.Observer.DBPath)
	if !codeIntel {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("home directory: %w", err)
	}
	mcpCfg := filepath.Join(home, filepath.FromSlash(cloudsession.SandboxMCPConfig))
	if err := os.MkdirAll(filepath.Dir(mcpCfg), 0o700); err != nil {
		return fmt.Errorf("mcp config dir: %w", err)
	}
	if err := os.WriteFile(mcpCfg, []byte(sandboxMCPConfigBody), 0o600); err != nil {
		return fmt.Errorf("write the MCP config: %w", err)
	}
	root, err := resolveRepo(repo)
	if err != nil {
		return err
	}
	// The ordinary `observer index`, so a build without the codeintel
	// component answers "not in this build" exactly as it does there.
	idx := newIndexCmd()
	idx.SetArgs([]string{root, "--config", mcpCfg})
	idx.SetOut(out)
	idx.SetErr(out)
	idx.SilenceUsage = true
	if err := idx.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(out, "cloud-session setup: WARNING: indexing %s failed (%v); the MCP symbol tools answer without an index\n", root, err)
		return nil
	}
	fmt.Fprintf(out, "cloud-session setup: code intelligence index built for %s\n", root)
	return nil
}
