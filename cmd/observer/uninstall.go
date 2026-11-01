package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// newUninstallCmd implements `observer uninstall` — reverse of `init`.
// Removes hook entries and the MCP server registration from each selected
// AI coding tool's config, preserving any user-authored entries. Checksum
// tracking from `init` is consulted to refuse changes to files that have
// drifted (unless --force is given). Optionally --purge also deletes
// ~/.observer/ (DB + config + checksums registry).
func newUninstallCmd() *cobra.Command {
	var (
		flagClaudeCode bool
		flagCodex      bool
		flagCursor     bool
		flagCline      bool
		flagAll        bool
		flagDryRun     bool
		flagForce      bool
		flagSkipHooks  bool
		flagSkipMCP    bool
		flagPurge      bool

		flagSkipProxyRoute bool
	)
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove observer hooks, MCP server and proxy route from AI coding tools",
		Long: `Remove observer's hook entries, MCP server registration and proxy route
from each selected AI coding tool's config. Only entries whose command matches
the observer binary are removed; user-authored hooks are preserved, and so is
an entry in observer's "<bin> hook <tool> <event>" shape that runs another
program (reported as kept, with or without --force). The proxy
route (Claude Code env.ANTHROPIC_BASE_URL, the Codex openai-observer provider)
is removed only when it points at this install's proxy port, and Codex's
previous model_provider is put back. Skip it with --skip-proxy-route.

By default the tool data dir (~/.observer/) is kept so a later re-install
retains history. Pass --purge to delete it. --all and --purge also remove
this Observer home's OS keychain entries (Windows Credential Manager, macOS
Keychain, the Secret Service); another Observer home's entries are kept.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			binary, err := absoluteBinaryPath()
			if err != nil {
				return err
			}
			// clientwire.Remover is the ONE removal seam: the dashboard's
			// Connected tools Remove step drives the same registries
			// through it, so the CLI and the dashboard cannot disagree on
			// what an uninstall removes.
			rem, err := clientwire.NewRemover(clientwire.RemoveOptions{
				BinaryPath: binary,
				ProxyPort:  uninstallProxyPort(),
				DryRun:     flagDryRun,
				Force:      flagForce,
			})
			if err != nil {
				return err
			}

			tools := selectTools(flagAll, flagClaudeCode, flagCodex, flagCursor, flagCline, rem.Installed())
			if len(tools) == 0 && !flagPurge && !flagAll {
				fmt.Fprintln(cmd.OutOrStdout(), noToolsLine("remove Observer from", flagAll,
					"--claude-code / --cursor / --codex / --all / --purge"))
				return nil
			}

			out := cmd.OutOrStdout()
			anyError := false
			for _, t := range tools {
				var parts []clientwire.Part
				if !flagSkipHooks {
					parts = append(parts, clientwire.PartHooks)
				}
				if !flagSkipMCP {
					parts = append(parts, clientwire.PartMCP)
				}
				m := rem.Remove(t, parts...)
				if m.Hooks != nil {
					printHookUnregisterResult(out, t, *m.Hooks, flagDryRun)
				}
				if m.MCP != nil {
					printMCPUnregisterResult(out, t, *m.MCP, flagDryRun)
				}
				if m.Failed() {
					anyError = true
				}
			}

			if !flagSkipProxyRoute {
				if rerr := rem.RouteRegistrarErr(); rerr != nil {
					fmt.Fprintf(out, "%-12s proxy ✗ %v\n", "observer", rerr)
					anyError = true
				} else {
					for _, t := range tools {
						if m := rem.Remove(t, clientwire.PartRoute); m.Route != nil && printProxyRouteRemoval(out, t, *m.Route, flagDryRun) {
							anyError = true
						}
					}
				}
			}

			// T-537: remove the opt-in OTLP exporter wiring too (only
			// Observer's own keys; a user's exporter setting is kept).
			for _, t := range tools {
				if m := rem.Remove(t, clientwire.PartTelemetry); m.Telemetry != nil && (m.Telemetry.Changed || m.Telemetry.Error != nil) {
					printTelemetryResult(out, *m.Telemetry)
					if m.Telemetry.Error != nil {
						anyError = true
					}
				}
			}

			if flagPurge {
				if err := purgeDataDir(out, flagDryRun); err != nil {
					fmt.Fprintf(out, "%-12s data ✗ %v\n", "observer", err)
					anyError = true
				}
			}

			// D2: --all (and --purge) also removes this home's OS keychain
			// entries; another Observer home's are untouched.
			if flagAll || flagPurge {
				if removeKeystoreEntries(out, flagDryRun) {
					anyError = true
				}
			}

			if anyError {
				return fmt.Errorf("uninstall completed with errors; see above")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&flagClaudeCode, "claude-code", false, "Unregister from Claude Code")
	cmd.Flags().BoolVar(&flagCodex, "codex", false, "Unregister from OpenAI Codex")
	cmd.Flags().BoolVar(&flagCursor, "cursor", false, "Unregister from Cursor")
	cmd.Flags().BoolVar(&flagCline, "cline", false, "Unregister from Cline / Roo Code")
	cmd.Flags().BoolVar(&flagAll, "all", false, "Select every detected tool")
	cmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "Print intended changes without writing any files")
	cmd.Flags().BoolVar(&flagForce, "force", false, "Bypass checksum mismatch; remove observer entries even if the config file was modified since install")
	cmd.Flags().BoolVar(&flagSkipHooks, "skip-hooks", false, "Only unregister MCP, leave hooks alone")
	cmd.Flags().BoolVar(&flagSkipMCP, "skip-mcp", false, "Only unregister hooks, leave MCP alone")
	cmd.Flags().BoolVar(&flagSkipProxyRoute, "skip-proxy-route", false, "Leave this install's proxy route (Claude Code ANTHROPIC_BASE_URL, Codex provider) in place")
	cmd.Flags().BoolVar(&flagPurge, "purge", false, "Also delete ~/.observer/ (observer.db, config.toml, hook_checksums.json)")
	return cmd
}

func printHookUnregisterResult(out io.Writer, tool string, res hook.UnregistrationResult, dryRun bool) {
	if res.Error != nil {
		fmt.Fprintf(out, "%-12s hook ✗ %v\n", tool, res.Error)
		return
	}
	// FU-203: an entry in Observer's command shape that runs another binary
	// is kept, and said so whatever else the result reports.
	// FU-213: a removal spanning several files names each one.
	switch {
	case len(res.HooksKeptForeignIn) > 0:
		for _, k := range res.HooksKeptForeignIn {
			fmt.Fprintf(out, "%-12s hook kept %v in %s (%s)\n", tool, k.Events, k.Path, hook.ForeignBinaryReason)
		}
	case len(res.HooksKeptForeign) > 0:
		fmt.Fprintf(out, "%-12s hook kept %v in %s (%s)\n", tool, res.HooksKeptForeign, res.ConfigPath, hook.ForeignBinaryReason)
	}
	// FU-212: a whole file Observer would have deleted that is not
	// Observer's is kept, and said so.
	for _, p := range res.FilesKeptForeign {
		fmt.Fprintf(out, "%-12s hook kept %s (%s)\n", tool, p, hook.ForeignFileReason)
	}
	if res.Skipped {
		fmt.Fprintf(out, "%-12s hook no-op (no observer entries in %s)\n", tool, res.ConfigPath)
		return
	}
	verb := "removed"
	if dryRun {
		verb = "would remove"
	}
	if len(res.HooksRemoved) > 0 {
		fmt.Fprintf(out, "%-12s hook %s %d hook(s) from %s: %v\n",
			tool, verb, len(res.HooksRemoved), res.ConfigPath, res.HooksRemoved)
	} else {
		fmt.Fprintf(out, "%-12s hook no observer entries found in %s\n", tool, res.ConfigPath)
	}
	if len(res.HooksKept) > 0 {
		fmt.Fprintf(out, "%-12s hook preserved user entries in: %v\n", tool, res.HooksKept)
	}
	if len(res.TrustRemoved) > 0 {
		fmt.Fprintf(out, "%-12s hook removed Observer's trust records for: %v\n", tool, res.TrustRemoved)
	}
	if res.TrustNote != "" {
		fmt.Fprintf(out, "%-12s hook note: %s\n", tool, res.TrustNote)
	}
}

func printMCPUnregisterResult(out io.Writer, tool string, res mcpregister.UnregistrationResult, dryRun bool) {
	if res.Error != nil {
		fmt.Fprintf(out, "%-12s mcp  ✗ %v\n", tool, res.Error)
		return
	}
	if res.Skipped && res.SkipReason != "" {
		fmt.Fprintf(out, "%-12s mcp  no-op (%s)\n", tool, res.SkipReason)
		return
	}
	if res.Skipped {
		fmt.Fprintf(out, "%-12s mcp  no-op (no observer entry in %s)\n", tool, res.ConfigPath)
		return
	}
	verb := "removed"
	if dryRun {
		verb = "would remove"
	}
	if res.Removed {
		fmt.Fprintf(out, "%-12s mcp  %s observer entry from %s\n", tool, verb, res.ConfigPath)
	}
}

// printProxyRouteRemoval prints one tool's proxy-route removal outcome and
// reports whether it failed (the caller folds that into the exit status).
// The route undo itself is clientwire's (RouteRemover), the seam the
// dashboard's Compression-page undo and Connected tools Remove step share.
func printProxyRouteRemoval(out io.Writer, tool string, res proxyroute.RegistrationResult, dryRun bool) (failed bool) {
	switch {
	case res.Error != nil:
		fmt.Fprintf(out, "%-12s proxy ✗ %v\n", tool, res.Error)
		return true
	case res.Added && dryRun:
		fmt.Fprintf(out, "%-12s proxy would remove proxy route %s from %s\n", tool, res.BaseURL, res.ConfigPath)
	case res.Added:
		fmt.Fprintf(out, "%-12s proxy removed proxy route %s from %s\n", tool, res.BaseURL, res.ConfigPath)
	case res.BaseURL != "":
		fmt.Fprintf(out, "%-12s proxy kept %s in %s (not this install's route)\n", tool, res.BaseURL, res.ConfigPath)
	default:
		fmt.Fprintf(out, "%-12s proxy no-op (no proxy route in %s)\n", tool, res.ConfigPath)
	}
	return false
}

// uninstallProxyPort is the proxy port whose route counts as this install's:
// the configured [proxy] port, or the default when the config cannot be read.
func uninstallProxyPort() int {
	if cfg, err := config.Load(config.LoadOptions{}); err == nil && cfg.Proxy.Port > 0 {
		return cfg.Proxy.Port
	}
	return 8820
}

// purgeDataDir removes ~/.observer/ after --purge. Best-effort: missing
// dir is not an error; residual lock-holding processes surface as errors.
//
// FU-212 keeps this one os.RemoveAll on purpose: ~/.observer is Observer's
// own home (its database, config, checksums and keys, every name in it
// Observer's), never a tool's directory a user shares with Observer, and
// --purge is the operator's explicit request to delete exactly it (the
// flag's help names it). Every other uninstall path deletes only files that
// read as Observer's and removes a directory only once it is empty.
func purgeDataDir(out io.Writer, dryRun bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home: %w", err)
	}
	dir := filepath.Join(home, ".observer")
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(out, "%-12s data no-op (%s not found)\n", "observer", dir)
			return nil
		}
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	verb := "deleted"
	if dryRun {
		verb = "would delete"
	}
	fmt.Fprintf(out, "%-12s data %s %s\n", "observer", verb, dir)
	if dryRun {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove %s: %w", dir, err)
	}
	return nil
}
