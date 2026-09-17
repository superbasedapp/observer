package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/browserhost/hostfiles"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard/compile"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newInitCmd implements `observer init` — the explicit one-shot
// registration entry point for every supported AI coding tool. A
// single `init` writes settings.json/hooks.json hook entries AND
// mcp.json/.claude.json/config.toml MCP server entries AND proxy
// routing (codex config.toml `base_url`; claude-code settings.json
// `env.ANTHROPIC_BASE_URL`) for every selected tool. Batch mode
// delegates the whole flow to wireAIClients — the same registration
// step `observer enroll` runs (D18 first brought the old inline loop
// up to wireAIClients parity; the dedup then collapsed it into the
// call). newInitCmd keeps only what wireAIClients deliberately
// doesn't own: the interactive checklist, the hermes install path,
// `--uninstall` (hermes-only), the hermes-only flag-suppression
// guard, and the "no tools selected" message.
//
// With ZERO flags on a real terminal, init runs the interactive
// checklist instead (P6.10; see init_interactive.go) — one consent
// per write, the dashboard wizard's semantics.
//
// Default scope: hooks + MCP + proxy-route are all ON. Opt out
// per-side with `--skip-hooks`, `--skip-mcp`, `--skip-proxy-route`.
// MCP-supported tools are claude-code, cursor, codex (cline is
// hook-and-watcher only; windows variants are hook-only). See
// [mcpSupported] for the whitelist.
//
// Init vs start (frequently confused):
//   - `observer init` writes per-client config and is the only path
//     to MCP registration / codex proxy routing.
//   - `observer start` runs the daemon AND idempotently
//     auto-registers HOOKS (only) for any detected AI tool. MCP and
//     codex proxy-route are deliberately NOT auto-wired on start —
//     they treat per-client config as explicit user opt-in.
func newInitCmd() *cobra.Command {
	var (
		flagClaudeCode       bool
		flagCodex            bool
		flagCursor           bool
		flagCline            bool
		flagHermes           bool
		flagStatusline       bool
		flagUninstall        bool
		flagAll              bool
		flagDryRun           bool
		flagForce            bool
		flagSkipHooks        bool
		flagSkipMCP          bool
		flagSkipProxy        bool
		flagSkipExtension    bool
		flagBrowser          bool
		flagBrowserExtID     string
		flagGuard            bool
		flagSkipGuardDialect bool
		flagProxyPort        int
		flagConfigPath       string
		flagWinClaudeHome    string
		flagWinCodexHome     string
		flagWinCursorHome    string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Register hooks + MCP server with AI coding tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			binary, err := absoluteBinaryPath()
			if err != nil {
				return err
			}
			resolvedConfig, err := resolveInitConfigPath(flagConfigPath)
			if err != nil {
				return err
			}
			// Validate the supplied extension id(s) up front (before any
			// write) so an obviously-wrong value fails loud instead of baking
			// a manifest the browser rejects. The flag accepts a comma-
			// separated list (an unpacked extension's id is path-derived, so
			// the same extension under WSL Chrome vs Windows Chrome needs two
			// ids in one manifest); EVERY element is validated and the whole
			// flag is rejected naming the offending element. The value is
			// re-normalised to a trimmed, comma-joined form so downstream
			// splitting is clean. Empty = "not supplied" (placeholder /
			// prompt); a single id normalises to itself (byte-identical to the
			// pre-multi-id behaviour). A value that WAS supplied but
			// tokenizes to zero ids (e.g. ", ,") is rejected rather than
			// silently normalised to "" — see resolveBrowserExtensionIDFlag.
			normalizedExtID, err := resolveBrowserExtensionIDFlag(cmd.Flags().Changed("browser-extension-id"), flagBrowserExtID)
			if err != nil {
				return err
			}
			flagBrowserExtID = normalizedExtID
			// `observer init --browser` (optionally with --browser-extension-id)
			// installs ONLY the browser rail — the native-messaging host + the
			// per-browser manifest — leaving AI-tool configs untouched. Mirrors
			// the --hermes "only that rail" guard. A bare --browser-extension-id
			// implies the same browser-only intent.
			browserRequested := flagBrowser || flagBrowserExtID != ""
			anyClassicFlagEarly := flagClaudeCode || flagCodex || flagCursor || flagCline
			if browserRequested && !anyClassicFlagEarly && !flagAll && !flagHermes {
				winHomes, winDistro, newReg := productionWindowsBrowserInputs()
				return runBrowserOnlyInit(cmd.OutOrStdout(), cmd.InOrStdin(), browserOnlyOptions{
					BinaryPath:          binary,
					ConfigPath:          resolvedConfig,
					ExtensionID:         flagBrowserExtID,
					DryRun:              flagDryRun,
					Interactive:         stdinIsTerminal() && stdoutIsTerminal(),
					WindowsBrowserHomes: winHomes,
					WSLDistro:           winDistro,
					NewWindowsRegistry:  newReg,
				})
			}
			// P6.10: zero flags + a human on both ends of the pipe →
			// the interactive checklist (one consent per write, the
			// wizard's semantics). Any flag, or any redirection, keeps
			// the classic batch behaviour for scripts and muscle
			// memory.
			if cmd.Flags().NFlag() == 0 && stdinIsTerminal() && stdoutIsTerminal() {
				winHomes, winDistro, newReg := productionWindowsBrowserInputs()
				return runInteractiveInit(cmd.OutOrStdout(), cmd.InOrStdin(), interactiveInitOptions{
					BinaryPath:          binary,
					ConfigPath:          resolvedConfig,
					ProxyPort:           flagProxyPort,
					WindowsBrowserHomes: winHomes,
					WSLDistro:           winDistro,
					NewWindowsRegistry:  newReg,
				})
			}
			out := cmd.OutOrStdout()
			// Hermes lives on a separate install path (~/.hermes/plugins/) so
			// it isn't enumerated by hook.Registry / mcp.Registrar today;
			// handled out-of-band below. --all opts it in too.
			runHermes := flagHermes || flagAll
			// When the operator passes ONLY --hermes (no other per-tool flag,
			// no --all), skip the classic wire entirely — they explicitly
			// asked for hermes, not for "init everything detected plus
			// hermes". Without this guard, `observer init --hermes`
			// re-registers every other detected tool's hooks/MCP too, which
			// has bitten the operator at least once during local smoke
			// testing.
			anyClassicFlag := flagClaudeCode || flagCodex || flagCursor || flagCline
			hermesOnly := flagHermes && !anyClassicFlag && !flagAll
			if !hermesOnly {
				winHomes, winDistro, newReg := productionWindowsBrowserInputs()
				lines, claudeHint, codexHint, codexHooksHint, err := wireAIClients(WireAIClientsOptions{
					ConfigPath:          resolvedConfig,
					ProxyPort:           flagProxyPort,
					DryRun:              flagDryRun,
					Force:               flagForce,
					SkipHooks:           flagSkipHooks,
					SkipMCP:             flagSkipMCP,
					SkipProxy:           flagSkipProxy,
					SkipExtension:       flagSkipExtension,
					BrowserExtensionID:  flagBrowserExtID,
					OnlyClaudeCode:      flagClaudeCode,
					OnlyCodex:           flagCodex,
					OnlyCursor:          flagCursor,
					OnlyCline:           flagCline,
					All:                 flagAll,
					WindowsClaudeHome:   flagWinClaudeHome,
					WindowsCodexHome:    flagWinCodexHome,
					WindowsCursorHome:   flagWinCursorHome,
					WindowsBrowserHomes: winHomes,
					WSLDistro:           winDistro,
					NewWindowsRegistry:  newReg,
				})
				if err != nil {
					return err
				}
				// nil lines ⇔ wireAIClients selected no tools (it returns
				// silently); the CLI keeps its explicit message. A single
				// empty-string line means tools WERE selected but every
				// registration was skipped or silent — print nothing,
				// matching the pre-dedup inline loop.
				if lines == nil && !runHermes {
					fmt.Fprintln(out, "no tools selected and none auto-detected — pass --claude-code / --cursor / --codex / --hermes / --all")
					return nil
				}
				if len(lines) != 1 || lines[0] != "" {
					for _, line := range lines {
						fmt.Fprintln(out, line)
					}
				}
				// Hooks + MCP capture the JSONL adapter side and on-demand
				// queries, but the proxy stream — the only accurate token
				// source per spec §24 — only engages when the AI tool routes
				// API traffic through it. The hints fire only when the
				// operator explicitly skipped the route write (D18: the
				// write now happens by default — a redundant "next: export
				// ANTHROPIC_BASE_URL" right after writing it would mislead).
				if claudeHint != "" {
					fmt.Fprint(out, claudeHint)
				}
				if codexHint != "" {
					fmt.Fprintln(out)
					fmt.Fprint(out, codexHint)
				}
				if codexHooksHint {
					printCodexTrustHint(out)
				}
			}
			// Guard native-dialect compilation (spec §13.2): init is
			// the default-on application point — selected tools with an
			// implemented dialect get the effective policy compiled
			// into their native permission rules. Opt out per-run with
			// --skip-guard-dialect / --guard=false, or persistently via
			// [guard.dialects] compile=false. The selection is
			// recomputed (detection-only) because wireAIClients owns it
			// internally now; hermes-only runs skip — the operator
			// asked for hermes, not "compile every detected tool".
			// The interactive path returns before this point and does
			// not compile dialects (P6.10 integration is a recorded
			// follow-up; `observer guard compile` covers it).
			if flagGuard && !flagSkipGuardDialect && !flagUninstall && !hermesOnly {
				initGuardDialects(cmd.Context(), out,
					initSelectedTools(binary, resolvedConfig, flagAll, flagClaudeCode, flagCodex, flagCursor, flagCline),
					resolvedConfig, flagDryRun)
			}

			if runHermes {
				if err := runHermesInit(out, hook.HermesOptions{
					BinaryPath: binary,
					ConfigPath: resolvedConfig,
					DryRun:     flagDryRun,
				}, flagSkipHooks, flagSkipMCP, flagUninstall); err != nil {
					return err
				}
			}
			// Statusline registration (docs/plans/observer-statusline-plan-2026-07-30.md
			// §5.1): strictly opt-in via --statusline — never implied by --all,
			// never touched by `observer start`. Only fires when claude-code
			// resolves into the SAME selected/detected set the rest of init
			// already computed (reusing initSelectedTools, the one place that
			// selection logic lives) so `--codex --statusline` alone (claude-code
			// neither requested nor detected) is correctly a no-op.
			if flagStatusline {
				selected := initSelectedTools(binary, resolvedConfig, flagAll, flagClaudeCode, flagCodex, flagCursor, flagCline)
				if err := runStatuslineInit(out, hook.Options{
					BinaryPath:        binary,
					ConfigPath:        resolvedConfig,
					DryRun:            flagDryRun,
					Force:             flagForce,
					WindowsClaudeHome: flagWinClaudeHome,
				}, selected, flagUninstall); err != nil {
					return err
				}
			}
			// Elevated-ETW-capturer setup surface (process-obs plan §W4).
			// Writes nothing — it probes for the Scheduled Task and, when
			// absent, emits the one elevated command observer is structurally
			// unable to run itself. Silent unless [observer.process.etw] is
			// enabled AND this host has schtasks.exe.
			if !flagUninstall {
				initProcessBridgeTaskStep(cmd.Context(), out, resolvedConfig)
				printCommunityFooter(out)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&flagClaudeCode, "claude-code", false, "Register hooks + MCP for Claude Code")
	cmd.Flags().BoolVar(&flagCodex, "codex", false, "Register MCP + hooks for OpenAI Codex (sets [features].hooks=true; per-hook trust approval still required via codex /hooks one-time)")
	cmd.Flags().BoolVar(&flagCursor, "cursor", false, "Register hooks + MCP for Cursor")
	cmd.Flags().BoolVar(&flagCline, "cline", false, "Register for Cline / Roo Code (no hooks; captured via file watcher)")
	cmd.Flags().BoolVar(&flagHermes, "hermes", false, "Register Python plugin + MCP entry for Nous Research's Hermes Agent (~/.hermes/plugins/superbased-observer/ + ~/.hermes/config.yaml)")
	cmd.Flags().BoolVar(&flagStatusline, "statusline", false, "Register the observer statusline (writes Claude Code settings.json's top-level \"statusLine\" key to run `observer statusline`) — a one-line cost/session status; opt-in only, never implied by --all and never registered by `observer start`")
	cmd.Flags().BoolVar(&flagUninstall, "uninstall", false, "Uninstall instead of install — honoured for --hermes and --statusline")
	cmd.Flags().BoolVar(&flagAll, "all", false, "Select every detected tool")
	cmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "Print intended changes without writing any files")
	cmd.Flags().BoolVar(&flagForce, "force", false, "Overwrite existing non-observer hook / MCP entries")
	cmd.Flags().BoolVar(&flagSkipHooks, "skip-hooks", false, "Only register MCP, leave hooks alone")
	cmd.Flags().BoolVar(&flagSkipMCP, "skip-mcp", false, "Only register hooks, leave MCP alone")
	cmd.Flags().BoolVar(&flagSkipProxy, "skip-proxy-route", false, "Skip writing per-tool proxy routing config (e.g. codex base_url) — print a hint instead")
	cmd.Flags().BoolVar(&flagSkipExtension, "skip-extension", false, "Skip writing the browser extension's per-browser native-messaging host manifest")
	cmd.Flags().BoolVar(&flagBrowser, "browser", false, "Install ONLY the browser-capture native-messaging host + per-browser manifest (skips AI-tool hooks/MCP/proxy). Pair with --browser-extension-id for a complete manifest")
	cmd.Flags().StringVar(&flagBrowserExtID, "browser-extension-id", "", "Chromium extension id(s) (32 lowercase a-p chars each from chrome://extensions after load-unpacked) to bake into the native-messaging host manifest allowed_origins. Comma-separate multiple ids — an unpacked extension's id is path-derived, so the same extension under WSL Chrome vs Windows Chrome needs both ids in one manifest")
	cmd.Flags().BoolVar(&flagGuard, "guard", true, "Compile guard policy into each selected tool's native permission rules (guard spec §13.2); --guard=false skips the guard side of init")
	cmd.Flags().BoolVar(&flagSkipGuardDialect, "skip-guard-dialect", false, "Skip writing native guard permission rules into tool configs (narrower than --guard=false)")
	cmd.Flags().IntVar(&flagProxyPort, "proxy-port", 8820, "Observer proxy port to wire into per-tool routing config")
	cmd.Flags().StringVar(&flagConfigPath, "config", "", "Path to observer config.toml — when set, registered hook + MCP commands include --config so they read the same config as the proxy you'll run against this install")
	cmd.Flags().StringVar(&flagWinClaudeHome, "windows-claude-home", "", "Windows user home (e.g. /mnt/c/Users/<you>) holding the .claude to route/hook when a WSL daemon can't safely auto-pick among several Windows homes (see `observer doctor`)")
	cmd.Flags().StringVar(&flagWinCodexHome, "windows-codex-home", "", "Windows user home (e.g. /mnt/c/Users/<you>) holding the .codex to route when a WSL daemon can't safely auto-pick among several Windows homes")
	cmd.Flags().StringVar(&flagWinCursorHome, "windows-cursor-home", "", "Windows user home (e.g. /mnt/c/Users/<you>) holding the .cursor to hook when a WSL daemon can't safely auto-pick among several Windows homes (cursor-windows is hooks-only — no proxy route)")
	return cmd
}

// initSelectedTools recomputes the wireAIClients tool selection for
// the guard-dialect step (the P6.x init refactor moved selection
// inside wireAIClients). Detection-only: dry-run registries, zero
// writes; any construction failure selects nothing — a detection
// problem must never fail the init (the initGuardDialects contract).
func initSelectedTools(binary, configPath string, all, cc, codex, cursor, cline bool) []string {
	hookReg, err := hook.NewRegistry(hook.Options{BinaryPath: binary, DryRun: true, ConfigPath: configPath})
	if err != nil {
		return nil
	}
	mcpReg, err := mcp.NewRegistrar(mcp.RegisterOptions{BinaryPath: binary, DryRun: true, ConfigPath: configPath})
	if err != nil {
		return nil
	}
	return selectToolsForInit(all, cc, codex, cursor, cline, unionStrings(hookReg.Installed(), mcpReg.Installed()))
}

// initGuardDialects compiles the effective guard policy into the
// selected tools' native permission dialects (guard spec §13.2 —
// `observer init` is the default-on application point). Only tools
// with an IMPLEMENTED dialect compile (claude-code today; opencode is
// not an init tool and joins via `observer guard compile`); the
// [guard.dialects].targets allow-list is honoured when set. Every
// failure path prints and returns — the hooks/MCP sides already
// registered, and a dialect problem must never fail the init.
func initGuardDialects(ctx context.Context, out io.Writer, tools []string, configPath string, dryRun bool) {
	var names []string
	for _, t := range tools {
		if tgt, ok := compile.TargetFor(t); ok && tgt.Implemented {
			names = append(names, string(tgt.Dialect))
		}
	}
	if len(names) == 0 {
		return
	}
	cfg, g, err := buildCLIGuard(configPath)
	if err != nil {
		fmt.Fprintf(out, "guard dialects: skipped (%v)\n", err)
		return
	}
	if !cfg.Guard.Enabled || cfg.Guard.Mode == "off" || !cfg.Guard.Dialects.Compile {
		fmt.Fprintln(out, "guard dialects: skipped (disabled via [guard] / [guard.dialects])")
		return
	}
	if len(cfg.Guard.Dialects.Targets) > 0 {
		allow := map[string]bool{}
		for _, t := range cfg.Guard.Dialects.Targets {
			allow[t] = true
		}
		kept := names[:0]
		for _, n := range names {
			if allow[n] {
				kept = append(kept, n)
			}
		}
		if names = kept; len(names) == 0 {
			return
		}
	}
	var st *store.Store
	if !dryRun {
		if database, derr := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath}); derr == nil {
			defer database.Close()
			st = store.New(database)
		} else {
			fmt.Fprintf(out, "guard dialects: WARN observer DB unavailable (%v) — compiling without pinning\n", derr)
		}
	}
	r := newDialectRunner(configGuardDialects{
		Compile: true, Targets: cfg.Guard.Dialects.Targets,
	}, st, g, newLogger(cfg.Observer.LogLevel))
	if r == nil {
		return
	}
	// Explicit tool selection creates the config file when absent
	// (requireExisting=false) — the same posture as hook registration.
	reports := r.CompileTargets(ctx, names, !dryRun, false)
	for _, rep := range reports {
		switch {
		case rep.Target.Dialect == "":
			// candidate-resolution issues only (printed below).
		case dryRun:
			fmt.Fprintf(out, "guard dialect %s: would compile %d native entr%s (%d to add, %d to retire) into %s\n",
				rep.Target.Dialect, rep.Entries, pluralIES(rep.Entries), len(rep.Added), len(rep.Removed), rep.Path)
		case rep.Wrote:
			fmt.Fprintf(out, "guard dialect %s: wrote %d native entr%s (%d added, %d retired) → %s\n",
				rep.Target.Dialect, rep.Entries, pluralIES(rep.Entries), len(rep.Added), len(rep.Removed), rep.Path)
		default:
			fmt.Fprintf(out, "guard dialect %s: already in sync (%d native entr%s) — %s\n",
				rep.Target.Dialect, rep.Entries, pluralIES(rep.Entries), rep.Path)
		}
		for _, issue := range rep.Issues {
			fmt.Fprintf(out, "guard dialect: ISSUE: %s\n", issue)
		}
	}
}

// runHermesInit installs (or uninstalls when uninstall=true) the
// SuperBased Observer Python plugin into ~/.hermes/plugins/ AND the
// MCP entry in ~/.hermes/config.yaml. Lives out-of-band from
// wireAIClients because Hermes's plugin install path is
// fundamentally different from Claude Code / cursor / codex (a
// per-plugin directory with a Python __init__.py, not entries in a
// settings.json).
//
// Logs one line per file touched (or "would write" under DryRun).
// Errors propagate to the cobra RunE — the caller exits 1 on
// failure, matching the existing init behaviour.
func runHermesInit(out io.Writer, opts hook.HermesOptions, skipHooks, skipMCP, uninstall bool) error {
	verb := "wrote"
	if opts.DryRun {
		verb = "would write"
	}
	if uninstall {
		if !skipHooks {
			path, err := hook.UnregisterHermes(opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "hermes: removed plugin dir %s\n", path)
			cfgPath, err := hook.UnregisterHermesPluginEnabled(opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "hermes: removed plugins.enabled entry from %s\n", cfgPath)
		}
		if !skipMCP {
			path, err := hook.UnregisterHermesMCP(opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "hermes: removed mcp entry from %s\n", path)
		}
		return nil
	}
	if !skipHooks {
		path, err := hook.RegisterHermes(opts)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "hermes: %s plugin to %s\n", verb, path)
		// Plugin discovery picks up the dropped files but Hermes
		// skips loading anything not in `plugins.enabled` (verified
		// against hermes_cli/plugins.py at validation time). Write
		// the allow-list entry too. Same config.yaml as the MCP
		// merge below; both writes are idempotent.
		cfgPath, err := hook.RegisterHermesPluginEnabled(opts)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "hermes: %s plugins.enabled entry to %s\n", verb, cfgPath)
	}
	if !skipMCP {
		path, err := hook.RegisterHermesMCP(opts)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "hermes: %s mcp entry to %s\n", verb, path)
	}
	return nil
}

// runStatuslineInit installs (or uninstalls when uninstall=true) the
// Claude Code statusline registration (docs/plans/observer-statusline-plan-2026-07-30.md
// §5.1). It is called ONLY when --statusline is explicitly passed —
// never implied by --all, never invoked from `observer start`.
//
// v1 scope is the native-OS Claude Code case only: a statusLine
// command runs on every render tick, and bridging that through
// `wsl.exe -d <distro> -- ...` (the pattern registerClaudeCodeWindows
// uses for discrete hook events) risks the command's own latency
// budget for a cadence this frequent, so a cross-OS-only detection
// (claude-code present solely on the Windows side of a WSL daemon)
// prints an honest WARN and returns rather than attempting a bridge.
//
// selected is the already-resolved tool selection (initSelectedTools)
// so this reuses the SAME "selected/detected" semantics as the rest
// of init, rather than re-deriving detection independently.
func runStatuslineInit(out io.Writer, opts hook.Options, selected []string, uninstall bool) error {
	native := contains(selected, "claude-code")
	windowsOnly := !native && contains(selected, "claude-code-windows")
	if windowsOnly {
		fmt.Fprintln(out, "statusline: claude-code was detected only on the Windows side of a cross-OS WSL setup — v1 scope is native-OS only, skipping (see docs/observer-statusline.md). Run `observer init --statusline` from the OS where Claude Code itself runs.")
		return nil
	}
	if !native {
		fmt.Fprintln(out, "statusline: claude-code not selected/detected — nothing to register (pass --claude-code, or --all, or run this on a host with ~/.claude)")
		return nil
	}

	reg, err := hook.NewRegistry(opts)
	if err != nil {
		return err
	}

	if uninstall {
		res := reg.UnregisterClaudeCodeStatusline()
		if res.Error != nil {
			return res.Error
		}
		if res.Skipped {
			if len(res.HooksKept) > 0 {
				fmt.Fprintf(out, "statusline: %s has a non-observer \"statusLine\" entry — left untouched\n", res.ConfigPath)
			} else {
				fmt.Fprintf(out, "statusline: nothing to remove in %s\n", res.ConfigPath)
			}
			return nil
		}
		verb := "removed"
		if opts.DryRun {
			verb = "would remove"
		}
		fmt.Fprintf(out, "statusline: %s \"statusLine\" key from %s\n", verb, res.ConfigPath)
		return nil
	}

	res := reg.RegisterClaudeCodeStatusline()
	if res.Error != nil {
		return res.Error
	}
	if len(res.AlreadySet) > 0 {
		fmt.Fprintf(out, "statusline: already set in %s\n", res.ConfigPath)
		return nil
	}
	verb := "registered"
	if opts.DryRun {
		verb = "would register"
	}
	fmt.Fprintf(out, "statusline: %s claude-code \"statusLine\" -> %s statusline (in %s)\n", verb, opts.BinaryPath, res.ConfigPath)
	// §4.2: the disclaimer is said ONCE, here, at registration time —
	// never per-render (a one-line statusline has no room for it).
	fmt.Fprintln(out, "statusline: dollar figures it prints are an estimated list price, not invoiced — see `observer statusline --help`")
	return nil
}

// WireAIClientsOptions parameterises wireAIClients — the reusable
// AI-client integration step used by both `observer init` and the
// post-enrol auto-wire path in `observer enroll` (M4.2 of the v1.8.0
// teams remediation). Zero value = "install hooks + MCP + proxy
// routing for every detected tool".
type WireAIClientsOptions struct {
	ConfigPath string // absolute path to observer config.toml; "" = legacy mode
	ProxyPort  int    // observer proxy port to wire into per-tool routing (0 = 8820 default)
	DryRun     bool
	Force      bool
	SkipHooks  bool
	SkipMCP    bool
	SkipProxy  bool
	// SkipExtension skips the 4th consent step — writing the browser
	// extension's per-browser native-messaging host manifest. Default off
	// (the step runs when a Chromium browser is detected), consistent with
	// SkipHooks/SkipMCP/SkipProxy defaulting the write ON.
	SkipExtension bool
	// BrowserExtensionID is the Chromium extension id baked into the
	// native-messaging host manifest allowed_origins. "" writes a
	// clearly-marked placeholder plus a precise follow-up instruction
	// (batch/CI stays working; a TTY user supplies it via the flag or the
	// interactive prompt). Validated by the caller before it reaches here.
	BrowserExtensionID string
	// HomeDir overrides every registry's home resolution (tests only —
	// the same seam interactiveInitOptions carries). "" = real home.
	HomeDir string
	// Restrict the wire to a specific subset. Empty = every detected tool.
	OnlyClaudeCode, OnlyCodex, OnlyCursor, OnlyCline bool
	// All is a convenience flag matching --all on `observer init`.
	All bool
	// WindowsClaudeHome / WindowsCodexHome disambiguate the cross-OS route
	// (a WSL daemon writing into a Windows-side .claude/.codex) when the
	// registrar refuses to auto-pick among several Windows homes or can't
	// verify ownership (R1/F3). Each is the Windows USER home (e.g.
	// /mnt/c/Users/<you>) — the registrar appends .claude/.codex. The claude
	// value ALSO feeds the hook registrar's WindowsClaudeHome so the two
	// Windows writers agree on the same home; the codex value likewise feeds
	// the hook registrar's WindowsCodexHome (the `codex-windows` hook bridge,
	// IDE-11 parity) so the proxy-route and hook writers target one home.
	// Empty = auto-detect (the production default). Fed by the
	// --windows-claude-home / --windows-codex-home flags.
	WindowsClaudeHome string
	WindowsCodexHome  string
	// WindowsCursorHome disambiguates the cross-OS cursor-windows HOOK write
	// (cursor is hooks-only for the cross-OS surface — no proxy-route writer),
	// mirroring the claude/codex overrides. It is the Windows USER home; the
	// hook registrar appends .cursor. Empty = auto-detect. Fed by the
	// --windows-cursor-home flag.
	WindowsCursorHome string
	// WindowsBrowserHomes / WSLDistro / NewWindowsRegistry carry the
	// registry-based Windows browser path INJECTED by the cobra entry point
	// (productionWindowsBrowserInputs). wireAIClients never reads ambient
	// crossmount/$WSL_DISTRO_NAME itself, so a test leaving these zero can
	// never reach a real /mnt/c profile or reg.exe (FIX 1).
	WindowsBrowserHomes []string
	WSLDistro           string
	NewWindowsRegistry  func() (browserhost.RegistryWriter, error)
}

// wireAIClients runs the same hook + MCP + proxy-route registration
// flow as `observer init`. Returns a list of human-readable lines
// summarising what was registered (for the caller to print), and
// whether the user should be told to set ANTHROPIC_BASE_URL manually
// (Claude Code's proxy hint).
//
// Used by both newInitCmd (batch mode delegates here — the M4.2
// follow-up landed with the post-D18 dedup) and newEnrollCmd.
func wireAIClients(opts WireAIClientsOptions) (lines []string, claudeProxyHint, codexProxyHint string, codexHooksHint bool, err error) {
	binary, err := absoluteBinaryPath()
	if err != nil {
		return nil, "", "", false, err
	}
	port := opts.ProxyPort
	if port == 0 {
		port = 8820
	}
	hookReg, err := hook.NewRegistry(hook.Options{
		BinaryPath:        binary,
		DryRun:            opts.DryRun,
		Force:             opts.Force,
		ConfigPath:        opts.ConfigPath,
		HomeDir:           opts.HomeDir,
		WindowsClaudeHome: opts.WindowsClaudeHome,
		WindowsCursorHome: opts.WindowsCursorHome,
		WindowsCodexHome:  opts.WindowsCodexHome,
	})
	if err != nil {
		return nil, "", "", false, err
	}
	mcpReg, err := mcp.NewRegistrar(mcp.RegisterOptions{
		BinaryPath: binary,
		DryRun:     opts.DryRun,
		Force:      opts.Force,
		ConfigPath: opts.ConfigPath,
		HomeDir:    opts.HomeDir,
	})
	if err != nil {
		return nil, "", "", false, err
	}
	var routeReg *proxyroute.Registrar
	if !opts.SkipProxy {
		routeReg, err = proxyroute.NewRegistrar(proxyroute.RegisterOptions{
			ProxyPort:         port,
			DryRun:            opts.DryRun,
			Force:             opts.Force,
			HomeDir:           opts.HomeDir,
			WindowsClaudeHome: opts.WindowsClaudeHome,
			WindowsCodexHome:  opts.WindowsCodexHome,
		})
		if err != nil {
			return nil, "", "", false, err
		}
	}

	installed := unionStrings(hookReg.Installed(), mcpReg.Installed())
	if routeReg != nil {
		// Surface the cross-OS "<tool>-windows" route targets (a WSL daemon
		// writing the route into a Windows-side .claude/.codex) the same way
		// hook.Registry.Installed surfaces claude-code-windows. Empty on a
		// native host; skipped entirely under --skip-proxy-route (routeReg
		// stays nil).
		installed = unionStrings(installed, routeReg.WindowsRouteTargets())
	}
	tools := selectToolsForInit(opts.All, opts.OnlyClaudeCode, opts.OnlyCodex, opts.OnlyCursor, opts.OnlyCline, installed)
	if len(tools) == 0 {
		return nil, "", "", false, nil
	}

	// FIXED (B3, final-fix review): mirrors autoRegisterHooks'
	// promptLaneEnabled gate (cmd/observer/start.go) — a mechanism
	// whose ENTIRE hook surface is one prompt-submit event
	// (integration.Capability.Hook.PromptLaneOnly: gemini-cli,
	// qwen-code, droid, qoder, poolside, devin/cascade,
	// command-code) has nothing useful to register when the
	// operator's own config says the prompt-submit engine won't
	// evaluate the hook lane at all. None of these six vendors has a
	// dedicated `--<tool>` selector flag (only claude-code/codex/
	// cursor/cline do, none of which is PromptLaneOnly) — they can
	// only ever enter `tools` via `--all` or the zero-flag
	// auto-detect fallback (resolveTools), never by the operator
	// "naming the tool explicitly" — so a disabled prompt lane must
	// skip their HOOK registration unconditionally, exactly like the
	// auto-register path — but gates the HOOK step only: a
	// PromptLaneOnly tool can still carry its own independent MCP
	// capability (e.g. droid's ~/.factory/mcp.json), which has
	// nothing to do with the prompt-submit engine and must not be
	// skipped just because the hook lane is off.
	promptCfg, _ := config.Load(config.LoadOptions{GlobalPath: opts.ConfigPath})
	promptLaneEnabled := promptCfg.Guard.Prompt.Enabled && promptCfg.Guard.Prompt.HookLane

	var buf strings.Builder
	registeredClaudeCode := false
	registeredCodex := false
	registeredCodexHooks := false
	for _, t := range tools {
		promptLaneOnlyBlocked := false
		if c, _, ok := advertisedCapability(t); ok && c.Hook.PromptLaneOnly && !promptLaneEnabled {
			promptLaneOnlyBlocked = true
		}
		if !opts.SkipHooks && hookSupported(t) && !promptLaneOnlyBlocked {
			res := hookReg.Register(t)
			printHookResult(&buf, t, res, opts.DryRun)
			if t == "codex" && res.Error == nil && len(res.HooksAdded) > 0 {
				registeredCodexHooks = true
			}
		}
		if !opts.SkipMCP && mcpSupported(t) {
			printMCPResult(&buf, t, mcpReg.Register(t), opts.DryRun)
		}
		if !opts.SkipProxy && routeSupported(t) && !hasProbeRouteWriter(t) {
			// Dispatch on the route's capability KIND, not tool name
			// (CLAUDE.md #3). proxyroute.Registrar holds the per-client
			// writers; the registry says which kind each tool needs.
			// routeSupported guarantees a non-nil Proxy.
			//
			// hasProbeRouteWriter excludes config-lane tools (kimi-code,
			// crush, …): they share the codex/claude-code RouteKinds but are
			// applied by the probe-route step below via their OWN writers.
			// The main step's kind-switch only knows the codex/claude-code
			// writers — running RegisterCodex() for kimi-code would write the
			// wrong config file.
			//
			// The "-windows" virtual target (WindowsRouteTargets) resolves to
			// its BASE adapter's capability KIND, then dispatches the cross-OS
			// writer — mirroring how the hook step handles claude-code-windows.
			base, isWindows := strings.CutSuffix(t, "-windows")
			ic, _ := integration.For(base)
			switch ic.Proxy.Kind {
			case integration.RouteConfigFile:
				if isWindows {
					printProxyRouteResult(&buf, t, routeReg.RegisterCodexWindows(), opts.DryRun)
				} else {
					printProxyRouteResult(&buf, t, routeReg.RegisterCodex(), opts.DryRun)
				}
			case integration.RouteEnvSettings:
				if isWindows {
					printProxyRouteResult(&buf, t, routeReg.RegisterClaudeCodeWindows(), opts.DryRun)
				} else {
					printProxyRouteResult(&buf, t, routeReg.RegisterClaudeCode(), opts.DryRun)
				}
			}
		}
		if t == "claude-code" {
			registeredClaudeCode = true
		}
		if t == "codex" {
			registeredCodex = true
		}
	}

	// Probe-route step: tools whose guarded, ADDITIVE config-lane writer
	// exists but is NOT yet live-verified (registry ProxyProbe != nil; Proxy
	// stays nil). They are NOT surfaced by selectTools (not hook/MCP clients),
	// so the eligible set derives from the registry, detected by config-file
	// presence at write time (ConfigMissing → benign skip). Only fired under
	// an explicit `--all` "wire everything I have" (never on a tool-scoped
	// init, which must respect the operator's scope) and honouring
	// --skip-proxy-route. Interactive init offers these per-consent instead.
	if opts.All && !opts.SkipProxy && routeReg != nil {
		for _, t := range probeRouteTools() {
			writer, ok := probeRouteWriter(routeReg, t)
			if !ok {
				continue
			}
			res := writer()
			if res.ConfigMissing {
				continue // tool not installed/configured — nothing to route
			}
			printProxyRouteResult(&buf, t, res, opts.DryRun)
		}
	}

	// Browser-extension step (the 4th consent step's batch form): write the
	// per-browser native-messaging host manifest when a Chromium browser is
	// detected. Registry-gated (anyExtensionSupported), honouring
	// --skip-extension. The write is per-BROWSER (a profile dir), not
	// per-AI-tool, so it runs once after the tool loop — a machine with no
	// Chromium browser writes nothing.
	if !opts.SkipExtension && anyExtensionSupported() {
		if berr := runBrowserExtensionStep(&buf, browserExtStepParams{
			HomeDir:            opts.HomeDir,
			ObserverBin:        binary,
			ConfigPath:         opts.ConfigPath,
			ExtensionID:        opts.BrowserExtensionID,
			DryRun:             opts.DryRun,
			WindowsHomes:       opts.WindowsBrowserHomes,
			WSLDistro:          opts.WSLDistro,
			NewWindowsRegistry: opts.NewWindowsRegistry,
		}); berr != nil {
			// Surface the browser lines gathered so far, then fail (FIX 4).
			lines = strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
			return lines, "", "", false, berr
		}
	}

	// Claude Code proxy hint is now only emitted when the operator
	// explicitly skipped proxy-routing — otherwise the write above
	// did the work and a redundant "next: export ANTHROPIC_BASE_URL"
	// would be misleading. Pre-v1.8.2 the env var was print-only,
	// which is N4 in docs/audits/teams-test-regression-2026-06-03.md.
	if registeredClaudeCode && !opts.DryRun && opts.SkipProxy {
		var hint strings.Builder
		printProxyRoutingHint(&hint, port)
		claudeProxyHint = hint.String()
	}
	if registeredCodex && opts.SkipProxy {
		codexProxyHint = proxyroute.CodexHint(port)
	}
	codexHooksHint = registeredCodexHooks && !opts.DryRun

	lines = strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	return lines, claudeProxyHint, codexProxyHint, codexHooksHint, nil
}

// resolveInitConfigPath validates and absolutizes the --config flag value
// for `observer init`. Empty input means "no flag passed" — returns ""
// so registrations omit --config entirely (legacy behaviour). Non-empty
// input must point at an existing file; we absolutize the path so the
// registered hook/MCP commands keep working when invoked from any CWD.
func resolveInitConfigPath(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("resolve --config %q: %w", raw, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("--config %q: %w", abs, err)
	}
	return abs, nil
}

func printHookResult(out io.Writer, tool string, res hook.RegistrationResult, dryRun bool) {
	if res.Error != nil {
		fmt.Fprintf(out, "%-12s hook ✗ %v\n", tool, res.Error)
		return
	}
	if res.Skipped {
		printWiringSkip(out, tool, "hook", res.SkipReason, res.SkipAdvice)
		return
	}
	printProbeWarning(out, tool, "hook", res.ProbeWarning)
	verb := "registered"
	if dryRun {
		verb = "would register"
	}
	if len(res.HooksAdded) > 0 {
		fmt.Fprintf(out, "%-12s hook %s %d hook(s) in %s: %v\n",
			tool, verb, len(res.HooksAdded), res.ConfigPath, res.HooksAdded)
	}
	if len(res.AlreadySet) > 0 {
		fmt.Fprintf(out, "%-12s hook already set: %v\n", tool, res.AlreadySet)
	}
}

func printMCPResult(out io.Writer, tool string, res mcp.RegistrationResult, dryRun bool) {
	if res.Error != nil {
		fmt.Fprintf(out, "%-12s mcp  ✗ %v\n", tool, res.Error)
		return
	}
	if res.Skipped {
		printWiringSkip(out, tool, "mcp ", res.SkipReason, res.SkipAdvice)
		return
	}
	printProbeWarning(out, tool, "mcp ", res.ProbeWarning)
	verb := "registered"
	if dryRun {
		verb = "would register"
	}
	if res.AlreadySet {
		fmt.Fprintf(out, "%-12s mcp  already set in %s\n", tool, res.ConfigPath)
		return
	}
	if res.Added {
		fmt.Fprintf(out, "%-12s mcp  %s in %s\n", tool, verb, res.ConfigPath)
	}
}

// printWiringSkip renders a registrar's deliberate no-write. Capability-shaped
// — any registrar that sets RegistrationResult.Skipped renders here; the
// reason AND the follow-up advice are the registrar's, not this printer's.
//
// advice == "" keeps the historical plugin wording (the tool already carries
// observer's wiring through its own packaging surface, so --force is the
// escape hatch). A registrar whose skip has different semantics — the
// cross-OS sandbox gate, where --force deliberately does NOT apply — supplies
// its own advice instead of being misdescribed by this printer.
func printWiringSkip(out io.Writer, tool, kind, reason, advice string) {
	if reason == "" {
		reason = "this tool already carries observer's wiring"
	}
	if advice == "" {
		advice = "nothing written; the plugin already provides it. " +
			"Re-run with --force to register anyway (both fire, doubling every event)."
	}
	fmt.Fprintf(out, "%-12s %s skipped — %s\n", tool, kind, reason)
	fmt.Fprintf(out, "%-12s %s   %s\n", "", kind, advice)
}

// printProbeWarning renders a registrar's NON-FATAL probe failure: it
// registered, but could not first rule out an in-tool plugin providing
// the same wiring. Silent on every conclusive path.
func printProbeWarning(out io.Writer, tool, kind, warning string) {
	if warning == "" {
		return
	}
	fmt.Fprintf(out, "%-12s %s ! %s\n", tool, kind, warning)
}

// printProxyRoutingHint reminds the user that hook + MCP installation
// alone won't engage the proxy — Claude Code needs ANTHROPIC_BASE_URL
// pointed at the proxy's listen address, otherwise traffic flies past
// to api.anthropic.com directly and the only token-count source left is
// the unreliable JSONL stream.
func printProxyRoutingHint(out io.Writer, port int) {
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "next: route Claude Code through the observer proxy for accurate token capture.")
	fmt.Fprintln(out, "  start the proxy:    observer proxy start")
	fmt.Fprintf(out, "  point Claude Code:  export ANTHROPIC_BASE_URL=%s\n", url)
	fmt.Fprintln(out, "  or persist via ~/.claude/settings.json:")
	fmt.Fprintf(out, "      \"env\": { \"ANTHROPIC_BASE_URL\": %q }\n", url)
	fmt.Fprintln(out, "  see docs/proxy-routing.md for verification + per-shell setup.")
}

// printCommunityFooter echoes a short "get involved" line at the tail of
// `observer init`, mirroring the dashboard Community & support card. Honest,
// link-only — no fabricated social proof.
func printCommunityFooter(out io.Writer) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "★ Observer is open source — a star helps others find it:")
	fmt.Fprintln(out, "    https://github.com/marmutapp/superbased-observer")
	fmt.Fprintln(out, "  issues + feedback: .../issues · contact@superbased.app")
}

// printProxyRouteResult prints the outcome of a proxyroute registration
// in the same single-line shape as MCP/hook results.
func printProxyRouteResult(out io.Writer, tool string, res proxyroute.RegistrationResult, dryRun bool) {
	if res.Error != nil {
		fmt.Fprintf(out, "%-12s route ✗ %v\n", tool, res.Error)
		return
	}
	verb := "registered"
	if dryRun {
		verb = "would register"
	}
	if res.SkipReason != "" {
		// A deliberate, benign no-write that is NOT "tool not installed"
		// (today: the cross-OS sandbox gate). Surfaced rather than silently
		// swallowed with the other ConfigMissing skips.
		fmt.Fprintf(out, "%-12s route skipped — %s\n", tool, res.SkipReason)
		return
	}
	if res.AlreadySet {
		fmt.Fprintf(out, "%-12s route already set in %s → %s\n", tool, res.ConfigPath, res.BaseURL)
		return
	}
	if res.Added {
		fmt.Fprintf(out, "%-12s route %s in %s → %s\n", tool, verb, res.ConfigPath, res.BaseURL)
	}
}

// hookSupported reports whether `observer init`'s hook.Registry can write
// hooks for tool. Registry-driven (CLAUDE.md #3/#5): it dispatches on the
// tool's HookMechanism, not its name, and treats the cross-OS "-windows"
// variant as the CrossOSBridge capability rather than a separate tool.
// The hook.Registry handles the settings.json / cursor / codex.toml
// mechanisms; Hermes' embedded plugin is AutoWired but written by
// runHermesInit (separate `observer init --hermes` path), and cline-cli's
// hooks.jsonl is a tailer the operator wires manually (AutoWired=false) —
// both are excluded here by mechanism, not by a tool branch. A new
// hook-capable client is a registry row + (if a new mechanism) one writer.
// advertisedCapability resolves an `observer init` TARGET name to its
// registry row, applying the two rules every init predicate below shares:
//
//  1. the cross-OS "-windows" virtual target (a WSL daemon writing into a
//     Windows-side .claude / .codex / VS Code) resolves to its BASE adapter —
//     isWindows tells the caller to gate on that capability's own
//     CrossOSBridge flag;
//  2. a row the harness lifecycle policy no longer ADVERTISES (deprecated or
//     dead — integration.Capability.Advertised) is refused up front, so init
//     never wires a fresh install into a sunset product. Capture is untouched:
//     lifecycle gates advertising only (docs/harness-lifecycle-policy.md).
//
// ok is false for an unknown tool and for an unadvertised one; the caller then
// answers false without inspecting any further capability shape.
func advertisedCapability(tool string) (c integration.Capability, isWindows bool, ok bool) {
	base, isWindows := strings.CutSuffix(tool, "-windows")
	c, ok = integration.For(base)
	if !ok || !c.Advertised() {
		return integration.Capability{Tool: base}, isWindows, false
	}
	return c, isWindows, true
}

func hookSupported(tool string) bool {
	c, isWindows, ok := advertisedCapability(tool)
	if !ok || !c.Hook.AutoWired {
		return false
	}
	switch c.Hook.Mechanism {
	case integration.HookClaudeSettings, integration.HookCursor, integration.HookCodexConfig,
		integration.HookGeminiSettings, integration.HookQwenSettings, integration.HookFactoryJSON,
		// Part B item 2 (phase-3a): the documented long-tail vendors —
		// all four handled by hook.Registry.Register like every other
		// case here. zcode is NOT listed: its AutoWired stays false
		// (no register* writer exists at all, gated on a liveness
		// probe), so it never reaches this switch.
		integration.HookQoderJSON, integration.HookPoolsideYAML, integration.HookCascadeJSON, integration.HookCommandCodeMod:
		// handled by hook.Registry.Register
	default:
		return false // HermesPlugin → runHermesInit; ClineCLIJSONL → manual tailer
	}
	if isWindows {
		return c.Hook.CrossOSBridge
	}
	return true
}

// mcpSupported reports whether `observer init` can write MCP server config
// for tool via the mcp.Registrar. It is registry-driven (CLAUDE.md #3/#5):
// the answer is the SHAPE of the tool's MCP capability, not its name. The
// registrar handles the JSON {"mcpServers":{…}} object, Codex's
// [mcp_servers] TOML table, and OpenCode's "mcp" object; Hermes' YAML
// target is Implemented but written by its own runHermesInit path, so it's
// excluded here by format, not by a tool branch. A new MCP-capable client
// becomes a registry row + (if a new format) one writer — no edit to this
// predicate.
func mcpSupported(tool string) bool {
	// Resolve the cross-OS "-windows" virtual target to its base adapter and
	// gate on the registry's MCP.CrossOSBridge flag (mirrors hookSupported).
	c, isWindows, ok := advertisedCapability(tool)
	if !ok || c.MCP == nil || !c.MCP.Implemented {
		return false
	}
	if isWindows && !c.MCP.CrossOSBridge {
		return false
	}
	switch c.MCP.Format {
	case integration.MCPServersJSON, integration.MCPCodexTOML, integration.MCPOpenCodeJSON:
		return true
	default:
		return false
	}
}

// routeSupported reports whether `observer init` can PERSIST a proxy route
// into a per-tool config file. Registry-driven (CLAUDE.md #3/#5): true only
// for the persisted route kinds the proxyroute.Registrar writes —
// RouteEnvSettings (claude-code → ~/.claude/settings.json "env") and
// RouteConfigFile (codex → ~/.codex/config.toml openai_base_url).
// RouteLauncher tools (opencode) are routed at exec time by their
// `observer <x>` launcher, not persisted by init, so they're false here.
// Proxy-exempt tools (Proxy == nil) are likewise false. A new routable
// client is a registry row + (if a new kind) one writer.
//
// The cross-OS "-windows" virtual target (a WSL daemon writing the route
// into a Windows-side .claude/.codex) is resolved to its base adapter and
// gated on the registry's Proxy.CrossOSBridge flag — the exact template
// hookSupported/mcpSupported use for their own "-windows" variants.
func routeSupported(tool string) bool {
	c, isWindows, ok := advertisedCapability(tool)
	if !ok || c.Proxy == nil {
		return false
	}
	if isWindows && !c.Proxy.CrossOSBridge {
		return false
	}
	switch c.Proxy.Kind {
	case integration.RouteEnvSettings, integration.RouteConfigFile:
		return true
	default:
		return false
	}
}

// routeProbeSupported reports whether a GUARDED, ADDITIVE config-lane proxy
// writer exists for tool but is NOT yet live-verified — the registry's
// ProxyProbe (Proxy stays nil, Routability stays probe_required). Distinct
// from routeSupported, which gates the VERIFIED routes init writes on a
// plain scoped run. Registry-driven (CLAUDE.md #3): the answer is the shape
// of the registry row, never a tool-name hand-list.
func routeProbeSupported(tool string) bool {
	c, _, ok := advertisedCapability(tool)
	return ok && c.ProxyProbe != nil
}

// extensionSupported reports whether tool is a browser-chatbot rail whose
// capture attaches via the MV3 extension's native-messaging bridge — the
// 4th `observer init` consent step writes its per-browser host manifest.
// Registry-driven (CLAUDE.md #3/#5): the answer is the SHAPE of the tool's
// hook capability (Mechanism == HookBrowserExtension), never a tool-name
// branch. Mirrors hookSupported / mcpSupported / routeSupported. The write
// itself is per-BROWSER (a Chromium profile dir), not per-tool, so init
// runs a single browser-extension step when ANY *-web tool is
// extensionSupported — the manifest is shared across every browser site.
func extensionSupported(tool string) bool {
	c, _, ok := advertisedCapability(tool)
	if !ok || !c.Hook.AutoWired {
		return false
	}
	return c.Hook.Mechanism == integration.HookBrowserExtension
}

// anyExtensionSupported reports whether the registry declares at least one
// browser-extension rail (so init offers the 4th step). Derived from the
// registry — a new *-web row makes this true with no edit here.
func anyExtensionSupported() bool {
	for _, c := range integration.Capabilities() {
		if extensionSupported(c.Tool) {
			return true
		}
	}
	return false
}

// splitExtensionIDs parses a comma-separated --browser-extension-id value into
// its individual ids: each element is trimmed and empties are dropped, so ""
// yields nil (the placeholder path) and a single bare id yields a one-element
// slice (byte-identical to the pre-multi-id behaviour). Deduplication and the
// placeholder fallback are the browserhost package's job (allowedOriginsFor);
// this only tokenises.
func splitExtensionIDs(raw string) []string {
	var ids []string
	for _, part := range strings.Split(raw, ",") {
		if id := strings.TrimSpace(part); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// resolveBrowserExtensionIDFlag validates and normalizes the raw
// --browser-extension-id flag value. It tokenizes the comma-separated list
// (splitExtensionIDs) and validates every element is a well-formed Chromium
// extension id up front — before any write — so an obviously-wrong value
// fails loud instead of baking a manifest the browser rejects.
//
// changed must be cmd.Flags().Changed("browser-extension-id"): it
// distinguishes "the flag was never passed" (ids empty is fine — that's the
// placeholder / interactive-prompt case) from "the flag was passed but
// tokenizes to zero ids" (e.g. ", ," — all commas and whitespace), which is
// REJECTED rather than silently normalized to "". Silently accepting the
// latter would make the caller's browserRequested check (flagBrowser ||
// flagBrowserExtID != "") false even though the operator explicitly asked
// for a browser-only init, falling through to the classic wireAIClients path
// and writing hooks/MCP/proxy config for every detected AI tool instead of
// the intended browser-only run.
//
// On success it returns the normalized (trimmed, comma-rejoined) value: ""
// for "not supplied", a single id normalizes to itself (byte-identical to
// the pre-multi-id behaviour).
func resolveBrowserExtensionIDFlag(changed bool, raw string) (string, error) {
	ids := splitExtensionIDs(raw)
	if changed && len(ids) == 0 {
		return "", fmt.Errorf("--browser-extension-id %q was supplied but contains no usable extension id after splitting on commas and trimming whitespace — pass at least one 32-character extension id, or omit the flag entirely", raw)
	}
	for _, id := range ids {
		if !browserhost.ValidExtensionID(id) {
			return "", fmt.Errorf("--browser-extension-id element %q is not a valid Chromium extension id (expected 32 lowercase a-p characters, e.g. from chrome://extensions)", id)
		}
	}
	return strings.Join(ids, ","), nil
}

// browserExtStepParams carries everything runBrowserExtensionStep needs to
// emit a WORKING browser rail: the vendored native-messaging host (A3) plus a
// per-browser manifest whose "path" points at it and whose allowed_origins
// carries the real (or placeholder) extension id (A1).
type browserExtStepParams struct {
	// HomeDir overrides home resolution (tests). "" = real home.
	HomeDir string
	// ObserverBin is the resolved observer binary baked into the launcher's
	// OBSERVER_BIN so the host doesn't depend on PATH at runtime.
	ObserverBin string
	// ConfigPath is the observer config baked into OBSERVER_CONFIG so the
	// host writes to the same observer.db as the daemon. "" = daemon default.
	ConfigPath string
	// ExtensionID is the validated Chromium extension id, or "" for the
	// placeholder + follow-up instruction path. It may be a comma-separated
	// list of ids (split via splitExtensionIDs at the browserhost boundary);
	// a single id is byte-identical to the pre-multi-id behaviour.
	ExtensionID string
	// DryRun previews without writing (host files AND manifests).
	DryRun bool
	// WindowsHomes are the cross-mounted Windows user-profile dirs (e.g.
	// "/mnt/c/Users/<u>") to offer the registry-based Windows browser path
	// for. INJECTED by the caller (from crossmount) — never read from ambient
	// state inside the step — so tests that leave it nil never touch a real
	// /mnt/c profile or the real registry. Real entry points populate it via
	// detectWindowsBrowserHomes().
	WindowsHomes []string
	// WSLDistro is the distro name the Windows bridge's `wsl.exe -d <distro>`
	// targets, paired with WindowsHomes. "" disables the Windows path (an
	// honest note prints when Windows browsers exist but the distro is
	// unknown).
	WSLDistro string
	// NewWindowsRegistry builds the RegistryWriter for HKCU writes. INJECTED
	// so tests supply a fake and the REAL reg.exe writer
	// (browserhost.NewRegExeWriter) is constructed ONLY at the cobra init
	// entry points. When a Windows browser needs registering and this is nil,
	// the step fails closed (an honest note, nothing written) rather than
	// touching the real machine. Errors from the factory (reg.exe absent from
	// the trusted system path) surface as an honest skip too.
	NewWindowsRegistry func() (browserhost.RegistryWriter, error)
	// WinPathTranslator overrides the WSL→Windows path translation (tests, so
	// artifact writes land in a temp dir and never a real /mnt/c profile).
	// nil = the real /mnt-based translator.
	WinPathTranslator func(string) (string, bool)
}

// runBrowserExtensionStep installs the vendored native-messaging host (A3)
// and writes the per-browser manifest pointing at it (A1) for every detected
// Chromium-family browser (the 4th consent step's write). It is the browser
// rail's peer of hook.Registry.Register: detection is "a browser profile dir
// exists"; a machine with no Chromium browser writes nothing (though a
// Windows machine gets an honest note that its registry rail isn't shipped
// yet — A2 deferred). After it runs, the host EXISTS under the observer dir
// and the manifest POINTS at it — no repo dependency, no hand-edit.
func runBrowserExtensionStep(buf *strings.Builder, p browserExtStepParams) error {
	hostDir, err := browserhost.HostInstallDir(p.HomeDir)
	if err != nil {
		fmt.Fprintf(buf, "browser extension: ✗ %v\n", err)
		return fmt.Errorf("browser extension: resolve host install dir: %w", err)
	}
	launcherPath := hostfiles.LauncherPath(hostDir)

	reg, err := browserhost.NewRegistrar(browserhost.Options{
		Home:         p.HomeDir,
		DryRun:       p.DryRun,
		HostPath:     launcherPath,
		ExtensionIDs: splitExtensionIDs(p.ExtensionID),
	})
	if err != nil {
		fmt.Fprintf(buf, "browser extension: ✗ %v\n", err)
		return fmt.Errorf("browser extension: %w", err)
	}
	det := reg.Detect()

	// Windows browsers reachable cross-mount from a WSL daemon are
	// registry-based, not dir-based — a separate rail (browserhost's
	// WindowsRegistrar). This is the operator's actual topology (WSL daemon +
	// Windows browser), which the dir path can never serve. Branch on "any
	// target exists (dir-based OR Windows)" below so a WSL box with ONLY
	// Windows browsers is still served (FIX 2).
	winTargets := resolveWindowsBrowserTargets(buf, p, launcherPath)

	if len(det) == 0 && len(winTargets) == 0 {
		// Native Windows daemon (same-host) still isn't wired — the registry
		// rail here targets a WSL daemon. Say so plainly.
		if runtime.GOOS == "windows" {
			fmt.Fprintln(buf, "browser: same-host Windows native-messaging registration is not yet shipped; run the daemon under WSL to wire Windows browsers, or load the extension on a Linux/macOS profile — nothing was written.")
		}
		return nil // no Chromium browser (dir or Windows) — an honest no-op, not an error.
	}

	// A3: vendor the native host launcher + script into the LINUX observer dir
	// so the manifest points at real files (no repo dependency). This host is
	// needed by BOTH the dir-based manifests AND the Windows bridge (which
	// execs this same host-launcher.sh inside WSL via wsl.exe). The host runs
	// under Node — resolve it and warn honestly if it's missing.
	nodeBin, nodeErr := exec.LookPath("node")
	if p.DryRun {
		fmt.Fprintf(buf, "browser: would write native-messaging host (%s + %s) → %s\n",
			hostfiles.HostScriptName, hostfiles.LauncherName, hostDir)
	} else if _, werr := hostfiles.WriteHost(hostDir, hostfiles.Env{
		ObserverBin:    p.ObserverBin,
		ObserverConfig: p.ConfigPath,
		NodeBin:        nodeBin,
	}); werr != nil {
		fmt.Fprintf(buf, "browser: ✗ host install: %v\n", werr)
		return fmt.Errorf("browser: native-messaging host install failed: %w", werr)
	} else {
		fmt.Fprintf(buf, "browser: wrote native-messaging host → %s\n", launcherPath)
	}
	if nodeErr != nil {
		fmt.Fprintln(buf, "browser: WARN node was not found on PATH — the native-messaging host runs under Node.js; install it (https://nodejs.org/) or captured turns won't reach observer.")
	}

	// A1: per-browser manifest pointing at the installed launcher (dir-based
	// Linux/macOS browsers).
	var manifestPaths []string
	for _, res := range reg.Register() {
		switch {
		case res.Error != nil:
			fmt.Fprintf(buf, "browser (%s): ✗ %v\n", res.Browser, res.Error)
		case res.AlreadySet:
			manifestPaths = append(manifestPaths, res.ConfigPath)
			fmt.Fprintf(buf, "browser (%s): native-messaging host manifest already set in %s\n", res.Browser, res.ConfigPath)
		case res.Wrote && p.DryRun:
			manifestPaths = append(manifestPaths, res.ConfigPath)
			fmt.Fprintf(buf, "browser (%s): would write native-messaging host manifest → %s\n", res.Browser, res.ConfigPath)
		case res.Wrote:
			manifestPaths = append(manifestPaths, res.ConfigPath)
			fmt.Fprintf(buf, "browser (%s): wrote native-messaging host manifest → %s\n", res.Browser, res.ConfigPath)
		}
	}

	// Windows-registry registration (WSL-daemon topology). Runs the shared
	// manifest + bridge write and the per-browser HKCU keys.
	winManifests, winOutcome := runWindowsBrowserRegistration(buf, p, winTargets)
	manifestPaths = append(manifestPaths, winManifests...)

	// Extension-id honesty. With a real id the manifest is complete. Without
	// one we wrote a clearly-marked placeholder — print the PRECISE follow-up
	// so batch/CI users can finish the one edit (A1).
	if p.ExtensionID == "" && len(manifestPaths) > 0 {
		fmt.Fprintf(buf, "browser: no extension id supplied — wrote the placeholder %q in allowed_origins.\n", browserhost.PlaceholderExtensionID)
		fmt.Fprintln(buf, "  after `load-unpacked` in chrome://extensions, copy the extension id and either:")
		fmt.Fprintln(buf, "    re-run: observer init --browser-extension-id <id>")
		fmt.Fprintf(buf, "    or edit the \"allowed_origins\" field (replace %s) in:\n", browserhost.PlaceholderExtensionID)
		for _, mp := range manifestPaths {
			fmt.Fprintf(buf, "      %s\n", mp)
		}
	}

	// FIX 4: surface registration failures instead of print-and-discard. When
	// Windows registration was actually attempted (a registrar was built) but
	// EVERY target failed, return an aggregate error so the CLI exits non-zero
	// rather than reporting success. Partial success warns (the per-target
	// lines above already name each failure) but is not a hard error. The
	// honest no-browser / distro-unknown paths never set requested, so they
	// stay a clean no-op.
	if winOutcome.requested && !winOutcome.anySuccess {
		return fmt.Errorf("browser: Windows native-messaging registration failed for every target: %s", strings.Join(winOutcome.failures, "; "))
	}
	if winOutcome.requested && len(winOutcome.failures) > 0 {
		fmt.Fprintf(buf, "browser (windows): WARN %d registration(s) failed: %s\n", len(winOutcome.failures), strings.Join(winOutcome.failures, "; "))
	}
	return nil
}

// browserOfferedBrowsers returns the human-readable ids of every browser the
// browser step would offer to register: dir-based (Linux/macOS, from Detect)
// PLUS registry-based Windows browsers reachable under the injected
// windowsHomes. An empty result means "no browser to offer" — so the caller
// skips the step. Because it counts BOTH rails, a WSL box with ONLY Windows
// browsers (empty det) is still offered the registration (FIX 2). It reads
// only the injected windowsHomes, never ambient crossmount.
func browserOfferedBrowsers(det []browserhost.Browser, windowsHomes []string) []string {
	var ids []string
	for _, b := range det {
		ids = append(ids, b.BrowserID())
	}
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	for _, home := range windowsHomes {
		for _, b := range browserhost.WindowsBrowsersInstalled(home) {
			if id := b.BrowserID(); !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// resolveWindowsBrowserTargets discovers cross-mounted Windows homes with a
// Chromium browser installed and returns a WindowsRegistrar per home, ready to
// register the registry-based native-messaging host that bridges into this WSL
// daemon (the operator's actual topology: WSL daemon + Windows browser). It
// dispatches on a CAPABILITY — "a cross-mounted Windows home has a browser
// profile dir" — not on runtime.GOOS: on a native Windows host crossmount only
// yields WSL *Linux* homes, so this naturally returns nothing there.
//
// linuxLauncher is the absolute Linux path to host-launcher.sh the bridge
// execs via wsl.exe. When Windows browsers exist but the WSL distro can't be
// resolved (empty $WSL_DISTRO_NAME), it prints an honest note and skips — the
// `wsl.exe -d <distro>` bridge cannot be built without it.
func resolveWindowsBrowserTargets(buf *strings.Builder, p browserExtStepParams, linuxLauncher string) []*browserhost.WindowsRegistrar {
	distro := strings.TrimSpace(p.WSLDistro)

	// Only homes that actually have a Windows browser profile matter.
	var homesWithBrowser []string
	for _, home := range p.WindowsHomes {
		if len(browserhost.WindowsBrowsersInstalled(home)) > 0 {
			homesWithBrowser = append(homesWithBrowser, home)
		}
	}
	if len(homesWithBrowser) == 0 {
		return nil // no Windows browser — nothing to wire.
	}

	// Distro check FIRST: without it the `wsl.exe -d <distro>` bridge cannot
	// be built regardless of the registry writer, so we skip with an honest
	// note and NEVER construct the (real) writer.
	if distro == "" {
		for _, home := range homesWithBrowser {
			fmt.Fprintf(buf, "browser: found a Windows browser under %s but the WSL distro is unknown ($WSL_DISTRO_NAME empty) — can't build the wsl.exe bridge; run init from inside WSL. Nothing written for Windows.\n", home)
		}
		return nil
	}

	// Distro known → we WILL write. Resolve the RegistryWriter ONCE via the
	// INJECTED factory. The real reg.exe writer is constructed ONLY here, and
	// ONLY from the factory the cobra entry point injected
	// (browserhost.NewRegExeWriter). A nil factory or a factory error (reg.exe
	// absent from the trusted system path) FAILS CLOSED — an honest note,
	// nothing written — rather than silently touching the real machine.
	if p.NewWindowsRegistry == nil {
		fmt.Fprintln(buf, "browser: a Windows browser was found but no registry writer was provided (internal wiring) — skipping Windows registration; nothing written.")
		return nil
	}
	writer, err := p.NewWindowsRegistry()
	if err != nil {
		fmt.Fprintf(buf, "browser: %v — skipping Windows registration; nothing written.\n", err)
		return nil
	}

	var regs []*browserhost.WindowsRegistrar
	for _, home := range homesWithBrowser {
		wr, werr := browserhost.NewWindowsRegistrar(browserhost.WindowsOptions{
			WindowsHome:       home,
			WSLDistro:         distro,
			LinuxLauncherPath: linuxLauncher,
			ExtensionIDs:      splitExtensionIDs(p.ExtensionID),
			DryRun:            p.DryRun,
			Registry:          writer,
			ToWin:             p.WinPathTranslator,
		})
		if werr != nil {
			fmt.Fprintf(buf, "browser: ✗ Windows registrar (%s): %v\n", home, werr)
			continue
		}
		regs = append(regs, wr)
	}
	return regs
}

// detectWindowsBrowserHomes resolves the cross-mounted Windows user-profile
// dirs and the WSL distro name for the real init entry points to inject into
// browserExtStepParams. Ambient I/O (crossmount + $WSL_DISTRO_NAME) is read
// HERE, at the composition layer — never inside runBrowserExtensionStep — so
// the step stays testable without touching a real /mnt/c profile or registry.
func detectWindowsBrowserHomes() (homes []string, distro string) {
	distro = strings.TrimSpace(os.Getenv("WSL_DISTRO_NAME"))
	for _, h := range crossmount.AllHomes() {
		if h.OS == crossmount.OSWindows {
			homes = append(homes, h.Path)
		}
	}
	return homes, distro
}

// productionWindowsBrowserInputs binds the ambient Windows/WSL state to the
// REAL reg.exe RegistryWriter factory for injection into the browser step. It
// is the SINGLE place that reads ambient crossmount/$WSL_DISTRO_NAME AND the
// only supplier of the production RegistryWriter (browserhost.NewRegExeWriter,
// which itself fails closed if reg.exe is absent) — so call it ONLY from a
// cobra RunE. Every test injects fakes instead, which is exactly why no test
// can reach the real registry, /mnt/c, or ambient env
// (feedback_browserhost_tests_touch_real_registry).
func productionWindowsBrowserInputs() (homes []string, distro string, newRegistry func() (browserhost.RegistryWriter, error)) {
	homes, distro = detectWindowsBrowserHomes()
	return homes, distro, browserhost.NewRegExeWriter
}

// windowsRegOutcome summarises a Windows registration pass so the caller can
// decide whether to fail (every target failed) or merely warn (partial). It is
// a small value, not a type threaded through the step (CLAUDE.md #2).
type windowsRegOutcome struct {
	// requested is true once at least one registrar was actually run (a
	// Windows browser was found AND the bridge inputs resolved). The honest
	// no-browser / distro-unknown / fail-closed paths leave it false so they
	// stay a clean no-op.
	requested bool
	// anySuccess is true when at least one target registered cleanly (files +
	// at least one registry entry without error).
	anySuccess bool
	// failures holds a human-readable note per failed target/entry.
	failures []string
}

// runWindowsBrowserRegistration writes the shared Windows bridge launcher +
// manifest and the per-browser HKCU registry keys for each resolved Windows
// target, printing an honest line per artifact. Returns the manifest paths (in
// WSL form) for the extension-id follow-up footer, plus an outcome summary so
// the caller can propagate an all-failed registration as an error (FIX 4).
func runWindowsBrowserRegistration(buf *strings.Builder, p browserExtStepParams, regs []*browserhost.WindowsRegistrar) ([]string, windowsRegOutcome) {
	var manifestPaths []string
	var outcome windowsRegOutcome
	for _, wr := range regs {
		outcome.requested = true
		res := wr.Register()
		if res.Error != nil {
			fmt.Fprintf(buf, "browser (windows): ✗ %v\n", res.Error)
			outcome.failures = append(outcome.failures, res.Error.Error())
			continue
		}
		switch {
		case p.DryRun:
			fmt.Fprintf(buf, "browser (windows): would write wsl.exe bridge launcher → %s\n", res.BridgeWSLPath)
			fmt.Fprintf(buf, "browser (windows): would write native-messaging manifest → %s\n", res.ManifestWSLPath)
		case res.FilesAlreadySet:
			fmt.Fprintf(buf, "browser (windows): bridge launcher + manifest already set (%s)\n", res.ManifestWSLPath)
		default:
			fmt.Fprintf(buf, "browser (windows): wrote wsl.exe bridge launcher → %s\n", res.BridgeWSLPath)
			fmt.Fprintf(buf, "browser (windows): wrote native-messaging manifest → %s\n", res.ManifestWSLPath)
		}
		if len(res.ManifestWSLPath) > 0 {
			manifestPaths = append(manifestPaths, res.ManifestWSLPath)
		}
		entryOK := false
		for _, e := range res.Entries {
			switch {
			case e.Error != nil:
				fmt.Fprintf(buf, "browser (windows/%s): ✗ registry: %v\n", e.Browser, e.Error)
				outcome.failures = append(outcome.failures, fmt.Sprintf("%s: %v", e.Browser, e.Error))
			case e.AlreadySet:
				entryOK = true
				fmt.Fprintf(buf, "browser (windows/%s): registry key already points at the manifest → %s\n", e.Browser, e.KeyPath)
			case e.Applied && p.DryRun:
				entryOK = true
				fmt.Fprintf(buf, "browser (windows/%s): would set registry key → %s (Default)=%s\n", e.Browser, e.KeyPath, res.ManifestPath)
			case e.Applied:
				entryOK = true
				fmt.Fprintf(buf, "browser (windows/%s): set registry key → %s\n", e.Browser, e.KeyPath)
			}
		}
		if entryOK {
			outcome.anySuccess = true
		}
	}
	return manifestPaths, outcome
}

// browserOnlyOptions parameterises runBrowserOnlyInit — the `observer init
// --browser` fast path that installs ONLY the browser rail.
type browserOnlyOptions struct {
	BinaryPath  string
	ConfigPath  string
	ExtensionID string // validated, or "" (placeholder / prompt)
	DryRun      bool
	// Interactive prompts for a missing extension id (a human on both ends).
	Interactive bool
	// HomeDir overrides home resolution (tests). "" = real home.
	HomeDir string
	// Windows browser injection (FIX 1) — the cobra entry point supplies
	// these via productionWindowsBrowserInputs; a test injects fakes.
	WindowsBrowserHomes []string
	WSLDistro           string
	NewWindowsRegistry  func() (browserhost.RegistryWriter, error)
}

// runBrowserOnlyInit runs just the browser-extension step — the vendored
// native-messaging host + the per-browser manifest — without touching any
// AI-tool config. It is the browser peer of the `--hermes`-only path. On an
// interactive terminal with no --browser-extension-id it PROMPTS for the id
// (blank = keep the placeholder + instruction); non-interactive keeps the
// batch placeholder behaviour.
func runBrowserOnlyInit(out io.Writer, in io.Reader, opts browserOnlyOptions) error {
	if !anyExtensionSupported() {
		fmt.Fprintln(out, "browser: no browser-capture rail is registered in this build.")
		return nil
	}
	extID := opts.ExtensionID
	if extID == "" && opts.Interactive {
		resolved, err := promptBrowserExtensionID(out, bufio.NewReader(in))
		if err != nil {
			return err
		}
		extID = resolved
	}
	var buf strings.Builder
	stepErr := runBrowserExtensionStep(&buf, browserExtStepParams{
		HomeDir:            opts.HomeDir,
		ObserverBin:        opts.BinaryPath,
		ConfigPath:         opts.ConfigPath,
		ExtensionID:        extID,
		DryRun:             opts.DryRun,
		WindowsHomes:       opts.WindowsBrowserHomes,
		WSLDistro:          opts.WSLDistro,
		NewWindowsRegistry: opts.NewWindowsRegistry,
	})
	if buf.Len() == 0 && stepErr == nil {
		fmt.Fprintln(out, "browser: no Chromium-family browser detected — install one and re-run, or load the extension elsewhere.")
		return nil
	}
	fmt.Fprint(out, buf.String())
	if stepErr != nil {
		return stepErr
	}
	printCommunityFooter(out)
	return nil
}

// promptBrowserExtensionID asks for the Chromium extension id on an
// interactive terminal, re-asking on an invalid (obviously-wrong) value.
// Blank input returns "" — the caller keeps the placeholder + follow-up
// instruction. EOF aborts cleanly (returns "" with no error so the manifest
// is still written with the placeholder).
func promptBrowserExtensionID(out io.Writer, r *bufio.Reader) (string, error) {
	for {
		fmt.Fprintln(out, "browser: load the extension via `load-unpacked` in chrome://extensions, then paste its id.")
		fmt.Fprint(out, "  extension id (32 lowercase a-p chars; blank to fill in later): ")
		line, err := r.ReadString('\n')
		id := strings.TrimSpace(line)
		if id == "" {
			// Blank or EOF → keep the placeholder; not an error.
			return "", nil
		}
		if browserhost.ValidExtensionID(id) {
			return id, nil
		}
		fmt.Fprintln(out, "  that doesn't look like a Chromium extension id (need 32 lowercase a-p chars). Try again, or press enter to skip.")
		if err != nil {
			return "", nil // EOF after a bad line — skip rather than loop forever.
		}
	}
}

// probeRouteTools returns the sorted set of tools carrying a guarded
// config-lane probe writer (registry ProxyProbe != nil). The enumeration
// DERIVES from the registry — a new probe writer is a registry row, not an
// edit here (one-owner rule).
func probeRouteTools() []string {
	var out []string
	for _, c := range integration.Capabilities() {
		if c.ProxyProbe != nil {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// probeRouteWriterBindings is the DATA table binding each probe-route tool to
// the proxyroute writer for the config file + schema its guarded writer knows.
// The eligible SET derives from the registry (probeRouteTools / ProxyProbe);
// this table maps each of those tools to its writer. The writers are
// inherently per-config-shape (and two share the RouteConfigFile kind —
// kimi-code's config.toml vs qwen-code's settings.json — so a Kind switch
// alone can't distinguish them), so this is a per-tool table (CLAUDE.md #5),
// not a nested conditional. probeRouteWriter and hasProbeRouteWriter both read
// it, so the eligible set has ONE owner. A new probe writer is one registry
// ProxyProbe row + one row here + the writer itself.
var probeRouteWriterBindings = map[string]func(*proxyroute.Registrar) func() proxyroute.RegistrationResult{
	"kimi-code": func(r *proxyroute.Registrar) func() proxyroute.RegistrationResult { return r.RegisterKimiCode },
	"crush":     func(r *proxyroute.Registrar) func() proxyroute.RegistrationResult { return r.RegisterCrush },
	"qwen-code": func(r *proxyroute.Registrar) func() proxyroute.RegistrationResult { return r.RegisterQwenCode },
}

// probeRouteWriter binds a probe-route tool to its proxyroute writer, reading
// the shared probeRouteWriterBindings table.
func probeRouteWriter(reg *proxyroute.Registrar, tool string) (func() proxyroute.RegistrationResult, bool) {
	bind, ok := probeRouteWriterBindings[tool]
	if !ok {
		return nil, false
	}
	return bind(reg), true
}

// hasProbeRouteWriter reports whether tool is applied by the probe-route step
// via its own config-lane writer (shared probeRouteWriterBindings table). The
// main route step guards on this so it never runs its codex/claude-code
// writers for a config-lane tool that shares those RouteKinds.
func hasProbeRouteWriter(tool string) bool {
	_, ok := probeRouteWriterBindings[tool]
	return ok
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// selectTools resolves the requested tool set from flags + detection with
// BASE-ONLY semantics: an explicit --claude-code selects exactly "claude-code"
// (plus whatever `installed` already lists under --all / auto-detect). It does
// NOT fan an explicit base selector out to its cross-OS "<base>-windows"
// virtual target — that union is init-only (see selectToolsForInit).
//
// `observer uninstall` calls THIS directly (F3): `uninstall --claude-code` must
// keep its pre-existing scope and never silently strip the Windows-side hooks
// too. Uninstalling a Windows-side target stays reachable only via the explicit
// mechanisms (e.g. --all, or a direct Windows-side uninstall path).
func selectTools(all, cc, codex, cursor, cline bool, installed []string) []string {
	return resolveTools(all, cc, codex, cursor, cline, installed, false)
}

// selectToolsForInit is selectTools plus the init-only cross-OS union: an
// explicit --claude-code / --codex / --cursor / --cline ALSO selects its
// detected, wireable "<base>-windows" virtual target so `observer init` writes
// the Windows-side home too. Init is the ONLY place this widening is safe: init
// writes are additive + consented, whereas widening it in uninstall would be a
// destructive scope change (F3).
func selectToolsForInit(all, cc, codex, cursor, cline bool, installed []string) []string {
	return resolveTools(all, cc, codex, cursor, cline, installed, true)
}

// resolveTools is the shared core. crossOSWindows gates the init-only union of
// an explicit base selector with its "<base>-windows" cross-OS target.
func resolveTools(all, cc, codex, cursor, cline bool, installed []string, crossOSWindows bool) []string {
	installedSet := map[string]bool{}
	for _, t := range installed {
		installedSet[t] = true
	}
	requested := map[string]bool{}
	if all {
		for _, t := range installed {
			requested[t] = true
		}
	}
	// selectBase requests a base tool AND (init-only) its cross-OS
	// "<base>-windows" virtual target when that target was detected/resolvable
	// (present in installed) and is actually wireable for a cross-OS surface
	// (route OR hook capable). F3: without this, `observer init --codex
	// --windows-codex-home=…` would select only "codex" and write NOTHING to
	// the Windows home. The union is gated on detection + the capability
	// predicates (CLAUDE.md #3), never a bare name switch beyond the
	// established "-windows" suffix convention — AND it is init-only, so
	// `observer uninstall --codex` keeps base-only scope.
	selectBase := func(base string) {
		requested[base] = true
		if !crossOSWindows {
			return
		}
		win := base + "-windows"
		if installedSet[win] && (routeSupported(win) || hookSupported(win)) {
			requested[win] = true
		}
	}
	if cc {
		selectBase("claude-code")
	}
	if codex {
		selectBase("codex")
	}
	if cursor {
		selectBase("cursor")
	}
	if cline {
		selectBase("cline")
	}
	if len(requested) == 0 && !all {
		for _, t := range installed {
			requested[t] = true
		}
	}
	var out []string
	for t := range requested {
		if autoInitSupported(t) {
			out = append(out, t)
		}
	}
	return out
}

// autoInitSupported reports whether tool participates in a no-flag
// (auto-detected) `observer init`/`observer uninstall` selection —
// resolveTools' shared vocabulary gate. Registry-driven (CLAUDE.md
// #3/#5): a tool qualifies the moment it has ANY init-writable
// capability SHAPE — a hook mechanism init can auto-wire
// (hookSupported), an MCP format init can write (mcpSupported), or a
// persisted proxy-route kind init can write (routeSupported) —
// dispatched through the SAME predicates every other init/uninstall
// call site already uses, never a hardcoded tool-name list.
//
// B2 (phase-3a review): this used to be a hardcoded `supported` map
// naming only 2 of the 7 vendors Part B item 2 wired hook mechanisms
// for (droid + command-code) — `observer init --all` silently skipped
// gemini-cli/qwen-code/qoder/poolside/devin even though their hook
// rows are HookSpec{AutoWired: true} today, and `observer uninstall`
// (selectTools shares resolveTools with selectToolsForInit) could
// never reach those hosts to remove what `observer start`'s
// auto-register loop had already written there.
//
// zcode correctly stays excluded: its registry row deliberately sets
// Hook.AutoWired=false pending a liveness probe (see internal/
// integration's zcode row), so hookSupported already answers false
// for it — no special-casing needed. hermes and cline-cli correctly
// stay excluded too: their mechanisms (HermesPlugin, HookClineCLIJSONL)
// and hermes' MCP format (YAML) are deliberately excluded from
// hookSupported/mcpSupported's own switches (see those functions' doc
// comments) — hermes is wired through its own --hermes path instead.
func autoInitSupported(tool string) bool {
	return hookSupported(tool) || mcpSupported(tool) || routeSupported(tool)
}

// absoluteBinaryPath returns the absolute path of the running binary so that
// hook commands written into settings files are stable across shells and
// $PATH changes.
func absoluteBinaryPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve binary path: %w", err)
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return abs, nil
}
