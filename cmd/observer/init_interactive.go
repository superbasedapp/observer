package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// Interactive `observer init` (usability arc P6.10) — the CLI twin of
// the dashboard's setup wizard. Engaged only when init runs with ZERO
// flags on a real terminal (stdin AND stdout are char devices);
// scripts, CI, and any flagged invocation get the classic
// non-interactive behaviour untouched.
//
// Consent semantics mirror the wizard exactly: every write is
// previewed (the dry-run registry shows the precise file + entries)
// and asks its OWN yes/no — one consent per write, no apply-all.
// Hooks and proxy-route default to yes; the MCP step is never
// pre-selected and carries the per-turn token honesty note (the Q4
// rule). Plain stdin prompts; no TUI dependency.

// interactiveInitOptions parameterises runInteractiveInit so tests
// can sandbox the home directory and script stdin.
type interactiveInitOptions struct {
	BinaryPath string
	ConfigPath string
	ProxyPort  int
	// HomeDir overrides the registries' home resolution (tests). ""
	// = real home.
	HomeDir string
	// WindowsBrowserHomes / WSLDistro / NewWindowsRegistry carry the
	// registry-based Windows browser path INJECTED by the cobra entry point
	// (productionWindowsBrowserInputs). The interactive flow never reads
	// ambient crossmount/$WSL_DISTRO_NAME or builds the real reg.exe writer
	// itself, so a test leaving these zero can never reach a real /mnt/c
	// profile or reg.exe (FIX 1).
	WindowsBrowserHomes []string
	WSLDistro           string
	NewWindowsRegistry  func() (browserhost.RegistryWriter, error)
	// Components, when set, runs the install-time component chooser
	// (components_chooser.go) first on a machine with no [components]
	// selection. Nil (tests, embedders) skips it.
	Components chooserService
}

// stdinIsTerminal mirrors stdoutIsTerminal for the input side — the
// interactive checklist needs a human on both ends.
func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// initPrompter reads y/n answers from a line-oriented stdin. Empty
// input takes the default; anything unparseable re-asks; EOF aborts
// the whole flow (no further writes).
type initPrompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p *initPrompter) ask(question string, def bool) (bool, error) {
	suffix := "[Y/n]"
	if !def {
		suffix = "[y/N]"
	}
	for {
		fmt.Fprintf(p.out, "  %s %s ", question, suffix)
		line, err := p.in.ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		if err != nil && answer == "" {
			return false, fmt.Errorf("stdin closed - stopping; nothing further was written")
		}
		switch answer {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(p.out, "  please answer y or n (enter for the default)")
			if err != nil {
				return false, fmt.Errorf("stdin closed - stopping; nothing further was written")
			}
		}
	}
}

// askChoice reads a 1..max selection (returning the 0-based index) or a skip
// (empty / n / no → -1). Anything else re-asks. EOF aborts the whole flow like
// ask. Used by the cross-OS route disambiguation picker (R1/F3) where the
// operator selects which of several detected Windows homes to route.
func (p *initPrompter) askChoice(question string, max int) (int, error) {
	for {
		fmt.Fprintf(p.out, "  %s ", question)
		line, err := p.in.ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		if err != nil && answer == "" {
			return -1, fmt.Errorf("stdin closed - stopping; nothing further was written")
		}
		switch answer {
		case "", "n", "no":
			return -1, nil
		}
		if n, convErr := strconv.Atoi(answer); convErr == nil && n >= 1 && n <= max {
			return n - 1, nil
		}
		fmt.Fprintf(p.out, "  please enter a number 1-%d, or n to skip\n", max)
		if err != nil {
			return -1, fmt.Errorf("stdin closed - stopping; nothing further was written")
		}
	}
}

// printRouteTradeoff prints, before a route consent, what the tool switches
// off by itself while the route is in force (surface-gap CC-11; the
// registry's RouteTradeoff, "" for a tool with none grounded), so the
// developer accepts it knowingly instead of stripping the route later.
func printRouteTradeoff(out io.Writer, tool string) {
	if tr := integration.RouteTradeoff(tool); tr != "" {
		fmt.Fprintf(out, "  note: %s\n", tr)
	}
}

// runWindowsRouteDisambiguation offers a numbered picker for each cross-OS
// route tool whose Windows-side home could NOT be auto-resolved (R1 ownership
// unverifiable / F3 several homes). These tools are excluded from
// WindowsRouteTargets, so they never reach the main consent loop — this step
// is where the operator resolves them. candidates is keyed by "<tool>-windows"
// → the Windows USER homes to choose among (as returned by
// Registrar.WindowsRouteCandidates). The chosen home feeds a one-off override
// registrar that performs the write. Returns on the first stdin error (EOF),
// like the rest of the flow. port is the proxy port; homeDir threads the test
// home seam through to the one-off registrar.
func runWindowsRouteDisambiguation(out io.Writer, p *initPrompter, candidates map[string][]string, port int, opts interactiveInitOptions) error {
	for _, label := range []string{"claude-code-windows", "codex-windows"} {
		homes := candidates[label]
		if len(homes) == 0 {
			continue
		}
		base, _ := strings.CutSuffix(label, "-windows")
		ic, _ := integration.For(base)
		fmt.Fprintf(out, "\n%s\n", label)
		fmt.Fprintln(out, "  several Windows-side homes were detected and ownership could not be")
		fmt.Fprintln(out, "  auto-verified against the current Windows user - pick which one to wire:")
		for i, h := range homes {
			fmt.Fprintf(out, "    %d) %s\n", i+1, h)
		}
		printRouteTradeoff(out, label)
		choice, err := p.askChoice(fmt.Sprintf("route %s through the observer proxy? [1-%d, or n to skip]", label, len(homes)), len(homes))
		if err != nil {
			return err
		}
		if choice < 0 {
			fmt.Fprintln(out, "  skipped.")
			continue
		}
		chosen := homes[choice]
		rOpts := proxyroute.RegisterOptions{ProxyPort: port, HomeDir: opts.HomeDir, Writer: routeprov.WriterInit}
		switch ic.Proxy.Kind {
		case integration.RouteEnvSettings:
			rOpts.WindowsClaudeHome = chosen
		case integration.RouteConfigFile:
			rOpts.WindowsCodexHome = chosen
		}
		reg, err := proxyroute.NewRegistrar(rOpts)
		if err != nil {
			return err
		}
		var res proxyroute.RegistrationResult
		switch ic.Proxy.Kind {
		case integration.RouteEnvSettings:
			res = reg.RegisterClaudeCodeWindows()
		case integration.RouteConfigFile:
			res = reg.RegisterCodexWindows()
		}
		printProxyRouteResult(out, label, res, false)

		// F1: the route write and the hook registration are SEPARATE writes, so
		// they get SEPARATE consents (init's one-consent-per-write contract).
		// Gate the hook offer on the route RESULT: when the route write refused
		// (Error set — e.g. an existing third-party ANTHROPIC_BASE_URL in the
		// picked home), do NOT silently write hooks into that home. The refusal
		// was already surfaced honestly by printProxyRouteResult above; just
		// move on.
		if res.Error != nil {
			continue
		}
		// No cross-OS hook to offer when the route was a benign off-WSL skip
		// (ConfigMissing) — localhost forwarding needs WSL, so there's no
		// cross-OS case to hook — when the picked target carries no hook
		// (codex-windows is route-only), or when no binary path is available
		// (nothing to write into the hook command; hook.NewRegistry requires
		// it).
		if res.ConfigMissing || !hookSupported(label) || opts.BinaryPath == "" {
			continue
		}
		// Its OWN yes/no, defaulting NO (a second file write into a Windows-side
		// home the operator only just disambiguated deserves an explicit yes).
		hookYes, herr := p.ask(fmt.Sprintf("also register Claude Code hooks into %s?", chosen), false)
		if herr != nil {
			return herr
		}
		if !hookYes {
			fmt.Fprintln(out, "  skipped.")
			continue
		}
		hr, herr := hook.NewRegistry(hook.Options{
			BinaryPath:        registrationCommand(opts.BinaryPath),
			WSLTwinBinaryPath: registrationWSLTwinBinary(opts.BinaryPath),
			ConfigPath:        registrationConfigArg(opts.ConfigPath, opts.HomeDir),
			HomeDir:           opts.HomeDir,
			WSLDistro:         opts.WSLDistro,
			WindowsClaudeHome: chosen,
		})
		if herr != nil {
			return herr
		}
		printHookResult(out, label, hr.Register(label), false)
	}
	return nil
}

// runInteractiveInit walks every detected tool and asks one consent
// per write, executing each write immediately after its yes.
//
//nolint:gocyclo // one prompt branch per consent step by design; the checklist reads top-to-bottom (P6.10 arc).
func runInteractiveInit(out io.Writer, in io.Reader, opts interactiveInitOptions) error {
	port := opts.ProxyPort
	if port == 0 {
		port = 8820
	}
	newHookReg := func(dryRun bool) (*hook.Registry, error) {
		return hook.NewRegistry(interactiveHookOptions(opts, dryRun))
	}
	newMCPReg := func(dryRun bool) (*mcpregister.Registrar, error) {
		return mcpregister.NewRegistrar(mcpregister.RegisterOptions{
			BinaryPath: mcpRegistrationCommand(opts.BinaryPath, registrationStableMCPCommand(opts.ConfigPath)), DryRun: dryRun,
			ConfigPath: registrationConfigArg(opts.ConfigPath, opts.HomeDir), HomeDir: opts.HomeDir,
			SelfBinary: opts.BinaryPath,
		})
	}
	clientToken := registrationProxyClientToken(opts.ConfigPath)
	newRouteReg := func(dryRun bool) (*proxyroute.Registrar, error) {
		return proxyroute.NewRegistrar(proxyroute.RegisterOptions{
			ProxyPort: port, DryRun: dryRun, HomeDir: opts.HomeDir, Writer: routeprov.WriterInit,
			ClientToken: clientToken,
		})
	}

	previewHooks, err := newHookReg(true)
	if err != nil {
		return err
	}
	writeHooks, err := newHookReg(false)
	if err != nil {
		return err
	}
	previewMCP, err := newMCPReg(true)
	if err != nil {
		return err
	}
	writeMCP, err := newMCPReg(false)
	if err != nil {
		return err
	}
	previewRoute, err := newRouteReg(true)
	if err != nil {
		return err
	}
	writeRoute, err := newRouteReg(false)
	if err != nil {
		return err
	}

	installed := unionStrings(previewHooks.Installed(), previewMCP.Installed())
	// WINNODE item 5, as in wireAIClients: a registry install signal (a VS
	// Code extension, a freshly installed binary) counts before the tool's
	// config home exists. Each write below still asks its own consent.
	installed = unionStrings(installed, installSignalToolsFor(opts.HomeDir))
	// Cross-OS "<tool>-windows" route targets (a WSL daemon writing the
	// route into a Windows-side .claude/.codex) join the checklist the same
	// way hook.Registry.Installed surfaces claude-code-windows.
	installed = unionStrings(installed, previewRoute.WindowsRouteTargets())
	tools := selectToolsForInit(false, nil, installed)
	p := &initPrompter{in: bufio.NewReader(in), out: out}
	// Install-time component chooser (modular packaging 7.1): before the
	// gate resolves, so the checklist below offers only what was chosen.
	if opts.Components != nil {
		if err := runComponentChooser(context.Background(), out, p, opts.Components, installed); err != nil {
			return err
		}
	}
	// Component gate: no consent is offered for an inactive component.
	gate := initGateForHome(opts.ConfigPath, opts.HomeDir)
	var gateNotes strings.Builder
	tools = gate.tools(tools, &gateNotes)
	hooksOn := gate.allow(&gateNotes, true, "hooks", "integration.hooks")
	mcpOn := gate.allow(&gateNotes, true, "mcp", "integration.mcp-server")
	routeOn := gate.allow(&gateNotes, true, "proxy route", "integration.proxy-route")
	browserOn := gate.allow(&gateNotes, anyExtensionSupported(), "browser", "capture.browser")
	sort.Strings(tools)
	// F2: a cross-OS "<tool>-windows" whose Windows home is ownership-unverified
	// or ambiguous is EXCLUDED from WindowsRouteTargets (so it isn't in tools),
	// but it IS reported by WindowsRouteCandidates. On a box whose ONLY AI tool
	// is such a Windows-side install, tools is empty yet there is real work to
	// do — the disambiguation picker below. Only conclude "no AI tools detected"
	// when there are neither tools NOR candidates.
	routeCandidates := previewRoute.WindowsRouteCandidates()
	if !routeOn {
		routeCandidates = nil
	}
	fmt.Fprint(out, gateNotes.String())
	if len(tools) == 0 && len(routeCandidates) == 0 {
		fmt.Fprintln(out, "no AI tools detected - install one (or pass --claude-code / --cursor / --codex / --antigravity / --hermes explicitly) and re-run")
		return nil
	}

	fmt.Fprintln(out, "observer init - interactive setup")
	if len(tools) > 0 {
		fmt.Fprintf(out, "detected: %s\n", strings.Join(tools, ", "))
	}
	fmt.Fprintln(out, "each write below asks first; nothing is written without a yes.")

	codexHooksAdded := false
	claudeRouteDeclined := false
	for _, t := range tools {
		fmt.Fprintf(out, "\n%s\n", t)

		if hooksOn && hookSupported(t) {
			pre := previewHooks.Register(t)
			switch {
			case pre.Error != nil:
				fmt.Fprintf(out, "  hooks: ✗ %v\n", pre.Error)
			// Skipped is NOT "already set": nothing is in ConfigPath and
			// nothing will be. Never offer a consent for a write the
			// registrar would then decline — say what is actually true.
			case pre.Skipped && pre.SkipAdvice != "":
				// A skip with its OWN advice is not the plugin case (today:
				// the cross-OS sandbox gate, where --force does not apply).
				fmt.Fprintf(out, "  hooks: skipped - %s\n", pre.SkipReason)
				fmt.Fprintf(out, "         %s\n", pre.SkipAdvice)
			case pre.Skipped:
				fmt.Fprintf(out, "  hooks: wired via the Claude Code plugin - %s\n", pre.SkipReason)
				fmt.Fprintln(out, "         nothing to register; `observer init --force` would add a second copy.")
			case len(pre.HooksAdded) == 0:
				fmt.Fprintf(out, "  hooks: already set in %s\n", pre.ConfigPath)
			default:
				fmt.Fprintln(out, "  hooks - session + tool-call capture into the local observer database.")
				fmt.Fprintf(out, "  would add %d hook(s) in %s\n", len(pre.HooksAdded), pre.ConfigPath)
				yes, err := p.ask(fmt.Sprintf("register hooks for %s?", t), true)
				if err != nil {
					return err
				}
				if yes {
					res := writeHooks.Register(t)
					printHookResult(out, t, res, false)
					if t == "codex" && res.Error == nil && len(res.HooksAdded) > 0 {
						codexHooksAdded = true
					}
				} else {
					fmt.Fprintln(out, "  skipped.")
				}
			}
		}

		if mcpOn && mcpSupported(t) {
			pre := previewMCP.Register(t)
			switch {
			case pre.Error != nil:
				fmt.Fprintf(out, "  mcp: ✗ %v\n", pre.Error)
			// As above: a skipped preview must not become a consent item.
			case pre.Skipped && pre.SkipAdvice != "":
				// See the hooks branch: a self-described skip is not the
				// plugin case.
				fmt.Fprintf(out, "  mcp: skipped - %s\n", pre.SkipReason)
				fmt.Fprintf(out, "       %s\n", pre.SkipAdvice)
			case pre.Skipped:
				fmt.Fprintf(out, "  mcp: wired via the Claude Code plugin - %s\n", pre.SkipReason)
				fmt.Fprintln(out, "       nothing to register; a second copy would load the tool schema twice.")
			case pre.AlreadySet:
				fmt.Fprintf(out, "  mcp: already set in %s\n", pre.ConfigPath)
			default:
				fmt.Fprintln(out, "  MCP server - on-demand project-knowledge queries from inside the tool.")
				fmt.Fprintln(out, "  note: the tool schema costs ~1,800 tokens on every turn - skip unless you'll use it.")
				fmt.Fprintf(out, "  would register in %s\n", pre.ConfigPath)
				yes, err := p.ask(fmt.Sprintf("register the MCP server for %s?", t), false)
				if err != nil {
					return err
				}
				if yes {
					printMCPResult(out, t, writeMCP.Register(t), false)
				} else {
					fmt.Fprintln(out, "  skipped.")
				}
			}
		}

		if routeOn && routeSupported(t) {
			// Dispatch on the base adapter's route KIND (CLAUDE.md #3), and on
			// the "-windows" virtual-target suffix for the cross-OS writer —
			// mirrors the batch dispatch in wireAIClients.
			base, isWindows := strings.CutSuffix(t, "-windows")
			ic, _ := integration.For(base)
			var previewFn, writeFn func() proxyroute.RegistrationResult
			switch ic.Proxy.Kind {
			case integration.RouteEnvSettings:
				if isWindows {
					previewFn, writeFn = previewRoute.RegisterClaudeCodeWindows, writeRoute.RegisterClaudeCodeWindows
				} else {
					previewFn, writeFn = previewRoute.RegisterClaudeCode, writeRoute.RegisterClaudeCode
				}
			case integration.RouteConfigFile:
				if isWindows {
					previewFn, writeFn = previewRoute.RegisterCodexWindows, writeRoute.RegisterCodexWindows
				} else {
					previewFn, writeFn = previewRoute.RegisterCodex, writeRoute.RegisterCodex
				}
			}
			pre := previewFn()
			switch {
			case pre.Error != nil:
				fmt.Fprintf(out, "  route: ✗ %v\n", pre.Error)
				if !isWindows {
					fmt.Fprintf(out, "  (an existing conflicting entry can be overwritten with `observer init --%s --force`)\n", t)
				}
			case pre.AlreadySet:
				fmt.Fprintf(out, "  route: already set in %s → %s\n", pre.ConfigPath, pre.BaseURL)
			default:
				if isWindows {
					fmt.Fprintf(out, "  proxy route (Windows → WSL) - route this Windows-installed tool's API traffic through the WSL proxy at %s.\n", pre.BaseURL)
				} else {
					fmt.Fprintln(out, "  proxy route - exact token accounting + conversation compression via the local proxy.")
				}
				fmt.Fprintf(out, "  would write %s → %s\n", pre.ConfigPath, pre.BaseURL)
				printRouteTradeoff(out, t)
				yes, err := p.ask(fmt.Sprintf("route %s through the observer proxy?", t), true)
				if err != nil {
					return err
				}
				if yes {
					printProxyRouteResult(out, t, writeFn(), false)
				} else {
					fmt.Fprintln(out, "  skipped.")
					if t == "claude-code" {
						claudeRouteDeclined = true
					}
				}
			}
		}
	}

	// Cross-OS route DISAMBIGUATION (R1/F3): tools whose Windows-side config
	// was detected but could not be auto-resolved — ownership unverifiable, or
	// several candidate homes — are excluded from WindowsRouteTargets, so they
	// never appeared in the loop above. Offer a numbered picker here; the
	// chosen home feeds a one-off override registrar. Nothing writes without a
	// pick.
	if err := runWindowsRouteDisambiguation(out, p, routeCandidates, port, opts); err != nil {
		return err
	}

	// Probe-route step: tools whose guarded, ADDITIVE config-lane writer
	// exists but is NOT yet live-verified (registry ProxyProbe != nil).
	// They aren't surfaced by selectTools (not hook/MCP clients), so the
	// eligible set derives from the registry and is detected by config-file
	// presence (ConfigMissing → silent skip). Being unverified, the write
	// is opt-in (default no), one consent per tool — the checklist's
	// semantics.
	for _, t := range probeRouteTools() {
		if !routeOn || !gate.snap.AdapterActive(t) {
			continue
		}
		previewFn, ok := probeRouteWriter(previewRoute, t)
		if !ok {
			continue
		}
		pre := previewFn()
		if pre.ConfigMissing {
			continue // tool not installed/configured
		}
		fmt.Fprintf(out, "\n%s\n", t)
		switch {
		case pre.Error != nil:
			fmt.Fprintf(out, "  route: ✗ %v\n", pre.Error)
		case pre.AlreadySet:
			fmt.Fprintf(out, "  route: already set in %s → %s\n", pre.ConfigPath, pre.BaseURL)
		case pre.SkipReason != "":
			// A deliberate no-write (a live-check gated writer, DEC-12):
			// nothing to consent to.
			fmt.Fprintf(out, "  route: skipped - %s\n", pre.SkipReason)
		default:
			fmt.Fprintln(out, "  proxy route (probe) - config-lane route through the local proxy; NOT yet")
			fmt.Fprintln(out, "  live-verified for this tool, so it's opt-in.")
			fmt.Fprintf(out, "  would write %s → %s\n", pre.ConfigPath, pre.BaseURL)
			yes, err := p.ask(fmt.Sprintf("route %s through the observer proxy (unverified probe)?", t), false)
			if err != nil {
				return err
			}
			if yes {
				writeFn, _ := probeRouteWriter(writeRoute, t)
				printProxyRouteResult(out, t, writeFn(), false)
			} else {
				fmt.Fprintln(out, "  skipped.")
			}
		}
	}

	// Browser-extension step (the 4th consent step): write the per-browser
	// native-messaging host manifest for the opt-in MV3 capture extension.
	// Detection is "a Chromium browser profile dir exists" (not an AI CLI
	// config), and the write is per-BROWSER, shared across every *-web site,
	// so it is one standalone step. Consent defaults YES like hooks/route
	// (the extension itself is opt-in regardless of the manifest existing).
	if browserOn && anyExtensionSupported() {
		reg, err := browserhost.NewRegistrar(browserhost.Options{Home: opts.HomeDir, DryRun: true})
		if err == nil {
			det := reg.Detect()
			// FIX 2: offer the registration when ANY target exists — dir-based
			// (Linux/macOS) OR a registry-based Windows browser reachable
			// cross-mount. A WSL box with ONLY Windows browsers (no Linux
			// browser) must still be offered the Windows path, so the gate
			// branches on the combined id list, not on len(det) alone.
			ids := browserOfferedBrowsers(det, opts.WindowsBrowserHomes)
			if len(ids) > 0 {
				fmt.Fprintf(out, "\nbrowser extension\n")
				fmt.Fprintln(out, "  native-messaging host - lets the opt-in browser-capture extension relay")
				fmt.Fprintln(out, "  ChatGPT/Claude/Perplexity/Gemini/Copilot web turns to observer.")
				fmt.Fprintf(out, "  detected browser(s): %s\n", strings.Join(ids, ", "))
				yes, aerr := p.ask("install the browser native-messaging host manifest?", true)
				if aerr != nil {
					return aerr
				}
				if yes {
					// Prompt for the extension id so the manifest is COMPLETE
					// (A1) — blank keeps the placeholder + follow-up.
					extID, perr := promptBrowserExtensionID(out, p.in, discoverExtensionIDs(opts.HomeDir, opts.WindowsBrowserHomes))
					if perr != nil {
						return perr
					}
					var buf strings.Builder
					berr := runBrowserExtensionStep(&buf, browserExtStepParams{
						HomeDir:            opts.HomeDir,
						ObserverBin:        opts.BinaryPath,
						ConfigPath:         opts.ConfigPath,
						ExtensionID:        extID,
						DryRun:             false,
						WindowsHomes:       opts.WindowsBrowserHomes,
						WSLDistro:          opts.WSLDistro,
						NewWindowsRegistry: opts.NewWindowsRegistry,
					})
					fmt.Fprint(out, buf.String())
					if berr != nil {
						return berr
					}
				} else {
					fmt.Fprintln(out, "  skipped.")
				}
			}
		}
	}

	if codexHooksAdded {
		printCodexTrustHint(out)
	}
	if claudeRouteDeclined && !claudeRoutedTo(opts.HomeDir, port) {
		printProxyRoutingHint(out, port)
	}
	home := opts.HomeDir
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if home != "" {
		if fi, err := os.Stat(filepath.Join(home, ".hermes")); err == nil && fi.IsDir() {
			fmt.Fprintln(out, "\nhermes detected - it lives on a separate install path; run `observer init --hermes` to wire it.")
		}
	}
	// The elevated-ETW setup surface is informational (it writes nothing), so
	// it is NOT a consent step — it just reports at the end of the checklist,
	// exactly as it does on the batch path.
	initProcessBridgeTaskStep(context.Background(), out, opts.ConfigPath)
	printCommunityFooter(out)
	return nil
}

// printCodexTrustHint tells the user how Codex's per-hook trust was
// handled: since the live check 2026-10-20 the codex hook writer records
// Codex's trust for Observer's own entries (printHookResult names them, or
// says which could not be recorded); /hooks remains the place to review or
// revoke it.
func printCodexTrustHint(out io.Writer) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, "note: codex runs a hook only once it is trusted (security feature).")
	fmt.Fprintln(out, codexTrustLine())
	fmt.Fprintln(out, "  review or revoke in codex /hooks; `observer doctor` reports any entry codex will not run.")
}

// codexTrustLine is the trust line with the number of entries the codex
// writer registers (U8: it said 6 after the writer grew to 9).
func codexTrustLine() string {
	return fmt.Sprintf("  observer recorded codex's trust for its own %d hook entries in ~/.codex/config.toml [hooks.state].", len(hook.CodexHookEvents()))
}

// interactiveHookOptions are the hook registration options of the
// interactive checklist. Selected stays nil: the checklist holds no
// component state, so its writers leave the opt-in events (the security
// feedback's) exactly as `observer start` left them (hook.Options.Selected).
func interactiveHookOptions(opts interactiveInitOptions, dryRun bool) hook.Options {
	return hook.Options{
		WindowsPATH: hook.PersistentWindowsPATH,
		BinaryPath:  registrationCommand(opts.BinaryPath), DryRun: dryRun,
		WSLTwinBinaryPath: registrationWSLTwinBinary(opts.BinaryPath),
		ConfigPath:        registrationConfigArg(opts.ConfigPath, opts.HomeDir), HomeDir: opts.HomeDir,
	}
}
