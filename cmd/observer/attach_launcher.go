package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// attach_launcher.go is the ONE shared attach gate every `observer <verb>`
// launcher funnels through (attach-all-launchers, 2026-07-24). Extracting it
// into its own file — disjoint from the per-launcher files the fan-out wave
// edits — keeps the contract (this file + the registry rows + the resume-gate
// seams) reviewable on its own, and lets a launcher opt into default-on attach
// by assembling ONE launcherAttachSpec at the top of its RunE instead of
// copy-pasting claude/codex's bespoke decideAttach block.
//
// The bespoke pieces stay expressed as spec CLOSURES (rejectFlags / noProxyRoute
// / attachEnv), so shared code never branches on tool identity (CLAUDE.md #3) —
// it walks the same decideAttach table, resolves the same escape-hatch verdict,
// and hands the same tool-agnostic runAttachSession the composed attachLaunch.
// decideAttach itself (attach_default.go) is UNTOUCHED.

// launcherAttachSpec is one launcher's attach-integration contract, assembled at
// the top of its RunE before any bare-launch work. Every hook is optional; a
// zero-ish spec means "grounded attach, no proxy routing, no escape hatch".
type launcherAttachSpec struct {
	tool          string // registry key, e.g. "kilo-code-cli"
	configPath    string // --config override ("" = default)
	proxyOverride string // raw --proxy / --proxy-url flag value ("" = none)
	proxyFlag     string // inner launcher's proxy-override flag name:
	// "--proxy" (most), "--proxy-url" (hermes, pi),
	// "" = launcher has no proxy flag (seed-only tools)
	flagAttach   bool // --attach
	flagNoAttach bool // --no-attach
	incompatible bool // launcher-owned incompatible-mode verdict
	// (continue-from family + headless args; see §4)
	rejectFlags func() error // loud per-flag rejection under explicit --attach
	// (claude/codex only in v1; nil = none)
	noProxyRoute func(routeProxy bool) bool // escape-hatch resolution from
	// [terminal.attach].route_proxy + launcher flags;
	// nil = tool self-routes or is non-proxied: never
	// forward --no-proxy-route (flag not registered)
	attachEnv func(proxyURL string, noProxyRoute bool) []string
	// env forwarded across the socket; nil = none.
	// claude: base URL (unless npr) + profile env (always)
	authEnvExtra []string // DYNAMIC credential-env NAMES to forward IN ADDITION
	// to the tool's registry AuthEnv row (hermes' non-default
	// --key-env NAME); merged registry-first + deduped by
	// mergeAuthKeys, gated by [terminal.attach].forward_auth_env.
	passthrough []string // wrapper flags forwarded to the inner launcher
	// (--<tool>-path, --resume, --model, --upstream…)
	toolArgs []string // the operator's `--` remainder
	stderr   io.Writer
}

// launcherAttachOutcome reports how the gate resolved.
type launcherAttachOutcome struct {
	handled bool // true: attach path fully owned the launch; return err as-is
	// daemonUnreachableNoticed: the one-line unreachable notice was printed on
	// the bare fallthrough — claude's F3(a) dedup consumes this.
	daemonUnreachableNoticed bool
}

// launcherAttach is the ONE attach gate every `observer <verb>` launcher calls
// first. It loads config (fail-OPEN to bare on load error so launchers that
// never loaded config keep launching), resolves the proxy URL, assembles
// attachDecisionInputs (grounded := integration.For(tool).Attach != nil, real
// TTY probes, runningAsDaemonChild/oobChannelActive, lazy
// attachSocketReachable), prints the decision notice, and on an attach verdict
// runs the tool-agnostic runAttachSession with the composed attachLaunch.
//
// Config fail-open (step 2) mirrors the launchers that never required a loadable
// config (cursor/kilo/qwen-family): a broken config yields {handled:false} so
// the launcher takes its normal bare path rather than being refused at the
// attach gate.
func launcherAttach(ctx context.Context, spec launcherAttachSpec) (launcherAttachOutcome, error) {
	capab, _ := integration.For(spec.tool)
	// attachInBuild is false in a build without the terminals component: there
	// is no attach server to reach, so a default-on attach stays a silent bare
	// launch (D-514) instead of claiming the daemon is unreachable.
	grounded := capab.Attach != nil && attachInBuild

	cfg, err := config.Load(config.LoadOptions{GlobalPath: spec.configPath})
	if err != nil {
		// Fail OPEN: never let a broken config block a bare launch at the attach
		// gate (preserves the config-optional launchers' behavior).
		return launcherAttachOutcome{}, nil
	}

	proxyURL := resolveProxyURL(cfg.Proxy.Port, spec.proxyOverride)

	in := attachDecisionInputs{
		enabled:       cfg.Terminal.Attach.Enabled,
		defaultOn:     cfg.Terminal.Attach.DefaultOn,
		grounded:      grounded,
		flagAttach:    spec.flagAttach,
		flagNoAttach:  spec.flagNoAttach,
		stdinTTY:      term.IsTerminal(int(os.Stdin.Fd())),
		stdoutTTY:     term.IsTerminal(int(os.Stdout.Fd())),
		incompatible:  spec.incompatible,
		daemonChild:   runningAsDaemonChild(),
		daemonSpawned: oobChannelSpawnedByDaemon(),
		reachable:     func() bool { return attachSocketReachable(cfg.Observer.DBPath) },
		inSandbox:     os.Getenv(sandboxEnvMarker) == "1",
	}
	decision := decideAttach(in)
	if in.inSandbox {
		// Inside a box the decision goes to the run's inner log with the
		// facts it read, so a run whose attach notice did not print says
		// which row it took (Windows 11 Pro run 3: a non-terminal stdin or
		// stdout is the scripted row, silent by design). Outside a box this
		// writes nothing.
		appendBoxInnerLog(attachDecisionNote(in, decision) + boxConsoleNote(os.Getenv, boxConsoleWindow()))
		// The box's environment in the run's posture (WINFIX2, ledger SBX-WIN-ENV-1).
		sandboxEnvPosture(spec.stderr)
	}

	var outcome launcherAttachOutcome
	if decision.notice != "" {
		fmt.Fprintln(spec.stderr, decision.notice)
		outcome.daemonUnreachableNoticed = decision.notice == attachDaemonUnreachableNotice
	}
	if !decision.attach() {
		return outcome, nil // handled=false → the launcher's bare path runs
	}

	// From here the attach path OWNS the launch (handled=true): any error is the
	// launch's error, returned as-is. The per-flag rejection (claude/codex only)
	// fires under an explicit --attach for a wrapper flag the daemon-spawned
	// inner launcher cannot honor — printed then returned, never silently
	// dropped (B2-6).
	if spec.rejectFlags != nil {
		if rerr := spec.rejectFlags(); rerr != nil {
			fmt.Fprintln(spec.stderr, rerr)
			outcome.handled = true
			return outcome, rerr
		}
	}

	// Escape hatch: a nil noProxyRoute closure means the tool self-routes or is
	// non-proxied (no --no-proxy-route flag to forward), so npr stays false.
	npr := spec.noProxyRoute != nil && spec.noProxyRoute(cfg.Terminal.Attach.RouteProxy)

	var env []string
	if spec.attachEnv != nil {
		env = spec.attachEnv(proxyURL, npr)
	}
	// Credential-env forwarding (default-on): layer the caller's own provider
	// keys — the tool's grounded registry AuthEnv row plus any launcher-supplied
	// DYNAMIC key (hermes' --key-env) — AFTER the base attachEnv, so a
	// shell-exported-only key reaches the daemon-spawned child as it would a bare
	// launch. capab is the registry row already resolved at the top of this func
	// — dispatch on capability DATA, never a tool-name branch (CLAUDE.md #3).
	// A CONDITIONAL route (ProxyRoute.Gate) is decided by the daemon-spawned
	// inner launcher, so it must see the caller's gate inputs (credential,
	// model and base-URL variable NAMES the gate reads) exactly as a bare
	// launch would; otherwise a shell-exported COPILOT_MODEL, say, would be
	// invisible to the decision. Nil for an ungated route.
	env = composeAttachEnv(env, cfg.Terminal.Attach.ForwardAuthEnv, capab.AuthEnv, attachExtraEnvKeys(capab, spec.authEnvExtra), os.Environ())

	extra := attachExtraArgs(npr, spec.proxyOverride, spec.proxyFlag, spec.configPath, spec.passthrough, spec.toolArgs)

	outcome.handled = true
	return outcome, runAttachSession(ctx, attachLaunch{
		tool:       spec.tool,
		configPath: spec.configPath,
		proxyURL:   proxyURL,
		proxyEnv:   env,
		extraArgs:  extra,
		stderr:     spec.stderr,
	})
}

// attachExtraEnvKeys is the launcher-supplied env NAMES forwarded across the
// attach socket on top of the registry AuthEnv row: the launcher's dynamic
// keys plus, for a gated route, every name the gate decision reads.
func attachExtraEnvKeys(capab integration.Capability, launcherExtra []string) []string {
	return mergeAuthKeys(launcherExtra, capab.Proxy.GateEnvNames())
}

// registerAttachFlags mirrors claude.go's conditional registration: --attach and
// --no-attach are registered ONLY when the tool's registry row grounds an Attach
// capability (capability dispatch, never tool-name — CLAUDE.md #3). It returns
// the bound values for the RunE closure; when the capability is ungrounded the
// returned pointers stay false (their flags are never registered), so a launcher
// can pass *attach/*noAttach into its spec unconditionally. runAttachSession is
// the runtime backstop for the honest-disable case (session-attach design §3.4).
func registerAttachFlags(cmd *cobra.Command, tool string) (attach, noAttach *bool) {
	attach = new(bool)
	noAttach = new(bool)
	if capab, _ := integration.For(tool); capab.Attach != nil {
		cmd.Flags().BoolVar(attach, "attach", false,
			"Attach mode: have the running observer daemon own this session's PTY so the dashboard can view and drive the SAME live session (session-attach). Your terminal stays interactive; detaching leaves the child running under the daemon, and Ctrl-C still reaches the tool. Requires `observer start`. Attach is the DEFAULT for an interactive launch when the daemon is reachable ([terminal.attach].default_on); this flag FORCES it. See docs/plans/session-attach-design-2026-07-19.md.")
		cmd.Flags().BoolVar(noAttach, "no-attach", false,
			"Opt out of attach for this launch: run the tool as a normal child of your shell (the bare launcher) even when attach would otherwise be the default. Use it to bypass the daemon-owned PTY for one run without changing [terminal.attach].default_on.")
	}
	return attach, noAttach
}

// continueFamilyEngaged is the shared incompatible-mode predicate for the
// handoff-fork flag family every launcher registers (--continue-from and its
// --carry/--from-message/--from-time modifiers). A handoff fork composes a NEW
// session from a distilled handover, which cannot compose with attach (attach
// launches a fresh session), so an engaged family forces the bare path.
func continueFamilyEngaged(continueFrom, carry string, fromMessage int, fromTime string) bool {
	return continueFrom != "" || carry != "" || fromMessage != 0 || fromTime != ""
}

// argsContainHeadlessFlag reports whether any of flags appears in the forwarded
// tool args (either as a bare token or a `flag=value` prefix). The scan STOPS at
// the first bare `--` (mirroring argsContainClaudePrint): tokens after a bare
// `--` are positional text the tool reads as a prompt, not flags, so a matching
// token there is a literal and does NOT force the bare path. Used by the
// per-launcher headless predicates (e.g. gemini/pi/qwen `-p`/`--prompt`).
func argsContainHeadlessFlag(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false // tokens after a bare -- are positional, not flags
		}
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	return false
}

// leadingVerbScan is ONE launcher's grounded argv shape for the
// leading-subcommand guard: the headless verb set plus the tool's own flag
// grammar, read verbatim off that tool's `--help` (each launcher file
// documents its source). It exists because the scanner CANNOT know which
// flags take a SPLIT value without per-tool data, and a split value occupies
// the operand position the guard reads:
//
//	droid --append-system-prompt x=y exec "…"
//
// A flag-blind scan stops at `x=y` (the VALUE), finds no verb, and lets the
// headless `exec` through — the very bypass the guard exists to prevent. So
// the data is per-tool (CLAUDE.md #5: a data table, never a new branch).
//
// Three flag classes, resolved at the token:
//
//   - valueFlags — grounded `--flag <value>` / `<VALUE>`-required spellings:
//     the scanner skips the flag AND the following token.
//   - boolFlags — grounded switches: the flag consumes nothing.
//   - everything else — UNKNOWN, OPTIONAL-value (`[value]`, which commander
//     and clap consume inconsistently), or VARIADIC (`<FILE>...`): the
//     scanner cannot align operands any more, so it goes AMBIGUOUS.
//
// A `=`-joined token (`--auto=high`) is self-delimiting and consumes nothing,
// whatever its class.
//
// The AMBIGUOUS direction is deliberately CONSERVATIVE. Once alignment is
// lost the scanner stops trusting "the first operand is the verb" and instead
// tests EVERY remaining operand-position token against subs. For a fail-fast
// guard a false REJECTION (an exotic argv refused with a named error) is
// strictly safer than a false PASS (silently launching a headless verb, or
// silently seeding a handover into a run that exits) — the argv is exotic by
// construction, since every documented flag of the tool is in one of the two
// grounded sets. In the clean case (all flags grounded) the scan stays
// precise: only the true operand position is tested, so a multi-word bare
// prompt whose Nth word happens to equal a verb (`droid fix the mcp config`)
// is NOT rejected.
//
// A launcher with NO grounded flag data (zero valueFlags and zero boolFlags)
// keeps the ORIGINAL flag-blind semantics verbatim — skip every `-`-prefixed
// token, test the first operand, done. That is the LEGACY path the 19
// pre-existing launchers ride via argsLeadWithSubcommand; they carry the
// split-value gap above as a known, unchanged limitation until each one's
// flag grammar is grounded off its own `--help`.
type leadingVerbScan struct {
	subs       map[string]bool // headless/management verbs to reject
	valueFlags map[string]bool // flags that consume the FOLLOWING token
	boolFlags  map[string]bool // flags that consume NOTHING
}

// leads reports whether args forward one of the scan's headless subcommands in
// an operand position. See leadingVerbScan for the flag-class table and the
// conservative ambiguity rule.
func (s leadingVerbScan) leads(args []string) bool {
	_, ok := s.leadingVerb(args)
	return ok
}

// leadingVerb returns the forwarded headless subcommand the scan found (so a
// launcher's fail-fast error can NAME it) and whether one was found at all.
// The scan STOPS at a bare `--` (tokens after it are positional text the tool
// reads as a prompt, never a verb), mirroring argsContainHeadlessFlag's
// boundary.
func (s leadingVerbScan) leadingVerb(args []string) (string, bool) {
	grounded := len(s.valueFlags) > 0 || len(s.boolFlags) > 0
	ambiguous := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return "", false // positional remainder — no subcommand
		case strings.HasPrefix(a, "-"):
			if strings.ContainsRune(a, '=') {
				// `--flag=value` is self-delimiting: consumes nothing, and
				// never costs alignment whatever the flag's class.
				continue
			}
			switch {
			case s.valueFlags[a]:
				i++ // skip the SPLIT value so the operand position stays true
			case s.boolFlags[a]:
				// A grounded switch consumes nothing — alignment holds.
			case grounded:
				ambiguous = true
			}
		default:
			if s.subs[a] {
				return a, true
			}
			if !ambiguous {
				return "", false // aligned: the first operand IS the verb slot
			}
			// Ambiguous: keep testing later operand-position tokens.
		}
	}
	return "", false
}

// argsLeadWithSubcommand reports whether the FIRST bare word in the forwarded
// tool args (skipping any leading flags) is one of the headless subcommands in
// subs — the generic analogue of argsAreCodexHeadless for launchers whose
// non-interactive mode is a leading verb (opencode/kilo/goose `run`). It is the
// UNGROUNDED (flag-blind) form of leadingVerbScan.leads: no per-tool flag
// grammar, so a SPLIT flag value in the operand position hides a following verb
// (see leadingVerbScan). Launchers that have grounded their tool's flag grammar
// build a leadingVerbScan instead.
func argsLeadWithSubcommand(args []string, subs map[string]bool) bool {
	return leadingVerbScan{subs: subs}.leads(args)
}
