// attach_default.go — the default-on attach decision helper (resilient-attach
// arc, WP-C).
//
// `observer claude` / `observer codex` attach to the running daemon's PTY by
// DEFAULT when it is safe to do so (config [terminal.attach].default_on, TRUE by
// default), so a live session shows up on the dashboard with no extra flag. The
// operator opts out per-launch with `--no-attach`; `--attach` still FORCES
// attach (a no-op when the default already applies, never an error merely for
// being redundant). When default-on attach is wanted but the daemon socket is
// unreachable, the launcher prints ONE stderr notice and FALLS BACK to the
// normal bare launch with exit codes preserved — it never refuses, never
// silently drops the launch.
//
// The decision itself is a PURE, table-driven helper (decideAttach): all inputs
// are injected — no config load, no TTY probe, no socket dial happens inside it
// (repo discipline: decision logic is a data table walked top-down, one row per
// case). The launchers compute the inputs (config flags, capability grounding,
// TTY-ness, incompatible-mode, and a lazily-invoked reachability closure) and
// act on the verdict.
package main

import (
	"fmt"
	"strings"
)

// attachDaemonUnreachableNotice is the stderr line printed when default-on
// attach is desired (enabled + default_on + grounded + interactive) but the
// daemon attach socket cannot be reached. The launcher then proceeds down the
// normal bare-launch path (operator decision: notice + bare launch, never
// refuse, never silent).
//
// Wording note (notice-ordering wart, 2026-07-20): this deliberately says
// "attach disabled for this run" rather than "launching without attach". A
// daemon that is down for the attach dial is typically also down for the proxy
// dial, so this notice is printed BEFORE the decideProxyFallback verdict — which
// may itself FAIL CLOSED on the residual it cannot neutralize (a baked-in route
// the launcher can't override). "launching without attach" then read as a
// promise the fail-closed immediately broke; "attach disabled for this run"
// composes cleanly with BOTH a subsequent bare launch AND a subsequent refusal.
const attachDaemonUnreachableNotice = "observer: daemon unreachable - attach disabled for this run"

// attachInSandboxNotice replaces attachDaemonUnreachableNotice when the launcher
// runs inside an Observer sandbox (the sandbox marker in its environment): the
// box reaches the daemon only through its relay and model proxy, never through
// the attach socket, so an unreachable socket there is by design and not a
// daemon failure (Windows 11 Pro rerun 2026-10-22, where every in-box launch
// printed "daemon unreachable" while the daemon was answering). A launcher on
// the host never carries the marker, so a real daemon failure there keeps its
// own notice.
const attachInSandboxNotice = "observer: attach is not available inside the sandbox; this run continues without attach"

// attachDaemonChildNotice is printed when the OBSERVER_DAEMON_CHILD env marker is
// present but there is NO live OOB channel — a user manually running
// `observer <tool>` from a shell INSIDE a daemon-owned PTY (or, rarely, an inner
// launcher whose best-effort OOB channel died). Attaching there would recurse
// into an unbounded spawn loop, so the launch goes bare; this line explains the
// otherwise-silent decline to an operator who expected attach. It is NOT printed
// on the daemon's own healthy inner launcher (daemonSpawned) — see decideAttach
// row 0 for why that high-frequency path stays silent.
const attachDaemonChildNotice = "observer: attach skipped - already inside a daemon-owned terminal"

// attachConfigDisabledNotice is printed on the config-contradiction row:
// [terminal.attach].default_on is true (the operator opted into attach-by-
// default) but [terminal.attach].enabled is false (the master switch is off), on
// an otherwise attach-eligible interactive launch. Naming the exact key lets the
// operator resolve the contradiction instead of silently getting bare launches.
const attachConfigDisabledNotice = "observer: attach skipped - [terminal.attach].enabled is false while default_on is set; set [terminal.attach].enabled = true to auto-attach"

// attachVerdict is the outcome of decideAttach. attach/forcedAttach both route
// to the attach path; bare/forcedBare both route to the bare-launch path. The
// four values are kept distinct (rather than a single bool) so the reason for
// each outcome is legible to callers and tests — a forced verdict came from an
// explicit flag, a plain verdict from the default-on policy.
type attachVerdict int

const (
	// verdictBare: take the normal bare launch. Emitted for scripted/opted-out
	// paths (incompatible mode, non-TTY, attach disabled/not-default/ungrounded)
	// and for the daemon-unreachable fallback (which additionally carries a
	// notice).
	verdictBare attachVerdict = iota
	// verdictAttach: default-on policy conditions are all met — attach.
	verdictAttach
	// verdictForcedAttach: `--attach` was passed — attach regardless of the
	// default-on policy. Groundedness is enforced downstream by runAttachSession
	// (the honest-disable error), preserving today's `--attach` behavior.
	verdictForcedAttach
	// verdictForcedBare: `--no-attach` was passed — bare launch, no notice.
	verdictForcedBare
)

// attachDecision is decideAttach's result: the routing verdict plus an optional
// one-line notice the caller prints to stderr before a bare launch. notice is
// non-empty on the ENVIRONMENTAL-SURPRISE rows only — daemon-owned-child,
// daemon-unreachable, and the enabled/default_on config contradiction — where an
// operator who expected attach would otherwise get a bare launch with zero
// explanation. It stays EMPTY (silent) on every row the user explicitly chose or
// scripted: --no-attach, --attach, an incompatible mode, a non-TTY/piped launch,
// or a plain default_on=false / ungrounded launch. See decideAttach's row table
// for the deliberate quiet/loud split per row.
type attachDecision struct {
	verdict attachVerdict
	notice  string
	// row names the decideAttach row that decided, for the box's inner log
	// (attachDecisionNote).
	row string
}

// attach reports whether the verdict routes to the attach path (either the
// default-on attach or an explicit `--attach`).
func (d attachDecision) attach() bool {
	return d.verdict == verdictAttach || d.verdict == verdictForcedAttach
}

// attachDecisionInputs are the injected facts decideAttach walks. Every field is
// a plain value or a pure closure — no I/O is performed inside decideAttach, so
// the reachability dial and the TTY probes happen in the caller (and are
// injectable in tests). reachable is invoked AT MOST ONCE and ONLY on the
// default-on row, so scripted/opted-out launches never pay for a socket dial.
type attachDecisionInputs struct {
	// enabled is cfg.Terminal.Attach.Enabled — the master attach switch.
	enabled bool
	// defaultOn is cfg.Terminal.Attach.DefaultOn — attach-by-default policy.
	defaultOn bool
	// grounded is true when the tool declares an Attach capability in the
	// integration registry (dispatch on capability shape, never tool name).
	grounded bool
	// flagAttach is the `--attach` flag (force attach).
	flagAttach bool
	// flagNoAttach is the `--no-attach` flag (force bare).
	flagNoAttach bool
	// stdinTTY / stdoutTTY report whether the launcher's stdin/stdout are
	// interactive terminals. Attach drives a live TUI, so both must be TTYs.
	stdinTTY  bool
	stdoutTTY bool
	// incompatible is true when a launcher flag/mode cannot compose with attach
	// (verify/continue-from/headless-print/etc). Such launches go bare SILENTLY
	// — they are scripted paths and a notice would be spam.
	incompatible bool
	// daemonChild is the INFALLIBLE anti-recursion signal (review finding H1):
	// true when the daemon's OBSERVER_DAEMON_CHILD marker is present in this
	// process's env. The daemon sets it on EVERY child it spawns through its
	// terminal launcher (both the attach-spawn and dashboard PTY paths funnel
	// through launchChildEnv), so — unlike daemonSpawned — it is set even when
	// the best-effort OOB channel failed to authenticate. Checked EARLY (after
	// daemonSpawned, which is a subset kept silent — see decideAttach rows 0/0b): a
	// daemon-owned child (or a user manually running `observer claude` from a
	// shell INSIDE a daemon-owned PTY) must exec bare, never re-attach — a nested
	// attach would dial the daemon and recurse into an unbounded spawn loop.
	daemonChild bool
	// daemonSpawned is true when THIS process is the inner launcher the daemon
	// already spawned for an attach (or dashboard) PTY — i.e. a live trusted OOB
	// channel (oobChannelActive). It is the PRIMARY-BY-ORDER anti-recursion row —
	// checked BEFORE daemonChild (decideAttach row 0) — but only for the NOTICE
	// split: both are silent-vs-loud, never a different verdict. daemonSpawned is
	// the daemon's OWN healthy inner launcher (the high-frequency normal attach
	// path), whose stderr IS the user's attached PTY, so it stays SILENT to avoid
	// printing "attach skipped" on every attached session; the daemonChild row
	// below (env marker without a live OOB channel) is the genuine surprise that
	// earns the notice. daemonChild still infallibly covers a dead-OOB child.
	daemonSpawned bool
	// reachable probes the daemon attach socket. Invoked lazily (see above); a
	// nil closure is treated as unreachable.
	reachable func() bool
	// inSandbox is true when this launcher runs inside an Observer sandbox
	// (the sandbox marker): an unreachable attach socket is then by design,
	// and row 5 says so instead of naming a daemon failure.
	inSandbox bool
}

// The rows' names in the box's inner log.
const (
	attachRowDaemonSpawned  = "the daemon's own inner launcher"
	attachRowDaemonSandbox  = "a daemon-owned sandbox terminal"
	attachRowDaemonChild    = "inside a daemon-owned terminal"
	attachRowNoAttach       = "--no-attach"
	attachRowAttach         = "--attach"
	attachRowIncompatible   = "a launch mode that cannot attach"
	attachRowNotTTY         = "stdin or stdout is not a terminal"
	attachRowAttaches       = "attach by default, the daemon reachable"
	attachRowSandbox        = "attach is not available inside the sandbox"
	attachRowUnreachable    = "the daemon is unreachable"
	attachRowConfigDisabled = "[terminal.attach].enabled is false"
	attachRowNotRequested   = "attach not requested"
)

// decideAttach is the pure, table-driven attach-mode decision. Rows are walked
// top-down; the first match wins. The rightmost column is the deliberate
// quiet/loud split (2026-07-20 UX-honesty wave): a NOTICE is printed only on an
// ENVIRONMENTAL surprise an attach-expecting operator must see; every row the
// user explicitly chose or scripted stays SILENT (a stray stderr line in a
// script is worse than a missed interactive notice — "when in doubt, silent").
//
//  0. daemon-spawned inner launcher (live OOB)        → bare   SILENT   (anti-recursion; normal path)
//     0a. daemon-child env marker inside a sandbox       → bare   SILENT   (a dashboard sandbox terminal: daemon-owned already)
//     0b. daemon-child env marker, no live OOB            → bare   NOTICE*  (surprise: bare inside a daemon PTY)
//     *notice ONLY when interactive + !--no-attach + !incompatible; else SILENT (finding 5)
//  1. --no-attach                                     → forced bare  SILENT (explicit opt-out)
//  2. --attach                                        → forced attach       (downstream guards groundedness)
//  3. incompatible mode OR not both-TTY               → bare   SILENT   (chosen mode / scripted-piped)
//  4. enabled && default_on && grounded && reachable  → attach
//  5. enabled && default_on && grounded && !reachable → bare   NOTICE   (daemon unreachable;
//     inside a sandbox: attach is not available there)
//  6. default_on && grounded (⇒ enabled==false)       → bare   NOTICE   (config contradiction)
//  7. otherwise (default_on off / ungrounded)         → bare   SILENT   (attach not requested)
//
// Rows 0/0b are FIRST so a daemon-owned launcher never re-attaches regardless of
// any flag — attaching there would dial the daemon and recurse into an unbounded
// spawn loop. They split by the live-OOB signal for NOTICE purposes only (the
// anti-recursion verdict is identical — both bare):
//   - Row 0 (daemonSpawned, a live trusted OOB channel) is the daemon's OWN inner
//     launcher — the normal, high-frequency attach path. THIS process's stderr IS
//     the user's attached PTY, so a notice here would print "attach skipped" at
//     the top of every attached session and mislead (attach DID happen, at the
//     outer launcher). Checked FIRST and kept SILENT.
//   - Row 0b (the OBSERVER_DAEMON_CHILD env marker present but NO live OOB
//     channel) is a user manually running `observer <tool>` from a shell INSIDE a
//     daemon-owned PTY (the child inherits the marker), or, rarely, an inner
//     launcher whose OOB auth died. That is the genuine "I expected attach, why
//     bare?" surprise → NOTICE — but ONLY on an interactive launch that did not
//     also opt out or run in an incompatible/non-TTY mode (finding 5): a
//     daemon-child + --no-attach / --print / CI-pipe is a scripted path where the
//     notice would be spam, so it stays SILENT there (verdict still bare). The env
//     marker still infallibly forces bare here even when daemonSpawned is false,
//     so anti-recursion is unchanged.
//
// Row 3 keeps BOTH the incompatible-mode and the non-TTY launch SILENT: an
// incompatible mode is a mode the user chose, and a non-TTY stdin/stdout is the
// near-certain signature of a script or pipe (the `observer <tool> -- --print`
// wrapper, CI, `observer run`) where a stray stderr line is the top regression
// risk. We deliberately do NOT try to notice an "interactive-looking non-TTY"
// launch: non-TTY IS the scripting signal and there is no clean way to separate a
// piped-but-interactive launch from a scripted one, so silence is the safe error.
//
// Rows 4/5/6 are reached only after row 3 filtered out non-interactive and
// incompatible launches, so both-TTY + compatible is already guaranteed. Row 6
// fires only when the prior row's `enabled` was false (else row 4/5 matched), so
// `default_on && grounded` here is exactly the enabled=false/default_on=true
// config contradiction — named explicitly so the operator can fix it rather than
// silently receiving bare launches.
func decideAttach(in attachDecisionInputs) attachDecision {
	bothTTY := in.stdinTTY && in.stdoutTTY
	switch {
	case in.daemonSpawned:
		return attachDecision{verdict: verdictBare, row: attachRowDaemonSpawned}
	case in.daemonChild && in.inSandbox:
		// A sandbox box's launcher whose environment carries the daemon-child
		// marker runs in a dashboard sandbox terminal, which the daemon owns
		// already; a sandbox box's own OOB stream is not the daemon's spawn
		// channel (oobChannelSpawnedByDaemon), so row 0 no longer covers it.
		return attachDecision{verdict: verdictBare, row: attachRowDaemonSandbox}
	case in.daemonChild:
		// Anti-recursion VERDICT is unconditional: a daemon-owned child always
		// execs bare. The NOTICE, however, is suppressed whenever this same launch
		// ALSO carries an explicit opt-out (--no-attach) or a non-interactive /
		// incompatible signature (finding 5) — those are exactly the
		// `observer claude -- --print`, CI-pipe, and explicit-opt-out paths where a
		// stray stderr line is the top regression risk (mirrors row 3's silence).
		// --attach does NOT suppress it: a daemon-child that asked for attach is a
		// genuine "why bare?" surprise that still earns the one-line explanation.
		if bothTTY && !in.flagNoAttach && !in.incompatible {
			return attachDecision{verdict: verdictBare, notice: attachDaemonChildNotice, row: attachRowDaemonChild}
		}
		return attachDecision{verdict: verdictBare, row: attachRowDaemonChild}
	case in.flagNoAttach:
		return attachDecision{verdict: verdictForcedBare, row: attachRowNoAttach}
	case in.flagAttach:
		return attachDecision{verdict: verdictForcedAttach, row: attachRowAttach}
	case in.incompatible:
		return attachDecision{verdict: verdictBare, row: attachRowIncompatible}
	case !bothTTY:
		return attachDecision{verdict: verdictBare, row: attachRowNotTTY}
	case in.enabled && in.defaultOn && in.grounded:
		if in.reachable != nil && in.reachable() {
			return attachDecision{verdict: verdictAttach, row: attachRowAttaches}
		}
		if in.inSandbox {
			return attachDecision{verdict: verdictBare, notice: attachInSandboxNotice, row: attachRowSandbox}
		}
		return attachDecision{verdict: verdictBare, notice: attachDaemonUnreachableNotice, row: attachRowUnreachable}
	case in.defaultOn && in.grounded:
		return attachDecision{verdict: verdictBare, notice: attachConfigDisabledNotice, row: attachRowConfigDisabled}
	default:
		return attachDecision{verdict: verdictBare, row: attachRowNotRequested}
	}
}

// attachDecisionNote is one line naming what decideAttach chose, the row
// that decided and the terminal facts it read (the box's inner log records
// it). Windows 11 Pro run 4 logged "no notice" beside two terminals with no
// row named: the in-box launcher had taken the daemon-spawned row.
func attachDecisionNote(in attachDecisionInputs, d attachDecision) string {
	what := "launches without attach, no notice"
	switch {
	case d.attach():
		what = "attaches"
	case d.notice != "":
		what = "launches without attach, notice printed"
	}
	row := ""
	if d.row != "" {
		row = "row: " + d.row + "; "
	}
	return fmt.Sprintf("attach: %s (%sstdin is a terminal: %t, stdout is a terminal: %t)", what, row, in.stdinTTY, in.stdoutTTY)
}

// argsContainClaudePrint reports whether claude's headless print mode (`-p` /
// `--print`) appears in the forwarded tool args. Headless print is a scripted,
// non-interactive path (the `observer claude -- --print "hi"` wrapper contract),
// so default-on attach must NOT engage for it — it is an incompatible mode.
//
// The scan STOPS at the first bare `--` (M6): claude treats everything after its
// own `--` as positional text, so a `--print` appearing AFTER a bare `--` (e.g.
// `foo -- --print`) is a literal prompt token, not the print flag — that launch
// is interactive and may attach. A `--print` BEFORE any `--` is the real flag →
// headless → bare. This mirrors claude's own parsing while staying conservative:
// the only reclassification is toward attach in the unambiguous
// positional-after-`--` case.
func argsContainClaudePrint(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false // tokens after a bare -- are positional, not flags
		}
		if a == "-p" || a == "--print" || strings.HasPrefix(a, "--print=") || strings.HasPrefix(a, "-p=") {
			return true
		}
	}
	return false
}

// codexValueFlags are the codex GLOBAL flags that take a separate value token
// (space-separated form). The scan must skip both the flag and its value so a
// value that happens to be a bare word (e.g. `--model gpt exec`) is not mistaken
// for the subcommand (M6). Combined `flag=value` forms are handled separately.
// Kept in sync with codex's global-flag surface (see cmd/observer/codex.go's
// prepareCodexArgs / hasUserCodexConfigOverride): -c/--config, -C/--cd,
// -m/--model, -i/--image, -p/--profile, -s/--sandbox, -a/--ask-for-approval.
var codexValueFlags = map[string]bool{
	"-c": true, "--config": true,
	"-C": true, "--cd": true,
	"-m": true, "--model": true,
	"-i": true, "--image": true,
	"-p": true, "--profile": true,
	"-s": true, "--sandbox": true,
	"-a": true, "--ask-for-approval": true,
}

// codexHeadlessSubcommands are the non-interactive codex subcommands that must
// take the bare launch path — the codex analogues of claude's `--print`: `exec`
// (and its `e` alias) and `review` (M6). Attaching to a one-shot scripted run
// would be spam.
var codexHeadlessSubcommands = map[string]bool{
	"exec": true, "e": true, "review": true,
}

// argsAreCodexHeadless reports whether a non-interactive codex subcommand
// (`exec`/`e`/`review`) leads the forwarded tool args — the codex analogue of
// claude's `--print`. It first skips ANY leading global flags with values
// (space-separated pairs via codexValueFlags, and every `flag=value` combined
// form), then treats the first BARE word as the subcommand. This generic
// "skip flags until the first bare word" scan is why `--model gpt exec` now
// classifies as headless: `--model`'s value `gpt` is consumed, so `exec` is
// correctly seen as the subcommand. A bare `--` boundary before any subcommand
// means the remainder is positional (no subcommand) → not headless. Headless
// runs are scripted paths, so default-on attach must not engage.
func argsAreCodexHeadless(args []string) bool {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--":
			// Tokens after a bare -- are positional; no subcommand precedes it.
			return false
		case codexValueFlags[a]:
			i += 2 // skip the flag and its separate value token
			continue
		case strings.HasPrefix(a, "-") && strings.Contains(a, "="):
			i++ // combined flag=value token (--config=… / -c=… / --model=…)
			continue
		case strings.HasPrefix(a, "-"):
			// A boolean or unknown global flag with no value token: skip it and
			// keep scanning for the subcommand rather than bailing out.
			i++
			continue
		default:
			return codexHeadlessSubcommands[a]
		}
	}
	return false
}
