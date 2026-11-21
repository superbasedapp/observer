//go:build !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/execevidence"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termoob"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_launch.go holds the cmd-side adapters the terminal application
// service (internal/termsvc) depends on: the persistence recorder over
// internal/store, and the PTY launcher over internal/termsession that also
// allocates + drains the trusted out-of-band control channel (internal/termoob,
// plan §2.1b / F1). termsvc speaks internal/termrun's pure types; these
// adapters translate to the store's row types and to the termsession spec.

// termRunRecorder persists run identity + correlations for termsvc.
type termRunRecorder struct{ st *store.Store }

func (r termRunRecorder) RecordRun(ctx context.Context, run termrun.Run) error {
	return r.st.InsertTerminalRun(ctx, store.TerminalRun{
		RunID:                run.RunID,
		Tool:                 run.Tool,
		Kind:                 string(run.Kind),
		SourceSessionID:      run.SourceSessionID,
		ProjectRootHash:      run.ProjectRootHash,
		CorrelationTokenHash: run.CorrelationTokenHash,
		LaunchedAt:           run.LaunchedAt,
		Isolation:            runIsolationRecord(run),
		// Lane cli-2 (migration 220): only the closed set is recorded.
		Initiator:       string(run.Origin.Normalized().Initiator),
		ParentSessionID: run.Origin.Normalized().ParentSessionID,
	})
}

// runIsolationRecord turns a run's G19 isolation evidence into its stored
// row and seals the execution evidence envelope over it (sandbox plan v2
// section 8.4, roadmap F0-13). A run that recorded nothing stores nothing,
// not even a digest. An envelope that does not validate (an unknown enum
// slipped through) keeps its facts but gets no digest, so nothing can cite
// evidence that was never valid.
func runIsolationRecord(run termrun.Run) store.TerminalRunIsolation {
	iso := run.Isolation
	rec := store.TerminalRunIsolation{
		Class: iso.Class, Stack: iso.Stack, EgressTier: iso.EgressTier,
		CaptureLevel: iso.CaptureLevel, CaptureRule: iso.CaptureRule,
		CaptureOrigin: iso.CaptureOrigin, CaptureDegraded: iso.CaptureDegraded,
		NativeSandboxState: iso.NativeSandboxState, Verification: iso.Verification,
		KeyCustody: iso.KeyCustody, Seccomp: iso.Seccomp,
	}
	if iso.Class == "" && iso.CaptureLevel == "" && iso.CaptureOrigin == "" {
		return rec
	}
	component := "terminals"
	if len(iso.Stack) > 0 {
		component = "terminals.sandbox"
	}
	env := isolationEnvelope(run.RunID, component, version, rec)
	if d, err := env.Seal(); err == nil {
		rec.EvidenceDigest = d
		rec.EvidenceProducer = string(env.Producer.Kind)
		rec.EvidenceComponent = env.Producer.Component
		rec.EvidenceComponentVersion = env.Producer.ComponentVersion
	}
	return rec
}

// isolationEnvelope is the execution evidence envelope of a stored run's
// isolation facts, sealed under the given producer (one builder, so the
// launch seal and a later reseal cover the same fields).
func isolationEnvelope(runID, component, componentVersion string, iso store.TerminalRunIsolation) execevidence.Envelope {
	return execevidence.Envelope{
		RunID:    runID,
		Producer: execevidence.Producer{Kind: execevidence.KindTerminalRun, Component: component, ComponentVersion: componentVersion},
		Isolation: execevidence.Isolation{
			Class: vocab.IsoClass(iso.Class), Stack: iso.Stack, EgressTier: vocab.Tier(iso.EgressTier),
			CaptureLevel: vocab.CaptureLevel(iso.CaptureLevel), CaptureRule: iso.CaptureRule,
			GatewayGuarded: iso.CaptureRule == "C6" && iso.CaptureLevel == string(vocab.CaptureFull),
			CaptureOrigin:  vocab.CaptureOrigin(iso.CaptureOrigin), CaptureDegraded: iso.CaptureDegraded,
			NativeSandboxState: vocab.NativeSandboxState(iso.NativeSandboxState),
			Verification:       vocab.Verification(iso.Verification), KeyCustody: vocab.KeyCustody(iso.KeyCustody),
		},
	}
}

// resealRunEvidence is the digest of a stored run's evidence after its
// capture was lowered (store.LowerTerminalRunCapture): the envelope is
// rebuilt from the row, under the producer the row recorded at launch
// (never this build's), so the digest can still be recomputed from the
// row. An envelope that does not validate gets no digest.
func resealRunEvidence(runID string, iso store.TerminalRunIsolation) string {
	if iso.EvidenceProducer != string(execevidence.KindTerminalRun) {
		return ""
	}
	d, err := isolationEnvelope(runID, iso.EvidenceComponent, iso.EvidenceComponentVersion, iso).Seal()
	if err != nil {
		return ""
	}
	return d
}

func (r termRunRecorder) EndRun(ctx context.Context, runID string, endedAt time.Time, exitCode int, reason string) error {
	return r.st.EndTerminalRun(ctx, runID, endedAt, exitCode, reason)
}

func (r termRunRecorder) RecordCorrelation(ctx context.Context, c termrun.Correlation) error {
	return r.st.UpsertCorrelation(ctx, store.TerminalCorrelation{
		RunID:      c.RunID,
		SessionID:  c.SessionID,
		Confidence: c.Confidence,
		Source:     string(c.Source),
		ObservedAt: c.ObservedAt,
	})
}

// configArgAlreadyPresent reports whether an argv slice already expresses its own
// `--config`. It stops at the first bare `--`: everything after that separator
// belongs to the launched TOOL, so a tool's own `--config` must not suppress the
// daemon's (the two flags address different programs).
func configArgAlreadyPresent(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--config" || strings.HasPrefix(a, "--config=") {
			return true
		}
	}
	return false
}

// launchConfigArgs returns the `--config <path>` tokens a daemon-spawned
// `observer <verb>` launch should carry, or nil when it should carry none.
//
// The decision is capability-shaped, never tool-shaped (CLAUDE.md #3): EVERY
// launcher verb in the capability registry accepts `--config` (verified against
// the built binary's own flag sets, 2026-09-03), so the only two questions are
// whether the daemon HAS an explicit path to propagate and whether the caller
// already expressed one. The attach path composes its own `--proxy`/`--config`
// overrides into ExtraArgs; those win, because they are the CLI client's
// deliberate per-launch intent rather than the daemon-wide default.
func launchConfigArgs(cfgPath string, extraArgs []string) []string {
	if cfgPath == "" || configArgAlreadyPresent(extraArgs) {
		return nil
	}
	return []string{"--config", cfgPath}
}

// launchExtraArgs composes the ExtraArgs a spawn hands termsession: the daemon's
// `--config` propagation PREFIXED to the caller's own tokens.
//
// Prefixed, never appended: ExtraArgs can end in a bare `--` remainder destined
// for the tool (`-- --model X`) or a native resume tail, and a flag appended past
// that separator would be handed to the TOOL instead of to `observer <verb>`.
// The prefix lands immediately after the subcommand (and after a handoff's
// `--continue-from <id>`), which every launcher's flag parser accepts.
//
// Shell and SSH launches are unaffected by construction, not by a branch here:
// termsession.Spec.argv() ignores ExtraArgs entirely for SpecShell/SpecSSH, so
// the `shell` pseudo-tool can never receive an `observer` flag.
func launchExtraArgs(extraArgs []string) []string {
	add := launchConfigArgs(daemonConfigPath(), extraArgs)
	if len(add) == 0 {
		return extraArgs
	}
	return append(add, extraArgs...)
}

// ptyLauncher implements termsvc.Launcher over *termsession.Manager. It
// allocates the trusted OOB control-channel pipe, hands the child the write end
// at fd 3 (via ExtraFiles), keeps + drains the read end on a goroutine, and
// builds the server-derived termsession spec.
type ptyLauncher struct {
	mgr     *termsession.Manager
	binPath string
	feed    *termfeed.Feed
	logger  *slog.Logger
	// correlate is the production run->session correlation seam (P2-1). When the
	// launcher wrapper announces the child's agent session id on the TRUSTED OOB
	// channel (termoob.TypeSession), drainOOB records it here at oob confidence.
	// Wired to termsvc.Service.Correlate in buildTerminalStack; nil disables
	// correlation (the drain still runs — it just doesn't establish links).
	correlate func(ctx context.Context, runID, sessionID string, source termrun.Source, at time.Time) error
}

// argvModeTable maps a run KIND onto the termsession argv SHAPE (CLAUDE.md #5 —
// a data table, not an if-ladder). Fresh, attach, AND resume all launch a BARE
// `observer <sub>` base: a fresh launch has no continuation, an attach launch
// carries only routing escape-hatch ExtraArgs, and a resume's native `--resume
// <id>` tail rides in ExtraArgs (so it must NOT get the handoff --continue-from
// prefix — claude/codex reject `--continue-from … --resume …` together, F2).
// Only a handoff launch takes --continue-from.
var argvModeTable = map[termrun.Kind]termsession.ArgvMode{
	termrun.KindFresh:   termsession.ArgvModeFresh,
	termrun.KindAttach:  termsession.ArgvModeFresh,
	termrun.KindResume:  termsession.ArgvModeFresh,
	termrun.KindHandoff: termsession.ArgvModeHandoff,
}

// argvModeForKind resolves a run kind to its argv shape. An unlisted kind falls
// back to ArgvModeHandoff (the zero value), the more restrictive default — it
// requires a SessionID, so a mis-mapped kind fails closed at Create rather than
// silently launching a bare agent.
func argvModeForKind(kind termrun.Kind) termsession.ArgvMode {
	return argvModeTable[kind]
}

// resolveShellArgv (the server-derived SpecShell argv: the daemon's own $SHELL
// with a per-OS fallback ladder) lives in terminal_launch_shell.go, where the
// OS and its I/O are injected so both ladders are table-tested.

// Spawn starts a PTY-backed launcher for a validated request and returns its
// opaque handle. It is the single place the OOB FD is allocated: after the
// child is spawned the daemon closes its own copy of the write end so the read
// end reports EOF when the child exits, and a goroutine drains framed OOB
// signals (which the launcher wrapper begins emitting in F3).
func (l *ptyLauncher) Spawn(req termsvc.LaunchRequest) (string, error) {
	// A sandboxed run's relay record learns the stored run it belongs to,
	// so the relay can lower that run's capture evidence (lane sbx-p2c).
	if req.Sandboxed {
		bindSandboxRelayRun(req.WrapArgv, req.RunID)
	}
	authToken, err := termoob.NewSessionToken()
	if err != nil {
		return "", err
	}
	oobRead, oobWrite, err := os.Pipe()
	if err != nil {
		return "", err
	}

	spec := termsession.Spec{
		BinPath:    l.binPath,
		Subcommand: req.Subcommand,
		// The run KIND selects the argv SHAPE through argvModeForKind (below): a
		// fresh, attach, OR native-resume launch is a bare `observer <sub>` base
		// (a resume's `--resume <id>` tail rides in ExtraArgs), and only a
		// handoff launch takes the --continue-from argv. Table, not a boolean —
		// a resume is NOT "fresh", it just shares the fresh base argv (F2).
		ArgvMode:    argvModeForKind(req.Kind),
		SessionID:   req.SessionID,
		Carry:       req.Carry,
		FromMessage: req.FromMessage,
		Rows:        req.Rows,
		Cols:        req.Cols,
		Dir:         req.Dir,
		Env:         launchChildEnv(req, authToken),
		ExtraFiles:  []*os.File{oobWrite},
		// Attach launches carry the CLI client's allow-listed argv (routing
		// escape hatch + `--` tool remainder) so the inner `observer <sub>`
		// self-configures exactly like a bare launch (B2/B3). Dashboard
		// fresh/handoff launches carry none of their own — but EVERY launch
		// gets the daemon's `--config` propagation prefixed here
		// (launchExtraArgs), so a child resolves the same proxy port and DB
		// the daemon did instead of re-deriving them from the default path.
		ExtraArgs: launchExtraArgs(req.ExtraArgs),
		// B9 Seam-B application (plan §1/§3/D2): the bwrap wrapper prefix the
		// Sandboxer resolved. termsession.Spec.argv() prepends it before
		// [BinPath, Subcommand, ...ExtraArgs], so the whole inner `observer
		// <verb>` launch runs inside the isolation boundary. Empty for every
		// non-sandboxed launch → argv byte-identical to today.
		WrapArgv: req.WrapArgv,
		// A sandboxed run's OSC 52 clipboard sequences are removed from its
		// output (ruling P-175) unless [terminal.sandbox].allow_osc52_clipboard.
		StripOSC52: sandboxStripsOSC52(req.Sandboxed, req.SandboxAllowOSC52),
	}
	if len(req.SSHArgv) > 0 {
		// An outbound SSH remote-system session (plan §2). Like SpecShell it
		// runs no `observer <sub>` at all — SpecSSH carries its own
		// server-derived argv, composed by internal/sshprofile from an
		// operator-authored config profile. It deliberately does NOT take
		// WrapArgv: bwrap would blind the known_hosts / key file / agent
		// socket ssh needs (see termsession.SpecSSH).
		spec.Kind = termsession.SpecSSH
		spec.SSHArgv = req.SSHArgv
	} else if req.IsShell {
		// A plain-shell fresh launch runs no `observer <sub>` at all — SpecShell
		// carries its own server-derived argv (resolveShellArgv), ignoring
		// BinPath/Subcommand/ArgvMode/SessionID entirely (see Spec.argv()).
		spec.Kind = termsession.SpecShell
		spec.ShellArgv = resolveShellArgv()
	}
	handle, cerr := l.mgr.Create(spec)
	// Close the daemon's copy of the write end unconditionally: the child has
	// its own dup (on success), and on failure it frees the pipe.
	_ = oobWrite.Close()
	if cerr != nil {
		_ = oobRead.Close()
		return "", cerr
	}
	if note := sandboxOSC52Notice(req.Sandboxed, req.SandboxAllowOSC52); note != "" {
		l.mgr.Notice(handle, note+"\r\n")
	}
	go l.drainOOB(req.RunID, req.Tool, oobRead, authToken)
	// A sandbox driver whose PTY child cannot inherit the pipe above (the
	// ConPTY child on Windows inherits no handles) hands its own OOB
	// stream instead (lane SBX-P6, sandbox plan section 5.6); none for
	// every other launch.
	if req.Sandboxed {
		if src, ok := sandboxOOBSourceFor(req.WrapArgv); ok {
			go l.drainOOB(req.RunID, req.Tool, src, authToken)
		}
	}
	l.auditEnv(req, spec.Env)
	return handle, nil
}

// launchChildEnv builds the child environment: the daemon env with any stale
// OOB variables stripped (defence — a nested launch must never inherit a
// parent's channel), plus the request's ExtraEnv, plus this launch's fresh OOB
// variables.
//
// The ExtraEnv append is load-bearing for the attach path: LaunchRequest.
// ExtraEnv carries the attach launcher's proxy-routing variables, and dropping
// it here (the pre-2026-07-19 bug) silently voided them. ExtraEnv is layered
// AFTER the inherited env (so an explicit routing var the launcher chose wins
// over a stale inherited one) and BEFORE the OOB vars (which are internal and
// must never be overridden by a caller-supplied entry).
//
// NOTE (deviation from a strict allow-list, plan §F1): a coding agent
// legitimately needs the operator's provider env (API keys it uses to talk to
// its model), so a hard allow-list would break every launched tool. The
// daemon, when started via `observer start`, runs with the user's own shell
// env (observer keeps its own secrets in config files, not env), so the
// residual exposure is the user's own env — which the agent needs anyway. We
// therefore strip only the internal OOB channel variables and emit a per-launch
// env audit line. A tighter policy is a documented follow-up. The one other
// strip is an agent session's marker (isAgentSessionMarkerEnv, lane cli-2
// fixes-3, audit L4): it names whoever started the daemon, not this terminal.
//
// CREDENTIAL-BEARING: req.ExtraEnv may include the caller's forwarded provider-
// credential values (forwardAuthEnv, gated by [terminal.attach].forward_auth_env)
// layered last-wins over the inherited env. Never log or persist these values —
// the env audit line (l.auditEnv) records key NAMES + counts only, never values.
func launchChildEnv(req termsvc.LaunchRequest, authToken string) []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+len(req.ExtraEnv)+6)
	for _, kv := range parent {
		if isInternalChildEnv(kv) || isAgentSessionMarkerEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	// The inherited env describes whoever started the daemon, not the xterm.js
	// emulator this child is attached to: advertise the emulator's color
	// capabilities so auto-detecting programs do not print monochrome (see
	// terminal_color_env.go). Layered BEFORE ExtraEnv so a deliberate caller
	// value still wins.
	out = terminalColorEnv(out, runtime.GOOS == "windows")
	// Caller-supplied extra env (attach proxy-routing vars). Defensively drop
	// any OBSERVER_OOB_ / OBSERVER_DAEMON_CHILD entry so the internal channel and
	// the daemon-child marker can't be spoofed in by a caller.
	for _, kv := range req.ExtraEnv {
		if isInternalChildEnv(kv) || isAgentSessionMarkerEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	// PATH parity (audit DI-04b): the child EXECUTES with the merged PATH the
	// daemon RESOLVED the tool on, so a binary that was only reachable through
	// the operator's login shell can actually run — an `#!/usr/bin/env node`
	// shim otherwise starts fine and dies at exit 127. Layered AFTER ExtraEnv
	// (a caller that set PATH explicitly still gets its dirs kept, widened) and
	// BEFORE the internal OOB vars. Strictly additive: every daemon PATH entry
	// survives in order, and a launch with nothing grounded to add is a no-op.
	out = applyChildPATH(out, launchLoginPathDirs(req.LoginPathDirs), req.BinPath)
	out = append(
		out,
		// Infallible daemon-child marker (H1): set on EVERY spawned child so an
		// inner launcher never re-attaches even when its OOB channel is dead.
		envDaemonChild+"=1",
		envOOBFD+"=3", // ExtraFiles[0] → fd 3 in the child
		envOOBAuth+"="+authToken,
		envOOBCorr+"="+req.CorrelationToken,
		envOOBTool+"="+req.Tool,
		envOOBRun+"="+req.RunID,
	)
	// B9 (plan §6): when this launch runs inside the bwrap boundary, stamp the
	// sandbox marker so the hook lane can honestly set Event.Caps.Sandboxed. It
	// is set here AND stripped from inherited/caller env by isInternalChildEnv,
	// so a user env can never spoof OBSERVER_SANDBOX=1 into a non-sandboxed
	// child (U9 finding). Never set on an unsandboxed launch → honest zero.
	if req.Sandboxed {
		out = sandboxTierChildEnv(out, req.WrapArgv)
		// The names the box's allow-list adds (WINFIX2, ledger SBX-WIN-ENV-1).
		out = sandboxLaunchEnv(out, req)
		// A sandboxed launch in a managed clone: the inner launcher's
		// repository trust check honours the source repository's accepts.
		out = append(out, repoTrustChildEnv(req.SourceDir)...)
	}
	// Windows env keys are case-insensitive, so the layering above can leave
	// both `Path=` (inherited) and `PATH=` (ExtraEnv) in one block and "last
	// wins" stops being true. Branching on runtime.GOOS here is a PLATFORM
	// CAPABILITY test (how the OS keys an environment block), not a tool or
	// caller identity — see dedupEnvWindows.
	if runtime.GOOS == "windows" {
		return dedupEnvWindows(out)
	}
	return out
}

// setupChildEnv builds the environment for a SETUP session (CreateSetup) — the
// one daemon-child path that does NOT go through termsvc/ptyLauncher, so it
// bypasses launchChildEnv. It is the daemon's own env (a setup command like the
// Tailscale operator grant needs a sane PATH/TERM), with any internal child vars
// stripped (defence against spoofing), PLUS the infallible OBSERVER_DAEMON_CHILD
// marker. A setup session has no OOB channel (no LaunchRequest), so it carries
// ONLY the marker — not the OOB fd/auth vars — which keeps the invariant "every
// daemon child carries the marker" true for the setup path too (finding: marker
// completeness). Recursion via a setup command is currently unreachable (the
// argv is a fixed, server-derived command), so the marker here is belt-and-
// suspenders that makes the invariant claim honest rather than aspirational.
func setupChildEnv() []string { return setupChildEnvFor("") }

// setupChildEnvFor is setupChildEnv for a setup command whose PROGRAM the
// daemon has already resolved to an absolute path (the guided tool install:
// dashboardInstallPlanFor resolves `npm` / `bash` / `uv` over the merged PATH).
// It widens the setup PTY's PATH the same way a tool launch is widened (audit
// DI-04a/b) so the installer itself — an npm shim needing node, a vendor script
// needing curl from a login-only dir — can run on a daemon whose own PATH is
// narrower than the operator's shell. binPath "" adds only the login-only dirs;
// a daemon with none of those is unchanged.
func setupChildEnvFor(binPath string) []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+1)
	for _, kv := range parent {
		if isInternalChildEnv(kv) || isAgentSessionMarkerEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	// A setup session renders in the same xterm.js emulator as a launch.
	out = terminalColorEnv(out, runtime.GOOS == "windows")
	out = applyChildPATH(out, daemonLoginPathDirs(), binPath)
	out = append(out, envDaemonChild+"=1")
	// Same Windows case-insensitive-key hardening as launchChildEnv.
	if runtime.GOOS == "windows" {
		return dedupEnvWindows(out)
	}
	return out
}

// auditEnv logs one metadata-only line per launch: the var count and the
// launch's identity (no values). This is the plan §F1 per-launch env audit.
func (l *ptyLauncher) auditEnv(req termsvc.LaunchRequest, env []string) {
	if l.logger == nil {
		return
	}
	l.logger.Info("terminal launch: spawned",
		"run", req.RunID, "tool", req.Tool, "kind", string(req.Kind),
		"env_vars", strconv.Itoa(len(env)), "dir_set", req.Dir != "")
}

// drainOOB reads framed OOB signals from the child on a daemon goroutine. In
// F1 the launcher wrapper does not yet emit (that is F3), so this typically
// just blocks until the child exits (EOF). When frames do arrive it publishes
// them to the status feed as TRUSTED events (the channel is authenticated and
// unforgeable — §2.1b). Any framing violation poisons the decoder (fail-closed)
// and ends the drain; it never affects the PTY session.
func (l *ptyLauncher) drainOOB(runID, tool string, r io.ReadCloser, authToken string) {
	defer func() { _ = r.Close() }()
	dec := termoob.NewDecoder(r, authToken)
	for {
		frame, err := dec.Read()
		if err != nil {
			if !errors.Is(err, io.EOF) && l.logger != nil {
				l.logger.Debug("terminal oob: drain ended", "run", runID, "err", err)
			}
			return
		}
		l.publishOOB(runID, tool, frame)
	}
}

// oobSessionSourceToTermrun maps a Session frame's optional Source hint onto the
// correlation Source the daemon records (CLAUDE.md #5 — a data table, not an
// if-ladder; #3 — dispatch on the frame's declared capability, never on which
// tool sent it). Only KNOWN mappings live here. An EMPTY hint is the back-compat
// known-id case (the launcher KNEW the id: claude's forced `--session-id`, a
// codex `--resume` short-circuit) → SourceOOB; a value IN this table maps to its
// class; a non-empty value NOT in this table is an evidence class this daemon
// does not know and is REFUSED (never guessed) — see termrunSourceForFrame.
var oobSessionSourceToTermrun = map[string]termrun.Source{
	termoob.SessionSourceDiscovered: termrun.SourceDiscovered,
}

// termrunSourceForFrame resolves a Session frame's Source hint to the
// correlation Source the daemon records, returning ok=false when the hint is an
// UNKNOWN non-empty value. An empty hint is the back-compat known-id echo →
// (SourceOOB, true); a hint in oobSessionSourceToTermrun maps to its class (e.g.
// "discovered" → SourceDiscovered, true); anything else — a weaker evidence
// class a NEWER launcher might emit against an OLDER daemon (in-place upgrade) —
// returns ("", false) so the caller SKIPS the correlation rather than promoting
// unknown evidence to full OOB confidence (R2-6).
func termrunSourceForFrame(frameSource string) (termrun.Source, bool) {
	if frameSource == "" {
		return termrun.SourceOOB, true
	}
	if s, ok := oobSessionSourceToTermrun[frameSource]; ok {
		return s, true
	}
	return "", false
}

// publishOOB turns a trusted OOB frame into a status-feed event (F4 consumes
// it) and, for a session-announce frame, records the run->session correlation
// at the confidence its Source hint implies (P2-1 — the ONE production caller of
// the correlation seam). A KNOWN-id echo (empty hint) records at oob confidence;
// a heuristically-DISCOVERED id (Source="discovered") records at the lower
// SourceDiscovered confidence, so a later known-id OOB echo strictly upgrades
// it. Unknown frame types are ignored (forward-compat).
func (l *ptyLauncher) publishOOB(runID, tool string, frame termoob.Frame) {
	if frame.Type == termoob.TypeSession {
		// The launcher learned the child's agent session id (by forcing it, or
		// by heuristic discovery) and echoed it on the authenticated channel.
		// Establish the run->session link at the confidence the frame's Source
		// hint implies so Snapshot's SessionForRun can surface it for "Jump in"
		// — the production path that populates termsvc's bySession map.
		if frame.Session == nil || frame.Session.SessionID == "" {
			return
		}
		source, known := termrunSourceForFrame(frame.Session.Source)
		if !known {
			// An unknown, non-empty evidence class (e.g. a newer launcher emitting
			// a weaker source string to an older daemon after an in-place upgrade).
			// SKIP the correlation entirely rather than guess a confidence for a
			// class this daemon doesn't understand — and skip the feed event too,
			// since we can't trust the id's provenance (R2-6).
			if l.logger != nil {
				l.logger.Warn("terminal oob: skipping session correlation for unknown source class",
					"run", runID, "tool", tool, "source", frame.Session.Source)
			}
			return
		}
		if l.correlate != nil {
			if err := l.correlate(context.Background(), runID, frame.Session.SessionID, source, time.Now().UTC()); err != nil && l.logger != nil {
				l.logger.Debug("terminal oob: correlate failed", "run", runID, "err", err)
			}
		}
		if l.feed != nil {
			l.feed.Publish(termfeed.Event{
				Kind: "oob:session", RunID: runID, Tool: tool, SessionID: frame.Session.SessionID,
				Trust: termfeed.TrustTrusted, At: time.Now().UTC(),
			})
		}
		return
	}
	if l.feed == nil {
		return
	}
	switch frame.Type {
	case termoob.TypeHello:
		l.feed.Publish(termfeed.Event{
			Kind: "oob:hello", RunID: runID, Tool: tool,
			Trust: termfeed.TrustTrusted, At: time.Now().UTC(),
		})
	case termoob.TypeLifecycle:
		if frame.Lifecycle != nil {
			ev := termfeed.Event{
				Kind: "oob:" + string(frame.Lifecycle.Phase), RunID: runID, Tool: tool,
				Trust: termfeed.TrustTrusted, At: time.Now().UTC(),
			}
			if c := frame.Lifecycle.Count; c != nil && *c > 0 {
				ev.Count = *c
			}
			l.feed.Publish(ev)
		}
	}
}
