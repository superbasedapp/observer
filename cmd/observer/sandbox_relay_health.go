//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandbox_relay_health.go carries a relay run's capture health to the
// run's evidence (sandbox plan v2 sections 5.2 and 8.4, plans decision log
// P-032, lane sbx-p2c): the launcher binds the relay run to the stored
// terminal run it spawns, the daemon's relay handler lowers that row
// (capture_degraded, the causes, the missed heartbeats, the evidence digest
// resealed) each time the run's health changes, and the run pill reads the
// same health while the run is live. The host helper verifies the box's
// hook registration from the host side (relayHookProbe).

// bindSandboxRelayRun records, in the relay run record a sandboxed launch's
// wrap argv names, the stored terminal run being spawned. A launch with no
// relay binds nothing; a bind that fails leaves the run's health in the
// relay handler and the log only.
func bindSandboxRelayRun(wrapArgv []string, runID string) {
	relayRun, observerDir, ok := sandbox.RelayOfWrap(wrapArgv)
	for _, of := range sandboxWrapRelays {
		if ok {
			break
		}
		relayRun, observerDir, ok = of(wrapArgv)
	}
	if !ok || runID == "" {
		return
	}
	if err := sandboxrelayd.BindTerminalRun(observerDir, relayRun, runID); err != nil {
		slog.Default().Warn("sandbox relay: the run's capture health will not reach its evidence", "run", runID, "err", err)
	}
}

// sandboxWrapRelays read the relay run from a driver's own wrap argv (a
// driver whose PTY child is not a sandbox-host command, the MXC driver's
// sandbox-mxc-host, registers one from init; lane SBX-P6).
var sandboxWrapRelays []func(wrapArgv []string) (runID, observerDir string, ok bool)

// sandboxOOBSources give the launcher a driver's own OOB stream for a wrap
// argv, where the PTY child cannot inherit the OOB pipe (the ConPTY child
// on Windows, sandbox plan section 5.6); none matches every wrap argv of a
// build without such a driver.
var sandboxOOBSources []func(wrapArgv []string) (io.ReadCloser, bool)

// sandboxOOBSourceFor is the first registered OOB source for wrapArgv.
func sandboxOOBSourceFor(wrapArgv []string) (io.ReadCloser, bool) {
	for _, src := range sandboxOOBSources {
		if r, ok := src(wrapArgv); ok {
			return r, true
		}
	}
	return nil, false
}

// relayHealthByRun is the live health of each sandboxed terminal run whose
// capture was lowered, keyed by terminal run id (the run pill's source and
// the floor sweep's; the stored row is the durable record). An entry goes
// when the daemon ends the relay run (relayOnRunEnd, from the run-end
// sweep), so the map holds only live runs (P-040).
var relayHealthByRun sync.Map

// relayRunHealth is one relayHealthByRun entry: the relay run (the floor
// sweep ends it by its records) and its latest health.
type relayRunHealth struct {
	run    sandboxrelayd.RunRecord
	health sandboxrelayd.Health
}

// relayOnRunEnd is the daemon relay handler's OnRunEnd: the ended run's
// live health is dropped (the stored row keeps the record).
func relayOnRunEnd(run sandboxrelayd.RunRecord) {
	if run.TerminalRunID != "" {
		relayHealthByRun.Delete(run.TerminalRunID)
	}
	relayEndedByFloor.Delete(run.RunID)
	relayRunEnded(run.RunID)
}

// relayLowerTimeout bounds one evidence write.
const relayLowerTimeout = 5 * time.Second

// relayOnHealth is the daemon relay handler's OnHealth: it keeps the live
// health for the pill and lowers the stored run through lower.
func relayOnHealth(lower func(ctx context.Context, terminalRunID string, h store.TerminalRunCaptureHealth) error, logger *slog.Logger) func(sandboxrelayd.RunRecord, sandboxrelayd.Health) {
	return func(run sandboxrelayd.RunRecord, h sandboxrelayd.Health) {
		if logger != nil {
			logger.Warn("sandbox relay: the run's capture is degraded", "relay_run", run.RunID, "causes", h.CauseList(), "missed_heartbeats", h.MissedHeartbeats)
		}
		if run.TerminalRunID == "" {
			return
		}
		relayHealthByRun.Store(run.TerminalRunID, relayRunHealth{run: run, health: h})
		if lower == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), relayLowerTimeout)
		defer cancel()
		if err := lower(ctx, run.TerminalRunID, store.TerminalRunCaptureHealth{Causes: h.CauseList(), MissedHeartbeats: h.MissedHeartbeats}); err != nil && logger != nil {
			logger.Warn("sandbox relay: record the run's degraded capture", "run", run.TerminalRunID, "err", err)
		}
	}
}

// relayPillHealth adds a live run's degraded capture to its pill.
func relayPillHealth(iso *dashapi.LaunchIsolation, runID string) {
	if iso == nil || runID == "" {
		return
	}
	v, ok := relayHealthByRun.Load(runID)
	if !ok {
		return
	}
	rh, _ := v.(relayRunHealth)
	h := rh.health
	if !h.Degraded() {
		return
	}
	iso.CaptureDegraded = true
	for _, c := range h.Causes {
		iso.CaptureCauses = append(iso.CaptureCauses, string(c))
	}
}

// relayHookProbe reads the run's tool hook registration from the host side
// of the box's mount, through the same dry-run registration writer `observer
// doctor` uses (readHookHomeEvents), never from a guest report, and the
// hooks-off switches for the tool (relayHooksDisabled). nil for a tool with
// no hook mechanism (nothing to verify).
func relayHookProbe(run sandboxrelayd.RunRecord) func() (sandboxrelayd.HookRegistration, error) {
	if run.Tool == "" || !hookSupported(run.Tool) {
		return nil
	}
	binary, err := os.Executable()
	if err != nil {
		return nil
	}
	return func() (sandboxrelayd.HookRegistration, error) {
		out := sandboxrelayd.HookRegistration{Disabled: relayHooksDisabled(run)}
		homes := readHookHomeEvents(binary, run.ConfigPath, run.Tool)
		if len(homes) == 0 {
			return out, nil
		}
		h := homes[0]
		if h.err != nil {
			return sandboxrelayd.HookRegistration{}, h.err
		}
		out.Covered, out.Conflict = h.covered, h.conflict
		for ev := range h.present {
			out.Events = append(out.Events, ev)
		}
		slices.Sort(out.Events)
		return out, nil
	}
}

// relayHooksDisabled is every hooks-off switch (the hookdisable table, the
// one per-tool owner of which file and key turn a vendor's hooks off) set
// for the run's tool: the user and managed files, and the project files
// under the run's workspace and roots, which the box can write (sandbox plan
// P2 audit finding 1: a project settings.local.json with disableAllHooks).
func relayHooksDisabled(run sandboxrelayd.RunRecord) []string {
	home, _ := os.UserHomeDir()
	roots := append([]string{run.WorkspaceDir}, run.ReadRoots()...)
	var out []string
	for _, f := range hookdisable.Detect(diag.HookSwitchInputs(hookdisable.Options{Home: home, GOOS: runtime.GOOS, ProjectRoots: roots, ReadFile: diag.ReadHookSwitchFile})) {
		if slices.Contains(f.Tools, run.Tool) {
			out = append(out, f.SwitchID+"@"+f.Path)
		}
	}
	slices.Sort(out)
	return out
}

// relayGateDrift is the daemon's transcript-versus-gate comparison: what
// is compared comes from the run's tool's registry row
// (integration.SandboxSpec.GateDrift; a tool with none is not compared) and
// which events are gate events from its tool gate binding, never a tool
// name.
func relayGateDrift() *sandboxrelayd.GateDrift {
	return &sandboxrelayd.GateDrift{
		Spec: func(tool string) (integration.TranscriptGateSpec, bool) {
			c, ok := integration.For(tool)
			if !ok {
				return integration.TranscriptGateSpec{}, false
			}
			return c.Sandbox.GateDrift, c.Sandbox.GateDrift.Compared()
		},
		IsGate: relayRequestIsToolGate,
	}
}

// relayRequestIsToolGate reports whether a relayed hook request is its
// tool's tool gate event (the HookCapToolGate binding the hook command
// names).
func relayRequestIsToolGate(req sandboxrelay.HookRequest) bool {
	if req.Kind != sandboxrelay.KindHook || len(req.Args) < 2 {
		return false
	}
	b, ok := resolveHookInvocationBinding(req.Args[0], req.Args[1])
	return ok && b.Cap == integration.HookCapToolGate
}

// relayFloorEnd is what ending a run for a cause records and shows: the
// stored run's end reason (naming the org floor and the cause) and the final
// line the run's terminal shows (finding 5 of the SBX-P2E audit).
type relayFloorEnd struct {
	endReason string
	notice    string
}

// relayFullCaptureEndCauses are the capture causes that end a live run
// while the org's require_full_capture floor is in force (sandbox plan
// section 13.12 A10). Only hook drift ends a run: the run's gate events
// stopped arriving, so what it does next is not captured. A refused,
// rate-limited, replayed or dropped event, or a missed heartbeat, is the
// relay working or a single lost event the row already records; those
// lower the run's evidence and leave it running. A closed table: a later
// cause is added by a row, never a branch.
var relayFullCaptureEndCauses = map[sandboxrelayd.DegradedCause]relayFloorEnd{
	sandboxrelayd.CauseHooksDrifted: {
		endReason: store.EndReasonOrgFloorHooksDrifted,
		notice: "\r\n[observer] This sandboxed run was ended by your organization's sandbox floor \"Require full capture\": " +
			"the run's hooks drifted (its tool calls stopped reaching Observer's hooks), so its capture was no longer full.\r\n",
	},
}

// relayEndsUnderFullCapture reports the cause that ends a run with health h
// under the floors in force (requireFull), or "" when the run keeps going.
func relayEndsUnderFullCapture(h sandboxrelayd.Health, requireFull bool) sandboxrelayd.DegradedCause {
	if !requireFull {
		return ""
	}
	for _, c := range h.Causes {
		if _, ok := relayFullCaptureEndCauses[c]; ok {
			return c
		}
	}
	return ""
}

// relayEndedByFloor holds the relay run ids ended for a floor (and, while
// an end is being attempted, the run being ended), so a run is ended once
// however many later health changes or sweeps arrive. An entry is kept only
// when the end succeeded, so a failed end is retried on the run's next
// health change or the next floor publish; it goes with the run
// (relayOnRunEnd).
var relayEndedByFloor sync.Map

// relayRequireFullCapture reports whether the org's require_full_capture
// floor is in force now (a seam for tests).
var relayRequireFullCapture = func() bool {
	spec, ok := isolationFloorsInForce()
	return ok && spec.RequireFullCapture
}

// relayRunEnder ends a live daemon-launched terminal run by its stored run
// id, recording endReason on the run and showing notice as the terminal's
// last line first; false when there is no such live run here.
type relayRunEnder func(terminalRunID, endReason, notice string) bool

// relayFloorEnder returns the OnHealth step that ends a live terminal run
// whose capture drifted while require_full_capture is in force (endRun is
// the daemon's terminal teardown; nil: the daemon cannot end runs and the
// step only logs). It runs on the run's health delivery goroutine, never on
// the answer path.
func relayFloorEnder(endRun relayRunEnder, logger *slog.Logger) func(sandboxrelayd.RunRecord, sandboxrelayd.Health) {
	return func(run sandboxrelayd.RunRecord, h sandboxrelayd.Health) {
		relayEndForFloor(run, h, endRun, logger)
	}
}

// relayEndForFloor ends one run if its health ends it under the floors in
// force: the run is marked ended only when endRun says it ended it, and the
// warning says what actually happened.
func relayEndForFloor(run sandboxrelayd.RunRecord, h sandboxrelayd.Health, endRun relayRunEnder, logger *slog.Logger) {
	cause := relayEndsUnderFullCapture(h, relayRequireFullCapture())
	if cause == "" {
		return
	}
	if _, busy := relayEndedByFloor.LoadOrStore(run.RunID, true); busy {
		return
	}
	end := relayFullCaptureEndCauses[cause]
	ended := run.TerminalRunID != "" && endRun != nil && endRun(run.TerminalRunID, end.endReason, end.notice)
	if !ended {
		relayEndedByFloor.Delete(run.RunID)
	}
	if logger == nil {
		return
	}
	const msg = "sandbox relay: the run's capture is no longer full and your organization's sandbox setting \"Require full capture\" is in force"
	if ended {
		logger.Warn(msg+"; the run is ended", "relay_run", run.RunID, "terminal_run", run.TerminalRunID, "cause", cause, "end_reason", end.endReason)
		return
	}
	logger.Warn(msg+"; the run is NOT ended: this daemon holds no live terminal for it (a CLI sandboxed launch, or a run not yet bound), retried on its next health change or the next floor publish",
		"relay_run", run.RunID, "terminal_run", run.TerminalRunID, "cause", cause)
}

// relayFloorSweeper is the running relay's sweep of live runs that drifted
// before the floor arrived (nil until the relay serves; one owner,
// serveSandboxRelay).
var relayFloorSweeper atomic.Pointer[func()]

// relayFloorSweep returns the sweep over relayHealthByRun: every live run
// whose latest health ends it under the floors in force is ended now
// (finding 4 of the SBX-P2E audit: the ender acts on a health change, so a
// run that drifted before the floor was published would otherwise keep
// running until its health changed again).
func relayFloorSweep(endRun relayRunEnder, logger *slog.Logger) func() {
	return func() {
		relayHealthByRun.Range(func(_, v any) bool {
			if rh, ok := v.(relayRunHealth); ok {
				relayEndForFloor(rh.run, rh.health, endRun, logger)
			}
			return true
		})
	}
}

// relayFloorsApplied runs the relay's sweep (off the caller's goroutine)
// when a floor body that requires full capture is now in force; called by
// isolationFloorsPublish.
func relayFloorsApplied() {
	if !relayRequireFullCapture() {
		return
	}
	if f := relayFloorSweeper.Load(); f != nil {
		go (*f)()
	}
}

// relayHealthSteps runs each OnHealth step in order.
func relayHealthSteps(steps ...func(sandboxrelayd.RunRecord, sandboxrelayd.Health)) func(sandboxrelayd.RunRecord, sandboxrelayd.Health) {
	return func(run sandboxrelayd.RunRecord, h sandboxrelayd.Health) {
		for _, s := range steps {
			s(run, h)
		}
	}
}

// ---- ending a sandboxed CLI launch under the floor ---------------------------

// A sandboxed CLI launch (`observer <tool> --observer-sandbox`) runs in the
// user's own terminal, so the daemon holds no live terminal to close for it
// (terminalRunEnder answers false). It is ended the same way a dashboard run
// is (SBX-P2E audit item routed to the SBX-P3A merge): the daemon stamps the
// end reason on the run's row, then leaves an END REQUEST for the CLI process,
// which shows the same final line, hangs up its child (the terminal-closed
// path every host helper handles, so the box is torn down and the container
// stopped) and records the run's end with that reason. The request is left
// only for a launch whose CLI process marked itself as watching, so a
// dashboard run that is not yet bound is never mistaken for one.

// sandboxCLIEndDirName is the directory of the watch markers and end
// requests, under the relay's directory (owner-only).
const sandboxCLIEndDirName = "cli-end"

// sandboxCLIEndDir is that directory for observerDir.
func sandboxCLIEndDir(observerDir string) string {
	return filepath.Join(observerDir, sandboxrelayd.RelayDirName, sandboxCLIEndDirName)
}

// sandboxCLIRunIDRE is the shape of a terminal run id a marker or request may
// be named after.
var sandboxCLIRunIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{4,128}$`)

// sandboxCLIEndRequest is one end request: why, and the line to show.
type sandboxCLIEndRequest struct {
	EndReason string `json:"end_reason"`
	Notice    string `json:"notice"`
}

// sandboxCLIEndPaths returns the watch marker and the end request of runID.
func sandboxCLIEndPaths(observerDir, runID string) (watch, end string) {
	dir := sandboxCLIEndDir(observerDir)
	return filepath.Join(dir, runID+".watch"), filepath.Join(dir, runID+".end")
}

// sandboxCLIMarkerBody is a watch marker's content: the CLI process that
// watches the run, and a token naming that process's start
// (peerproc.StartToken: the boot id and start time on Linux, the creation
// time on Windows), so a pid reused after a reboot or by a later process
// is not read as the CLI (lane callerid, L1). A marker an older build wrote
// is empty (PID 0, unknown) or has no start ("": the pid alone decides).
type sandboxCLIMarkerBody struct {
	PID   int    `json:"pid"`
	Start string `json:"start,omitempty"`
}

// sandboxCLIProcessAlive reports whether the marker's CLI still runs: its
// pid is live and, when the marker recorded a start, the process at that
// pid is that same start.
func sandboxCLIProcessAlive(pid int, start string) bool {
	if pid <= 0 || !oneShotProcessAlive(pid) {
		return false
	}
	if start == "" {
		return true
	}
	now, ok := peerproc.StartToken(pid)
	return ok && now == start
}

// sandboxCLIMarkerMax bounds the marker a reader accepts.
const sandboxCLIMarkerMax = 4 << 10

// sandboxCLIMarkers lists the watch markers under observerDir: one per
// sandboxed CLI launch whose CLI marked itself as watching, with the PID it
// recorded (0 when unknown). Only regular files named after a well-formed
// run id count. A missing directory has none.
func sandboxCLIMarkers(observerDir string) []sandboxCLIMarker {
	if observerDir == "" {
		return nil
	}
	dir := sandboxCLIEndDir(observerDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []sandboxCLIMarker
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".watch")
		if !ok || !e.Type().IsRegular() || !sandboxCLIRunIDRE.MatchString(id) {
			continue
		}
		m := sandboxCLIMarker{RunID: id, Path: filepath.Join(dir, e.Name())}
		if f, err := os.Open(m.Path); err == nil { //nolint:gosec // G304: a regular file under the observer's own relay directory, name shape-checked
			var body sandboxCLIMarkerBody
			if json.NewDecoder(io.LimitReader(f, sandboxCLIMarkerMax)).Decode(&body) == nil && body.PID > 0 {
				m.PID, m.Start = body.PID, body.Start
			}
			_ = f.Close()
		}
		out = append(out, m)
	}
	return out
}

// cliMarkerFacts are what the sweep knows about one marker's run.
type cliMarkerFacts struct {
	// RowKnown: the run has a terminal_run row that recorded a sandbox.
	RowKnown bool
	// RowEndedForGood: that row records an end other than daemon_shutdown.
	// A graceful daemon stop stamps daemon_shutdown on every live
	// non-attach row while a CLI launch and its box keep running (P-074),
	// so that stamp alone never proves the box is gone (fixes-4, N1).
	RowEndedForGood bool
	// BoxLive: a relay run bound to it still has a live helper.
	BoxLive bool
	// PIDKnown / CLIAlive: the marker names a CLI process, and it runs.
	PIDKnown, CLIAlive bool
	// RowEnded: the row records any end, daemon_shutdown included.
	RowEnded bool
}

// cliMarkerRules decide whether a marker stays (the run counts as a live
// box for the loopback exposure gate) or is dropped as stale, walked
// top-down; the first deciding row wins (TestCLIMarkerRules). A live box or
// a live CLI keeps the marker before any end the row records is read, and
// every undecided case keeps it: an unseen live box would be an escape.
var cliMarkerRules = []struct {
	id     string
	decide func(f cliMarkerFacts) (keep, decided bool)
}{
	{"K1-no-sandboxed-row", func(f cliMarkerFacts) (bool, bool) { return false, !f.RowKnown }},
	{"K2-box-live", func(f cliMarkerFacts) (bool, bool) { return true, f.BoxLive }},
	{"K3-cli-alive", func(f cliMarkerFacts) (bool, bool) { return true, f.PIDKnown && f.CLIAlive }},
	{"K4-row-ended", func(f cliMarkerFacts) (bool, bool) { return false, f.RowEndedForGood }},
	{"K5-cli-and-box-gone", func(f cliMarkerFacts) (bool, bool) { return false, f.PIDKnown && !f.CLIAlive }},
	// An older build's marker names no CLI: with its box gone (K2 did not
	// keep it) and any end recorded, daemon_shutdown included, nothing
	// shows it is still running (lane callerid, L2).
	{"K6-unknown-cli-row-ended", func(f cliMarkerFacts) (bool, bool) { return false, !f.PIDKnown && f.RowEnded }},
	{"K7-unknown-cli", func(cliMarkerFacts) (bool, bool) { return true, true }},
}

// cliMarkerKeep walks cliMarkerRules for one marker.
func cliMarkerKeep(f cliMarkerFacts) (keep bool, rule string) {
	for _, r := range cliMarkerRules {
		if k, ok := r.decide(f); ok {
			return k, r.id
		}
	}
	return true, ""
}

// sweepSandboxCLIMarkers removes the markers (and any end request) that the
// rules call stale and returns the ones that stay. rows holds the sandboxed
// terminal_run rows of the markers' runs, ended or not; alive and boxLive
// are the process and helper probes.
func sweepSandboxCLIMarkers(observerDir string, markers []sandboxCLIMarker, rows map[string]cliRunState, alive func(pid int, start string) bool, boxLive func(runID string) bool) []sandboxCLIMarker {
	var kept []sandboxCLIMarker
	for _, m := range markers {
		row, known := rows[m.RunID]
		f := cliMarkerFacts{RowKnown: known, RowEndedForGood: known && row.endedForGood(), RowEnded: known && row.Ended, PIDKnown: m.PID > 0}
		if known {
			f.BoxLive = boxLive(m.RunID)
			if f.PIDKnown {
				f.CLIAlive = alive(m.PID, m.Start)
			}
		}
		if keep, _ := cliMarkerKeep(f); keep {
			kept = append(kept, m)
			continue
		}
		_, end := sandboxCLIEndPaths(observerDir, m.RunID)
		_ = os.Remove(m.Path)
		_ = os.Remove(end)
	}
	return kept
}

// sandboxCLIMarkerSweeper binds the sweep to observerDir and the real
// probes (the CLI process, the run's relay helper).
func sandboxCLIMarkerSweeper(observerDir string) func(markers []sandboxCLIMarker, rows map[string]cliRunState) []sandboxCLIMarker {
	return func(markers []sandboxCLIMarker, rows map[string]cliRunState) []sandboxCLIMarker {
		return sweepSandboxCLIMarkers(observerDir, markers, rows, sandboxCLIProcessAlive, func(runID string) bool {
			return sandboxrelayd.TerminalRunLive(observerDir, runID)
		})
	}
}

// relayCLIRunEnder is the floor ender for a sandboxed CLI launch: false when
// no CLI process watches terminalRunID; otherwise the end reason is stamped
// on the row (stamp may be nil) and the end request written, create-only (an
// existing one is the same request), and true is returned.
func relayCLIRunEnder(observerDir string, stamp func(ctx context.Context, runID, reason string) error, logger *slog.Logger) relayRunEnder {
	return func(terminalRunID, endReason, notice string) bool {
		if observerDir == "" || !sandboxCLIRunIDRE.MatchString(terminalRunID) {
			return false
		}
		watch, end := sandboxCLIEndPaths(observerDir, terminalRunID)
		if fi, err := os.Lstat(watch); err != nil || !fi.Mode().IsRegular() {
			return false
		}
		if stamp != nil && endReason != "" {
			ctx, cancel := context.WithTimeout(context.Background(), terminalEndStampTimeout)
			err := stamp(ctx, terminalRunID, endReason)
			cancel()
			if err != nil && logger != nil {
				logger.Warn("terminal: record why the sandboxed CLI run is ended", "run", terminalRunID, "end_reason", endReason, "err", err)
			}
		}
		b, err := json.Marshal(sandboxCLIEndRequest{EndReason: endReason, Notice: notice})
		if err != nil {
			return false
		}
		f, err := os.OpenFile(end, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed name under the daemon's own relay directory, run id shape-checked
		if errors.Is(err, fs.ErrExist) {
			return true
		}
		if err != nil {
			return false
		}
		_, werr := f.Write(b)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = ownSandboxRecord(end)
		}
		if werr != nil {
			_ = os.Remove(end)
			return false
		}
		return true
	}
}

// ownSandboxRecord and mkdirSandboxOwned are the ownership helper
// (sandboxrelayd.OwnRecord, owned.go) as this package calls it at every
// place the sandbox creates a record file or folder on the host: an
// elevated daemon or launcher hands each to the token user instead of
// leaving it owned by BUILTIN\Administrators (Windows 11 Pro live run,
// B2). A variable so a test sees every site call it.
var ownSandboxRecord = sandboxrelayd.OwnRecord

// mkdirSandboxOwned creates dir (0700, parents too) and owns each folder it
// created.
func mkdirSandboxOwned(dir string) error {
	return sandboxrelayd.MkdirAllClaimed(dir, func(p string) error { return ownSandboxRecord(p) })
}

// relayGoneRunEnder is the running daemon's ender for a run whose helper
// died (relayGoneRunEnd), set by startSandboxRelay and shared by every
// sweep that prunes a dead helper's record: the relay's own and the oci
// reaper's. nil until the relay is started.
var relayGoneRunEnder atomic.Pointer[func(sandboxrelayd.RunRecord)]

// pruneGoneRelayRuns is how a sweep outside the relay prunes the records of
// runs whose helper died: only once the daemon's run ender is set, and every
// pruned record is handed to it (D7), so a killed CLI launch's stored row is
// ended with process_gone. A sweep that runs earlier leaves the records for
// a later one; it never removes a record whose row would then read running
// for good (Linux live check 2026-10-23, R2: the oci start sweep pruned
// them before the ender existed). It reports whether it pruned.
func pruneGoneRelayRuns(observerDir string) bool {
	if relayGoneRunEnder.Load() == nil {
		return false
	}
	pruned, _ := sandboxrelayd.PruneDeadRunRecords(observerDir)
	endGoneRelayRuns(pruned)
	return true
}

// awaitRelayGoneRunEnder waits until the daemon's run ender is set
// (startSandboxRelay sets it first thing), at most within; it reports
// whether it is set.
func awaitRelayGoneRunEnder(within time.Duration) bool {
	deadline := time.Now().Add(within)
	for relayGoneRunEnder.Load() == nil {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return true
}

// endGoneRelayRuns ends what each pruned run left behind; false when no
// ender is set yet (the caller then keeps the records for a later sweep).
func endGoneRelayRuns(pruned []sandboxrelayd.RunRecord) bool {
	f := relayGoneRunEnder.Load()
	if f == nil {
		return false
	}
	for _, rec := range pruned {
		(*f)(rec)
	}
	return true
}

// relayGoneRunEnd is the ender for a run whose host helper died with its
// record left behind (live check 2026-10-22, D7): when the run is a
// sandboxed CLI launch (its CLI left its watch marker, which only a CLI
// writes and which its clean exit removes), its stored row is ended with
// store.EndReasonProcessGone, once (end touches only a row with no recorded
// end), and the stale marker goes. A dashboard run is left to its own PTY
// exit, which the daemon sees. A CLI that is in fact still alive (only its
// helper was killed) records its exit code itself a moment later; the row
// then keeps this reason.
func relayGoneRunEnd(observerDir string, end func(ctx context.Context, runID, reason string) (bool, error), logger *slog.Logger) func(sandboxrelayd.RunRecord) {
	return func(run sandboxrelayd.RunRecord) {
		if end == nil || observerDir == "" || !sandboxCLIRunIDRE.MatchString(run.TerminalRunID) {
			return
		}
		watch, _ := sandboxCLIEndPaths(observerDir, run.TerminalRunID)
		if fi, err := os.Lstat(watch); err != nil || !fi.Mode().IsRegular() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), terminalEndStampTimeout)
		ended, err := end(ctx, run.TerminalRunID, store.EndReasonProcessGone)
		cancel()
		if err != nil {
			if logger != nil {
				logger.Warn("terminal: end a sandboxed CLI run whose process is gone", "run", run.TerminalRunID, "err", err)
			}
			return
		}
		_ = os.Remove(watch)
		if ended && logger != nil {
			logger.Info("terminal: ended a sandboxed CLI run whose process is gone", "run", run.TerminalRunID, "end_reason", store.EndReasonProcessGone)
		}
	}
}

// relayFirstEnder tries each ender in order and reports whether one ended
// the run (nil enders are skipped).
func relayFirstEnder(enders ...func(terminalRunID, endReason, notice string) bool) relayRunEnder {
	return func(terminalRunID, endReason, notice string) bool {
		for _, e := range enders {
			if e != nil && e(terminalRunID, endReason, notice) {
				return true
			}
		}
		return false
	}
}

// sandboxCLIEndPoll is how often a sandboxed CLI launch looks for an end
// request; sandboxCLIEndGrace how long its child has after the hangup before
// it is killed (seams for tests).
var (
	sandboxCLIEndPoll  = time.Second
	sandboxCLIEndGrace = 30 * time.Second
)

// watchSandboxCLIEnd marks the CLI launch of runID as watched and polls for
// an end request. On one it writes the request's line to out, asks the child
// to stop through sigs (SIGHUP, then SIGKILL after sandboxCLIEndGrace) and
// keeps the reason, which reason returns for the run's end record. stop ends
// the watch and removes the marker and the request. A marker that cannot be
// written (no run id, no directory, a write failure) is an error: the
// caller refuses the launch.
func watchSandboxCLIEnd(observerDir, runID string, sigs chan<- os.Signal, out io.Writer) (reason func() string, stop func(), err error) {
	var got atomic.Value
	got.Store("")
	reason = func() string { return got.Load().(string) }
	// The marker is how the daemon's loopback exposure gate finds this box
	// (cli-1b fixes-3 C), so a launch that cannot write it is refused
	// rather than run unseen (fixes-4 N2).
	refuse := func(why error) (func() string, func(), error) {
		return reason, func() {}, fmt.Errorf("the run's watch marker cannot be written (%w), and the daemon finds a sandboxed CLI box through it; the launch is refused and nothing was started", why)
	}
	if observerDir == "" || !sandboxCLIRunIDRE.MatchString(runID) {
		return refuse(errors.New("no observer directory or no run id"))
	}
	watch, end := sandboxCLIEndPaths(observerDir, runID)
	if err := mkdirSandboxOwned(filepath.Dir(watch)); err != nil {
		return refuse(err)
	}
	f, err := os.OpenFile(watch, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: a fixed name under the observer's relay directory, run id shape-checked
	if err != nil {
		return refuse(err)
	}
	// The marker names this CLI process, so the daemon's sweep can tell a
	// marker a killed CLI left behind from a live one (cli-1b fixes-3, B).
	start, _ := peerproc.StartToken(os.Getpid())
	werr := json.NewEncoder(f).Encode(sandboxCLIMarkerBody{PID: os.Getpid(), Start: start})
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(watch)
		return refuse(werr)
	}
	if err := ownSandboxRecord(watch); err != nil {
		_ = os.Remove(watch)
		return refuse(err)
	}
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(sandboxCLIEndPoll)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			fi, err := os.Lstat(end)
			if err != nil || !fi.Mode().IsRegular() || fi.Size() > 64<<10 {
				continue
			}
			b, err := os.ReadFile(end) //nolint:gosec // G304: a fixed name under the observer's relay directory, lstat-checked regular and capped
			if err != nil {
				continue
			}
			var req sandboxCLIEndRequest
			if json.Unmarshal(b, &req) != nil {
				continue
			}
			got.Store(req.EndReason)
			if req.Notice != "" {
				_, _ = io.WriteString(out, req.Notice)
			}
			select {
			case sigs <- syscall.SIGHUP:
			case <-done:
				return
			}
			select {
			case <-done:
				return
			case <-time.After(sandboxCLIEndGrace):
			}
			select {
			case sigs <- syscall.SIGKILL:
			case <-done:
			}
			return
		}
	}()
	return reason, func() {
		once.Do(func() {
			close(done)
			_ = os.Remove(watch)
			_ = os.Remove(end)
		})
	}, nil
}
