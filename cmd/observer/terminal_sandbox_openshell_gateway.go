//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_gateway.go is the managed local gateway's
// driver (lane O2; decision D2, OB-039: the default gateway_mode once this
// lane shipped). It gathers sandboxopenshell.GatewayFacts, walks the pure
// lifecycle table (DecideGateway) and executes the action: start, stop or
// restart Observer's PRIVATE OpenShell gateway as a transient systemd user
// unit, through the driver's one exec seam (openShellRunner, extrun).
//
// What the private gateway is: its own loopback port (a block from 17700),
// its own config (<state dir>/gateway/gateway.toml, written here, never the
// user's ~/.config/openshell), its own database (<state dir>/gateway/
// openshell.db), its own CLI registry and PKI in a private RAM dir
// ($XDG_RUNTIME_DIR/observer-openshell-<install>/), its keys held in
// internal/keystore (terminal_sandbox_openshell_gateway_custody.go),
// telemetry forced off, the version pinned by the tested table and the
// CLI and gateway pair. The bind-mount opt-in (decision D3) is set on this
// gateway only, which only Observer's runs use.
//
// Restart ordering (docs/daemon-restart-runbook.md): the unit is not the
// daemon's child, so a daemon stop or restart leaves it running and every
// live box keeps its gateway. The daemon's reconcile loop stops it only
// when managed mode is no longer wanted and no run holds it, and restarts
// it (an upgrade of the OpenShell package, a changed config, an unhealthy
// gateway) only when no run holds it. One lock file serializes every
// lifecycle action across the daemon and CLI launches (one owner of the
// gateway's state: the executor under the lock).

// The managed gateway's programs, resolved like the CLI (on PATH, shims
// excluded). Observer never installs any of them.
var (
	openShellGatewaySpec = integration.BinaryResolveSpec{
		Names:       integration.BinaryNames{Unix: []string{sandboxopenshell.GatewayProgram}},
		WindowsNote: "the openshell row is native Linux only",
		InstallNote: "managed gateway mode: openshell-gateway comes with the OpenShell package the user installs; Observer never installs it",
	}
	openShellSystemdRunSpec = integration.BinaryResolveSpec{
		Names:       integration.BinaryNames{Unix: []string{"systemd-run"}},
		WindowsNote: "the openshell row is native Linux only",
		InstallNote: "managed gateway mode runs the private gateway as a transient systemd user unit",
	}
	openShellSystemctlSpec = integration.BinaryResolveSpec{
		Names:       integration.BinaryNames{Unix: []string{"systemctl"}},
		WindowsNote: "the openshell row is native Linux only",
		InstallNote: "managed gateway mode asks the systemd user manager for the private gateway unit's state",
	}
)

// openShellUnitEnvInherit is what systemctl and systemd-run need to reach
// the user manager (its bus is found through XDG_RUNTIME_DIR, or the
// session bus address).
var openShellUnitEnvInherit = []string{"HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LANG"}

// openShellGatewayStartWait bounds how long a start waits for the gateway
// to listen and then to authenticate (the first start pulls its supervisor
// and sandbox images, about 13 seconds on the 2026-09-29 host).
var openShellGatewayStartWait = 120 * time.Second

// openShellGatewayPoll is the wait loop's interval (a variable so a test
// does not sleep).
var openShellGatewayPoll = time.Second

// openShellGatewayOCSFEndpoint names the OTLP/gRPC endpoint the private
// gateway's supervisors export OCSF events to ("" renders no export at
// all). Observer owns this gateway's config (decision D3 governs only the
// user's own gateway), so it names the daemon's loopback receiver
// (openShellManagedOCSFEndpoint, lane O3's owner) whenever the receiver is
// part of the row, which it is wherever the row is listed (lane OC). It
// is a constant of the build, never of the process that renders: the
// daemon and a CLI launch render the same config and so the same digest,
// and a change of it restarts an idle gateway only through the lifecycle
// table's config digest rows (G18, G23). A variable so a test renders
// without it.
var openShellGatewayOCSFEndpoint = openShellManagedOCSFEndpoint

// openShellGatewayHostT are the managed gateway's host facts and
// effects that are not a program's answer (a variable so a test feeds
// them): the runtime dir, the filesystem checks, the port check, the lock
// and the random source.
type openShellGatewayHostT struct {
	// RuntimeDir is $XDG_RUNTIME_DIR ("" when not set).
	RuntimeDir func() string
	// StateFS classifies the filesystem a dir (or its nearest existing
	// parent) is on (sandboxopenshell.GatewayStateFS).
	StateFS func(dir string) (sandboxopenshell.Tri, string)
	// RuntimeFS checks the runtime dir (sandboxopenshell.GatewayRuntimeFS).
	RuntimeFS func(dir string) (sandboxopenshell.Tri, string)
	// PortFree reports whether 127.0.0.1:port can be bound now.
	PortFree func(port int) bool
	// Lock takes the lifecycle lock (blocking); the func releases it.
	Lock func(path string) (func(), error)
	// DockerAccess reports whether the systemd user manager can reach the
	// Docker engine the unit is given (unit, from the one owner
	// dockerHostFor names), and whether this launch's own environment
	// drives the same one (lifecycle row G9; TriUnknown when it cannot
	// tell).
	DockerAccess func(unit openShellUnitEngine) (sandboxopenshell.Tri, string)
	// DockerHost is this process's local DOCKER_HOST ("" for none); the
	// unit is given the one owner's (dockerHostFor).
	DockerHost func() string
	// Rand is the key-encryption key's source.
	Rand io.Reader
}

// openShellGatewayHostFn returns the host facts (the per-OS file sets it).
var openShellGatewayHostFn = openShellGatewayHost

// openShellManaged is one lifecycle pass's outcome: the decision after
// the action, and the names the probe pins the run to.
type openShellManaged struct {
	decision sandboxopenshell.GatewayDecision
	id       sandboxopenshell.GatewayIdentity
	layout   sandboxopenshell.GatewayLayout
	record   *sandboxopenshell.GatewayRecord
	// custody is the custody the keys are held in (CustodyKeychain or
	// CustodyOwnerFile; "" before it was read).
	custody string
	// runDirs are the run dirs the reaper cannot remove, as the pass's own
	// facts read them (not-wanted mode only), so the reconcile loop's log
	// reuses them instead of scanning again (tracker F-032).
	runDirs []sandboxopenshell.RunDirNote
}

// target is the Target every box command about the managed gateway names:
// its private name and its private CLI registry.
func (m openShellManaged) target() sandboxopenshell.Target {
	return sandboxopenshell.Target{Gateway: m.id.Name, ConfigHome: m.layout.CLIConfigHome}
}

// openShellGatewayExec is everything one lifecycle pass works with.
type openShellGatewayExec struct {
	stateDir string
	runner   *extrun.Runner
	host     openShellGatewayHostT
	// store and backend are the custody keystore; nil until the
	// filesystem rows passed (audit finding O2-A11: nothing is created
	// before they do), then opened once per process (openKeystore).
	store   openShellCustody
	backend string
	// openKeystore opens the keystore for the state dir, told the custody
	// the keys are pinned to ("" none yet) so a pin to the owner-only file
	// store skips the keychain probe (a variable seam: the process cache in
	// production, a memory store in tests).
	openKeystore func(stateDir, pinned string) (keystore.Store, string)
	// forgetKeystore marks the cached open stale, so the keychain is
	// probed again once the backoff has passed (a locked keychain, or a
	// file store while the keys were pinned to the keychain; audit
	// findings O2-V3, O2-W1).
	forgetKeystore func(stateDir string)
	// reason is the keychain fallback reason of the open store ("" when
	// the keychain is in use).
	reason string
	// daemon reports whether this executor runs in the process that owns
	// the engine endpoint (nil: the process's reconcile loop runs for
	// the state dir; a variable seam for tests; audit finding O2-W4).
	daemon func() bool
	log    *slog.Logger
}

// newOpenShellGatewayExec builds the executor over a state dir. The
// keystore is not opened here.
func newOpenShellGatewayExec(stateDir string, logger *slog.Logger) *openShellGatewayExec {
	if logger == nil {
		logger = slog.Default()
	}
	return &openShellGatewayExec{stateDir: stateDir, runner: openShellRunner(), host: openShellGatewayHostFn(), openKeystore: openShellGatewayKeystoreCached, forgetKeystore: openShellGatewayKeystoreForget, log: logger}
}

// openShellGatewayKeystores caches one opened keystore per state dir for
// the process: the backend is chosen once, never on every 30 s pass (audit
// finding O2-A5), and the keychain probe is bounded (keystore.OpenReport).
// An outcome a pass cannot use (a locked keychain, or a file store while
// the keys are pinned to the keychain) is probed again only after a
// bounded backoff, never while an earlier probe is still blocked in the
// keychain (keystore.ProbeInFlight), so a locked keychain neither piles
// up blocked goroutines nor raises an unlock prompt on every pass (audit
// finding O2-W1).
var openShellGatewayKeystores sync.Map

// openShellKeystoreRetryFirst and openShellKeystoreRetryMax bound the
// re-probe backoff: the first re-probe waits openShellKeystoreRetryFirst,
// each later one twice the last, never more than openShellKeystoreRetryMax.
// Variables so a test does not wait.
var (
	openShellKeystoreRetryFirst = time.Minute
	openShellKeystoreRetryMax   = 10 * time.Minute
)

// openShellKeystoreLate is keystore.LateProbeSuccesses of the custody
// service (a variable for tests).
var openShellKeystoreLate = func() uint64 { return keystore.LateProbeSuccesses(openShellGatewayKeystoreService) }

// openShellKeystoreNow is the cache's clock (a variable for tests).
var openShellKeystoreNow = time.Now

// openShellGatewayKeystoreEntry is one cached open.
type openShellGatewayKeystoreEntry struct {
	mu     sync.Mutex
	store  keystore.Store
	reason string
	// stale: a pass found the outcome unusable and asked for a re-probe,
	// which runs once next is reached.
	stale bool
	next  time.Time
	// fails counts the unusable outcomes in a row (the backoff's step).
	fails int
	// lateSeen is keystore.LateProbeSuccesses as it was when this outcome
	// was probed: when it has grown, a probe given up on answered after
	// all (the keychain was unlocked), and an unusable outcome is probed
	// again at once, not after the backoff (audit finding OC-A4).
	lateSeen uint64
}

// openShellReasonPinnedOwnerFile is the reason of a store opened straight
// from the owner-only file store because the keys are pinned there: no
// keychain probe ran (audit finding O2-W1).
const openShellReasonPinnedOwnerFile = "pinned_owner_file"

// openShellGatewayFileKeystore opens the owner-only file store of a state
// dir directly (fail-closed where this build's file store is not
// verified); a variable so a test hands a memory store.
var openShellGatewayFileKeystore = func(stateDir string) keystore.Store {
	if !keystore.FileFallbackSecure() {
		return keystore.FailClosed()
	}
	return keystore.NewFileStore(openShellGatewayKeystoreService, filepath.Join(stateDir, "gateway", "keys"))
}

// openShellGatewayKeystoreCached returns the custody keystore of a state
// dir with the keychain fallback reason ("" when the keychain is in use).
// Keys pinned to the owner-only file store open it directly with no
// keychain probe at all (a keychain that times out never refuses an
// install that does not use it). Otherwise the first call probes, and a
// later call probes again when a pass marked the outcome stale and its
// backoff has passed, or at once when an unusable outcome's probe answered
// late (audit finding OC-A4); never while an earlier probe is still
// blocked.
func openShellGatewayKeystoreCached(stateDir, pinned string) (keystore.Store, string) {
	if pinned == sandboxopenshell.CustodyOwnerFile {
		return openShellGatewayFileKeystore(stateDir), openShellReasonPinnedOwnerFile
	}
	v, _ := openShellGatewayKeystores.LoadOrStore(stateDir, &openShellGatewayKeystoreEntry{})
	ent := v.(*openShellGatewayKeystoreEntry)
	ent.mu.Lock()
	defer ent.mu.Unlock()
	now := openShellKeystoreNow()
	late := openShellKeystoreLate()
	recovered := ent.reason != "" && late != ent.lateSeen
	if ent.store != nil && ((!recovered && (!ent.stale || now.Before(ent.next))) || keystore.ProbeInFlight(openShellGatewayKeystoreService)) {
		return ent.store, ent.reason
	}
	ent.store, ent.reason = openShellGatewayKeystore(stateDir)
	ent.stale, ent.lateSeen = false, late
	if ent.reason == "" {
		ent.fails = 0
	} else {
		ent.fails++
	}
	ent.next = now.Add(openShellKeystoreBackoff(ent.fails))
	return ent.store, ent.reason
}

// openShellKeystoreBackoff is the wait before the re-probe after fails
// unusable outcomes in a row.
func openShellKeystoreBackoff(fails int) time.Duration {
	d := openShellKeystoreRetryFirst
	for i := 1; i < fails && d < openShellKeystoreRetryMax; i++ {
		d *= 2
	}
	return min(d, openShellKeystoreRetryMax)
}

// openShellGatewayKeystoreForget marks a state dir's cached open stale:
// the keychain is probed again once the backoff has passed (never at once,
// and never while an earlier probe is still blocked).
func openShellGatewayKeystoreForget(stateDir string) {
	if v, ok := openShellGatewayKeystores.Load(stateDir); ok {
		ent := v.(*openShellGatewayKeystoreEntry)
		ent.mu.Lock()
		ent.stale = true
		ent.mu.Unlock()
	}
}

// ensureStore opens the keystore if it is not open yet, telling the opener
// where the keys are pinned.
func (e *openShellGatewayExec) ensureStore(l sandboxopenshell.GatewayLayout) {
	if e.store.s != nil || e.openKeystore == nil {
		return
	}
	ks, reason := e.openKeystore(e.stateDir, openShellCustodyPinned(l))
	if ks == nil {
		return
	}
	e.store, e.backend, e.reason = openShellCustody{s: ks}, ks.Backend(), reason
}

// openShellKeychainLocked reports a keychain fallback reason that means a
// keychain exists but did not answer now (locked, or no answer in time),
// as against a host that has none: managed mode is then refused and the
// keychain probed again after a backoff, never silently moved to the file
// store (audit findings O2-V3, O2-W1).
func openShellKeychainLocked(reason string) bool {
	return reason == keystore.ReasonProbeTimeout || reason == keystore.ReasonInteractionNotAllowed
}

// custody is the custody this pass offers, with the reason when none is.
func (e *openShellGatewayExec) custody() (string, string) {
	if openShellKeychainLocked(e.reason) {
		return "", "the OS keychain is there but did not answer: " + keystore.FallbackDetail(e.reason) + "; unlock it (sign in to the desktop session) and Observer probes it again within " + openShellKeystoreRetryMax.String() + ", or on the next pass once a waiting probe answers (a probe still waiting holds off new ones for at most " + keystore.ProbeAbandonAfter().String() + ", no restart needed)"
	}
	return sandboxopenshell.CustodyFor(e.backend), ""
}

// openShellGatewayMaxPasses bounds one ensure (decide, act, decide again).
const openShellGatewayMaxPasses = 3

// ensure runs the lifecycle until it settles or acts openShellGatewayMaxPasses
// times. With wanted false and nothing recorded it runs no program at all
// (the row's opt-in rule).
func (e *openShellGatewayExec) ensure(ctx context.Context, wanted bool) openShellManaged {
	none := openShellManaged{decision: sandboxopenshell.GatewayDecision{Rule: "G3", Action: sandboxopenshell.GatewayNone}}
	if wanted {
		// The filesystem rows first, before anything is created (audit
		// finding O2-A11): the row state dir (or its nearest existing
		// parent) and the runtime dir.
		pre := sandboxopenshell.GatewayFacts{Wanted: true}
		pre.StateDirLocal, pre.StateDirFS = e.host.StateFS(e.stateDir)
		pre.RuntimeDirPrivate, pre.RuntimeDirDetail = e.host.RuntimeFS(e.host.RuntimeDir())
		if pre.StateDirLocal != sandboxopenshell.TriYes || pre.RuntimeDirPrivate != sandboxopenshell.TriYes {
			return openShellManaged{decision: sandboxopenshell.DecideGateway(pre)}
		}
	}
	var installID string
	if wanted {
		id, err := openShellInstallID(e.stateDir)
		if err != nil {
			return openShellManaged{decision: openShellGatewayRefusal(sandboxopenshell.VerdictGatewayStateForeignFS, err.Error())}
		}
		installID = id
	} else if installID = openShellReadInstallID(e.stateDir); installID == "" {
		return none
	}
	id, err := sandboxopenshell.IdentityFor(installID)
	if err != nil {
		return openShellManaged{decision: openShellGatewayRefusal(sandboxopenshell.VerdictGatewayNotReady, err.Error())}
	}
	m := openShellManaged{id: id}
	layout, err := sandboxopenshell.LayoutFor(e.stateDir, e.host.RuntimeDir(), id)
	if err != nil {
		if !wanted {
			return none
		}
		m.decision = openShellGatewayRefusal(sandboxopenshell.VerdictGatewayRuntimeDirUnsafe, "the managed gateway's private runtime dir cannot be placed: "+err.Error()+"; it needs XDG_RUNTIME_DIR from a systemd user session")
		return m
	}
	m.layout = layout
	if !wanted && !openShellGatewayRecorded(e.stateDir) {
		// Nothing of a managed gateway was ever made here: no program runs.
		return none
	}
	// The gateway's own dirs must not be links to another filesystem: the
	// filesystem rows classified the row state dir only.
	for _, d := range []string{layout.StateDir, layout.KeysDir} {
		if fi, err := os.Lstat(d); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			m.decision = openShellGatewayRefusal(sandboxopenshell.VerdictGatewayStateForeignFS, d+" is a symbolic link; the managed gateway's state must sit on the state dir's own filesystem")
			return m
		}
	}
	if wanted {
		e.ensureStore(layout)
		m.custody, _ = e.custody()
	}
	if err := os.MkdirAll(layout.StateDir, 0o700); err != nil {
		m.decision = openShellGatewayRefusal(sandboxopenshell.VerdictGatewayStateForeignFS, "the managed gateway's state dir: "+err.Error())
		return m
	}
	unlock, err := e.host.Lock(layout.LockPath)
	if err != nil {
		m.decision = openShellGatewayRefusal(sandboxopenshell.VerdictGatewayNotReady, "the managed gateway's lifecycle lock: "+err.Error())
		return m
	}
	defer unlock()
	return e.passes(ctx, wanted, id, layout, m)
}

// passes decides and acts until the lifecycle settles or has acted
// openShellGatewayMaxPasses times (the lifecycle lock is held).
func (e *openShellGatewayExec) passes(ctx context.Context, wanted bool, id sandboxopenshell.GatewayIdentity, layout sandboxopenshell.GatewayLayout, m openShellManaged) openShellManaged {
	for pass := 0; pass < openShellGatewayMaxPasses; pass++ {
		f := e.facts(ctx, wanted, id, layout)
		m.record = f.Record
		m.runDirs = f.UnreadableRunDirs
		if f.Unit != sandboxopenshell.UnitUnknown && f.Unit != sandboxopenshell.UnitActive && f.Unit != sandboxopenshell.UnitActivating {
			// No gateway runs: nothing may read the RAM dir, so the PKI copy
			// and the KEK env file an early failure or a crash left there go
			// now, on every not-running path (audit finding O2-V4).
			_ = os.RemoveAll(layout.RuntimeDir)
		}
		d := sandboxopenshell.DecideGateway(f)
		m.decision = d
		var aerr error
		switch d.Action {
		case sandboxopenshell.GatewayStart:
			if d.FailedRetry {
				// Counted before it runs (row G14r, audit finding O2-W2):
				// a retry that fails again waits longer, and after the
				// last one G14a holds.
				_ = openShellWriteFailedRetries(layout, openShellFailedRetries{Retries: f.FailedRetries + 1, Since: openShellGatewayNow().Unix()})
			}
			aerr = e.start(ctx, id, layout, f)
		case sandboxopenshell.GatewayRestart:
			if aerr = e.stop(ctx, id, layout); aerr == nil {
				aerr = e.start(ctx, id, layout, f)
			}
		case sandboxopenshell.GatewayFinish:
			aerr = e.finish(ctx, id, layout, f.Record, openShellGatewayFinishWait)
		case sandboxopenshell.GatewayStop:
			aerr = e.stop(ctx, id, layout)
			if aerr == nil && d.Verdict != "" {
				// A start that overran its budget (G14c): stopped and
				// cleaned up; the verdict says so.
				return m
			}
		default:
			return m
		}
		if errors.Is(aerr, errOpenShellGatewayStarting) {
			// Still pulling or starting, not failed (audit finding O2-V1):
			// the next pass looks again (row G14b reports the wait).
			if d.Action == sandboxopenshell.GatewayFinish {
				return m
			}
			continue
		}
		if errors.Is(aerr, errOpenShellUnitForeign) {
			m.decision = openShellGatewayRefusal(sandboxopenshell.VerdictGatewayUnitForeign, aerr.Error())
			return m
		}
		if aerr != nil {
			e.log.Warn("terminal_sandbox: openshell: the managed gateway's "+string(d.Action)+" failed", "rule", d.Rule, "err", aerr)
			m.decision = openShellGatewayRefusal(sandboxopenshell.VerdictGatewayStartFailed, "Observer's private gateway did not "+string(d.Action)+": "+aerr.Error())
			return m
		}
		e.log.Info("terminal_sandbox: openshell: managed gateway "+string(d.Action), "rule", d.Rule, "unit", id.Unit)
	}
	return m
}

// errOpenShellUnitForeign is a unit of this install's name that runs a
// gateway from another state dir's config (ledger row OSH-42).
var errOpenShellUnitForeign = errors.New("the unit runs another state dir's gateway")

// unitIsThisLayouts checks, before a stop or restart, that the unit of
// this install's name runs this layout's config (ledger row OSH-42): a
// unit whose --config is another path belongs to another state dir (a
// copy of this one from before the install-id binding) and is never
// stopped from here. A unit that is not loaded names no start command and
// passes; an answer that cannot be read refuses the stop.
func (e *openShellGatewayExec) unitIsThisLayouts(ctx context.Context, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout) error {
	argv, err := sandboxopenshell.UnitShowArgv(id.Unit)
	if err != nil {
		return err
	}
	res := e.run(ctx, openShellSystemctlSpec, argv[1:], nil, openShellUnitEnvInherit, openShellCmdTimeout)
	if res.Outcome != extrun.OutcomeOK {
		return fmt.Errorf("systemctl could not read %s's start command, so it is not stopped%s", id.Unit, openShellResultDetail(res))
	}
	if cfg, ok := sandboxopenshell.UnitConfigPath(string(res.Stdout)); ok && cfg != l.ConfigPath {
		return fmt.Errorf("%w: %s runs the gateway of %s, not this install's %s; it is not stopped. Two Observer state dirs share one install id (a copy of ~/.observer made before Observer bound the id to its dir): stop that profile's gateway from that profile, or remove the copy's %s and %s* files so it mints its own id",
			errOpenShellUnitForeign, id.Unit, strconv.Quote(cfg), strconv.Quote(l.ConfigPath), sandboxopenshell.LegacyInstallIDFile, sandboxopenshell.LegacyInstallIDFile+"-")
	}
	return nil
}

// openShellGatewayRefusal is a refusal decision the executor makes itself.
func openShellGatewayRefusal(verdict, reason string) sandboxopenshell.GatewayDecision {
	return sandboxopenshell.GatewayDecision{Rule: "GX", Action: sandboxopenshell.GatewayRefuse, Verdict: verdict, Reason: reason}
}

// run runs one program with a fixed environment through the exec seam.
func (e *openShellGatewayExec) run(ctx context.Context, spec integration.BinaryResolveSpec, args, set, inherit []string, wall time.Duration) extrun.Result {
	ctx, cancel := context.WithTimeout(ctx, wall)
	defer cancel()
	prog, why, found := openShellProgram(e.runner, spec)
	switch {
	case !found:
		return openShellNotFound(spec)
	case why != "":
		return openShellUntrusted(why)
	}
	return e.runner.Run(ctx, extrun.Request{
		Component: openShellComponentID,
		Program:   prog,
		Args:      args,
		Env:       extrun.EnvSpec{Set: set, Inherit: inherit},
		Limits:    extrun.Limits{Wall: wall, StdoutBytes: 1 << 20, StderrBytes: 64 << 10},
	})
}

// unit runs `systemctl --user VERB UNIT`.
func (e *openShellGatewayExec) unit(ctx context.Context, verb, unit string) extrun.Result {
	argv, err := sandboxopenshell.UnitArgv(verb, unit)
	if err != nil {
		return extrun.Result{Outcome: extrun.OutcomeRefused}
	}
	return e.run(ctx, openShellSystemctlSpec, argv[1:], nil, openShellUnitEnvInherit, openShellCmdTimeout)
}

// facts gathers the lifecycle facts. Only what the table can reach is
// read: with wanted false only the record, the unit's state and the live
// runs.
func (e *openShellGatewayExec) facts(ctx context.Context, wanted bool, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout) sandboxopenshell.GatewayFacts {
	f := sandboxopenshell.GatewayFacts{Wanted: wanted, Now: openShellGatewayNow().Unix(), FirstStartBudget: int64(openShellFirstStartBudget / time.Second)}
	f.Custody, f.CustodyDetail = e.custody()
	f.Record = openShellReadGatewayRecord(l.RecordPath)
	f.RecordedRuns = openShellRunsOn(e.stateDir, id.Name)
	if res := e.unit(ctx, "is-active", id.Unit); res.Outcome == extrun.OutcomeOK || res.Outcome == extrun.OutcomeExitNonZero {
		f.Unit = sandboxopenshell.ParseUnitState(string(res.Stdout))
	}
	f.LiveRuns = openShellLiveRunsOn(e.stateDir, id.Name)
	if !wanted {
		// Row G2 names the run dirs the reaper cannot remove (tracker
		// F-032).
		f.UnreadableRunDirs = openShellUnreadableRunNotes(e.stateDir, openShellGatewayNow())
		return f
	}
	f.FailedRetries, f.FailedSince = e.failedRetries(l, f.Unit, f.Now)
	f.StateDirLocal, f.StateDirFS = e.host.StateFS(l.StateDir)
	f.RuntimeDirPrivate, f.RuntimeDirDetail = e.host.RuntimeFS(filepath.Dir(l.RuntimeDir))
	f.CustodyPinned = openShellCustodyPinned(l)
	if f.CustodyPinned == "" && f.Custody != "" && e.store.s != nil {
		// Pin from where a record set is actually found (audit finding
		// O2-V3): a set this keystore holds with no pin file is pinned to
		// it now, so a later session in the other custody is refused, not
		// handed a fresh PKI.
		if _, err := sandboxopenshell.LoadPKI(e.store, id); err == nil || errors.Is(err, sandboxopenshell.ErrCustodyCorrupt) {
			if openShellPinCustody(l, f.Custody) == nil {
				f.CustodyPinned = f.Custody
			}
		}
	}
	if (f.Custody == "" && openShellKeychainLocked(e.reason)) || (f.CustodyPinned == sandboxopenshell.CustodyKeychain && f.Custody == sandboxopenshell.CustodyOwnerFile) {
		// Probe the keychain again on the next pass (it may be unlocked
		// by then); meanwhile G6 or G7 refuses.
		if e.forgetKeystore != nil {
			e.forgetKeystore(e.stateDir)
		}
		e.store, e.backend, e.reason = openShellCustody{}, "", ""
	}
	unitEngine := e.dockerHostFor(f)
	if e.host.DockerAccess != nil {
		f.DockerAccess, f.DockerAccessDetail = e.host.DockerAccess(unitEngine)
	}
	sup := e.run(ctx, openShellSystemctlSpec, sandboxopenshell.SupervisorArgv()[1:], nil, openShellUnitEnvInherit, openShellCmdTimeout)
	f.Supervisor = (sup.Outcome == extrun.OutcomeOK || sup.Outcome == extrun.OutcomeExitNonZero) && sandboxopenshell.ParseSupervisor(string(sup.Stdout))
	// Ledger row OSH-44: either program found only where the user or a box
	// could replace it refuses the gateway (row G11t), and stops an idle
	// one (row G10).
	for _, spec := range []integration.BinaryResolveSpec{openShellGatewaySpec, openShellCLISpec} {
		if _, why, _ := openShellProgram(e.runner, spec); why != "" && f.BinaryUntrusted == "" {
			f.BinaryUntrusted = why
		}
	}
	if f.BinaryUntrusted != "" {
		f.BinaryFound = true
	} else if bv := e.run(ctx, openShellGatewaySpec, sandboxopenshell.GatewayVersionArgv()[1:], nil, nil, openShellCmdTimeout); bv.Outcome == extrun.OutcomeOK {
		f.BinaryFound, f.BinaryVersion = true, string(bv.Stdout)
	} else {
		f.BinaryFound = bv.Outcome != extrun.OutcomeRefused && bv.Outcome != extrun.OutcomeStartFailed
	}
	if cv := e.run(ctx, openShellCLISpec, []string{"--version"}, nil, nil, openShellCmdTimeout); cv.Outcome == extrun.OutcomeOK {
		f.CLIVersion = string(cv.Stdout)
	}
	if rendered, err := openShellRenderGatewayConfig(id, openShellSandboxLabel(id, f), f.BinaryVersion); err == nil {
		f.WantConfigDigest = sandboxopenshell.GatewayConfigDigest(rendered, unitEngine.DockerHost)
	}
	if f.Unit == sandboxopenshell.UnitActive && f.Record != nil {
		f.Healthy = e.healthy(ctx, id, l, f.Record.Server)
	}
	return f
}

// openShellRenderGatewayConfig renders this install's private config in
// the sandbox namespace label (sandboxopenshell.SandboxLabelFor) for the
// gateway version gatewayVersion (a version answer or a record's version):
// a tested version's runtime images are written as digest references
// (ledger row OSH-48, lane FU7); "" or an untested version writes none,
// which is also how a config written before the pins renders.
func openShellRenderGatewayConfig(id sandboxopenshell.GatewayIdentity, label, gatewayVersion string) (string, error) {
	return sandboxopenshell.RenderGatewayConfig(sandboxopenshell.GatewayConfigInput{
		Name: id.Name, OCSFEndpoint: openShellGatewayOCSFEndpoint(), SandboxLabel: label,
		Images: openShellPinnedImages(gatewayVersion),
	})
}

// openShellPinnedImages are the digest references of a gateway version's
// runtime images (zero when the version cannot be read or is untested).
func openShellPinnedImages(gatewayVersion string) sandboxopenshell.RuntimeImages {
	v, err := sandboxopenshell.ParseVersion(gatewayVersion)
	if err != nil {
		return sandboxopenshell.RuntimeImages{}
	}
	images, _ := sandboxopenshell.PinnedRuntimeImages(v)
	return images
}

// openShellRenderFn renders this install's private config for an identity,
// a sandbox namespace label and a gateway version
// (openShellRenderGatewayConfig, or a test's render).
type openShellRenderFn = func(id sandboxopenshell.GatewayIdentity, label, gatewayVersion string) (string, error)

// openShellSandboxLabel is the namespace label the private gateway is
// rendered with (sandboxopenshell.SandboxLabelFor); a record with no label
// field is matched against its own digest, rendered here under a label
// with the DOCKER_HOST the record says its unit was started with
// (finding OC2-V1).
func openShellSandboxLabel(id sandboxopenshell.GatewayIdentity, f sandboxopenshell.GatewayFacts) string {
	return sandboxopenshell.SandboxLabelFor(id.Name, f.Record, f.RecordedRuns, openShellRecordDigestFor(id, f.Record, openShellRenderGatewayConfig))
}

// openShellRecordDigestFor digests render's config for id under a label
// the way rec's was digested (with the DOCKER_HOST rec says its unit was
// started with), for the label inference of a record with no label field;
// "" when there is no record or the render fails. Such a record may
// predate the image pins (lane FU7) or not, so the render under the
// record's own version (its pins) is tried first and the render with no
// image second: the digest that matches the record's is returned, else
// the render with no image's.
func openShellRecordDigestFor(id sandboxopenshell.GatewayIdentity, rec *sandboxopenshell.GatewayRecord, render openShellRenderFn) func(string) string {
	return func(label string) string {
		if rec == nil {
			return ""
		}
		out := ""
		for _, version := range []string{rec.Version, ""} {
			rendered, err := render(id, label, version)
			if err != nil {
				continue
			}
			out = sandboxopenshell.GatewayConfigDigest(rendered, rec.DockerHost)
			if out == rec.ConfigDigest {
				return out
			}
		}
		return out
	}
}

// healthy asks the private gateway's status through its private registry:
// yes only for connected, authenticated, under its own name and from the
// recorded server.
func (e *openShellGatewayExec) healthy(ctx context.Context, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout, server string) sandboxopenshell.Tri {
	t := sandboxopenshell.Target{Gateway: id.Name, ConfigHome: l.CLIConfigHome}
	argv, err := sandboxopenshell.StatusArgv(t)
	if err != nil {
		return sandboxopenshell.TriNo
	}
	res := openShellRunAt(ctx, e.runner, t, openShellCLISpec, argv[1:])
	if res.Outcome != extrun.OutcomeOK {
		return sandboxopenshell.TriNo
	}
	st, err := sandboxopenshell.ParseStatus(res.Stdout)
	if err != nil || st.Status != "connected" || st.Authentication != "authenticated" || st.Server != server || st.Gateway != id.Name {
		return sandboxopenshell.TriNo
	}
	return sandboxopenshell.TriYes
}

// start starts the private gateway: runtime dir, PKI from the keystore
// (generated and taken into custody on the first start), config, port,
// unit, registration, then a wait until it authenticates; the record is
// written last.
func (e *openShellGatewayExec) start(ctx context.Context, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout, f sandboxopenshell.GatewayFacts) error {
	if err := openShellPrivateDirs(l.RuntimeDir, l.TLSDir, l.CLIConfigHome, l.XDGStateHome); err != nil {
		return err
	}
	if err := e.restorePKI(ctx, id, l); err != nil {
		return err
	}
	kek, err := sandboxopenshell.LoadOrCreateKEK(e.store, id, e.host.Rand)
	if err != nil {
		return err
	}
	bv := e.run(ctx, openShellGatewaySpec, sandboxopenshell.GatewayVersionArgv()[1:], nil, nil, openShellCmdTimeout)
	v, err := sandboxopenshell.ParseVersion(string(bv.Stdout))
	if err != nil {
		return fmt.Errorf("read openshell-gateway's version: %w", err)
	}
	label := openShellSandboxLabel(id, f)
	rendered, err := openShellRenderGatewayConfig(id, label, v.String())
	if err != nil {
		return err
	}
	if err := openShellWriteAtomic(l.ConfigPath, []byte(rendered)); err != nil {
		return fmt.Errorf("write the gateway config: %w", err)
	}
	toolEnv := append(sandboxopenshell.GatewayToolEnv(l), sandboxopenshell.GatewayKEKEnv+"="+kek)
	if res := e.run(ctx, openShellGatewaySpec, sandboxopenshell.GatewayPreflightArgv(l)[1:], toolEnv, []string{"HOME"}, openShellCmdTimeout); res.Outcome != extrun.OutcomeOK {
		return fmt.Errorf("openshell-gateway config preflight refused the private config%s", openShellResultDetail(res))
	}
	port, err := e.pickPort(f)
	if err != nil {
		return err
	}
	bin, err := e.resolve(openShellGatewaySpec)
	if err != nil {
		return err
	}
	dockerHost := e.dockerHostFor(f).DockerHost
	argv, err := sandboxopenshell.GatewayStartArgv(sandboxopenshell.GatewayStartInput{ID: id, Layout: l, GatewayBin: bin, Port: port, DockerHost: dockerHost})
	if err != nil {
		return err
	}
	// The key-encryption key goes into the RAM dir's owner-only env file
	// the user manager reads (audit finding O2-A6); it is on no argv.
	envFile, err := sandboxopenshell.GatewayEnvFile(kek)
	if err != nil {
		return err
	}
	if err := openShellWriteAtomic(l.EnvFile, []byte(envFile)); err != nil {
		return fmt.Errorf("write the gateway's env file: %w", err)
	}
	_ = e.unit(ctx, "reset-failed", id.Unit)
	if res := e.run(ctx, openShellSystemdRunSpec, argv[1:], nil, openShellUnitEnvInherit, openShellCmdTimeout); res.Outcome != extrun.OutcomeOK {
		_ = os.RemoveAll(l.RuntimeDir)
		return fmt.Errorf("systemd-run could not start %s%s", id.Unit, openShellResultDetail(res))
	}
	// A provisional record right after the launch (audit findings O2-A3
	// and O2-V1): the start is under way until the gateway answers, and
	// the lifecycle table gives it its first-start budget.
	rec := &sandboxopenshell.GatewayRecord{
		Name: id.Name, Unit: id.Unit, Port: port, Server: sandboxopenshell.ServerFor(port), Version: v.String(),
		ConfigDigest: sandboxopenshell.GatewayConfigDigest(rendered, dockerHost), Starting: true, StartedAt: openShellGatewayNow().Unix(),
		DockerHost: dockerHost, SandboxLabel: label,
	}
	if err := openShellWriteRecord(l, rec); err != nil {
		_ = e.stopUnit(ctx, id, l, false)
		return err
	}
	return e.finish(ctx, id, l, rec, openShellGatewayStartWait)
}

// errOpenShellGatewayStarting means the launched gateway has not answered
// yet but its unit still runs: it is still pulling its images or
// starting, not failed (audit finding O2-V1).
var errOpenShellGatewayStarting = errors.New("the private gateway is still starting")

// openShellGatewayFinishWait bounds a later pass's look at a start under
// way (the first look, right after the launch, waits
// openShellGatewayStartWait).
var openShellGatewayFinishWait = 5 * time.Second

// openShellFirstStartBudget is how long a launched gateway may take to
// answer before its start counts as failed (row G14c).
var openShellFirstStartBudget = time.Duration(sandboxopenshell.DefaultFirstStartBudget) * time.Second

// dockerHost is this process's own local DOCKER_HOST ("" for none).
func (e *openShellGatewayExec) dockerHost() string {
	if e.host.DockerHost == nil {
		return ""
	}
	return e.host.DockerHost()
}

// openShellUnitEngine is the engine the private gateway's unit is given:
// its DOCKER_HOST ("" for none) and which owner chose it (audit findings
// O2-W4, OC-A6).
type openShellUnitEngine struct {
	DockerHost string
	Owner      string
}

// The owners of the unit's engine (openShellUnitEngine.Owner).
const (
	// openShellEngineOwnerDaemon: the daemon's own environment (its
	// reconcile loop runs for this state dir).
	openShellEngineOwnerDaemon = "daemon"
	// openShellEngineOwnerGateway: the recorded gateway's, while its unit
	// runs (or its state is unknown) or a run is recorded on it, with no
	// daemon loop.
	openShellEngineOwnerGateway = "gateway"
	// openShellEngineOwnerLaunch: this launch's own, with no daemon loop
	// and no gateway that holds one (the start records it).
	openShellEngineOwnerLaunch = "launch"
)

// dockerHostFor is the DOCKER_HOST the unit is given and the config
// digest takes, from ONE owner, never whichever process probes (audit
// findings O2-W4, OC-A6): the daemon's own (it runs the reconcile loop, so
// a change of its environment restarts an idle gateway through the
// digest); else the recorded gateway's while that gateway holds it (its
// unit runs, or its state is unknown, or a run is recorded on it); else
// this process's own, which the start records. So with no daemon a
// recorded value is not kept for good: once the gateway stopped and no
// run is recorded on it, the next launch's engine is taken.
func (e *openShellGatewayExec) dockerHostFor(f sandboxopenshell.GatewayFacts) openShellUnitEngine {
	if e.daemonOwned() {
		return openShellUnitEngine{DockerHost: e.dockerHost(), Owner: openShellEngineOwnerDaemon}
	}
	held := f.Unit == sandboxopenshell.UnitActive || f.Unit == sandboxopenshell.UnitActivating || f.Unit == sandboxopenshell.UnitUnknown || f.RecordedRuns > 0
	if f.Record != nil && held {
		return openShellUnitEngine{DockerHost: f.Record.DockerHost, Owner: openShellEngineOwnerGateway}
	}
	return openShellUnitEngine{DockerHost: e.dockerHost(), Owner: openShellEngineOwnerLaunch}
}

// daemonOwned reports whether this executor runs in the process that owns
// the gateway's engine endpoint: the daemon, whose reconcile loop runs for
// this state dir.
func (e *openShellGatewayExec) daemonOwned() bool {
	if e.daemon != nil {
		return e.daemon()
	}
	return processOpenShellGatewayLoop.runningFor(e.stateDir)
}

// openShellGatewayNow is the lifecycle's clock (a variable for tests).
var openShellGatewayNow = time.Now

// openShellFailedRetries is the automatic retry state of a failed unit
// (<state dir>/gateway/failed-retries.json, owner-only): one owner, the
// executor under the lifecycle lock (audit finding O2-W2). ActiveSince is
// when a pass first saw the unit active since its last failure (0: not
// seen active, or seen otherwise since; audit finding OC-A7).
type openShellFailedRetries struct {
	Retries     int   `json:"retries"`
	Since       int64 `json:"since"`
	ActiveSince int64 `json:"active_since,omitempty"`
}

// openShellFailedHealthy is how long a unit must be seen active, pass after
// pass with nothing else seen between, before its failure episode ends and
// a later failure gets its retries again (audit finding OC-A7). A gateway
// that answers and then crash-loops is seen activating or failed within
// systemd's start limit (five starts in two minutes), so it never earns
// fresh retries. A variable for tests.
var openShellFailedHealthy = 10 * time.Minute

// openShellFailedRetriesPath is the retry state's file.
func openShellFailedRetriesPath(l sandboxopenshell.GatewayLayout) string {
	return filepath.Join(l.StateDir, "failed-retries.json")
}

// openShellWriteFailedRetries records the retry state.
func openShellWriteFailedRetries(l sandboxopenshell.GatewayLayout, st openShellFailedRetries) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return openShellWriteAtomic(openShellFailedRetriesPath(l), b)
}

// openShellReadFailedRetries reads the retry state (false when there is
// none, or it cannot be read).
func openShellReadFailedRetries(l sandboxopenshell.GatewayLayout) (openShellFailedRetries, bool) {
	var st openShellFailedRetries
	b, err := openShellReadOwned(openShellFailedRetriesPath(l), 4096)
	if err != nil || json.Unmarshal(b, &st) != nil || st.Since <= 0 {
		return openShellFailedRetries{}, false
	}
	return st, true
}

// failedRetries reads the retry state for a pass and keeps the episode
// (audit findings O2-W2, OC-A7):
//   - failed: a unit failed for the first time in this episode starts the
//     clock now; the retries so far are answered;
//   - active: the episode ends only once the unit has been seen active for
//     openShellFailedHealthy with nothing else seen between (the first
//     such pass records when);
//   - activating: the unit is (re)starting, which a crash loop under
//     systemd's Restart=on-failure looks like; the episode is kept and the
//     healthy clock restarts;
//   - inactive: simply not running (the user ran reset-failed, a reboot,
//     or Observer's own stop, which resets a failed unit): the episode
//     ends, so the next failure gets its retries again;
//   - unknown: the state is kept as it is.
//
// The retries are answered only for a failed unit (rows G14r and G14a read
// them only then).
func (e *openShellGatewayExec) failedRetries(l sandboxopenshell.GatewayLayout, unit sandboxopenshell.UnitState, now int64) (int, int64) {
	st, ok := openShellReadFailedRetries(l)
	switch unit {
	case sandboxopenshell.UnitInactive:
		_ = os.Remove(openShellFailedRetriesPath(l))
	case sandboxopenshell.UnitActive:
		switch {
		case !ok:
		case st.ActiveSince == 0:
			st.ActiveSince = now
			_ = openShellWriteFailedRetries(l, st)
		case now-st.ActiveSince >= int64(openShellFailedHealthy/time.Second):
			_ = os.Remove(openShellFailedRetriesPath(l))
		}
	case sandboxopenshell.UnitActivating:
		if ok && st.ActiveSince != 0 {
			st.ActiveSince = 0
			_ = openShellWriteFailedRetries(l, st)
		}
	case sandboxopenshell.UnitFailed:
		if !ok {
			st = openShellFailedRetries{Since: now}
			_ = openShellWriteFailedRetries(l, st)
		} else if st.ActiveSince != 0 {
			st.ActiveSince = 0
			_ = openShellWriteFailedRetries(l, st)
		}
		return st.Retries, st.Since
	}
	return 0, 0
}

// unitRunning reports whether the unit is active or activating.
func (e *openShellGatewayExec) unitRunning(ctx context.Context, unit string) bool {
	st := sandboxopenshell.ParseUnitState(string(e.unit(ctx, "is-active", unit).Stdout))
	return st == sandboxopenshell.UnitActive || st == sandboxopenshell.UnitActivating
}

// finish waits up to wait for a launched gateway to listen, registers it,
// waits for it to authenticate, then records the finished start. It
// returns errOpenShellGatewayStarting while the unit runs but has not
// answered (still pulling or starting), and an error naming the failure
// when the unit stopped; only that real failure stops it and cleans up.
func (e *openShellGatewayExec) finish(ctx context.Context, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout, rec *sandboxopenshell.GatewayRecord, wait time.Duration) error {
	if rec == nil {
		return errors.New("no record of the start")
	}
	deadline := time.Now().Add(wait)
	registered := false
	for {
		if !e.host.PortFree(rec.Port) {
			if !registered {
				if err := e.register(ctx, id, l, rec.Port); err == nil {
					registered = true
				}
			}
			if registered && e.healthy(ctx, id, l, rec.Server) == sandboxopenshell.TriYes {
				break
			}
		}
		if !e.unitRunning(ctx, id.Unit) {
			// A real failure: cleaned up, but a failed unit stays failed
			// so rows G14r and G14a bound its retries (audit finding
			// O2-W2).
			_ = e.stopUnit(ctx, id, l, false)
			return fmt.Errorf("its unit %s stopped before the gateway answered connected and authenticated at %s; see `journalctl --user -u %s`", id.Unit, rec.Server, id.Unit)
		}
		if time.Now().After(deadline) {
			return errOpenShellGatewayStarting
		}
		select {
		case <-ctx.Done():
			return errOpenShellGatewayStarting
		case <-time.After(openShellGatewayPoll):
		}
	}
	if v, err := sandboxopenshell.ParseVersion(rec.Version); err == nil {
		e.waitSupervisorImage(ctx, v)
	}
	done := *rec
	done.Starting = false
	if err := openShellWriteRecord(l, &done); err != nil {
		return err
	}
	return openShellRecordGateway(e.stateDir, openShellGatewayEntry{Target: sandboxopenshell.Target{Gateway: id.Name, ConfigHome: l.CLIConfigHome}, Server: done.Server, Version: done.Version})
}

// openShellWriteRecord writes the gateway record.
func openShellWriteRecord(l sandboxopenshell.GatewayLayout, rec *sandboxopenshell.GatewayRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := openShellWriteAtomic(l.RecordPath, b); err != nil {
		return fmt.Errorf("record the private gateway: %w", err)
	}
	return nil
}

// restorePKI writes the held PKI into the runtime TLS dir, or, with none
// held, generates one there and takes it into custody.
func (e *openShellGatewayExec) restorePKI(ctx context.Context, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout) error {
	files, err := sandboxopenshell.LoadPKI(e.store, id)
	switch {
	case errors.Is(err, sandboxopenshell.ErrNoCustody):

		if err := os.RemoveAll(l.TLSDir); err != nil {
			return err
		}
		if err := openShellPrivateDirs(l.TLSDir); err != nil {
			return err
		}
		res := e.run(ctx, openShellGatewaySpec, sandboxopenshell.GenerateCertsArgv(l)[1:], sandboxopenshell.GatewayToolEnv(l), []string{"HOME"}, openShellCmdTimeout)
		if res.Outcome != extrun.OutcomeOK {
			return fmt.Errorf("openshell-gateway generate-certs failed%s", openShellResultDetail(res))
		}
		files = map[string][]byte{}
		for _, rel := range sandboxopenshell.PKIFiles {
			b, err := openShellReadOwned(filepath.Join(l.TLSDir, filepath.FromSlash(rel)), 64<<10)
			if err != nil {
				return fmt.Errorf("read the generated PKI: %w", err)
			}
			files[rel] = b
		}
		if err := sandboxopenshell.SavePKI(e.store, id, files); err != nil {
			return fmt.Errorf("hold the private gateway's PKI in the keystore: %w", err)
		}
		// Pin the custody only after a save that happened (audit finding
		// O2-V3), so a later session whose keystore offers the other one is
		// refused (row G7), never handed a fresh PKI; a save interrupted
		// before this line is pinned on the next pass from where the set
		// is found.
		c, _ := e.custody()
		return openShellPinCustody(l, c)
	case err != nil:
		return fmt.Errorf("%w; once no run uses the private gateway, remove the records of the keystore service %s and the file %s (or set gateway_mode = \"external\")", err, openShellGatewayKeystoreService, l.CustodyPath)
	}
	if err := os.RemoveAll(l.TLSDir); err != nil {
		return err
	}
	for _, rel := range sandboxopenshell.PKIFiles {
		p := filepath.Join(l.TLSDir, filepath.FromSlash(rel))
		if err := openShellPrivateDirs(filepath.Dir(p)); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if sandboxopenshell.PKISecretFiles[rel] {
			mode = 0o600
		}
		if err := os.WriteFile(p, files[rel], mode); err != nil { //nolint:gosec // G306: a public certificate is 0644 inside the 0700 RAM dir; keys are 0600
			return fmt.Errorf("restore the PKI: %w", err)
		}
	}
	return nil
}

// register (re)writes the private gateway's entry in its private CLI
// registry: the dir is Observer's own, so it is removed and added fresh.
func (e *openShellGatewayExec) register(ctx context.Context, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout, port int) error {
	if err := os.RemoveAll(filepath.Join(l.CLIConfigHome, "openshell", "gateways", id.Name)); err != nil {
		return err
	}
	argv, err := sandboxopenshell.GatewayAddArgv(id, port)
	if err != nil {
		return err
	}
	if res := e.run(ctx, openShellCLISpec, argv[1:], sandboxopenshell.GatewayToolEnv(l), []string{"HOME"}, openShellCmdTimeout); res.Outcome != extrun.OutcomeOK {
		return fmt.Errorf("openshell gateway add could not register the private gateway%s", openShellResultDetail(res))
	}
	return nil
}

// stop is Observer's own deliberate stop (not wanted, a restart, a start
// over its budget): it stops the unit, then resets a failed state the stop
// itself left (a gateway that exits non-zero on SIGTERM, or a stop that
// timed out), so the next wanted pass is never refused by row G14a for a
// failure Observer caused (audit finding O2-W2).
func (e *openShellGatewayExec) stop(ctx context.Context, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout) error {
	return e.stopUnit(ctx, id, l, true)
}

// stopUnit stops the unit and removes the runtime dir (the PKI's RAM copy
// and the private registry); the keystore keeps the keys and the record
// keeps the port. With reset false (the cleanup of a start whose unit
// died on its own) a failed unit stays failed, so rows G14r and G14a
// bound its retries.
func (e *openShellGatewayExec) stopUnit(ctx context.Context, id sandboxopenshell.GatewayIdentity, l sandboxopenshell.GatewayLayout, reset bool) error {
	if err := e.unitIsThisLayouts(ctx, id, l); err != nil {
		return err
	}
	res := e.unit(ctx, "stop", id.Unit)
	if res.Outcome != extrun.OutcomeOK && res.Outcome != extrun.OutcomeExitNonZero {
		return fmt.Errorf("systemctl could not stop %s%s", id.Unit, openShellResultDetail(res))
	}
	if reset {
		_ = e.unit(ctx, "reset-failed", id.Unit)
	}
	if st := e.unit(ctx, "is-active", id.Unit); sandboxopenshell.ParseUnitState(string(st.Stdout)) == sandboxopenshell.UnitActive {
		return fmt.Errorf("%s is still active after the stop", id.Unit)
	}
	return os.RemoveAll(l.RuntimeDir)
}

// pickPort picks the first free candidate (the recorded port alone while
// a run is recorded on the gateway, so its pin never moves).
func (e *openShellGatewayExec) pickPort(f sandboxopenshell.GatewayFacts) (int, error) {
	recorded := 0
	if f.Record != nil {
		recorded = f.Record.Port
	}
	id, _ := sandboxopenshell.IdentityFor(openShellReadInstallID(e.stateDir))
	runRecorded := openShellRunsOn(e.stateDir, id.Name) > 0
	cands := sandboxopenshell.PortCandidates(id, recorded, runRecorded)
	for _, p := range cands {
		if e.host.PortFree(p) {
			return p, nil
		}
	}
	if len(cands) == 1 && runRecorded {
		return 0, fmt.Errorf("the private gateway's recorded port %d is held by another process, and it cannot move while a run is recorded on it (the run's pin is name plus server); free the port, or, once those runs are gone, remove their dirs under %s", cands[0], filepath.Join(e.stateDir, "runs"))
	}
	return 0, fmt.Errorf("no free loopback port among %v for the private gateway", cands)
}

// resolve resolves a program to the absolute path the runner would run.
func (e *openShellGatewayExec) resolve(spec integration.BinaryResolveSpec) (string, error) {
	if e.runner.Resolve == nil {
		return "", errors.New("the runner has no resolver")
	}
	prog, why, found := openShellProgram(e.runner, spec)
	switch {
	case !found:
		return "", fmt.Errorf("%s is not installed or not on PATH", spec.Names.Unix[0])
	case why != "":
		return "", errors.New(why)
	case prog.Path == "":
		return "", fmt.Errorf("%s is not a program this check covers", spec.Names.Unix[0])
	}
	return prog.Path, nil
}

// openShellResultDetail renders a failed run's first stderr line (never
// stdout, which a key-printing tool could fill).
func openShellResultDetail(res extrun.Result) string {
	line := strings.TrimSpace(string(res.Stderr))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	if len(line) > 200 {
		line = line[:200] + "..."
	}
	if line == "" {
		return " (" + string(res.Outcome) + ")"
	}
	return " (" + string(res.Outcome) + ": " + line + ")"
}

// openShellPrivateDirs makes each dir (and its parents) owner-only.
func openShellPrivateDirs(dirs ...string) error {
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil { //nolint:gosec // G302: an owner-only dir
			return err
		}
	}
	return nil
}

// openShellWriteAtomic writes an owner-only file through a temp file and
// a rename in the same dir. Every step goes through an os.Root of that dir
// (fold audit H4, gosec G703; the FX3 precedent hostedReadToolState), so
// neither the temp name nor the rename can leave it.
func openShellWriteAtomic(p string, b []byte) error {
	root, err := os.OpenRoot(filepath.Dir(filepath.Clean(p)))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	base := filepath.Base(p)
	var tmp *os.File
	var name string
	for range 8 {
		name = "." + base + "-" + rand.Text()
		tmp, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if err != nil {
		return err
	}
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = root.Remove(name)
		return werr
	}
	return root.Rename(name, base)
}

// openShellReadGatewayRecord reads the record (nil when absent or not
// readable).
func openShellReadGatewayRecord(p string) *sandboxopenshell.GatewayRecord {
	b, err := openShellReadOwned(p, 64<<10)
	if err != nil {
		return nil
	}
	var r sandboxopenshell.GatewayRecord
	if json.Unmarshal(b, &r) != nil || r.Name == "" {
		return nil
	}
	return &r
}

// openShellRunsOn counts the run dirs whose plan pins the named gateway. A
// run dir whose plan cannot be read may pin it, so it counts too (O5 sweep
// L1: fail closed, the gateway is kept while such a dir exists), except an
// old unheld dir with no plan file at all, which never had a box and is
// bounded like the live count (O5 audit finding O5-A4).
func openShellRunsOn(stateDir, name string) int {
	n := 0
	now := time.Now()
	for _, dir := range openShellUnreadableRunDirs(stateDir) {
		if !openShellPlanlessDebris(dir, now) {
			n++
		}
	}
	for _, run := range openShellReadRuns(stateDir) {
		if run.plan.Target.Gateway == name {
			n++
		}
	}
	return n
}

// openShellLiveRunsOn counts the runs on the named gateway that a host
// helper holds or that are too young to judge (the reaper's rule): the
// lifecycle never stops or restarts a gateway they use.
func openShellLiveRunsOn(stateDir, name string) int {
	n := 0
	for _, run := range openShellReadRuns(stateDir) {
		if run.plan.Target.Gateway != name {
			continue
		}
		fi, err := os.Stat(run.planPath)
		if openShellRunHeld(run.dir) || err != nil || time.Since(fi.ModTime()) < openShellReapGrace {
			n++
		}
	}
	// A run dir whose plan cannot be read is live when a helper holds it or
	// it is too young to judge, whichever gateway it pins (O5 sweep L1).
	for _, dir := range openShellUnreadableRunDirs(stateDir) {
		fi, err := os.Stat(dir)
		if openShellRunHeld(dir) || err != nil || time.Since(fi.ModTime()) < openShellReapGrace {
			n++
		}
	}
	return n
}

// ---- the probe's managed step and the daemon's reconcile loop -------------

// openShellManagedFor runs one lifecycle pass for a probe (wanted: the
// row is listed and its effective mode is managed).
func openShellManagedFor(ctx context.Context, stateDir string, logger *slog.Logger) openShellManaged {
	return newOpenShellGatewayExec(stateDir, logger).ensure(ctx, true)
}

// openShellManagedHint is the probe's note on the managed gateway: the
// mode in posture and the custody in force, said truthfully (audit finding
// O2-A1, decision OB-050).
func openShellManagedHint(m openShellManaged) string {
	switch m.custody {
	case sandboxopenshell.CustodyKeychain:
		return "gateway_mode managed custody=keychain: Observer's private OpenShell gateway (telemetry off, loopback only), its PKI and key-encryption key held in the OS keychain"
	case sandboxopenshell.CustodyOwnerFile:
		return "gateway_mode managed custody=owner_file: Observer's private OpenShell gateway (telemetry off, loopback only); no OS keychain is usable here, so its PKI (the CA key included) and its key-encryption key are unencrypted owner-only files under " + m.layout.KeysDir + ", beside the database that key protects: against your own user account they are no stronger than your own OpenShell install"
	}
	return "gateway_mode managed: Observer's private OpenShell gateway"
}

// openShellGatewayLoopT is the daemon's managed gateway reconcile loop:
// one goroutine per process, every openShellPeriodicSweep, beside the
// reaper. While wanted it starts the gateway and performs a deferred
// upgrade once the runs end; once not wanted it stops the gateway when no
// run holds it, then exits.
type openShellGatewayLoopT struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	dir    string
	wanted bool
	// running is the state dir the loop runs for, read without mu: a
	// lifecycle pass reads it while it holds the gateway's file lock, and
	// taking mu there could deadlock with a reconcile that holds mu while it
	// waits for the loop, which waits for that file lock.
	running atomic.Pointer[string]
}

// processOpenShellGatewayLoop is the process's loop.
var processOpenShellGatewayLoop = &openShellGatewayLoopT{}

// openShellGatewayReconcile (re)starts the loop for a state dir with the
// given want. With nothing wanted and nothing recorded it starts nothing.
func openShellGatewayReconcile(stateDir string, wanted bool, logger *slog.Logger) {
	lp := processOpenShellGatewayLoop
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if lp.cancel != nil && lp.dir == stateDir && lp.wanted == wanted {
		return
	}
	lp.stopLocked()
	if !wanted && !openShellGatewayRecorded(stateDir) {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	lp.cancel, lp.done, lp.dir, lp.wanted = cancel, done, stateDir, wanted
	lp.running.Store(&stateDir)
	go func() {
		defer close(done)
		t := time.NewTicker(openShellPeriodicSweep)
		defer t.Stop()
		ex := newOpenShellGatewayExec(stateDir, logger)
		ex.daemon = func() bool { return true }
		lastWait := ""
		for {
			if !wanted {
				// Sweep the abandoned runs first: the gateway is stopped
				// only once none is recorded on it (row G1).
				openShellSweep(ctx, ex.runner, stateDir, openShellReadInstallID(stateDir), openShellRunHeld, time.Now)
			}
			m := ex.ensure(ctx, wanted)
			if !wanted && m.decision.Action == sandboxopenshell.GatewayNone {
				return
			}
			lastWait = openShellLogNotWantedWait(ex.log, m.runDirs, m.decision, lastWait)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// openShellLogNotWantedWait logs row G2's wait reason when run dirs the
// reaper cannot remove keep a gateway that is no longer wanted running
// (tracker F-032), once per change of those dirs rather than on every
// pass. notes are the pass's own (openShellManaged.runDirs), never a
// second scan. It returns the key the next pass compares ("" when there is
// nothing to name).
func openShellLogNotWantedWait(log *slog.Logger, notes []sandboxopenshell.RunDirNote, d sandboxopenshell.GatewayDecision, last string) string {
	if d.Rule != "G2" {
		return ""
	}
	var held []string
	for _, n := range notes {
		if n.Holds {
			held = append(held, n.Name)
		}
	}
	key := strings.Join(held, ",")
	if key != "" && key != last && log != nil {
		log.Warn("terminal_sandbox: openshell: the managed gateway is no longer wanted but run dirs the reaper cannot remove keep it running", "rule", d.Rule, "reason", d.Reason)
	}
	return key
}

// openShellGatewayRelease is the release path (the component or the
// sandbox was turned off): the loop goes on in not-wanted mode, so the
// gateway stops once no run holds it.
func openShellGatewayRelease(logger *slog.Logger) {
	lp := processOpenShellGatewayLoop
	lp.mu.Lock()
	dir := lp.dir
	lp.mu.Unlock()
	if dir != "" {
		openShellGatewayReconcile(dir, false, logger)
	}
}

// runningFor reports whether the process's loop runs for stateDir (the
// process is then the daemon that owns the gateway's engine endpoint).
func (lp *openShellGatewayLoopT) runningFor(stateDir string) bool {
	p := lp.running.Load()
	return p != nil && *p == stateDir
}

func (lp *openShellGatewayLoopT) stopLocked() {
	if lp.cancel == nil {
		return
	}
	lp.cancel()
	<-lp.done
	lp.running.Store(nil)
	lp.cancel, lp.done, lp.dir = nil, nil, ""
}

// openShellGatewayRecorded reports whether Observer may ever have started
// a managed gateway under the state dir: its gateway dir exists (made
// before any start, so a start that failed before its record was written
// still counts; audit finding O2-A3). An external-only install never has
// one.
func openShellGatewayRecorded(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, "gateway")) //nolint:gosec // G703: a fixed dir under the row's own state dir
	return err == nil
}

// openShellCustodyPinned is the custody the held record set was saved
// under: the custody file, or owner_file when the keystore's file store
// already holds a record of this service (a set saved before the file
// existed); "" when nothing was ever saved.
func openShellCustodyPinned(l sandboxopenshell.GatewayLayout) string {
	if b, err := openShellReadOwned(l.CustodyPath, 64); err == nil {
		return strings.TrimSpace(string(b))
	}
	entries, _ := os.ReadDir(l.KeysDir)
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), openShellGatewayKeystoreService+".") {
			return sandboxopenshell.CustodyOwnerFile
		}
	}
	return ""
}

// openShellPinCustody writes the custody file once (an existing one is
// kept: row G7 has already refused a mismatch).
func openShellPinCustody(l sandboxopenshell.GatewayLayout, custody string) error {
	if custody == "" {
		return errors.New("no custody to pin")
	}
	if _, err := os.Lstat(l.CustodyPath); err == nil {
		return nil
	}
	return openShellWriteAtomic(l.CustodyPath, []byte(custody+"\n"))
}

// openShellSupervisorWait bounds the wait for the gateway's supervisor
// image after a start (a variable so a test does not wait).
var openShellSupervisorWait = 3 * time.Minute

// waitSupervisorImage waits (bounded) until the Docker engine holds the
// supervisor image of the gateway's version: the probe's runtime canary
// runs in it with --pull never, and a fresh gateway pulls it at its first
// start (audit finding O2-A12). The image is the digest reference the
// private config names (lane FU7), else the version's default. A wait
// that runs out is logged, not fatal: the probe then reports the image
// missing.
func (e *openShellGatewayExec) waitSupervisorImage(ctx context.Context, v sandboxopenshell.Version) {
	image := sandboxopenshell.CanaryImage(v)
	if pinned, ok := sandboxopenshell.PinnedRuntimeImages(v); ok {
		image = pinned.Supervisor
	}
	deadline := time.Now().Add(openShellSupervisorWait)
	for {
		res := e.run(ctx, openShellDockerSpec, []string{"image", "inspect", "--format", "{{.Id}}", image}, nil, openShellEnvInherit, openShellCmdTimeout)
		if res.Outcome == extrun.OutcomeOK {
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			e.log.Warn("terminal_sandbox: openshell: the private gateway's supervisor image is not on this host yet", "image", image)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(openShellGatewayPoll * 5):
		}
	}
}

// openShellWantsManaged reports whether a config wants the managed
// gateway (the row listed is the caller's check).
func openShellWantsManaged(c config.TerminalSandboxOpenShellConfig) bool {
	return c.EffectiveGatewayMode() == sandboxopenshell.GatewayManaged
}

// openShellRunAt runs one openshell CLI command about a target: the
// fixed environment, with the target's private registry in place of the
// user's own when it names one.
func openShellRunAt(ctx context.Context, runner *extrun.Runner, t sandboxopenshell.Target, spec integration.BinaryResolveSpec, args []string) extrun.Result {
	env, ok := sandboxopenshell.TargetEnv(t)
	if !ok {
		return extrun.Result{Outcome: extrun.OutcomeRefused}
	}
	ctx, cancel := context.WithTimeout(ctx, openShellCmdTimeout)
	defer cancel()
	prog, why, found := openShellProgram(runner, spec)
	switch {
	case !found:
		return openShellNotFound(spec)
	case why != "":
		return openShellUntrusted(why)
	}
	return runner.Run(ctx, extrun.Request{
		Component: openShellComponentID,
		Program:   prog,
		Args:      args,
		Env:       extrun.EnvSpec{Set: env, Inherit: openShellInheritFor(t)},
		Limits:    extrun.Limits{Wall: openShellCmdTimeout, StdoutBytes: 1 << 20, StderrBytes: 64 << 10},
	})
}

// openShellInheritFor is the inherited environment of a command about t:
// a managed target drops the user's own registry location and active
// gateway, which its private registry replaces.
func openShellInheritFor(t sandboxopenshell.Target) []string {
	if t.ConfigHome == "" {
		return openShellEnvInherit
	}
	return slices.DeleteFunc(slices.Clone(openShellEnvInherit), func(k string) bool {
		return k == "XDG_CONFIG_HOME" || k == "OPENSHELL_GATEWAY"
	})
}

// openShellManagedStep is the gathering ladder's PG step: in managed mode
// it runs one lifecycle pass (start the private gateway, or report why
// not), points every later CLI call at its private name and registry,
// records its name and server for row P4m, and reads the bind-mount
// opt-in from its own config (row P9), never the user's gateway.toml.
func openShellManagedStep(ctx context.Context, g *openShellGathering) {
	if g.out.facts.GatewayMode != sandboxopenshell.GatewayManaged {
		return
	}
	if g.host.Managed == nil {
		return
	}
	m := g.host.Managed(ctx)
	g.out.facts.Managed = m.decision
	g.out.facts.ManagedName = m.id.Name
	if m.record != nil {
		g.out.facts.ManagedServer = m.record.Server
	}
	g.out.managedHint = openShellManagedHint(m)
	g.out.managedCustody = m.custody
	g.config = m.target()
	cfgPath := m.layout.ConfigPath
	// The egress check's D3 probe reads the OCSF export from the same
	// private config (lane OC), never the user's gateway.toml.
	g.out.managedConfigPath = cfgPath
	g.host.BindMounts = func(driver string) sandboxopenshell.Tri {
		if cfgPath == "" {
			return sandboxopenshell.TriUnknown
		}
		b, err := openShellReadOwned(cfgPath, 1<<20)
		return openShellBindMountsFrom(b, err, driver)
	}
	// Row P8i reads the runtime images the private config names (its
	// digest references), never the user's gateway.toml.
	g.host.GatewayImages = func(driver string) sandboxopenshell.RuntimeImages {
		if cfgPath == "" {
			return sandboxopenshell.RuntimeImages{}
		}
		b, err := openShellReadOwned(cfgPath, 1<<20)
		return openShellImagesFrom(b, err, driver)
	}
}

// openShellJoinHints joins the probe's notes.
func openShellJoinHints(hints ...string) string {
	var out []string
	for _, h := range hints {
		if h != "" {
			out = append(out, h)
		}
	}
	return strings.Join(out, "; ")
}

// openShellRelease is the driver's release: the managed gateway's loop
// goes on in not-wanted mode, sweeping the abandoned runs itself before
// every pass, until no run is recorded on the gateway (then it stops the
// gateway and exits; audit finding O2-A4); the daemon's reaper stops last.
func openShellRelease() {
	openShellGatewayRelease(nil)
	openShellReleaseReaper()
}

// openShellModeNote is the gateway part of the run's posture note (audit
// finding O2-A13): the mode, the custody in force and the telemetry state
// as Observer knows it (forced off in managed mode, unknown in external
// mode, where the gateway is the user's).
func openShellModeNote(p openShellProbe) string {
	if p.facts.GatewayMode == sandboxopenshell.GatewayManaged {
		return "gateway_mode=managed custody=" + p.managedCustody + " telemetry=off"
	}
	return "gateway_mode=external telemetry=unknown"
}
