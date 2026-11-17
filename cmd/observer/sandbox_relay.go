//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// sandbox_relay.go is the daemon side of the capture relay (sandbox plan v2
// section 5.2, lane sbx-p2): the owner-only link endpoint the host helpers
// reach, and the executor that runs a relayed request host-side. The
// executor runs the SAME hook pipeline a direct hook runs, as a short-lived
// child of the daemon (`observer hook <tool> <event>` against the daemon's
// own config), with the run's channel handed to it on fd 3: the child fills
// its context through hookctx's Daemon entry, so it reads only what the
// channel supplies (the declared environment, payload paths under the run's
// roots, no process ancestry of its own). Running the pipeline as a child
// keeps every hook-side global per process and the answer byte-identical to
// the direct path; the in-process call is a later optimisation.

// relayEnvFD is the variable naming the channel record's descriptor in a
// relay child.
const relayEnvFD = "OBSERVER_HOOK_RELAY_FD"

// relayGateCmd is the hidden `observer sandbox relay-gate` subcommand that
// walks the launch-gate table for a relayed launch_gate request.
const relayGateCmd = "relay-gate"

// relayChildRecord is the channel record a relay child reads on fd 3.
type relayChildRecord struct {
	V     int      `json:"v"`
	RunID string   `json:"run_id"`
	Tool  string   `json:"tool"`
	Roots []string `json:"roots"`
	// ProjectRoot is the root the hook's project-scoped security state
	// (posture, dirty marker, quick scan) keys on, taken from the run
	// record (relayRunProjectRoot), never a path the box reported.
	ProjectRoot string `json:"project_root,omitempty"`
	// CheckoutRoot is the checkout the run was launched in
	// (relayRunCheckoutRoot): the worktree of a live run in a linked git
	// worktree, whose ProjectRoot is the main repository.
	CheckoutRoot string            `json:"checkout_root,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	Cwd          string            `json:"cwd,omitempty"`
	Delivery     string            `json:"delivery,omitempty"`
	CopyHostPath string            `json:"copy_host_path,omitempty"`
	// TrustAcceptRoot is the source repository whose repository trust
	// accepts a copy run (a clone) honours, from the run record
	// (relayRunTrustAcceptRoot), never a path the box reported. Empty for a
	// live run, which is the repository itself.
	TrustAcceptRoot string `json:"trust_accept_root,omitempty"`
}

// relayDeclaredEnv are the environment variables a box may declare on a
// relayed request: the ones the hook side reads through hookctx.Getenv,
// minus every one that names a host path the daemon would write
// (OBSERVER_HOOK_SHAPE_LOG is not declarable), plus the CI markers the
// ask-host probe reads.
var relayDeclaredEnv = map[string]bool{
	sandboxEnvMarker:                true,
	"OBSERVER_HOOK_MAX_RUNTIME":     true,
	"OBSERVER_CLAUDE_WORKTREE_ROOT": true,
}

// relayEnvAllowed reports whether name may be declared.
func relayEnvAllowed(name string) bool {
	if relayDeclaredEnv[name] {
		return true
	}
	for _, k := range integration.CIEnvironment {
		if k == name {
			return true
		}
	}
	return false
}

// relayRules are the request rules every relay side applies.
var relayRules = sandboxrelay.RequestRules{EnvAllowed: relayEnvAllowed}

// sandboxRelayEndpoint is the daemon's link endpoint for observerDir: an
// owner-only socket under <observerDir>/sandbox-relay, which no box sees
// (the observer directory is a tmpfs inside every box).
func sandboxRelayEndpoint(observerDir string) (string, error) {
	return localipc.DefaultTransport().Endpoint(filepath.Join(observerDir, sandboxrelayd.RelayDirName, "ipc"))
}

// sandboxRelayAddr names the daemon's link endpoint for observerDir in a
// relay hop answer and a log line ("" when it cannot be named).
func sandboxRelayAddr(observerDir string) string {
	ep, err := sandboxRelayEndpoint(observerDir)
	if err != nil {
		return ""
	}
	return ep
}

// dialSandboxRelay reaches the daemon's link endpoint.
func dialSandboxRelay(observerDir string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		ep, err := sandboxRelayEndpoint(observerDir)
		if err != nil {
			return nil, err
		}
		return localipc.DefaultTransport().Dial(ctx, ep, 2*time.Second)
	}
}

// sandboxRelayReachable reports whether the daemon serves the link
// endpoint now (the CLI path refuses without it).
func sandboxRelayReachable(observerDir string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := dialSandboxRelay(observerDir)(ctx)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// startSandboxRelay serves the link endpoint for the daemon's life, only
// while the Sandboxes and VMs module is active (no listener otherwise) and
// only on an operating system a sandbox runs on (sandboxRelayOnOS:
// Linux, or a selected driver's own OS).
//
// It follows the EFFECTIVE sandbox switch (the local block with the in-force
// managed body composed onto it, effectiveSandboxConfig), not the local one
// alone (SBX-P1C merge finding 1): with the sandbox off it listens on
// nothing, and starts the moment the managed overlay turns the sandbox on
// while the daemon runs, or a local write applies (sandbox_live_apply.go:
// setup's Enable, the Settings save) with the module selected and a driver
// for this OS, so turning the sandbox on needs no restart. Once serving it
// stays up, idle, if the sandbox is later turned off: a box launched while
// it was on still reports through it, and an idle endpoint answers no one.
//
// deps.SessionOwner looks up the project the node records for a session id
// (the store's ProjectRootForSession), so a box cannot write rows under
// another project's session.
func startSandboxRelay(ctx context.Context, cfg config.Config, binPath string, logger *slog.Logger, deps sandboxRelayDeps) {
	// Set first, so every sweep that prunes a dead helper's record (this
	// relay's and the oci reaper's) ends the run it left behind (D7).
	onGone := relayGoneRunEnd(sandboxObserverDirFor(cfg), deps.EndGoneRun, logger)
	relayGoneRunEnder.Store(&onGone)
	if !localipc.Supported() {
		return
	}
	serve := func() bool { return serveSandboxRelay(ctx, cfg, binPath, logger, deps) }
	// The seams are read here, on the caller's goroutine, so a test that
	// restores them at cleanup never races the waiting goroutine.
	relayConfig, goos := sandboxRelayConfig, sandboxRelayGOOS()
	if sandboxRelayGateOn(cfg, goos) {
		serve()
		return
	}
	go awaitSandboxRelay(ctx, func() bool { return sandboxRelayGateOn(relayConfig(cfg), goos) }, serve)
}

// sandboxRelayGateOn is the relay's whole gate over one config, judged for
// the operating system goos: the module is active (an install with no
// [components] block resolves the module active, and it must not gain a
// listener for a feature it never turned on, plans decision log P-026), a
// driver serves goos, and the sandbox is wanted.
func sandboxRelayGateOn(cfg config.Config, goos string) bool {
	return sandboxModuleActive(componentSnapshotForConfig(cfg)) && sandboxRelayOnOS(goos, cfg) && sandboxRelayWanted(cfg)
}

// sandboxRelayGOOS is the operating system the relay gate judges (a test
// seam), read once per start on the caller's goroutine.
var sandboxRelayGOOS = func() string { return runtime.GOOS }

// sandboxRelayOnOS reports whether the daemon serves the relay on goos:
// always on Linux (bwrap and the containers), elsewhere only while a
// registered driver whose relayOS is goos is selected (the MXC driver on
// Windows, lane SBX-P6; the Seatbelt and Apple container drivers on macOS,
// lane SBX-P5). A build without such a driver keeps the relay Linux-only.
// The macOS drivers once registered no platform here, so a Mac daemon
// served no relay and every sandboxed CLI launch was refused as if the
// daemon were down (macOS live run 2026-10-22, D1).
func sandboxRelayOnOS(goos string, cfg config.Config) bool {
	if goos == "linux" {
		return true
	}
	var snap *componentstate.Snapshot
	for _, reg := range sandboxDriverRegs {
		if reg.relayOS != goos {
			continue
		}
		if snap == nil {
			s := componentSnapshotForConfig(cfg)
			snap = &s
		}
		if sandboxDriverSelected(*snap, reg.component) {
			return true
		}
	}
	return false
}

// sandboxRelayWanted is the relay's gate: the effective sandbox is on.
func sandboxRelayWanted(cfg config.Config) bool { return effectiveSandboxConfig(cfg).Enabled }

// sandboxRelayConfig is the config the gate reads after the managed overlay
// moves or a local write applies: the daemon's config.toml as it is now, or the boot config when it
// cannot be read. A seam for tests.
var sandboxRelayConfig = func(boot config.Config) config.Config {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	if err != nil {
		return boot
	}
	return cfg
}

// awaitSandboxRelay waits on the managed overlay and the local-apply signal
// until wanted holds, then serves once. A start that fails waits for the
// next move (no retry loop).
func awaitSandboxRelay(ctx context.Context, wanted, serve func() bool) {
	for {
		moved, applied := processSandboxManaged.changed(), processSandboxLocal.changed()
		if wanted() && serve() {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-moved:
		case <-applied:
		}
	}
}

// sandboxRelayStartHooks run once when the relay starts serving, with the
// daemon's Observer directory (a driver's own start work: the mxc-process
// driver's box folder sweep, RERUN2 D4).
var sandboxRelayStartHooks []func(ctx context.Context, observerDir string, logger *slog.Logger)

// sandboxEgressRefusalSources are a driver's own refusal feeds outside the
// relay link (lane O3: a backend whose own proxy exports its denials), each
// handed the daemon's one refusal hook when the relay starts serving (nil:
// refusals are not recorded), so every feed shares the one receiver, its
// flood bound and its store seam.
var sandboxEgressRefusalSources []func(sink func(sandboxrelayd.RunRecord, sandboxrelay.EgressRefusalReport))

// sandboxEgressRefusalDropSources are the same feeds' dropped-count hooks
// (lane OC, audit finding O3-W2): a feed that drops a run's refusals past
// its own bound hands the count to the refusal audit, which keeps it
// beside the run's rows (nil: not recorded).
var sandboxEgressRefusalDropSources []func(drop func(sandboxrelayd.RunRecord, egressRefusalDropCount))

// sandboxRelaySweepHooks run after the relay's prune of dead helpers'
// records, once at start and after every sweep of the relay daemon
// (sandboxrelayd.Daemon.OnSweep), so what a dead run left beside its relay
// record goes with it (its credential files, tracker F-055).
var sandboxRelaySweepHooks []func(observerDir string)

// runSandboxRelaySweepHooks runs every sweep hook for observerDir.
func runSandboxRelaySweepHooks(observerDir string) {
	for _, hook := range sandboxRelaySweepHooks {
		hook(observerDir)
	}
}

// serveSandboxRelay prunes stale run records and serves the endpoint; false
// when it could not listen.
func serveSandboxRelay(ctx context.Context, cfg config.Config, binPath string, logger *slog.Logger, deps sandboxRelayDeps) bool {
	observerDir := sandboxObserverDirFor(cfg)
	// A helper killed with SIGKILL cannot remove its run record: a dead
	// helper's liveness lock says so (the sweep repeats this while the
	// daemon runs), and a record from before the lock is pruned by age.
	if pruned, err := sandboxrelayd.PruneDeadRunRecords(observerDir); err == nil && len(pruned) > 0 {
		logger.Info("sandbox relay: removed the records of runs whose helper died", "count", len(pruned))
		endGoneRelayRuns(pruned)
	}
	if n, err := sandboxrelayd.PruneRuns(observerDir, relayRecordMaxAge, time.Now()); err == nil && n > 0 {
		logger.Info("sandbox relay: removed stale run records", "count", n)
	}
	runSandboxRelaySweepHooks(observerDir)
	for _, hook := range sandboxRelayStartHooks {
		hook(ctx, observerDir, logger)
	}
	ep, err := sandboxRelayEndpoint(observerDir)
	if err != nil {
		logger.Warn("sandbox relay: no endpoint; sandboxed hooks will block their gate events", "err", err)
		return false
	}
	ln, err := localipc.DefaultTransport().Listen(ep)
	if err != nil {
		logger.Warn("sandbox relay: cannot listen; sandboxed hooks will block their gate events", "err", err)
		return false
	}
	cfgPath, _ := config.ResolveGlobalPath(daemonConfigPath())
	// A drifted run ends under require_full_capture: a dashboard run through
	// the daemon's teardown, a sandboxed CLI launch through its end request
	// (relayCLIRunEnder).
	endRun := relayFirstEnder(deps.EndRun, relayCLIRunEnder(observerDir, deps.StampEndReason, logger))
	refusalReceiver := newEgressRefusalReceiver(ctx, deps.Refusals, logger)
	refusals := refusalReceiver.onEgressRefusal()
	for _, src := range sandboxEgressRefusalSources {
		src(refusals)
	}
	drops := refusalReceiver.onDropped()
	for _, src := range sandboxEgressRefusalDropSources {
		src(drops)
	}
	d := &sandboxrelayd.Daemon{
		ObserverDir:  observerDir,
		Exec:         relayExecutor(cfgPath, binPath),
		Rules:        relayRules,
		Peer:         sandboxrelayd.PeerSameUser,
		Gated:        relayRequestGated,
		SessionOwner: deps.SessionOwner,
		FreshStore:   relayFreshStoreFor(observerDir),
		CloneOrigin:  relayCloneOrigin(deps.ManagedRoot),
		// A box running an earlier binary sends version 1 requests and
		// cannot read a refusal: it gets the answer it would have given.
		LegacyRefusal: relayLegacyRefusal,
		// What lowered a run's capture reaches its evidence and its pill;
		// a drifted run then ends while the org requires full capture
		// (sandbox plan section 13.12 A10), after its row records why.
		OnHealth: relayHealthSteps(relayOnHealth(deps.LowerCapture, logger), relayFloorEnder(endRun, logger)),
		// The pill's live health goes with the run.
		OnRunEnd: relayOnRunEnd,
		// A run whose helper died ends its stored row (D7).
		OnPruned: func(rec sandboxrelayd.RunRecord) { endGoneRelayRuns([]sandboxrelayd.RunRecord{rec}) },
		// What a dead run left beside its record goes after each sweep
		// (its credential files, tracker F-055).
		OnSweep: func() { runSandboxRelaySweepHooks(observerDir) },
		// A run's gateway refusals land in the refusal audit (lane N1).
		OnEgressRefusal: refusals,
		// A call the transcript shows as run with no gate event is drift
		// (sandbox plan section 5.2 (2)).
		Drift: relayGateDrift(),
		// Every link the daemon closes unanswered and every request it
		// refuses is one line with the run id (Windows 11 Pro run 3).
		// A hosted run's line also goes to its kept relay log, where the
		// in-box answer points (lane FX6, F-P7-5).
		Log: relayDaemonLog(logger, observerDir),
	}
	relaySessionClaims.Store(d)
	// A floor published while runs are live ends the ones already drifted.
	sweep := relayFloorSweep(endRun, logger)
	relayFloorSweeper.Store(&sweep)
	go func() {
		if err := d.Serve(ctx, ln); err != nil {
			logger.Warn("sandbox relay: stopped", "err", err)
		}
	}()
	return true
}

// relayDaemonLog is the relay daemon's Log: one warning in the daemon's
// own log, and, for a run the daemon names, the same line in that run's
// kept relay log (noteHostedRelayLog). The daemon names a run only once
// its handshake proved it (sandboxrelayd.Daemon.Log, fold audit N4), so a
// box cannot write into another run's kept log by claiming its id.
func relayDaemonLog(logger *slog.Logger, observerDir string) func(runID, reason string) {
	return func(runID, reason string) {
		logger.Warn("sandbox relay: "+reason, "run", runID)
		noteHostedRelayLog(observerDir, runID, reason)
	}
}

// sandboxRelayDeps are the daemon facts the relay endpoint is wired with.
type sandboxRelayDeps struct {
	// SessionOwner is the store's ProjectRootForSession.
	SessionOwner func(context.Context, string) (string, error)
	// ManagedRoot is the managed-workspaces root (clones live under it).
	ManagedRoot string
	// LowerCapture records a run's lowered capture on its stored terminal
	// run (store.LowerTerminalRunCapture with the evidence reseal).
	LowerCapture func(ctx context.Context, terminalRunID string, h store.TerminalRunCaptureHealth) error
	// EndRun ends a live daemon-launched terminal run by its stored run id,
	// recording the end reason and showing the notice first (false: no such
	// live run here, such as a CLI sandboxed launch); nil: the daemon cannot
	// end runs.
	EndRun func(terminalRunID, endReason, notice string) bool
	// StampEndReason records why a live run is ended on its stored row
	// (store.StampTerminalRunEndReason); the sandboxed CLI launch's ender
	// stamps through it before it leaves the end request.
	StampEndReason func(ctx context.Context, runID, reason string) error
	// EndGoneRun ends the stored row of a run whose process is gone
	// (store.EndTerminalRunGone), once; nil: such rows stay as they are.
	EndGoneRun func(ctx context.Context, runID, reason string) (bool, error)
	// Refusals is the store seam the egress refusal receiver writes
	// through (lane N1); nil: refusals are not recorded.
	Refusals egressRefusalStore
}

// relayMaxMeta caps a managed workspace's meta.json read.
const relayMaxMeta = 64 << 10

// relayCloneOrigin returns the daemon's CloneOrigin over managedRoot: a
// recorded project root inside <managedRoot>/<id>/ is a managed workspace
// whose meta.json (beside the workspace, never inside a box) names the
// project it was made from. Only a local source (a clone-local copy or a
// worktree) names a project path; a remote clone has no project here.
func relayCloneOrigin(managedRoot string) func(string) string {
	if managedRoot == "" || !filepath.IsAbs(managedRoot) {
		return nil
	}
	if r, err := filepath.EvalSymlinks(managedRoot); err == nil {
		managedRoot = r
	}
	return func(root string) string {
		if !filepath.IsAbs(root) {
			return ""
		}
		if r, err := filepath.EvalSymlinks(root); err == nil {
			root = r
		}
		rel, err := filepath.Rel(managedRoot, filepath.Clean(root))
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ""
		}
		id, _, _ := strings.Cut(rel, string(filepath.Separator))
		metaPath := filepath.Join(managedRoot, id, "meta.json")
		if fi, err := os.Lstat(metaPath); err != nil || !fi.Mode().IsRegular() {
			return ""
		}
		f, err := os.Open(metaPath) //nolint:gosec // G304: <managedRoot>/<id>/meta.json, outside every box, checked not a link
		if err != nil {
			return ""
		}
		defer func() { _ = f.Close() }()
		if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
			return ""
		}
		var meta workspace.Meta
		if err := json.NewDecoder(io.LimitReader(f, relayMaxMeta)).Decode(&meta); err != nil {
			return ""
		}
		if meta.Source != workspace.SourceCloneLocal && meta.Source != workspace.SourceWorktree {
			return ""
		}
		if !filepath.IsAbs(meta.Origin) || filepath.Clean(meta.Origin) != meta.Origin {
			return ""
		}
		return meta.Origin
	}
}

// relayLegacyRefusal renders a refusal for a version 1 box: the answer a
// current box gives its tool (relayRefusalAnswer); a launch gate exits 1
// with the reason, as the relay-gate refusal does.
func relayLegacyRefusal(req sandboxrelay.HookRequest, why sandboxrelay.Refusal) sandboxrelay.HookResponse {
	if req.Kind == sandboxrelay.KindLaunchGate || len(req.Args) == 0 {
		return sandboxrelay.HookResponse{Exit: 1, Stderr: fmt.Appendf(nil, "%s (%s)\n", boxGateRefusals[boxGateRelayRefused], why)}
	}
	tool, event := req.Args[0], ""
	if len(req.Args) > 1 {
		event = canonicalHookEvent(tool, req.Args[1])
	}
	return relayRefusalAnswer(tool, event, relayRequestGated(req), why)
}

// relayRequestGated reports whether a relayed request is a gate event: a
// launch gate always is; a hook event is when the registry's provisional
// failure plan says its answer can block the tool (the same plan the box
// side reads to decide block or spool).
func relayRequestGated(req sandboxrelay.HookRequest) bool {
	if req.Kind != sandboxrelay.KindHook || len(req.Args) == 0 {
		return true
	}
	tool, event := req.Args[0], ""
	if len(req.Args) > 1 {
		event = canonicalHookEvent(tool, req.Args[1])
	}
	return provisionalHookFailurePlan(tool, event, "").Gated
}

// relayRecordMaxAge is how old a run record must be before the daemon
// prunes it at start (no live run lasts that long without a restart).
const relayRecordMaxAge = 7 * 24 * time.Hour

// Output caps of one relayed execution.
const (
	relayMaxStdout = 8 << 20
	relayMaxStderr = 64 << 10
)

// relayArgv is the closed table from a request Kind to the host-side argv
// that runs it (after the observer binary).
var relayArgv = map[sandboxrelay.Kind]func(req sandboxrelay.HookRequest, configPath string) []string{
	sandboxrelay.KindHook: func(req sandboxrelay.HookRequest, configPath string) []string {
		out := append([]string{"hook"}, req.Args...)
		if configPath != "" {
			out = append(out, "--config", configPath)
		}
		return out
	},
	sandboxrelay.KindLaunchGate: func(req sandboxrelay.HookRequest, configPath string) []string {
		return []string{"sandbox", relayGateCmd, "--tool", req.Args[0], "--config", configPath}
	},
}

// relayExecutor returns the daemon's Executor.
func relayExecutor(configPath, binPath string) sandboxrelayd.Executor {
	return func(ctx context.Context, run sandboxrelayd.RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
		build, ok := relayArgv[req.Kind]
		if !ok {
			return sandboxrelay.HookResponse{}, fmt.Errorf("relay: no executor for kind %q", req.Kind)
		}
		rec, err := json.Marshal(relayChildRecord{
			V: 1, RunID: run.RunID, Tool: run.Tool, Roots: run.ReadRoots(), Env: req.Env, Cwd: req.Cwd,
			ProjectRoot: relayRunProjectRoot(run), CheckoutRoot: relayRunCheckoutRoot(run),
			Delivery: string(run.Delivery), CopyHostPath: run.CopyHostPath,
			TrustAcceptRoot: relayRunTrustAcceptRoot(run),
		})
		if err != nil {
			return sandboxrelay.HookResponse{}, err
		}
		r, w, err := os.Pipe()
		if err != nil {
			return sandboxrelay.HookResponse{}, err
		}
		defer func() { _ = r.Close() }()
		//nolint:gosec // G204: the daemon's own binary and a closed argv table; the request's args passed sandboxrelay's schema (no flag, short ids)
		cmd := exec.CommandContext(ctx, binPath, build(req, configPath)...)
		fd, err := relayHandOff(cmd, r)
		if err != nil {
			_ = w.Close()
			return sandboxrelay.HookResponse{}, fmt.Errorf("relay: hand over the channel: %w", err)
		}
		cmd.Stdin = bytes.NewReader(req.Stdin)
		stdout := &cappedBuffer{max: relayMaxStdout}
		stderr := &cappedBuffer{max: relayMaxStderr}
		cmd.Stdout, cmd.Stderr = stdout, stderr
		cmd.Env = relayChildEnvFD(os.Environ(), req.Kind, fd)
		cmd.Dir = relayChildDir(run, req.Cwd)
		cmd.WaitDelay = 2 * time.Second
		if err := cmd.Start(); err != nil {
			_ = w.Close()
			return sandboxrelay.HookResponse{}, fmt.Errorf("relay: start: %w", err)
		}
		_, werr := w.Write(rec)
		_ = w.Close()
		err = cmd.Wait()
		if werr != nil {
			return sandboxrelay.HookResponse{}, fmt.Errorf("relay: hand over the channel: %w", werr)
		}
		exit := 0
		if err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ctx.Err() != nil {
				return sandboxrelay.HookResponse{}, fmt.Errorf("relay: run: %w", err)
			}
			exit = ee.ExitCode()
			if exit < 0 || exit > 255 {
				return sandboxrelay.HookResponse{}, fmt.Errorf("relay: run: %w", err)
			}
		}
		if stdout.over || stderr.over {
			return sandboxrelay.HookResponse{}, errors.New("relay: the answer is over its output cap")
		}
		return sandboxrelay.HookResponse{Exit: exit, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
	}
}

// relayRunProjectRoot is the root a relay child's security state keys on,
// from the run record only. A live run edits the project itself, so it is
// the run's project root. A copy run (a clone) edits its own workspace: the
// quick scan reads that root's git index and the dirty marker says that
// tree has unscanned writes, so it is the workspace, never the original
// project (whose index and posture say nothing about the clone's staged
// content). A record with no project root falls back to the workspace.
// A live run in a linked worktree keys on the main repository, as the host
// path's hookProjectRoot does (F0-14); the commit gate still knows the
// worktree is another checkout from the event's working directory (the
// child runs in the workspace), so the main checkout's clean never speaks
// for it (securityInOtherCheckout). A copy run whose workspace is a linked
// worktree (the worktree workspace source, lane SBX-WORKTREE-SOURCE) keys on
// the main repository the same way, so its findings land on the main
// project; a clone is never a linked worktree, so a clone run is unchanged.
func relayRunProjectRoot(run sandboxrelayd.RunRecord) string {
	root := relayRunCheckoutRoot(run)
	if run.ProjectRoot == "" {
		return root
	}
	if main, ok := git.FindRoot(root); ok {
		if checkout, ok := git.FindCheckoutRoot(root); ok && checkout != main {
			return main
		}
	}
	return root
}

// relayRunCheckoutRoot is the checkout a relay run was launched in, from
// the run record only: a copy run's workspace, else the run's project root
// as launched (a linked worktree stays the worktree). The commit gate
// compares it with the project root's checkout (securityInOtherCheckout).
func relayRunCheckoutRoot(run sandboxrelayd.RunRecord) string {
	if run.Delivery == sandboxrelayd.DeliveryCopy || run.ProjectRoot == "" {
		return run.WorkspaceDir
	}
	return run.ProjectRoot
}

// relayRunTrustAcceptRoot is the repository whose trust accepts a relayed
// launch gate honours, from the run record only: a copy run's workspace is
// a throwaway clone of the run's project, so the developer accepts the
// source project, and the gate reads those accepts while still checking the
// clone's own files (plans decision log P-037 finding 2). A live run, or a
// record with no project root, honours its own.
func relayRunTrustAcceptRoot(run sandboxrelayd.RunRecord) string {
	if run.Delivery != sandboxrelayd.DeliveryCopy || run.ProjectRoot == "" || run.ProjectRoot == run.WorkspaceDir {
		return ""
	}
	return run.ProjectRoot
}

// relayChildEnvFD is the daemon's environment for a relay child: every
// daemon-managed and sandbox variable removed (the child is a host process
// on the daemon path, not a box), the channel descriptor added, and for a
// launch gate the sandbox marker set (the run IS sandboxed, so its
// sandbox.select row proceeds).
//
// fd is the descriptor the platform's hand-off chose (relayHandOff: fd 3 on
// unix, an inherited handle value on Windows); relayChildEnv is the unix
// spelling (sandbox_relay_handoff_unix.go).
func relayChildEnvFD(base []string, kind sandboxrelay.Kind, fd string) []string {
	out := make([]string, 0, len(base)+2)
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if k == sandboxEnvMarker || k == relayEnvFD || isInternalChildEnv(kv) {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, relayEnvFD+"="+fd)
	if kind == sandboxrelay.KindLaunchGate {
		out = append(out, sandboxEnvMarker+"=1")
	}
	return out
}

// relayChildDir is where a relay child runs: the box's working directory
// when it lies under the run's roots once every symlink is resolved
// (same-path binds make it the host path too; a link the box planted that
// points outside the roots is not followed there), else the run's
// workspace. It returns the resolved directory, so the child never walks a
// link the box can swap afterwards.
func relayChildDir(run sandboxrelayd.RunRecord, cwd string) string {
	if cwd == "" {
		return run.WorkspaceDir
	}
	resolved, err := filepath.EvalSymlinks(cwd)
	if err != nil || !sandboxrelayd.RootsContain(run.ReadRoots(), resolved) {
		return run.WorkspaceDir
	}
	if fi, err := os.Stat(resolved); err != nil || !fi.IsDir() {
		return run.WorkspaceDir
	}
	return resolved
}

// cappedBuffer keeps at most max bytes and records an overflow.
type cappedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.max {
		c.over = true
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

var _ io.Writer = (*cappedBuffer)(nil)

// newSandboxRelayGateCmd is the hidden `observer sandbox relay-gate` the
// relay executor runs for a launch_gate request: it walks the CLI
// launch-gate table (path 2 of launch_gates.go) for the tool with the
// launcher's own evidence, in the box's working directory, against the
// daemon's config and database. Exit 0 allows; a refusal is printed and
// exits 1. It runs only as a relay child (the channel on fd 3 must be
// readable); anything else is refused.
func newSandboxRelayGateCmd() *cobra.Command {
	var tool, configPath string
	cmd := &cobra.Command{
		Use:    relayGateCmd,
		Short:  "Run a sandboxed launch's launch checks host-side (the capture relay runs this)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if code := runSandboxGate(cmd.Context(), tool, configPath, os.Stdin, cmd.ErrOrStderr()); code != 0 {
				return exitErr(code)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tool, "tool", "", "the tool being launched in the box")
	cmd.Flags().StringVar(&configPath, "config", "", "the daemon's config.toml")
	return cmd
}

// runSandboxGate is the relay-gate body: the channel record on fd 3 and the
// working directory the relay started it in (relayChildDir).
func runSandboxGate(ctx context.Context, tool, configPath string, stdin io.Reader, stderr io.Writer) int {
	return runSandboxGateWith(ctx, tool, configPath, stdin, stderr,
		func() (relayChildRecord, error) { return readRelayChildRecord(os.Getenv(relayEnvFD)) }, os.Getwd)
}

// runSandboxGateWith is runSandboxGate with the channel read and the
// working directory lookup injected (the tests' seam).
func runSandboxGateWith(ctx context.Context, tool, configPath string, stdin io.Reader, stderr io.Writer,
	readRecord func() (relayChildRecord, error), getwd func() (string, error),
) int {
	if tool == "" {
		fmt.Fprintln(stderr, "observer sandbox relay-gate: --tool is required")
		return 2
	}
	rec, err := readRecord()
	if err != nil {
		fmt.Fprintf(stderr, "observer sandbox relay-gate: runs only for the capture relay: %v\n", err)
		return 2
	}
	evidence, err := readBoxEvidence(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "observer sandbox relay-gate: %v\n", err)
		return 2
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dir, err := getwd()
	if err != nil {
		dir = ""
	}
	if err := sandboxGateWalk(ctx, configPath, tool, evidence, dir, rec.TrustAcceptRoot); err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 1
	}
	return 0
}

// sandboxGateWalk is the relay gate's walk of the launch-gate table. The
// daemon's relay starts the gate process in the box's working directory
// (relayChildDir, dir here) with the evidence on stdin: nobody can be asked
// there, so the walk is the daemon-started one (daemonLaunchGateRun): the
// trust row checks dir, its ask refuses and names where to accept, and no
// checked marker is set in any process environment. acceptDir, when set,
// is a copy run's source repository (relayRunTrustAcceptRoot): the trust row
// honours its accepts and still checks dir's own files.
func sandboxGateWalk(ctx context.Context, configPath, tool string, evidence budgetLaunchEvidence, dir, acceptDir string) error {
	_, err := enforceDaemonStartedLaunch(ctx, configPath, tool, evidence, daemonLaunch{dir: dir, acceptDir: acceptDir, boxed: true})
	return err
}

// Bounds of the launch evidence a box may send. They are shape and denial of
// service bounds on input the box chose, never policy: the gate walk reads
// only the first argument (an equality test against the registry's declared
// leading arguments) and the executable's identity, and nothing downstream
// stores or prints an argument.
//
// The agent's whole task rides as ONE argument (a security assessment's
// prompt is up to 24,576 bytes plus the target; the 2026-11-15 live run
// showed a 4,096 byte bound refusing every such launch), so the
// per-argument bound is the kernel's own (MAX_ARG_STRLEN, 32 pages of 4
// KiB): a longer string never reaches a started process, whatever this
// gate allows. The kernel counts the terminating NUL in that limit, so a
// string of exactly the bound would still fail execve; the one byte of
// slack is harmless for a shape bound. The total bounds the sum of all
// argument lengths: 1 MiB is about 40 times the largest real launch (a full
// task of about 25 KiB), eight maximal arguments, and half of the 2 MiB
// argument area (argv and environment together) a default 8 MiB stack gives
// execve; 256 arguments of the per-argument size (32 MiB) are refused. The
// executable is a path, so it keeps PATH_MAX. The proxy URL is a loopback
// address with at most a short route suffix.
const (
	maxBoxEvidenceArgs      = 256
	maxBoxEvidenceArgLen    = 32 * 4096
	maxBoxEvidenceArgsTotal = 1 << 20
	maxBoxEvidenceExeLen    = 4096
	maxBoxEvidenceProxyLen  = 2048

	// maxBoxEvidenceBody bounds the evidence document the relay-gate reads
	// from its stdin. It must hold the JSON of any evidence the field
	// bounds above accept: encoding/json writes a byte as up to six (an
	// escaped <, >, & or control character), so six times the
	// bounded text plus 64 KiB for the member names, quotes and commas, and
	// the room the box's own OrgRewrote list takes (the gate drops it). It
	// stays under the relay's own message cap (sandboxrelay.MaxMessage), so
	// nothing the relay can deliver is cut short here: a document cut at
	// the read bound would read as "not readable", which hid the cause.
	maxBoxEvidenceBody = 6*(maxBoxEvidenceArgsTotal+maxBoxEvidenceExeLen+maxBoxEvidenceProxyLen) + 64<<10
)

// readBoxEvidence reads the launch evidence the relay-gate got on stdin and
// validates it (boxLaunchEvidence). An error is the relay-gate's refusal
// text, naming the bound and never the value.
func readBoxEvidence(stdin io.Reader) (budgetLaunchEvidence, error) {
	// One byte past the bound is read so a document over it is refused as
	// such, not cut into a JSON error.
	body, err := io.ReadAll(io.LimitReader(stdin, maxBoxEvidenceBody+1))
	if err != nil {
		return budgetLaunchEvidence{}, fmt.Errorf("read the evidence: %w", err)
	}
	if len(body) > maxBoxEvidenceBody {
		return budgetLaunchEvidence{}, fmt.Errorf("the launch evidence is refused: the document is over the %d byte bound", maxBoxEvidenceBody)
	}
	var raw budgetLaunchEvidence
	if err := json.Unmarshal(body, &raw); err != nil {
		return budgetLaunchEvidence{}, fmt.Errorf("the launch evidence is not readable: %w", err)
	}
	evidence, err := boxLaunchEvidence(raw)
	if err != nil {
		return budgetLaunchEvidence{}, fmt.Errorf("the launch evidence is refused: %w", err)
	}
	return evidence, nil
}

// boxLaunchEvidence validates and rebuilds launch evidence a box sent: it
// is untrusted input (the box chose it), so every field is checked for
// shape and copied into a fresh value before the host gate walk reads it.
// The route is a closed enum, the executable an absolute clean path, the
// arguments bounded one by one and in total (maxBoxEvidenceArgLen,
// maxBoxEvidenceArgsTotal), the proxy URL a loopback http URL or empty, and
// the surface class empty or a registry value. A refusal names the field
// and its bound, never a value.
func boxLaunchEvidence(in budgetLaunchEvidence) (budgetLaunchEvidence, error) {
	var out budgetLaunchEvidence
	if in.Route > budgetLaunchRouteMaintenance {
		return out, fmt.Errorf("route %d", in.Route)
	}
	out.Route = in.Route
	if in.Executable != "" {
		exe := filepath.Clean(in.Executable)
		if !filepath.IsAbs(exe) || strings.ContainsRune(exe, 0) || len(exe) > maxBoxEvidenceExeLen {
			return out, errors.New("executable")
		}
		out.Executable = exe
	}
	if len(in.Arguments) > maxBoxEvidenceArgs {
		return out, fmt.Errorf("too many arguments (%d, at most %d)", len(in.Arguments), maxBoxEvidenceArgs)
	}
	total := 0
	for i, a := range in.Arguments {
		if len(a) > maxBoxEvidenceArgLen {
			return out, fmt.Errorf("argument %d is %d bytes, over the %d byte bound", i, len(a), maxBoxEvidenceArgLen)
		}
		if strings.ContainsRune(a, 0) {
			return out, fmt.Errorf("argument %d holds a NUL byte", i)
		}
		total += len(a)
		if total > maxBoxEvidenceArgsTotal {
			return out, fmt.Errorf("the arguments are over the %d byte total bound (at argument %d)", maxBoxEvidenceArgsTotal, i)
		}
		out.Arguments = append(out.Arguments, strings.Clone(a))
	}
	if in.ProxyURL != "" {
		host, _, ok := splitHostPortFromURL(in.ProxyURL)
		if !ok || len(in.ProxyURL) > maxBoxEvidenceProxyLen || (host != "127.0.0.1" && host != "localhost" && host != "::1") || !strings.HasPrefix(in.ProxyURL, "http://") {
			return out, errors.New("proxy url")
		}
		out.ProxyURL = strings.Clone(in.ProxyURL)
	}
	if in.SurfaceClass != "" {
		if !knownSurfaceClass(in.SurfaceClass) {
			return out, fmt.Errorf("surface class %q", in.SurfaceClass)
		}
		out.SurfaceClass = in.SurfaceClass
	}
	return out, nil
}

// knownSurfaceClass reports whether c is a registry surface class.
func knownSurfaceClass(c integration.InterventionSurfaceClass) bool {
	switch c {
	case integration.SurfaceDedicatedProcess, integration.SurfaceSharedHost, integration.SurfaceRemoteExecution, integration.SurfaceUnclassified:
		return true
	}
	return false
}
