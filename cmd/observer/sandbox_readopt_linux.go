//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_readopt_linux.go is the host side of re-adopting a LOCAL
// container run whose host helper went away (sandbox plan v2 section 5.5,
// gap G50, lane GATES-SBX), behind the opt-in component
// terminals.sandbox.oci.readopt. The decisions are internal/sandboxadopt's;
// this file keeps what a run needs to be re-adopted (its plan and host
// services' argv, which the helper deletes when it reads them), and, in the
// oci reaper's sweep BEFORE dead helpers' records are pruned, decides per
// container: offer it (the record re-keyed and kept, so neither the prune
// nor the orphan rule removes it), hold it while an update waits, or reap
// it as before. The re-adoption itself is a new host helper started by the
// user (sandbox_readopt_helper_linux.go), following the hosted precedent:
// a re-keyed relay, an EMPTY scrollback with a marker, capture resuming at
// the next event and the gap recorded.
//
// What re-adoption can and cannot cover today (recorded in docs and the
// ledger, SBX-BE-6): a helper that hangs up cleanly (the terminal closed,
// SIGHUP or SIGTERM, which a daemon exit sends through the PTY) still stops
// and removes its container, exactly as before; re-adoption covers helpers
// that died without their teardown (SIGKILL, the OOM killer, a control
// group kill), on an engine mode that keeps the container.

func init() {
	ociReadoptKeep = readoptKeep
	ociReadoptBeforeSweep = readoptSweep
	liveRunsReadoptCount = readoptLiveCount
	sandboxSubcommands = append(sandboxSubcommands, newSandboxRunsCmd, newSandboxReadoptCmd, newSandboxCheckpointCmd, newSandboxRestoreCmd)
	gatesSandboxRouteFuncs = append(gatesSandboxRouteFuncs, readoptDashboardRoutes)
	// Every prune of a dead helper's record asks this first (F-045), so the
	// sweep below decides a re-adoptable run whichever sweep runs first.
	sandboxrelayd.SetDeadRunHold(readoptHoldDeadRecord)
}

// readoptHoldDeadRecord is the dead-run hold (sandboxrelayd.SetDeadRunHold):
// a run whose helper is gone keeps its relay record and lock file while
// sandboxadopt.HoldDeadRecord says the re-adoption sweep decides it. Before
// it, the relay's start prune (a daemon restart) or its own sweep (a killed
// helper) removed them first; the sweep then read a run with no lock and no
// offer, decided nothing, and the orphan rule removed the container (the
// N1-L1 live pass of 2026-11-03, tracker F-045). The settings are read only
// for a run that has a kept entry. A kept entry the hold lets go (rows
// component and cli-run) gets the same decision log line as a decision of
// the sweep (fix round 1, audit FU10-A4), and nothing else: the hold runs
// in every process and goroutine that prunes, so it never writes
// readoptEndedFile, whose one writer is the oci reaper's sweep (fix round
// 2, audit FU10-R1).
func readoptHoldDeadRecord(observerDir, runID string) bool {
	if !sandboxoci.ValidToken(runID) {
		return false
	}
	if _, err := os.Lstat(readoptRunDir(observerDir, runID)); err != nil {
		return false
	}
	e := readoptRead(observerDir, runID)
	f := sandboxadopt.HoldFacts{Kept: e.keptOK && e.planOK}
	if f.Kept {
		f.Active = readoptLoadSettings(context.Background()).active
		f.CLIRun = readoptCLIRun(observerDir, e)
	}
	hold, d := sandboxadopt.HoldDeadRecord(f)
	if !hold && f.Kept {
		readoptLogDecision(runID, d)
	}
	return hold
}

// readoptDirName is the re-adoption directory under the observer dir.
const readoptDirName = "sandbox-adopt"

// The files of one run's entry.
const (
	readoptKeptFile  = "kept.json"
	readoptPlanFile  = "plan.json"
	readoptOfferFile = "offer.json"
	readoptVersion   = 1
	readoptMaxFile   = 4 << 20
)

// readoptStaleKept is how long an entry with a record and no container yet
// is kept (a run between its plan and its container create).
const readoptStaleKept = time.Hour

// readoptDir is the re-adoption directory of observerDir.
func readoptDir(observerDir string) string { return filepath.Join(observerDir, readoptDirName) }

// readoptRunDir is one run's entry.
func readoptRunDir(observerDir, runID string) string {
	return filepath.Join(readoptDir(observerDir), runID)
}

// readoptFacts are the run's relay facts, kept without its secrets: a
// re-adoption mints new ones.
type readoptFacts struct {
	Tool          string                 `json:"tool"`
	ProjectRoot   string                 `json:"project_root"`
	WorkspaceDir  string                 `json:"workspace_dir"`
	Roots         []string               `json:"roots"`
	Delivery      sandboxrelayd.Delivery `json:"delivery"`
	CopyHostPath  string                 `json:"copy_host_path,omitempty"`
	ConfigPath    string                 `json:"config_path,omitempty"`
	TerminalRunID string                 `json:"terminal_run_id,omitempty"`
}

// readoptKept is what the run's compose kept.
type readoptKept struct {
	V      int          `json:"v"`
	RunID  string       `json:"run_id"`
	Wrap   []string     `json:"wrap"`
	Facts  readoptFacts `json:"facts"`
	KeptAt time.Time    `json:"kept_at"`
	// Policy is what the run was launched under (nil in an entry kept
	// before it was recorded, which a re-adoption refuses).
	Policy *readoptPolicy `json:"policy,omitempty"`
}

// readoptPolicy is the part of [terminal.sandbox] a run was launched under
// that decides what its box may reach (audit F4). A re-adoption or a
// restore compares it with today's settings, the organization floors in
// force and the backend list, and refuses policy_changed unless the kept
// plan is the same or stricter.
type readoptPolicy struct {
	Backend          string   `json:"backend"`
	Tier             string   `json:"tier"`
	ExtraRWBinds     []string `json:"extra_rw_binds,omitempty"`
	ExtraROBinds     []string `json:"extra_ro_binds,omitempty"`
	AllowCIDRs       []string `json:"allow_cidrs,omitempty"`
	MaskPaths        []string `json:"mask_paths,omitempty"`
	ToolConfigWrites bool     `json:"tool_config_writes,omitempty"`
}

// readoptPolicyOf is the policy a run builds under cfg at tier on backend.
func readoptPolicyOf(cfg config.TerminalSandboxConfig, tier, backend string) readoptPolicy {
	if backend == "" {
		backend = sandboxbackend.BackendOCIRunc
	}
	return readoptPolicy{
		Backend: backend, Tier: tier,
		ExtraRWBinds: append([]string(nil), cfg.ExtraRWBinds...), ExtraROBinds: append([]string(nil), cfg.ExtraROBinds...),
		AllowCIDRs: append([]string(nil), cfg.EgressAllowCIDRs...), MaskPaths: append([]string(nil), cfg.MaskPaths...),
		ToolConfigWrites: cfg.AllowToolConfigWrites,
	}
}

// readoptToday reads today's [terminal.sandbox] settings (the organization's
// pins applied, as every config load applies them) and the organization
// floors in force through sandboxOrgFloorsFor, the one reader the daemon
// route and a CLI readopt or restore share (R-035; a test seam).
var readoptToday = func() (config.TerminalSandboxConfig, sandboxselect.Floors, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	if err != nil {
		return config.TerminalSandboxConfig{}, sandboxselect.Floors{}, err
	}
	// The one floors reader (R-035): the daemon's in-memory floors in the
	// daemon, the same verified cache in a CLI readopt or restore. A CLI
	// that cannot read them fails closed (R-166): the error refuses the
	// re-adoption with org_floors_unreadable.
	floors, err := sandboxOrgFloorsFor(context.Background(), cfg)
	if err != nil {
		return config.TerminalSandboxConfig{}, sandboxselect.Floors{}, err
	}
	return cfg.Terminal.Sandbox, floors, nil
}

// readoptPolicyCheck refuses policy_changed when the kept plan is wider
// than the one today's settings, floors and backend list would build.
func readoptPolicyCheck(kept *readoptPolicy) error {
	f := sandboxadopt.PolicyFacts{Recorded: kept != nil}
	if kept == nil {
		return *sandboxadopt.CheckPolicy(f)
	}
	f.Backend, f.KeptTier = kept.Backend, kept.Tier
	f.KeptTierStrictness = vocab.Tier(kept.Tier).Strictness()
	cfg, floors, err := readoptToday()
	todayTier := vocab.TierInternet
	if err == nil {
		var prof sandbox.EgressProfile
		if prof, err = sandbox.ResolveEgress(cfg.Egress); err == nil {
			todayTier = vocab.Tier(prof.Mode)
		}
	}
	if err != nil {
		f.TodayErr = err.Error()
		return *sandboxadopt.CheckPolicy(f)
	}
	f.TodayRead = true
	f.TodayTier, f.TodayTierStrictness = string(todayTier), todayTier.Strictness()
	row, ok := sandboxbackend.Get(kept.Backend)
	f.Listed = ok && slices.Contains(sandboxEnabledBackends(cfg), kept.Backend)
	if floor := vocab.IsoClass(cfg.MinIsolation); ok && floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		f.BelowMinIsolation = string(floor)
	}
	if ok && floors.InForce() {
		beta := true
		if v, vok := row.VerificationOn(sandboxHostKind()); vok {
			beta = v.Kind.IsBeta()
		}
		in := sandboxselect.Input{
			Request: sandboxselect.Request{Backend: row.ID, Tier: vocab.Tier(kept.Tier), Interactive: true, Custody: vocab.CustodyHostBound, AcceptReducedCapture: true, ProviderDirect: cfg.EffectiveProviderDirect()},
			Host:    sandboxHostKind(), Floors: floors,
			Tool: sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: true},
		}
		if drop, dropped := sandboxselect.FloorDrop(row, in, beta); dropped {
			f.FloorDropped = isolationFloorMessage(drop)
		}
	}
	f.WidenedBinds = sandboxadopt.WidenedBinds(kept.ExtraRWBinds, kept.ExtraROBinds, cfg.ExtraRWBinds, cfg.ExtraROBinds)
	f.WidenedCIDRs = sandboxadopt.Missing(kept.AllowCIDRs, cfg.EgressAllowCIDRs)
	f.DroppedMasks = sandboxadopt.Missing(cfg.MaskPaths, kept.MaskPaths)
	f.ToolConfigWritesWidened = kept.ToolConfigWrites && !cfg.AllowToolConfigWrites
	if r := sandboxadopt.CheckPolicy(f); r != nil {
		return *r
	}
	return nil
}

// readoptOffer is the run's offer, written by the sweep that first found
// its helper gone.
type readoptOffer struct {
	V           int               `json:"v"`
	RunID       string            `json:"run_id"`
	ContainerID string            `json:"container_id"`
	OfferedAt   time.Time         `json:"offered_at"`
	Expires     time.Time         `json:"expires"`
	Code        sandboxadopt.Code `json:"code"`
	// Row is the sandboxadopt table row that decided (F-046).
	Row      string `json:"row,omitempty"`
	Reason   string `json:"reason"`
	Declined bool   `json:"declined,omitempty"`
	// ReadoptedAt and GapFrom record a re-adoption: the run's capture has a
	// gap from GapFrom (the helper found gone) to ReadoptedAt.
	ReadoptedAt time.Time `json:"readopted_at,omitzero"`
	GapFrom     time.Time `json:"gap_from,omitzero"`
	// Checkpointed: the run's container was checkpointed to its export and
	// removed; it waits for a restore.
	Checkpointed bool   `json:"checkpointed,omitempty"`
	Export       string `json:"export,omitempty"`
}

// readoptEntry is one run's entry as read.
type readoptEntry struct {
	kept     readoptKept
	keptOK   bool
	keptErr  error
	plan     ociPlanFile
	planOK   bool
	offer    readoptOffer
	hasOffer bool
}

// readoptObserverDir is the daemon's observer dir, set by its first sweep
// (the live-run count reads the entries there).
var readoptObserverDir atomic.Pointer[string]

// readoptNow is the clock (a test seam).
var readoptNow = func() time.Time { return time.Now().UTC() }

// readoptSettings is the component state and the bound under cfgPath.
type readoptSettings struct {
	active   bool
	bound    time.Duration
	capBytes int64
}

// readoptLoadSettings reads the settings fresh (a variable so tests set it).
var readoptLoadSettings = func(ctx context.Context) readoptSettings {
	s := readoptSettings{active: sandboxFeatureActive(ctx, daemonConfigPath(), readoptComponent)}
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()}); err == nil {
		r := cfg.Terminal.Sandbox.Readopt
		s.bound = sandboxadopt.ClampBound(time.Duration(r.BoundMinutes) * time.Minute)
		if r.CheckpointCapMiB > 0 {
			s.capBytes = int64(r.CheckpointCapMiB) << 20
		}
	}
	if s.bound == 0 {
		s.bound = sandboxadopt.DefaultBound
	}
	return s
}

// readoptWriteFile writes name in dir (created 0700) whole: a fresh 0600
// file renamed over the old one, never through a link.
func readoptWriteFile(dir, name string, v any) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+".tmp")
	_ = os.Remove(tmp)
	f, err := ociCreateExcl(tmp)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// readoptKeep keeps a run's plan and host argv, and the settings it was
// launched under, when the component is on.
func readoptKeep(observerDir, runID, planPath string, wrap []string, cfg config.TerminalSandboxConfig, tier string) {
	if !sandboxoci.ValidToken(runID) || !readoptLoadSettings(context.Background()).active {
		return
	}
	rec, err := sandboxrelayd.ReadRun(observerDir, runID)
	if err != nil {
		return
	}
	b, err := readOwnedNoFollow(planPath, readoptMaxFile)
	if err != nil {
		return
	}
	dir := readoptRunDir(observerDir, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	var plan ociPlanFile
	if json.Unmarshal(b, &plan) != nil {
		return
	}
	pol := readoptPolicyOf(cfg, tier, plan.Backend)
	kept := readoptKept{V: readoptVersion, RunID: runID, Wrap: wrap, KeptAt: readoptNow(), Policy: &pol, Facts: readoptFacts{
		Tool: rec.Tool, ProjectRoot: rec.ProjectRoot, WorkspaceDir: rec.WorkspaceDir, Roots: rec.Roots,
		Delivery: rec.Delivery, CopyHostPath: rec.CopyHostPath, ConfigPath: rec.ConfigPath, TerminalRunID: rec.TerminalRunID,
	}}
	if readoptWriteFile(dir, readoptPlanFile, plan) != nil || readoptWriteFile(dir, readoptKeptFile, kept) != nil {
		_ = os.RemoveAll(dir)
	}
}

// readoptRead reads one run's entry; every file is owner-checked and read
// without following a link.
func readoptRead(observerDir, runID string) readoptEntry {
	var e readoptEntry
	dir := readoptRunDir(observerDir, runID)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || !ownedByMe(fi) || fi.Mode().Perm()&0o077 != 0 {
		e.keptErr = errors.New("the run's entry is not an owner-only directory of this user")
		return e
	}
	if b, err := readOwnedNoFollow(filepath.Join(dir, readoptKeptFile), readoptMaxFile); err != nil {
		e.keptErr = err
	} else if err := json.Unmarshal(b, &e.kept); err != nil {
		e.keptErr = err
	} else if e.kept.V != readoptVersion || e.kept.RunID != runID || len(e.kept.Wrap) < 6 {
		e.keptErr = errors.New("the kept record does not name this run")
	} else {
		e.keptOK = true
	}
	if plan, err := readOCIPlan(filepath.Join(dir, readoptPlanFile)); err == nil && plan.Create.RunID == runID {
		e.plan, e.planOK = plan, true
	}
	if b, err := readOwnedNoFollow(filepath.Join(dir, readoptOfferFile), readoptMaxFile); err == nil {
		if json.Unmarshal(b, &e.offer) == nil && e.offer.RunID == runID {
			e.hasOffer = true
		}
	}
	return e
}

// readoptHostArgs parses the kept host services' argv.
func readoptHostArgs(kept readoptKept) (sandbox.HostArgs, error) {
	_, h, err := parseOCIHostArgs(append(append([]string(nil), kept.Wrap[2:]...), "observer"))
	return h, err
}

// readoptSockDirCheck is the protected-path fact the read-back cannot see:
// the per-run socket dir (bound into the container) is still this user's
// owner-only directory, not a link.
func readoptSockDirCheck(dir string) error {
	if dir == "" {
		return nil
	}
	fi, err := os.Lstat(dir)
	switch {
	case err != nil:
		return fmt.Errorf("the socket dir %s is gone", dir)
	case !fi.IsDir():
		return fmt.Errorf("the socket dir %s is not a directory", dir)
	case !ownedByMe(fi) || fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("the socket dir %s is not an owner-only directory of this user", dir)
	}
	return nil
}

// readoptHelperState reads a run's liveness lock: held (a helper runs),
// gone (the lock file exists and nobody holds it) or none (no lock file).
type readoptHelperState int

const (
	readoptHelperNone readoptHelperState = iota
	readoptHelperHeld
	readoptHelperGone
)

func readoptHelper(observerDir, runID string) readoptHelperState {
	f, err := os.OpenFile(filepath.Join(sandboxrelayd.RunsDir(observerDir), runID+".alive"), os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a fixed name under the daemon's own runs dir, run id shape-checked
	if err != nil {
		return readoptHelperNone
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || !ownedByMe(fi) {
		return readoptHelperNone
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		return readoptHelperHeld
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // G115: a descriptor number
	return readoptHelperGone
}

// readoptRecordExists reports whether the run's relay record file exists.
func readoptRecordExists(observerDir, runID string) bool {
	_, err := os.Lstat(filepath.Join(sandboxrelayd.RunsDir(observerDir), runID+".json")) //nolint:gosec // G703: false positive; an existence check of a run record under the relay runs dir, nothing is read or written
	return err == nil
}

// readoptCLIRun reports whether a CLI process, not the daemon, watches the
// kept run: its CLI watch file is a regular file. The sweep reads it as
// Facts.CLIRun, and the daemon-exit mark skips such a run (LEFT2 audit S2):
// the daemon does not route a CLI run, so a user closing their own CLI
// terminal while the daemon is down must stop the container.
//
// The terminal run is resolved through readoptTerminalRun (audit FU11-A1):
// the compose keeps the facts before the launcher binds the terminal run,
// so the kept id alone is always empty and a CLI run was never seen; the
// run's relay record still exists at every caller (the live helper's
// daemon-exit mark, the dead-run hold before the prune, and the sweep after
// the hold kept it) and names it.
func readoptCLIRun(observerDir string, e readoptEntry) bool {
	if !e.keptOK {
		return false
	}
	terminalRun := readoptTerminalRun(observerDir, e.kept.RunID, e.kept.Facts.TerminalRunID)
	if terminalRun == "" {
		return false
	}
	watch, _ := sandboxCLIEndPaths(observerDir, terminalRun)
	fi, err := os.Lstat(watch)
	return err == nil && fi.Mode().IsRegular()
}

// readoptEngine is the engine facts one sweep reads once.
type readoptEngine struct {
	id    sandboxoci.Identity
	facts sandboxadopt.EngineFacts
	err   error
}

func readoptReadEngine(ctx context.Context, c *sandboxengine.Client) readoptEngine {
	qctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	v, err := c.Version(qctx)
	if err != nil {
		return readoptEngine{err: err}
	}
	pre, _ := sandboxoci.Classify(v, sandboxoci.InfoFacts{})
	info, err := c.Info(qctx, pre.Engine)
	if err != nil {
		return readoptEngine{err: err}
	}
	id, verdict := sandboxoci.Classify(v, info)
	if !verdict.OK() {
		return readoptEngine{err: verdict}
	}
	rf, err := c.RestartFacts(qctx, id.Engine)
	if err != nil {
		return readoptEngine{err: err}
	}
	return readoptEngine{id: id, facts: sandboxadopt.EngineFacts{
		Engine: sandboxadopt.Engine(id.Engine), Mode: sandboxadopt.Mode(id.Mode),
		LiveRestore: rf.LiveRestore, Conmon: rf.ConmonPath != "",
	}}
}

// readoptFactsFor gathers one container's facts.
func readoptFactsFor(ctx context.Context, c *sandboxengine.Client, observerDir string, e readoptEntry, ct sandboxoci.ContainerFact, installID string, eng readoptEngine, set readoptSettings, now time.Time) sandboxadopt.Facts {
	f := sandboxadopt.Facts{
		Active: set.active, RecordIntact: e.keptOK, RecordOwned: e.keptOK, PlanKept: e.planOK,
		LabelsMatch: ct.Labels[sandboxoci.LabelRole] == sandboxoci.RoleSandbox && ct.Labels[sandboxoci.LabelInstall] == installID && ct.Labels[sandboxoci.LabelRun] == e.kept.RunID,
		Running:     ct.Running, Engine: eng.facts, Now: now, Bound: set.bound,
		Declined: e.hasOffer && e.offer.Declined, UpdateDeferred: readoptUpdateDeferred(),
	}
	if e.keptErr != nil && errors.Is(e.keptErr, fs.ErrNotExist) {
		f.RecordOwned = true // missing, not foreign: the missing row says so
	}
	if e.hasOffer {
		f.OfferedAt = e.offer.OfferedAt
	}
	f.CLIRun = readoptCLIRun(observerDir, e)
	switch {
	case eng.err != nil:
		f.ReadBackReason = "the engine could not be read: " + eng.err.Error()
	case !e.planOK:
		f.ReadBackReason = "no kept plan"
	case e.plan.Socket != c.Socket():
		f.ReadBackReason = "the run was planned on another engine socket"
	case eng.id.Fingerprint != e.plan.Fingerprint || eng.id.Engine != e.plan.Engine || eng.id.Mode != e.plan.Mode:
		f.ReadBackReason = "the engine on the socket changed after the run was planned"
	default:
		if v := readoptReadBack(ctx, c, ct.ID, eng.id, e.plan.Create); v.OK() {
			f.ReadBackOK = true
		} else {
			f.ReadBackReason = v.Reason
		}
	}
	f.ProtectedIntact, f.ProtectedReason = true, ""
	if e.keptOK {
		h, err := readoptHostArgs(e.kept)
		if err == nil {
			err = readoptSockDirCheck(h.SockDir)
		}
		if err != nil {
			f.ProtectedIntact, f.ProtectedReason = false, err.Error()
		}
	}
	return f
}

// readoptReadBack is the existing oci read-back of a live container
// against its kept plan (a variable so a test drives an engine shape the
// fake does not model).
var readoptReadBack = func(ctx context.Context, c *sandboxengine.Client, cid string, id sandboxoci.Identity, cp sandboxoci.CreatePlan) sandboxoci.Verdict {
	return (&ociRun{c: c, id: cid, engine: id.Engine}).readBack(ctx, id, cp)
}

// readoptCheckSocket repeats the socket rules before a re-adoption,
// checkpoint or restore drives the engine (a test seam).
var readoptCheckSocket = ociCheckSocket

// readoptUpdateDeferred reports whether an update apply waits on live
// sandboxed runs (the SBX-UPD deferral).
func readoptUpdateDeferred() bool {
	h := updateLiveDeferredHook.Load()
	return h != nil && h.pending()
}

// readoptSweep is the reaper's first step (ociReadoptBeforeSweep).
func readoptSweep(ctx context.Context, c *sandboxengine.Client, installID, observerDir string) {
	entries, err := os.ReadDir(readoptDir(observerDir))
	if err != nil {
		return // nothing kept: the sweep runs exactly as before
	}
	od := observerDir
	readoptObserverDir.Store(&od)
	set := readoptLoadSettings(ctx)
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	list, err := c.ContainerList(lctx, sandboxoci.InstallFilter(installID))
	if err != nil {
		return // the engine is down: nothing is decided
	}
	byRun := map[string]sandboxoci.ContainerFact{}
	for _, ct := range list {
		if run := ct.Labels[sandboxoci.LabelRun]; run != "" {
			byRun[run] = ct
		}
	}
	var eng *readoptEngine
	now := readoptNow()
	for _, de := range entries {
		runID := de.Name()
		if !de.IsDir() || !sandboxoci.ValidToken(runID) {
			continue
		}
		readoptDecideOne(lctx, c, installID, observerDir, runID, byRun, &eng, set, now)
	}
}

// readoptDecideOne decides one entry.
func readoptDecideOne(ctx context.Context, c *sandboxengine.Client, installID, observerDir, runID string, byRun map[string]sandboxoci.ContainerFact, eng **readoptEngine, set readoptSettings, now time.Time) {
	helper := readoptHelper(observerDir, runID)
	if helper == readoptHelperHeld {
		return // a helper (the run's own, or a re-adoption) is alive
	}
	e := readoptRead(observerDir, runID)
	ct, has := byRun[runID]
	if !has {
		switch {
		case e.hasOffer && e.offer.Checkpointed && set.active && !e.offer.Declined && now.Before(e.offer.Expires):
			// Waits for its restore until its retention runs out; then the
			// next row ends it (record and export) like any offer (audit F9).
		case e.hasOffer:
			readoptDecided(observerDir, runID, e, readoptContainerGone, now)
			readoptEnd(observerDir, runID)
		case helper == readoptHelperGone:
			// The helper died with no container left (or before it made
			// one): nothing to re-adopt, and the entry goes now so the
			// dead-run hold lets the prune end the run (F-045).
			readoptDecided(observerDir, runID, e, readoptContainerGone, now)
			_ = os.RemoveAll(readoptRunDir(observerDir, runID))
		case !readoptRecordExists(observerDir, runID) || now.Sub(e.kept.KeptAt) > readoptStaleKept:
			_ = os.RemoveAll(readoptRunDir(observerDir, runID))
		}
		return
	}
	if helper == readoptHelperNone && !e.hasOffer {
		return // a live run from a helper without a lock, or one starting
	}
	if *eng == nil {
		re := readoptReadEngine(ctx, c)
		*eng = &re
	}
	d := sandboxadopt.Decide(readoptFactsFor(ctx, c, observerDir, e, ct, installID, **eng, set, now))
	readoptDecided(observerDir, runID, e, d, now)
	if d.Action == sandboxadopt.ActionReap {
		if e.hasOffer {
			readoptEnd(observerDir, runID)
		} else {
			_ = os.RemoveAll(readoptRunDir(observerDir, runID))
		}
		return
	}
	_ = readoptClaim(observerDir, e, ct, d, now)
}

// readoptClaim keeps an offered run: its stale liveness lock goes first (so
// no prune can remove the record), then the relay record is re-keyed from
// the kept facts (new secrets, the same attribution), then the offer is
// written.
func readoptClaim(observerDir string, e readoptEntry, ct sandboxoci.ContainerFact, d sandboxadopt.Decision, now time.Time) error {
	runID := e.kept.RunID
	if !e.hasOffer {
		_ = os.Remove(filepath.Join(sandboxrelayd.RunsDir(observerDir), runID+".alive"))
		if err := readoptRekey(observerDir, e.kept); err != nil {
			return err
		}
	}
	offer := e.offer
	if !e.hasOffer {
		offer = readoptOffer{V: readoptVersion, RunID: runID, OfferedAt: now, GapFrom: now}
	}
	offer.ContainerID, offer.Code, offer.Row, offer.Reason, offer.Expires = ct.ID, d.Code, d.Row, d.Reason, d.Expires
	return readoptWriteFile(readoptRunDir(observerDir, runID), readoptOfferFile, offer)
}

// readoptContainerGone is the decision for an entry whose container the
// engine no longer lists: the run ends (its offer, if any, with it).
var readoptContainerGone = sandboxadopt.Decision{
	Action: sandboxadopt.ActionReap, Code: sandboxadopt.CodeNotRunning, Row: sandboxadopt.RowContainerGone,
	Reason: "the engine no longer lists the run's container", Summary: "the engine no longer lists the run's container",
}

// readoptEndedFile keeps the last decisions that ended a run (F-046), so
// `observer sandbox runs` and `readopt` can say which row ended a run that
// is no longer offered. It sits beside the run entries, never inside one
// (an entry is removed with its run).
const readoptEndedFile = "ended.json"

// readoptEndedCap bounds the kept decisions (newest first).
const readoptEndedCap = 20

// readoptEnded is one kept decision that ended a run. It holds the run id,
// the row, the code and the row's fact-free line (Decision.Summary: no
// socket dir path, no engine error text; audit FU10-A2), never a secret.
type readoptEnded struct {
	RunID  string            `json:"run_id"`
	Tool   string            `json:"tool,omitempty"`
	Row    string            `json:"row"`
	Code   sandboxadopt.Code `json:"code"`
	Reason string            `json:"reason"`
	At     time.Time         `json:"at"`
}

// readoptLogger is the daemon's logger for the decisions (nil outside the
// daemon or before the reaper started: nothing is logged).
func readoptLogger() *slog.Logger { return processOCIReaper.logger.Load() }

// readoptDecided logs one decision as one structured line naming the run
// and the row (F-046) with the fact-free line (Decision.Summary; the full
// reason stays for the terminal that runs readopt), once per change: a
// sweep that gives an offered or held run the same answer as the last one
// logs nothing. A decision that ends the run is also kept in
// readoptEndedFile. Only the oci reaper's sweep calls it (one goroutine of
// the daemon), so readoptEndedFile has that one writer (fix round 2, audit
// FU10-R1); the dead-run hold, which runs wherever a prune does, calls
// readoptLogDecision only.
func readoptDecided(observerDir, runID string, e readoptEntry, d sandboxadopt.Decision, now time.Time) {
	if d.Action != sandboxadopt.ActionReap && e.hasOffer && e.offer.Code == d.Code && e.offer.Row == d.Row {
		return
	}
	readoptLogDecision(runID, d)
	if d.Action == sandboxadopt.ActionReap {
		readoptRecordEnded(observerDir, readoptEnded{RunID: runID, Tool: e.kept.Facts.Tool, Row: d.Row, Code: d.Code, Reason: d.Summary, At: now})
	}
}

// readoptLogDecision writes one decision's structured log line (run, row,
// action, code, fact-free line); nothing when no daemon logger is set.
func readoptLogDecision(runID string, d sandboxadopt.Decision) {
	if l := readoptLogger(); l != nil {
		l.Info("terminal_sandbox: re-adoption decision", "run", runID, "row", d.Row, "action", string(d.Action), "code", string(d.Code), "reason", d.Summary)
	}
}

// readoptEndedList reads the kept decisions (newest first; none when the
// file is missing or unreadable).
func readoptEndedList(observerDir string) []readoptEnded {
	b, err := readOwnedNoFollow(filepath.Join(readoptDir(observerDir), readoptEndedFile), readoptMaxFile)
	if err != nil {
		return nil
	}
	var out []readoptEnded
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// readoptRecordEnded puts rec first in readoptEndedFile, replacing an
// earlier decision for the same run, within readoptEndedCap. Best-effort.
func readoptRecordEnded(observerDir string, rec readoptEnded) {
	list := []readoptEnded{rec}
	for _, x := range readoptEndedList(observerDir) {
		if x.RunID != rec.RunID && len(list) < readoptEndedCap {
			list = append(list, x)
		}
	}
	_ = readoptWriteFile(readoptDir(observerDir), readoptEndedFile, list)
}

// readoptNotOffered is the refusal for a run that holds no offer: when the
// re-adoption step ended it, the refusal names the row that did (F-046).
func readoptNotOffered(observerDir, runID string) error {
	if x, ok := readoptEndedFor(observerDir, runID); ok {
		return fmt.Errorf("run %s is not offered for re-adoption: it was ended at %s by row %s (%s): %s", runID, x.At.Local().Format(time.RFC3339), x.Row, x.Code, x.Reason)
	}
	return fmt.Errorf("run %s is not offered for re-adoption (the offers are listed in Terminals > Settings > Sandbox isolation; see observer sandbox runs)", runID)
}

// readoptEndedFor is the kept decision that ended runID, if any.
func readoptEndedFor(observerDir, runID string) (readoptEnded, bool) {
	for _, x := range readoptEndedList(observerDir) {
		if x.RunID == runID {
			return x, true
		}
	}
	return readoptEnded{}, false
}

// readoptRekey writes a fresh relay record for the run from its kept facts.
func readoptRekey(observerDir string, kept readoptKept) error {
	f := kept.Facts
	// The record carries the run's own terminal run, the same as before the
	// re-adoption, so its refusal rows keep the run's id, backend and tier
	// (tracker F-053).
	terminalRun := readoptTerminalRun(observerDir, kept.RunID, f.TerminalRunID)
	fresh, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
		RunID: kept.RunID, Tool: f.Tool, ProjectRoot: f.ProjectRoot, WorkspaceDir: f.WorkspaceDir, Roots: f.Roots,
		Delivery: f.Delivery, CopyHostPath: f.CopyHostPath, ConfigPath: f.ConfigPath, TerminalRunID: terminalRun,
		RefusalAuditRequired: sandboxOrgFloors().RequireRefusalAudit,
	})
	if err != nil {
		return err
	}
	if err := sandboxrelayd.RemoveRun(observerDir, kept.RunID); err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, sandboxrelayd.ErrNoRecord) {
		return err
	}
	return sandboxrelayd.WriteRun(observerDir, fresh)
}

// readoptEnd ends a claimed run as a prune would (its record removed and
// handed to the daemon's run ender), and removes its entry; the reaper's
// orphan rule then removes its container in the same sweep. Like
// pruneGoneRelayRuns it does nothing until the daemon's run ender is set
// (the first sweep after start runs before it): removing the record then
// would leave a CLI launch's stored row reading running for good (audit F3,
// the R2 rule). A later sweep ends the run. It reports whether it ended it.
func readoptEnd(observerDir, runID string) bool {
	if relayGoneRunEnder.Load() == nil {
		return false
	}
	rec, err := sandboxrelayd.ReadRun(observerDir, runID)
	if err != nil {
		rec = sandboxrelayd.RunRecord{RunID: runID}
	}
	if sandboxrelayd.RemoveRun(observerDir, runID) == nil {
		endGoneRelayRuns([]sandboxrelayd.RunRecord{rec})
	}
	_ = os.RemoveAll(readoptRunDir(observerDir, runID))
	return true
}

// readoptEndOrDecline ends the run now in a process that holds the run
// ender (the daemon's dashboard routes), and otherwise (the CLI) marks the
// offer declined, so the daemon's next sweep ends it through its ender.
func readoptEndOrDecline(observerDir, runID string, e readoptEntry) {
	if readoptEnd(observerDir, runID) {
		return
	}
	offer := e.offer
	if !e.hasOffer {
		offer = readoptOffer{V: readoptVersion, RunID: runID, OfferedAt: readoptNow()}
	}
	offer.Declined = true
	_ = readoptWriteFile(readoptRunDir(observerDir, runID), readoptOfferFile, offer)
}

// readoptOffered lists the entries holding an offer (sorted by run id).
func readoptOffered(observerDir string) []readoptEntry {
	entries, err := os.ReadDir(readoptDir(observerDir))
	if err != nil {
		return nil
	}
	var out []readoptEntry
	for _, de := range entries {
		if !de.IsDir() || !sandboxoci.ValidToken(de.Name()) {
			continue
		}
		if e := readoptRead(observerDir, de.Name()); e.hasOffer {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].kept.RunID < out[j].kept.RunID })
	return out
}

// readoptLiveCount is the live-run gate's count: offers not yet past their
// bound (or held for an update), never a checkpointed run (no process).
func readoptLiveCount() int {
	p := readoptObserverDir.Load()
	if p == nil {
		return 0
	}
	now := readoptNow()
	n := 0
	for _, e := range readoptOffered(*p) {
		if e.offer.Checkpointed || e.offer.Declined || !e.offer.ReadoptedAt.IsZero() {
			continue
		}
		if e.offer.Code == sandboxadopt.CodeHeldForUpdate || now.Before(e.offer.Expires) {
			n++
		}
	}
	return n
}
