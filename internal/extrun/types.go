package extrun

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Program says which program to run. Exactly one of Spec and Path is set.
type Program struct {
	// Spec is a registry binary spec, resolved through the injected resolver
	// (production: internal/toolresolve with the shim exclusion).
	Spec *integration.BinaryResolveSpec
	// Path is an absolute path chosen elsewhere (a scanner manifest, an
	// already resolved vendor binary). A relative path or a bare name is
	// refused; the runner never looks a name up on PATH.
	Path string
	// Companions are absolute paths of files the program loads that must be
	// hashed with it (for example a scanner's bundled Windows DLLs).
	Companions []string
	// CompanionExecs are executables the program itself runs (gosec runs
	// go; Opengrep runs git). Each is checked and hashed like the program,
	// may carry its own expected digest, may put its directory on the
	// program's PATH, and may be asked its version, which the run records
	// (JSP-12: gosec built with Go 1.26 silently drops three rules against a
	// Go 1.27 toolchain, so the toolchain version belongs in the record).
	CompanionExecs []CompanionExec
	// AllowSymlink lets the executable or a companion be a symlink. When
	// set, the link's final target is what runs and what is hashed, never
	// the link itself. Off by default: a symlinked executable is refused.
	AllowSymlink bool
}

// CompanionExec is one companion executable of a program.
type CompanionExec struct {
	// Path is the companion's absolute path.
	Path string
	// Expect, when set, is its expected digest; a mismatch refuses the run.
	Expect string
	// OnPath puts the companion's directory on the program's PATH, after
	// EnvSpec.PathDirs.
	OnPath bool
	// Version, when set, is how to ask the companion its version before the
	// run (cached per digest, like ProbeVersion).
	Version *VersionProbe
}

// ToolVersion is one companion's identity on a run: its path, digest and
// the version it reported (empty when it was not asked or did not answer).
type ToolVersion struct {
	Path    string
	Digest  string
	Version string
}

// Digests are lowercase hex SHA-256 digests of the binary and its companion
// files. Companions is keyed by the path as the request named it.
type Digests struct {
	Binary     string
	Companions map[string]string
}

// EnvSpec is the explicit environment a program may see. Nothing from the
// daemon's environment reaches the program unless Inherit names it.
type EnvSpec struct {
	// Set are literal NAME=VALUE pairs the caller supplies. A credential the
	// caller deliberately hands to the program goes here.
	Set []string
	// Inherit names variables copied from the daemon's environment when
	// present. Secret-shaped names (provider keys, tokens, proxy settings,
	// the daemon's own OBSERVER_ variables) are refused here.
	Inherit []string
	// PathDirs, when non-empty, become the program's PATH, in order. Each
	// must be absolute. Empty means the program gets no PATH at all.
	PathDirs []string
}

// Limits are the caps on one run. A zero Wall, StdoutBytes or StderrBytes
// takes the default (DefaultLimits); a zero MemoryBytes or Children means
// that cap is off. Negative values are refused.
type Limits struct {
	Wall        time.Duration
	StdoutBytes int64
	StderrBytes int64
	// MemoryBytes caps the program's memory (Linux: the run's cgroup
	// memory.max with memory.swap.max = 0, else RLIMIT_DATA on each process,
	// set before exec by the trampoline; Windows: the job's committed
	// memory). RLIMIT_AS is never used: a Go program cannot start under it.
	MemoryBytes int64
	// Children caps how many tasks the run may have at one time, the
	// program included, in the unit the run record names (CapResult.Unit):
	// tasks (processes and threads) under a cgroup's pids.max on Linux,
	// processes under a Windows job's ActiveProcessLimit or the polling
	// fallback. The same number therefore means different things per OS
	// (JSP-12: pids.max 64 let 13 Go children start, ActiveProcessLimit 64
	// let 64); a picker labels its steps per OS. RLIMIT_NPROC is never used:
	// it counts every process and thread the user owns.
	Children int
	// CPU caps CPU time (Linux and macOS: RLIMIT_CPU on each process, set
	// before exec, rounded up to whole seconds; Windows: the job's user
	// time, which the OS enforces late, so Wall stays the timeliness
	// guarantee). Zero means off.
	CPU time.Duration
	// FileBytes caps the size of any file the program writes (RLIMIT_FSIZE,
	// set before exec). Zero means off.
	FileBytes int64
}

// Request is one run.
type Request struct {
	// Component is the catalog id of the component that owns this run
	// (internal/components). Required.
	Component string
	Program   Program
	Args      []string
	// Expect, when set, is compared against the recorded digests; any
	// mismatch refuses the run. A field left empty is not compared.
	Expect *Digests
	Env    EnvSpec
	// Dir is the working directory, absolute. Empty means the executor's
	// scratch default (the system temporary directory), never the daemon's
	// own working directory.
	Dir string
	// Stdin is fed to the program; nil means no input.
	Stdin  []byte
	Limits Limits
	// RequireIsolation refuses the run when no IsolationProvider is wired.
	RequireIsolation bool
	// CacheDir is an absolute, Observer-owned directory the program may keep
	// a cache in (gosec took 33 s per run with a cold build cache). An
	// Engine with OwnHome puts HOME and XDG_CACHE_HOME inside it. The
	// isolation one-shot binds the same directory read-write when the caller
	// passes it as OneShotDirs.Cache.
	CacheDir string
	// Engine, when set, is the engine profile of this run: its hardening,
	// its own home and cache, and its exit-code table.
	Engine *Engine
}

// Plan is what the Executor runs: everything already resolved and checked.
type Plan struct {
	// Component is the owning component id, carried for the executor, the
	// isolation provider and the process-declaration test.
	Component string
	// Path is the absolute path of the program to start.
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Stdin  []byte
	Limits Limits
	// MakeDirs are directories the executor creates (mode 0700, parents
	// included) before the start: an engine's own HOME and cache.
	MakeDirs []string
	// Program is the checked program path before any isolation provider
	// wrapped the plan (equal to Path when nothing wrapped it). The executor
	// uses it, with Path, as the run's executable identity when it looks for
	// survivors.
	Program string
	// PIDNamespace is true when an isolation provider wrapped the plan in
	// its own pid namespace tied to the launcher's life (the containment
	// table's second rung). The Runner sets it; see WrappedInPIDNamespace.
	PIDNamespace bool
}

// KillReason says why the executor stopped a run. Empty means it did not.
type KillReason string

// The closed kill-reason vocabulary.
const (
	KillNone        KillReason = ""
	KillTimeout     KillReason = "timeout"
	KillCanceled    KillReason = "canceled"
	KillOutputCap   KillReason = "output_cap"
	KillChildrenCap KillReason = "children_cap"
)

// ExecFacts is what the Executor observed. It carries facts only; the
// Runner classifies them.
type ExecFacts struct {
	// StartErr is non-empty when the program never ran (start failure, or
	// the group or job could not be set up, in which case the executor has
	// already killed it).
	StartErr   string
	ExitCode   int
	Signaled   bool
	Signal     string
	KillReason KillReason
	Stdout     []byte
	Stderr     []byte
	// StdoutTruncated and StderrTruncated mark output past the cap.
	StdoutTruncated bool
	StderrTruncated bool
	Duration        time.Duration
	// PeakChildren is the most processes seen beside the program at once;
	// -1 when they were not counted (no child cap, or an OS that cannot
	// count them).
	PeakChildren int
	// Leftover is true when the output pipes stayed open after the group
	// was killed: a process outside the group may still be running.
	Leftover bool
	// Applied reports, per cap, what the executor actually applied on this
	// run (mechanism, unit, state). It replaces the planned row; caps it
	// does not name keep the platform's plan.
	Applied map[Cap]CapApplied
	// Trampoline is true when the caps were applied before exec by the
	// trampoline (the runner's own binary re-executed in its trampoline
	// mode).
	Trampoline bool
	// Containment is the containment block of the run record: the rung of
	// the ordered table that held the run, and what it found.
	Containment Containment
}

// Executor is the one exec seam. The production implementation lives in
// internal/extrun/host; tests use a fake.
type Executor interface {
	// Platform reports which caps this executor enforces on this OS.
	Platform() Platform
	// Exec runs the plan and reports what happened. It must kill the whole
	// process group (a job object on Windows) on timeout, cancel or a cap,
	// and must not let anything it started outlive the call where the OS
	// lets it prevent that.
	Exec(ctx context.Context, p Plan) ExecFacts
}

// IsolationProvider wraps a checked plan so it runs inside an isolation
// layer (for example a no-network bwrap profile). The sandbox plan's
// isolation engine (roadmap F0-11) implements it; this package never does.
// The wrapped plan's Path must be absolute; it is recorded as the launcher.
type IsolationProvider interface {
	Name() string
	Wrap(ctx context.Context, p Plan) (Plan, error)
}

// OneShotDirs names the directories of one isolated one-shot run (sandbox
// plan v2 section 11.1, roadmap F0-11): the project the program reads, bound
// read-only and used as its working directory; the one directory it writes
// its result to; the one directory it may keep a cache in; and any extra
// read-only directories its companion files live in. Every path is
// absolute. ~/.observer is never one of them: the isolation engine refuses a
// run whose directories reach it.
type OneShotDirs struct {
	Project     string
	Output      string
	Cache       string
	ProgramDirs []string
}

// IsolationFactory builds the IsolationProvider for one run's directories.
// The cmd layer injects one when the isolation component is compiled in and
// active, and nil otherwise, so a consumer (the security module's scanner
// drivers) never imports the isolation engine and either side can be
// omitted. A nil factory means no isolation is available here.
type IsolationFactory func(OneShotDirs) (IsolationProvider, error)

// FileFacts is what the injected inspector reports about one path.
type FileFacts struct {
	// Exists is false when nothing is at the path.
	Exists bool
	// Symlink is true when the last path component is a symlink.
	Symlink bool
	// Real is the path with every symlink resolved.
	Real string
	// Regular is true when Real is a regular file.
	Regular bool
}

// Outcome is the classified result of a run. It is a closed vocabulary.
type Outcome string

// The closed outcome vocabulary.
const (
	// OutcomeRefused: the runner refused before starting anything.
	OutcomeRefused Outcome = "refused"
	// OutcomeStartFailed: the executor could not start the program.
	OutcomeStartFailed Outcome = "start_failed"
	// OutcomeOK: the program exited with status 0.
	OutcomeOK Outcome = "ok"
	// OutcomeExitNonZero: the program exited with a non-zero status.
	OutcomeExitNonZero Outcome = "exit_nonzero"
	// OutcomeSignaled: the program died of a signal the runner did not send.
	OutcomeSignaled Outcome = "signaled"
	// OutcomeTimeout: the wall-time cap was reached and the group killed.
	OutcomeTimeout Outcome = "killed_timeout"
	// OutcomeCanceled: the caller's context ended and the group was killed.
	OutcomeCanceled Outcome = "killed_canceled"
	// OutcomeOutputCap: stdout or stderr passed its cap and the group was
	// killed.
	OutcomeOutputCap Outcome = "killed_output_cap"
	// OutcomeChildrenCap: too many processes ran beside the program and the
	// group was killed.
	OutcomeChildrenCap Outcome = "killed_children_cap"
	// OutcomeCached: a version probe answered from its per-digest cache; no
	// process was started.
	OutcomeCached Outcome = "cached"
)

// RefuseReason says why a run was refused. It is a closed vocabulary.
type RefuseReason string

// The closed refuse-reason vocabulary.
const (
	RefuseNone              RefuseReason = ""
	RefuseNoComponent       RefuseReason = "no_component"
	RefuseBadRequest        RefuseReason = "bad_request"
	RefuseBadLimits         RefuseReason = "bad_limits"
	RefuseNotAbsolute       RefuseReason = "not_absolute"
	RefuseNotFound          RefuseReason = "not_found"
	RefuseSymlink           RefuseReason = "symlink_refused"
	RefuseNotRegular        RefuseReason = "not_regular"
	RefuseScriptShim        RefuseReason = "script_shim_refused"
	RefuseDigestUnavailable RefuseReason = "digest_unavailable"
	RefuseDigestMismatch    RefuseReason = "digest_mismatch"
	RefuseEnv               RefuseReason = "env_refused"
	RefuseIsolationRequired RefuseReason = "isolation_required"
	RefuseIsolationFailed   RefuseReason = "isolation_failed"
	RefuseNoExecutor        RefuseReason = "no_executor"
)

// Mismatch is one digest that differs from the expected one.
type Mismatch struct {
	// Path is "" for the binary, else the companion path.
	Path     string
	Expected string
	Actual   string
}

// Result is the full record of one run. Environment values are never
// echoed, only names.
type Result struct {
	Component string
	Outcome   Outcome
	Reason    RefuseReason
	// Detail is one plain sentence for a refusal or a start failure.
	Detail string
	// Verdict is the toolresolve verdict when the program came from a Spec.
	Verdict string
	// Path is the absolute path of the program that ran (the final target
	// when a symlink was allowed).
	Path string
	// Launcher is the absolute path the executor actually started when an
	// isolation provider wrapped the plan; empty otherwise.
	Launcher   string
	Isolation  string
	Digests    Digests
	Mismatches []Mismatch
	// EnvNames are the names of the variables the program saw, sorted.
	EnvNames []string
	Caps     []CapResult
	ExitCode int
	Signal   string
	Stdout   []byte
	Stderr   []byte
	// StdoutTruncated and StderrTruncated mark output past the cap.
	StdoutTruncated bool
	StderrTruncated bool
	Duration        time.Duration
	PeakChildren    int
	Leftover        bool
	// Toolchain records every companion executable with its digest and the
	// version it reported, in request order.
	Toolchain []ToolVersion
	// Engine is the engine profile's name, and ExitMeaning what its exit
	// status says (empty without an engine, or when the run did not exit on
	// its own).
	Engine      string
	ExitMeaning ExitMeaning
	// CacheDir is the request's cache directory.
	CacheDir string
	// Trampoline is true when the caps were applied before exec by the
	// trampoline.
	Trampoline bool
	// Containment names the rung of the ordered containment table that held
	// the run and what it found (survivors, swept processes, the cgroup).
	Containment Containment
}
