package seciac

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// driver.go is the one run seam both IaC drivers share (lane GATES-SEC
// decisions 1 to 4): resolve the engine (Observer's guided install first,
// else the one on the PATH, shims excluded), hash it and decide, check the
// isolation, ask the version and the --help flags under the same digest,
// pass the canary self-test once per binary, run the fixed argument list
// through internal/extrun with the binary digest expected, and turn the
// SARIF into iac findings. Background only, never in a hook. Every I/O is
// in Env.

// State is a driver's node-local state, one file per engine, written by one
// owner (the cmd layer's state store).
type State struct {
	// FirstUse is the digest of an unpinned binary the first time it ran
	// on this individual node (plan 8.1: recorded at first use, re-checked
	// every run).
	FirstUse string `json:"first_use,omitempty"`
	// FlagsOK is the binary digest whose --help listed every required flag.
	FlagsOK string `json:"flags_ok,omitempty"`
	// SelfTest is the binary digest whose canary run reported the canary.
	SelfTest   string    `json:"self_test,omitempty"`
	SelfTestAt time.Time `json:"self_test_at,omitempty"`
	// Tree is KICS's queries tree record (X9).
	Tree *secengine.TreeRecord `json:"tree,omitempty"`
	// Revoked are engine digests a manifest revoked, kept (nothing removes
	// from it) so a revocation outlives a stale manifest.
	Revoked []string `json:"revoked,omitempty"`
}

// StateStore loads and saves State.
type StateStore interface {
	Load() (State, error)
	Save(State) error
}

// Env is what the driver needs from the caller.
type Env struct {
	Engine EngineID
	// Runner is the unisolated runner; Isolate and IsolatedRunner build an
	// isolated one (nil: no isolation on this host).
	Runner         *extrun.Runner
	Isolate        func(extrun.OneShotDirs) (extrun.IsolationProvider, error)
	IsolatedRunner func(extrun.IsolationProvider) *extrun.Runner
	// CacheDir is the engine-owned HOME and cache root; OutDir this run's
	// output directory (made and removed by the caller); CanaryDir holds the
	// canary project (the caller writes CanaryFiles there).
	CacheDir  string
	OutDir    string
	CanaryDir string
	// Installed is the guided install's binary path ("" when none);
	// InstallRecord its verified record.
	Installed     string
	InstallRecord *InstallRecord
	Managed       bool
	// ProbeHash, when set, hashes the engine binary for the resolve step
	// (the daemon's 15 s probe and every decision): the cmd layer caches it
	// by path, size and modification time so an unchanged binary is not
	// rehashed (audit finding F5). The runner itself always re-hashes the
	// program it starts, so a binary swapped under the same size and time
	// is still refused at exec (digest_mismatch).
	ProbeHash func(path string) (string, error)
	// AllowUnpinned is [security.scan.<engine>].allow_unpinned on an
	// individual node (false on a managed one): only with it does a binary
	// no pin vouches for run, labelled (ruling P-143).
	AllowUnpinned bool
	Manifest      *ManifestPins
	// Compiled overrides the compiled pins (tests).
	Compiled []Pin
	State    StateStore
	// AllowRepoConfig keeps the engine's own reading of the project's
	// scanner configs (the org or the developer allowed it).
	AllowRepoConfig bool
	// TopNames lists a directory's top-level names (to say which
	// repository configs a run ignored); nil says nothing.
	TopNames func(dir string) []string
	// ListTree lists a directory tree (KICS's queries).
	ListTree func(dir string) secengine.TreeListing
	// ReadFile reads a file of at most limit bytes (the SARIF).
	ReadFile func(path string, limit int64) ([]byte, error)
	// RootHash is the project root hash (secposture.ProjectRootHash); nil
	// leaves it empty and RecordRun stamps it.
	RootHash     func(string) string
	GOOS, GOARCH string
	Now          func() time.Time
}

// Driver is one IaC engine's driver.
type Driver struct {
	env    Env
	engine Engine
}

// NewDriver returns the driver of env.Engine.
func NewDriver(env Env) *Driver {
	e, _ := Lookup(env.Engine)
	return &Driver{env: env, engine: e}
}

// Engine is the driver's engine row.
func (d *Driver) Engine() Engine { return d.engine }

// Row is the registry row.
func (d *Driver) Row() secscan.DriverRow { return Row(d.engine.ID) }

// Reason codes of a run that did not scan (beside driver_unverified).
const (
	ReasonNotInstalled      = "not_installed"
	ReasonNoQueries         = "queries_not_found"
	ReasonIsolation         = "isolation_refused"
	ReasonIsolationRequired = "isolation_required"
	ReasonFlagsMissing      = "engine_flags_missing"
	ReasonSelfTestFailed    = "self_test_failed"
	ReasonBudget            = "budget_exceeded"
	ReasonCanceled          = "canceled"
	ReasonCrashed           = "engine_crashed"
	ReasonOutput            = "output_unreadable"
	ReasonRunner            = "runner_refused"
	ReasonBadTarget         = "bad_target"
)

// notRunReasons are reasons of a run that stopped before the engine
// scanned anything (the run is recorded, but it is not a scan).
var notRunReasons = map[string]bool{
	ReasonNotInstalled: true, ReasonNoQueries: true, ReasonIsolation: true, ReasonIsolationRequired: true,
	ReasonFlagsMissing: true, ReasonRunner: true, ReasonBadTarget: true, ReasonUnverified: true,
}

// EngineRan reports whether a run's coverage is a scan.
func EngineRan(c secscan.Coverage) bool {
	switch c.Outcome {
	case secscan.OutcomeNotScanned:
		return false
	case secscan.OutcomeFailed:
		return !notRunReasons[c.Reason]
	}
	return true
}

// The fixed run notes' prefixes (Observer's own sentences, never engine
// text).
const (
	NotIsolatedPrefix = "Not isolated"
	UntestedPrefix    = "Untested engine version"
	UnverifiedPrefix  = "Unverified engine"
	RepoConfigPrefix  = "Repository scanner config ignored"
	DigestOnlyPrefix  = "Digest-only pin"
)

// Spec is how an engine binary is found: a separately installed program,
// never a command-wrapping shim (the runner's resolver excludes them).
func (e Engine) Spec() integration.BinaryResolveSpec {
	return integration.BinaryResolveSpec{Names: integration.BinaryNames{Unix: []string{e.Binary}, Windows: []string{e.Binary + ".exe"}}}
}

// ExtrunEngine is the engine's run profile: its own HOME and cache, a
// UTF-8 locale, and its exit table (findings are read from the SARIF,
// never from the exit code: Trivy runs with --exit-code 0 and KICS with
// --ignore-on-exit results, so 0 is a result and anything else a failure).
func (e Engine) ExtrunEngine() extrun.Engine {
	return extrun.Engine{Name: string(e.ID), OwnHome: true, Locale: "C.UTF-8", ExitCodes: []extrun.ExitCodeRow{{Code: 0, Meaning: extrun.ExitResult}}}
}

// Limits are one run's caps.
func Limits() extrun.Limits {
	return extrun.Limits{Wall: 600 * time.Second, StdoutBytes: 8 << 20, StderrBytes: 4 << 20, MemoryBytes: 2 << 30, Children: 64}
}

// MaxSARIFBytes caps the SARIF a run may write.
const MaxSARIFBytes = 32 << 20

func (d *Driver) sep() string {
	if d.env.GOOS == "windows" {
		return `\`
	}
	return "/"
}

func (d *Driver) paths(target, out, queries string) RunPaths {
	p := RunPaths{Target: target, Out: out, Cache: d.env.CacheDir, Sep: d.sep()}
	if d.engine.QueriesTree && queries != "" {
		p.Queries = queries
		p.Libraries = p.join(dirOfSep(queries, d.sep()), "libraries")
	}
	p.EmptyConfig = p.join(out, "empty-config.json")
	return p
}

// dirOfSep is the parent of p in sep spelling.
func dirOfSep(p, sep string) string {
	cut := "/"
	if sep == `\` {
		cut = `/\`
	}
	p = strings.TrimRight(p, cut)
	if i := strings.LastIndexAny(p, cut); i > 0 {
		return p[:i]
	}
	return p
}

// queriesCandidates are where KICS's queries live beside its binary:
// assets/queries in the binary's directory (the source and guided-install
// layout), else share/kics/assets/queries one level up (a package
// manager's).
func (d *Driver) queriesCandidates(real string) []string {
	dir := dirOfSep(real, d.sep())
	j := func(elem ...string) string { return strings.Join(elem, d.sep()) }
	return []string{j(dir, "assets", "queries"), j(dirOfSep(dir, d.sep()), "share", "kics", "assets", "queries")}
}

// resolved is what resolution and the decision found.
type resolved struct {
	bin, real string
	digest    string
	queries   string
	listing   secengine.TreeListing
	tree      secengine.TreeState
	state     State
	stateErr  bool
	decision  Decision
}

func launchable(v toolresolve.Verdict) bool {
	switch v {
	case toolresolve.VerdictOK, toolresolve.VerdictOKOffPath, toolresolve.VerdictShadowed:
		return true
	}
	return false
}

func (d *Driver) installedBinary() string {
	if d.env.Installed == "" || d.env.Runner == nil || d.env.Runner.Inspect == nil {
		return ""
	}
	f, err := d.env.Runner.Inspect(d.env.Installed)
	if err != nil || !f.Exists || f.Symlink || !f.Regular {
		return ""
	}
	return d.env.Installed
}

func (d *Driver) input(rs resolved, version string) Input {
	return Input{
		Engine: d.engine.ID, GOOS: d.env.GOOS, GOARCH: d.env.GOARCH, Digest: rs.digest, Version: version, Managed: d.env.Managed, AllowUnpinned: d.env.AllowUnpinned,
		Manifest: d.env.Manifest, Compiled: d.env.Compiled, Installed: d.env.InstallRecord, FirstUse: rs.state.FirstUse,
		Revoked: rs.state.Revoked, Tree: rs.tree,
	}
}

func (d *Driver) resolve() (resolved, string) {
	var out resolved
	r := d.env.Runner
	if r == nil || r.Resolve == nil || r.Hash == nil || r.Inspect == nil || d.engine.ID == "" {
		return out, ReasonNotInstalled
	}
	out.bin = d.installedBinary()
	if out.bin == "" {
		res := r.Resolve(d.engine.Spec())
		if !launchable(res.Verdict) || res.Bin == "" {
			return out, ReasonNotInstalled
		}
		out.bin = res.Bin
	}
	out.real = out.bin
	if f, err := r.Inspect(out.bin); err == nil && f.Real != "" {
		out.real = f.Real
	}
	hash := r.Hash
	if d.env.ProbeHash != nil {
		hash = d.env.ProbeHash
	}
	sum, err := hash(out.real)
	if err != nil {
		return out, ReasonUnverified
	}
	out.digest = strings.ToLower(sum)
	if d.env.State != nil {
		if st, err := d.env.State.Load(); err != nil {
			out.stateErr = true
		} else {
			out.state = st
		}
	}
	out.tree = secengine.TreeNone
	if d.engine.QueriesTree {
		for _, q := range d.queriesCandidates(out.real) {
			if f, err := r.Inspect(q); err == nil && f.Exists && !f.Symlink && !f.Regular {
				out.queries = q
				break
			}
		}
		if out.queries == "" {
			return out, ReasonNoQueries
		}
		switch {
		case out.stateErr:
			out.tree = secengine.TreeRecordUnreadable
		case out.state.Tree != nil && d.env.ListTree != nil:
			out.listing = d.env.ListTree(out.queries)
			out.tree, _ = secengine.CheckTree(out.state.Tree, out.digest, out.listing)
		}
	}
	out.decision = Decide(d.input(out, ""))
	return out, ""
}

// Probe resolves and decides without starting anything.
func (d *Driver) Probe(context.Context) secscan.Probe {
	p := secscan.Probe{Platform: d.platform()}
	rs, reason := d.resolve()
	switch reason {
	case ReasonNotInstalled:
		p.Reason = reason
		return p
	case "":
	default:
		p.Installed, p.Reason = true, reason
		return p
	}
	p.Installed = true
	p.Verified = rs.decision.Status == StatusVerified
	if !p.Verified {
		p.Reason = ReasonUnverified
	}
	if d.engine.RequireIsolation && (d.env.Isolate == nil || d.env.IsolatedRunner == nil) {
		p.Reason = ReasonIsolationRequired
	}
	p.Beta = p.Platform != secscan.SupportSupported
	return p
}

func (d *Driver) platform() secscan.Support {
	for _, r := range Row(d.engine.ID).Platforms {
		if r.Platform.OS == d.env.GOOS && r.Platform.Arch == d.env.GOARCH {
			return r.Support
		}
	}
	return secscan.SupportUnsupported
}

func failed(ident secscan.EngineIdentity, reason string, notes []string) secscan.Result {
	return secscan.Result{Engine: ident, Coverage: secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: reason, Notes: notes}}
}

func notScanned(ident secscan.EngineIdentity, reason string, notes []string) secscan.Result {
	return secscan.Result{Engine: ident, Coverage: secscan.Coverage{Outcome: secscan.OutcomeNotScanned, Reason: reason, Notes: notes}}
}

// Scan runs one scan of t: the whole checkout (an IaC engine reads a
// directory; the post-write trigger only decides when a scan starts).
func (d *Driver) Scan(ctx context.Context, t secscan.Target) (secscan.Result, error) {
	ident := secscan.EngineIdentity{Name: string(d.engine.ID)}
	if d.env.CacheDir == "" || d.env.OutDir == "" || d.env.ReadFile == nil || d.env.CanaryDir == "" {
		return notScanned(ident, ReasonRunner, nil), nil
	}
	dir := t.ProjectRoot
	if t.CheckoutRoot != "" {
		dir = t.CheckoutRoot
	}
	if dir == "" || strings.HasPrefix(dir, "-") || strings.Contains(dir, "::") {
		return failed(ident, ReasonBadTarget, nil), nil
	}
	rs, reason := d.resolve()
	switch reason {
	case "":
	case ReasonNotInstalled, ReasonNoQueries:
		return notScanned(ident, reason, nil), nil
	default:
		return failed(ident, reason, nil), nil
	}
	ident.Digest = rs.digest
	d.rememberRevocations(rs)
	if !rs.decision.Run() {
		return failed(ident, ReasonUnverified, d.refusalNotes(rs.decision)), nil
	}
	notes := d.decisionNotes(rs.decision)
	runner, isolated, err := d.runnerFor(dir, rs.queries)
	if err != nil {
		return failed(ident, ReasonIsolation, notes), nil
	}
	if !isolated {
		if d.engine.RequireIsolation {
			return notScanned(ident, ReasonIsolationRequired, append(notes, d.engine.IsolationWhy+", so "+d.engine.Title+" runs only inside the isolation component's no-network run, which is not available on this host; a scan without isolation is refused.")), nil
		}
		notes = append(notes, NotIsolatedPrefix+": no isolation provider is available on this host (the isolation component is off, or the host has no supported one), so "+d.engine.Title+" ran with its offline flags but with network access.")
	}
	v, pr := runner.ProbeVersion(ctx, d.request(rs, dir, nil), extrun.VersionProbe{Args: VersionArgs(d.engine.ID), Pattern: VersionPattern(d.engine.ID)})
	if pr.Outcome == extrun.OutcomeRefused {
		return failed(ident, refusedReason(pr), notes), nil
	}
	ident.Version = v.Version
	again := Decide(d.input(rs, v.Version))
	if !again.Run() || v.Version == "" {
		return failed(ident, ReasonUnverified, notes), nil
	}
	if again.Untested {
		notes = append(notes, UntestedPrefix+": this "+d.engine.Title+" is "+v.Version+", not the tested "+d.engine.TestedVersion+"; its results are shown, labelled untested.")
	}
	if why := d.checkFlags(ctx, runner, rs, dir); why != "" {
		return failed(ident, why, notes), nil
	}
	passed, res := d.selfTest(ctx, rs)
	if res != nil {
		res.Engine, res.Coverage.Notes = ident, append(notes, res.Coverage.Notes...)
		return *res, nil
	}
	if !d.env.AllowRepoConfig && d.env.TopNames != nil {
		if found := RepoConfigPresent(d.engine, d.env.TopNames(dir)); len(found) > 0 {
			notes = append(notes, RepoConfigPrefix+": "+strings.Join(found, ", ")+" in the project was not read (the repository is untrusted input; the org or you can allow it).")
		}
	}
	run := runner.Run(ctx, d.request(rs, dir, Args(d.engine.ID, d.paths(dir, d.env.OutDir, rs.queries), d.env.AllowRepoConfig)))
	if r := classify(run); r != "" {
		return failed(ident, r, notes), nil
	}
	out, why := d.read(t, dir, ident, passed)
	if why != "" {
		return failed(ident, why, notes), nil
	}
	out.Coverage.Notes = append(notes, out.Coverage.Notes...)
	d.afterRun(rs, v.Version)
	return out, nil
}

func (d *Driver) decisionNotes(dec Decision) []string {
	var notes []string
	if dec.Status == StatusUnverifiedLabelled {
		why := ""
		if dec.Unpinned {
			why = " because [security.scan." + string(d.engine.ID) + "].allow_unpinned is on"
		}
		notes = append(notes, UnverifiedPrefix+": this "+d.engine.Title+" binary is not covered by a verified pin ("+dec.Detail+", driver_unverified); it ran on this individual node"+why+", labelled. A managed node refuses it.")
	}
	if dec.DigestOnly {
		notes = append(notes, DigestOnlyPrefix+": "+d.engine.Title+" publishes no signature, so its pin rests on its digest alone.")
	}
	return notes
}

// isolatedFor returns the isolated runner of one directory set, nil when
// the host has none; an error refuses the run.
func (d *Driver) isolatedFor(dirs extrun.OneShotDirs) (*extrun.Runner, error) {
	if d.env.Isolate == nil || d.env.IsolatedRunner == nil {
		return nil, nil
	}
	prov, err := d.env.Isolate(dirs)
	if err != nil || prov == nil {
		return nil, err
	}
	return d.env.IsolatedRunner(prov), nil
}

func (d *Driver) dirsFor(project, queries string) extrun.OneShotDirs {
	dirs := extrun.OneShotDirs{Project: project, Output: d.env.OutDir, Cache: d.env.CacheDir}
	if queries != "" {
		dirs.ProgramDirs = []string{dirOfSep(queries, d.sep())}
	}
	return dirs
}

func (d *Driver) runnerFor(dir, queries string) (*extrun.Runner, bool, error) {
	iso, err := d.isolatedFor(d.dirsFor(dir, queries))
	switch {
	case err != nil:
		return nil, false, err
	case iso == nil:
		return d.env.Runner, false, nil
	}
	return iso, true, nil
}

// request is the runner request of one run (args nil for the version
// probe, which fills its own).
func (d *Driver) request(rs resolved, dir string, args []string) extrun.Request {
	eng := d.engine.ExtrunEngine()
	prog := extrun.Program{Path: rs.bin, AllowSymlink: true}
	expect := &extrun.Digests{Binary: rs.digest}
	if rec := rs.state.Tree; rec != nil && rec.BinaryDigest == rs.digest && rs.queries != "" && (rs.tree == secengine.TreeSame || rs.tree == secengine.TreeChanged) {
		present := map[string]bool{}
		for _, f := range rs.listing.Files {
			present[f] = true
		}
		names := make([]string, 0, len(rec.Files))
		for n := range rec.Files {
			if present[n] {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		if len(names) > 0 {
			expect.Companions = map[string]string{}
		}
		for _, n := range names {
			p := rs.queries + d.sep() + strings.ReplaceAll(n, "/", d.sep())
			prog.Companions = append(prog.Companions, p)
			expect.Companions[p] = rec.Files[n]
		}
	}
	return extrun.Request{
		Component: d.engine.ComponentID, Program: prog, Args: args, Expect: expect, Dir: dir,
		Limits: Limits(), CacheDir: d.env.CacheDir, Engine: &eng, RequireIsolation: d.engine.RequireIsolation,
	}
}

// checkFlags runs HelpArgs once per binary digest and refuses a version
// whose help lacks a required flag.
func (d *Driver) checkFlags(ctx context.Context, runner *extrun.Runner, rs resolved, dir string) string {
	if rs.state.FlagsOK == rs.digest {
		return ""
	}
	req := d.request(rs, dir, d.engine.HelpArgs)
	req.Limits = extrun.Limits{Wall: 20 * time.Second, StdoutBytes: 256 << 10, StderrBytes: 256 << 10}
	run := runner.Run(ctx, req)
	if run.Outcome == extrun.OutcomeRefused {
		return refusedReason(run)
	}
	help := append(append([]byte(nil), run.Stdout...), run.Stderr...)
	if len(MissingFlags(d.engine, help)) > 0 {
		return ReasonFlagsMissing
	}
	d.updateState(rs, func(st *State) { st.FlagsOK = rs.digest })
	return ""
}

// CanaryFiles is the canary project the caller writes into CanaryDir: a
// Dockerfile with no USER instruction, which Trivy's DS-0002 (the image
// user should not be root) and KICS's "Missing User Instruction" query
// both report. The self-test passes when a result names it.
var CanaryFiles = map[string]string{
	"Dockerfile": "FROM alpine:3.20\nRUN echo superbased-observer-iac-canary\n",
}

// CanaryHit reports whether a SARIF log carries a result at the canary's
// Dockerfile.
func CanaryHit(b []byte) bool {
	log, err := sarif.Decode(b)
	if err != nil {
		return false
	}
	for _, run := range log.Runs {
		for _, res := range run.Results {
			for _, l := range res.Locations {
				if strings.HasSuffix(strings.ReplaceAll(l.URI, `\`, "/"), "Dockerfile") {
					return true
				}
			}
		}
	}
	return false
}

// selfTest runs the canary once per binary digest (cached in State, for a
// verified binary and for one that runs labelled under allow_unpinned
// alike: a changed binary is a new digest and runs it again; audit finding
// F5). A non-nil result is a canary run that failed (the scan stops).
func (d *Driver) selfTest(ctx context.Context, rs resolved) (bool, *secscan.Result) {
	if rs.state.SelfTest == rs.digest && rs.tree != secengine.TreeChanged {
		return true, nil
	}
	out := strings.TrimRight(d.env.OutDir, `/\`) + d.sep() + "canary"
	paths := d.paths(d.env.CanaryDir, out, rs.queries)
	runner, _, err := d.runnerFor(d.env.CanaryDir, rs.queries)
	if err != nil {
		res := failed(secscan.EngineIdentity{}, ReasonIsolation, nil)
		return false, &res
	}
	run := runner.Run(ctx, d.request(rs, d.env.CanaryDir, Args(d.engine.ID, paths, false)))
	if why := classify(run); why != "" {
		res := failed(secscan.EngineIdentity{}, why, nil)
		return false, &res
	}
	b, err := d.env.ReadFile(SARIFPath(d.engine.ID, paths), MaxSARIFBytes)
	if err != nil || !CanaryHit(b) {
		res := failed(secscan.EngineIdentity{}, ReasonSelfTestFailed, []string{"The canary self-test did not report the known misconfiguration, so this engine's silence cannot mean clean."})
		return false, &res
	}
	if rs.decision.Run() {
		d.updateState(rs, func(st *State) { st.SelfTest, st.SelfTestAt = rs.digest, d.now().UTC() })
	}
	return true, nil
}

func (d *Driver) now() time.Time {
	if d.env.Now != nil {
		return d.env.Now()
	}
	return time.Now()
}

func refusedReason(r extrun.Result) string {
	switch r.Reason {
	case extrun.RefuseDigestMismatch, extrun.RefuseDigestUnavailable:
		return ReasonUnverified
	case extrun.RefuseIsolationRequired:
		return ReasonIsolationRequired
	case extrun.RefuseIsolationFailed:
		return ReasonIsolation
	}
	return ReasonRunner
}

// classifyRows maps a finished run onto a failure reason (an ordered
// table); no row matching means the output is a result.
var classifyRows = []struct {
	when   func(extrun.Result) bool
	reason func(extrun.Result) string
}{
	{func(r extrun.Result) bool { return r.Outcome == extrun.OutcomeRefused }, refusedReason},
	{func(r extrun.Result) bool {
		return r.Outcome == extrun.OutcomeTimeout || r.Outcome == extrun.OutcomeOutputCap || r.Outcome == extrun.OutcomeChildrenCap
	}, func(extrun.Result) string { return ReasonBudget }},
	{func(r extrun.Result) bool { return r.Outcome == extrun.OutcomeCanceled }, func(extrun.Result) string { return ReasonCanceled }},
	{func(r extrun.Result) bool { return r.ExitMeaning != extrun.ExitResult }, func(extrun.Result) string { return ReasonCrashed }},
}

func classify(r extrun.Result) string {
	for _, row := range classifyRows {
		if row.when(r) {
			return row.reason(r)
		}
	}
	return ""
}

// AdapterName is the secscan semantic adapter of an engine.
func AdapterName(id EngineID) string {
	if id == Trivy {
		return "trivy-config"
	}
	return string(id)
}

// read turns the run's SARIF into the result.
func (d *Driver) read(t secscan.Target, dir string, ident secscan.EngineIdentity, passed bool) (secscan.Result, string) {
	b, err := d.env.ReadFile(SARIFPath(d.engine.ID, d.paths(dir, d.env.OutDir, "")), MaxSARIFBytes)
	if err != nil {
		return secscan.Result{}, ReasonOutput
	}
	return ReadSARIF(d.engine.ID, b, t, dir, ident, passed, d.env.RootHash)
}

// ReadSARIF maps one engine SARIF onto the result: the secscan adapter,
// then the IaC rules (MapFindings). A log that does not decode, or holds
// other than one run, is unreadable output.
func ReadSARIF(id EngineID, b []byte, t secscan.Target, dir string, ident secscan.EngineIdentity, passed bool, rootHash func(string) string) (secscan.Result, string) {
	e, _ := Lookup(id)
	log, err := sarif.Decode(b)
	if err != nil || len(log.Runs) != 1 {
		return secscan.Result{}, ReasonOutput
	}
	hash := ""
	if rootHash != nil {
		hash = rootHash(t.ProjectRoot)
	}
	row, _ := secscan.Adapter(AdapterName(id))
	findings, cov := secscan.Adapt(row, log.Runs[0], secscan.AdaptOptions{
		ProjectRoot: dir, ProjectRootHash: hash, Scope: t.Scope, Engine: ident, SelfTestPassed: passed,
	})
	for i := range findings {
		f := &findings[i]
		f.Engine.Driver = string(id)
		f.Rule.Pack = string(id)
		f.Message = "Reported by " + e.Title + " rule " + f.Rule.ID
	}
	findings, cov = MapFindings(findings, cov)
	return secscan.Result{Findings: findings, Coverage: cov, Engine: ident}, ""
}

// updateState applies fn to a freshly loaded state and saves it; a state
// that did not load is never rewritten.
func (d *Driver) updateState(rs resolved, fn func(*State)) {
	if d.env.State == nil || rs.stateErr {
		return
	}
	st, err := d.env.State.Load()
	if err != nil {
		return
	}
	fn(&st)
	_ = d.env.State.Save(st)
}

func (d *Driver) rememberRevocations(rs resolved) {
	if d.env.Manifest == nil || len(d.env.Manifest.Revoked) == 0 {
		return
	}
	d.updateState(rs, func(st *State) {
		for _, r := range d.env.Manifest.Revoked {
			r = strings.ToLower(strings.TrimSpace(r))
			if r != "" && !slices.Contains(st.Revoked, r) {
				st.Revoked = append(st.Revoked, r)
			}
		}
		sort.Strings(st.Revoked)
	})
}

// afterRun records, after a run: the first-use digest of an unpinned
// binary on an individual node (once), and KICS's queries tree after the
// first verified run (X9), hashed through the runner's own hasher.
func (d *Driver) afterRun(rs resolved, version string) {
	if rs.decision.Status == StatusUnverifiedLabelled && rs.state.FirstUse == "" && !d.env.Managed {
		d.updateState(rs, func(st *State) { st.FirstUse = rs.digest })
	}
	if !d.engine.QueriesTree || rs.decision.Status != StatusVerified || rs.queries == "" || d.env.ListTree == nil {
		return
	}
	if rs.state.Tree != nil && rs.state.Tree.BinaryDigest == rs.digest && rs.tree != secengine.TreeNone {
		return
	}
	l := d.env.ListTree(rs.queries)
	if l.Err != "" || l.Irregular {
		return
	}
	sums := map[string]string{}
	for _, f := range l.Files {
		sum, err := d.env.Runner.Hash(rs.queries + d.sep() + strings.ReplaceAll(f, "/", d.sep()))
		if err != nil {
			return
		}
		sums[f] = sum
	}
	if rec, ok := NewQueriesRecord(rs.digest, version, sums, d.now()); ok {
		d.updateState(rs, func(st *State) { st.Tree = &rec })
	}
}

// Inspection is what status and doctor show, read without starting or
// writing anything.
type Inspection struct {
	Binary   string
	Digest   string
	Queries  string
	Decision Decision
	Tree     secengine.TreeState
	// SelfTestAt is when the canary last passed for this binary.
	SelfTestAt time.Time
	Reason     string
}

// Inspect resolves and decides without starting anything.
func (d *Driver) Inspect() Inspection {
	rs, reason := d.resolve()
	in := Inspection{Binary: rs.bin, Digest: rs.digest, Queries: rs.queries, Decision: rs.decision, Tree: rs.tree, Reason: reason}
	if rs.state.SelfTest == rs.digest && rs.digest != "" {
		in.SelfTestAt = rs.state.SelfTestAt
	}
	return in
}

// Row is the registry row of engine id (secscan.DriverRow).
func Row(id EngineID) secscan.DriverRow {
	e, _ := Lookup(id)
	var pinned []string
	for _, p := range CompiledPins(id) {
		if p.BinarySHA256 != "" {
			pinned = append(pinned, p.BinarySHA256)
		}
	}
	plat := func(goos, goarch string) secscan.PlatformRow {
		return secscan.PlatformRow{Platform: secscan.Platform{OS: goos, Arch: goarch}, Support: secscan.SupportUntested}
	}
	procs := []secscan.ProcessDecl{{Binary: e.Binary}}
	if e.QueriesTree {
		procs[0].Companions = []string{"its queries tree (assets/queries beside the binary), digest-recorded after the first verified run"}
	}
	inputs := []string{"Observer's own fixed flags and target directory"}
	for _, c := range e.RepoConfigs {
		inputs = append(inputs, c+" in the repository is ignored unless allowed")
	}
	return secscan.DriverRow{
		ID: string(id), Kind: secscan.KindProcess, ComponentID: e.ComponentID,
		Categories: []secfinding.Category{policy.FindingIaC},
		Triggers:   []secfinding.Scope{policy.FindingScopeManual, policy.FindingScopeScheduled, policy.FindingScopePostWrite},
		Platforms:  []secscan.PlatformRow{plat("linux", "amd64"), plat("linux", "arm64"), plat("darwin", "arm64"), plat("darwin", "amd64"), plat("windows", "amd64")},
		Offline:    secscan.Offline{NoNetwork: !e.RequireIsolation},
		Processes:  procs,
		MinVersion: e.MinVersion, TestedRange: "=" + e.TestedVersion, PinnedDigests: pinned,
		SemanticAdapter: AdapterName(id), ConfigInputs: inputs,
		Flags:     secscan.FlagRule{Always: e.RequiredFlags, Never: e.NeverFlags},
		ExitCodes: []secscan.ExitCode{{Code: 0, Meaning: secscan.ExitOK}},
		Licence:   e.Licence,
	}
}

// String renders a decision for one line of status.
func (dec Decision) String() string {
	s := string(dec.Status)
	if dec.Detail != "" {
		s += " (" + dec.Detail + ")"
	}
	if dec.Untested {
		s += ", untested version"
	}
	return s
}

// refusalNotes says why a refused binary did not run; an unpinned one names
// the key that would let it run on an individual node.
func (d *Driver) refusalNotes(dec Decision) []string {
	if dec.Detail != DetailUnpinnedNotAllowed {
		return nil
	}
	return []string{UnverifiedPrefix + ": this " + d.engine.Title + " binary is not covered by a verified pin, so it is refused by default. To run it anyway on this individual node, labelled unverified, set [security.scan." + string(d.engine.ID) + "].allow_unpinned = true (a managed node refuses it whatever the key says)."}
}
