package opengrep

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// SelfTest is the recorded pass of the canary for one binary, companion
// tree and pack: while all three digests are unchanged, a diff scope (which
// cannot carry the canary) relies on it.
type SelfTest struct {
	BinaryDigest string    `json:"binary_digest"`
	TreeDigest   string    `json:"tree_digest"`
	PackDigest   string    `json:"pack_digest"`
	PassedAt     time.Time `json:"passed_at"`
}

// State is the driver's node-local state: the companion tree record and
// the last self-test pass. One owner writes it (the cmd layer's file).
type State struct {
	Tree     *secengine.TreeRecord `json:"tree,omitempty"`
	SelfTest *SelfTest             `json:"self_test,omitempty"`
	// Revoked are the engine digests an engine manifest has revoked, kept
	// so a revocation keeps refusing when the manifest later goes stale,
	// fails to re-verify or is removed (lane SEC-G1 audit finding 5). A
	// scan adds to it; nothing removes from it.
	Revoked []string `json:"revoked,omitempty"`
}

// StateStore loads and saves State.
type StateStore interface {
	Load() (State, error)
	Save(State) error
}

// Env is what the driver needs from the caller. Every I/O is here.
type Env struct {
	// Runner is the unisolated runner (production: extrun/host.NewRunner).
	Runner *extrun.Runner
	// Isolate prepares the isolation provider of one run's directories;
	// nil, or a nil provider with no error, means this host has none (the
	// run goes ahead unisolated and labelled); an error refuses the run.
	Isolate func(extrun.OneShotDirs) (extrun.IsolationProvider, error)
	// IsolatedRunner builds the runner that wraps a run in a provider.
	IsolatedRunner func(extrun.IsolationProvider) *extrun.Runner
	// Pack is the rule pack in use; PackDir is where it was written (its
	// rules/ and canary/ directories), absolute and outside ~/.observer.
	Pack    *secrulepack.Pack
	PackDir string
	// CacheDir is the engine-owned HOME and cache root (absolute, outside
	// ~/.observer, which the isolation engine never binds).
	CacheDir string
	// OutDir is this run's output directory (the JSON copy); the caller
	// makes it and removes it.
	OutDir string
	// Managed: an unverified engine is refused, not labelled.
	Managed bool
	// Manifest is the verified engine manifest, nil when none.
	Manifest *secengine.ManifestPins
	State    StateStore
	// ListTree lists the companion tree directory.
	ListTree func(dir string) secengine.TreeListing
	// ReadFile reads a file of at most limit bytes (the JSON copy).
	ReadFile func(path string, limit int64) ([]byte, error)
	// LinkedCommonDir returns the main repository's git directory when dir
	// is a linked worktree ("" otherwise): an isolated run of a linked
	// worktree binds it read-only, since the worktree's own git data lives
	// there (lane SEC-G2; plans decision log P-046). Nil binds nothing.
	LinkedCommonDir func(dir string) string
	// Installed is the absolute path of Observer's guided install of the
	// engine (lane SEC-G2), "" when none: when a regular file is there it is
	// used before any Opengrep on the PATH, and it is decided by its digest
	// like any other binary.
	Installed string
	// Jobs is -j; 0 is DefaultJobs.
	Jobs         int
	GOOS, GOARCH string
	Now          func() time.Time
}

// Driver is the Opengrep driver.
type Driver struct{ env Env }

// New returns the driver over env.
func New(env Env) *Driver { return &Driver{env: env} }

// Row is the registry row.
func (d *Driver) Row() secscan.DriverRow { return Row() }

// sep is the GOOS path separator.
func (d *Driver) sep() string {
	if d.env.GOOS == "windows" {
		return `\`
	}
	return "/"
}

func (d *Driver) join(elem ...string) string {
	return strings.Join(elem, d.sep())
}

// xdgCache is the engine's XDG_CACHE_HOME: extrun's OwnHome puts it at
// <CacheDir>/xdg-cache (TestRequestEnv pins the two together).
func (d *Driver) xdgCache() string {
	return d.join(strings.TrimRight(d.env.CacheDir, `/\`), "xdg-cache")
}

// treeDir is the companion tree directory of the tested version.
func (d *Driver) treeDir(version string) string {
	dir := secengine.TreeDir(d.xdgCache(), version)
	if d.env.GOOS == "windows" {
		dir = strings.ReplaceAll(dir, "/", `\`)
	}
	return dir
}

func (d *Driver) rulesDir() string {
	return d.join(strings.TrimRight(d.env.PackDir, `/\`), secrulepack.RulesDir)
}

func (d *Driver) canary() string {
	t := d.env.Pack.Manifest.Canary.Target
	return d.join(strings.TrimRight(d.env.PackDir, `/\`), strings.ReplaceAll(t, "/", d.sep()))
}

func (d *Driver) now() time.Time {
	if d.env.Now != nil {
		return d.env.Now()
	}
	return time.Now()
}

// resolved is what resolution and the decision found.
type resolved struct {
	bin, git string
	digest   string
	decision secengine.Decision
	tree     secengine.TreeState
	state    State
	// stateErr: the state store did not load (the tree is then
	// TreeRecordUnreadable, and nothing rewrites the state).
	stateErr bool
	// listing is the companion tree directory as listed for the check.
	listing secengine.TreeListing
	// manifest is the engine manifest the decision read: the verified one
	// with the remembered revocations added.
	manifest *secengine.ManifestPins
}

// resolve resolves Opengrep and git, hashes the binary and decides.
func (d *Driver) resolve() (resolved, string) {
	var out resolved
	r := d.env.Runner
	if r == nil || r.Resolve == nil || r.Hash == nil || r.Inspect == nil {
		return out, ReasonNotInstalled
	}
	binPath := d.installedBinary()
	if binPath == "" {
		bin := r.Resolve(Spec)
		if !launchable(bin.Verdict) || bin.Bin == "" {
			return out, ReasonNotInstalled
		}
		binPath = bin.Bin
	}
	git := r.Resolve(GitSpec)
	if !launchable(git.Verdict) || git.Bin == "" {
		return out, ReasonNoGit
	}
	out.bin, out.git = binPath, git.Bin
	facts, err := r.Inspect(out.bin)
	real := out.bin
	if err == nil && facts.Real != "" {
		real = facts.Real
	}
	sum, err := r.Hash(real)
	if err != nil {
		return out, secengine.ReasonUnverified
	}
	out.digest = sum
	if d.env.State != nil {
		st, err := d.env.State.Load()
		if err != nil {
			out.stateErr = true
		} else {
			out.state = st
		}
	}
	out.tree = secengine.TreeNone
	switch {
	case out.stateErr:
		// A record that does not load is never "no record" (lane SEC-G1
		// audit finding 4): the run is driver_unverified, and the next
		// verified run does not record the current tree as the baseline.
		out.tree = secengine.TreeRecordUnreadable
	case out.state.Tree != nil && d.env.ListTree != nil:
		out.listing = d.env.ListTree(d.treeDir(out.state.Tree.Version))
		out.tree, _ = secengine.CheckTree(out.state.Tree, sum, out.listing)
	}
	out.manifest = d.manifestWith(out.state.Revoked)
	out.decision = secengine.Decide(secengine.Input{
		GOOS: d.env.GOOS, GOARCH: d.env.GOARCH, Digest: sum, Managed: d.env.Managed, Manifest: out.manifest, Tree: out.tree,
	})
	return out, ""
}

// installedBinary returns the guided install's path when a regular file
// (not a symlink) is there, "" otherwise.
func (d *Driver) installedBinary() string {
	if d.env.Installed == "" {
		return ""
	}
	f, err := d.env.Runner.Inspect(d.env.Installed)
	if err != nil || !f.Exists || f.Symlink || !f.Regular {
		return ""
	}
	return d.env.Installed
}

// manifestWith is the engine manifest with the remembered revocations
// added: a revoked digest is refused whatever the manifest's state, or with
// no manifest at all (a manifest of revocations only leaves the compiled
// pins in force for every platform).
func (d *Driver) manifestWith(revoked []string) *secengine.ManifestPins {
	if len(revoked) == 0 {
		return d.env.Manifest
	}
	var m secengine.ManifestPins
	if d.env.Manifest != nil {
		m = *d.env.Manifest
	}
	m.Revoked = append(slices.Clone(m.Revoked), revoked...)
	return &m
}

// rememberRevocations adds the engine manifest's revoked digests to the
// driver's state. Only a scan calls it (status and doctor write nothing),
// and a state that did not load is not rewritten.
func (d *Driver) rememberRevocations(rs resolved) {
	if d.env.State == nil || rs.stateErr || d.env.Manifest == nil {
		return
	}
	st := rs.state
	st.Revoked = slices.Clone(st.Revoked)
	added := false
	for _, r := range d.env.Manifest.Revoked {
		r = strings.ToLower(strings.TrimSpace(r))
		if r != "" && !slices.Contains(st.Revoked, r) {
			st.Revoked = append(st.Revoked, r)
			added = true
		}
	}
	if added {
		sort.Strings(st.Revoked)
		_ = d.env.State.Save(st)
	}
}

func launchable(v toolresolve.Verdict) bool {
	switch v {
	case toolresolve.VerdictOK, toolresolve.VerdictOKOffPath, toolresolve.VerdictShadowed:
		return true
	}
	return false
}

// Reason codes of a run that did not scan.
const (
	ReasonNotInstalled = "not_installed"
	ReasonNoGit        = "git_not_installed"
	ReasonNoPack       = "no_rule_pack"
	ReasonBadBase      = "bad_diff_base"
	ReasonIsolation    = "isolation_refused"
	ReasonBudget       = "budget_exceeded"
	ReasonCanceled     = "canceled"
	ReasonCrashed      = "engine_crashed"
	ReasonConfig       = "rule_config_error"
	ReasonOutput       = "output_unreadable"
	ReasonRunner       = "runner_refused"
	// ReasonGitFilter: the repository's own git config names a filter
	// driver command, which the checkout behind a diff run would start.
	ReasonGitFilter = "git_filter_driver"
	// ReasonGitConfig: that config could not be read, so a diff run is
	// refused as if it named one.
	ReasonGitConfig = "git_config_unreadable"
)

// Probe resolves the binary and decides, without starting anything.
func (d *Driver) Probe(context.Context) secscan.Probe {
	p := secscan.Probe{Platform: platformSupport(d.env.GOOS, d.env.GOARCH)}
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
	p.Verified = rs.decision.Status == secengine.StatusVerified
	if !rs.decision.Run() || rs.decision.Status == secengine.StatusUnverifiedLabelled {
		p.Reason = secengine.ReasonUnverified
	}
	p.Beta = p.Platform != secscan.SupportSupported
	return p
}

func platformSupport(goos, goarch string) secscan.Support {
	for _, r := range Row().Platforms {
		if r.Platform.OS == goos && r.Platform.Arch == goarch {
			return r.Support
		}
	}
	return secscan.SupportUnsupported
}

// Scan runs one scan; it is ScanFiles without the scanned file list.
func (d *Driver) Scan(ctx context.Context, t secscan.Target) (secscan.Result, error) {
	res, _, err := d.ScanFiles(ctx, t)
	return res, err
}

// The fixed run notes (Coverage.Notes; NotePrefixes maps them to labels).
const (
	NotIsolatedPrefix  = "Not isolated"
	UntestedPrefix     = "Untested engine version"
	UnverifiedPrefix   = "Unverified engine"
	notIsolatedNoHost  = NotIsolatedPrefix + ": no isolation provider is available on this host (the isolation component is off, or the host is not Linux with bwrap), so Opengrep ran with network access."
	notIsolatedNoWrap  = NotIsolatedPrefix + ": the isolation provider did not wrap the run, so Opengrep ran with network access."
	untestedNote       = UntestedPrefix + ": this Opengrep is not the tested " + secengine.TestedVersion + "; its results are shown, labelled untested."
	unverifiedNoMatch  = UnverifiedPrefix + ": this Opengrep binary's sha256 is not pinned (driver_unverified); it ran on this individual node, labelled. A managed node refuses it."
	unverifiedTreeNote = UnverifiedPrefix + ": the files Opengrep unpacked into its cache changed since the first verified run (driver_unverified); it ran on this individual node, labelled. A managed node refuses it."
	unverifiedRecNote  = UnverifiedPrefix + ": Observer's record of the files Opengrep unpacked could not be read (driver_unverified), so they were not checked; it ran on this individual node, labelled. A managed node refuses it."
)

// NoteLabels maps a note's fixed prefix to its label words, in order.
var NoteLabels = []struct{ Prefix, Words string }{
	{NotIsolatedPrefix, "not isolated"},
	{UntestedPrefix, "untested engine version"},
	{UnverifiedPrefix, "unverified engine"},
}

// failed is a run that did not scan: never clean, never closing anything.
func failed(ident secscan.EngineIdentity, reason string, notes []string) secscan.Result {
	return secscan.Result{Engine: ident, Coverage: secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: reason, Notes: notes}}
}

func notScanned(ident secscan.EngineIdentity, reason string) secscan.Result {
	return secscan.Result{Engine: ident, Coverage: secscan.Coverage{Outcome: secscan.OutcomeNotScanned, Reason: reason}}
}

// ScanFiles runs one scan of t and returns the result and the project
// files it scanned in full (a full scan only; a diff scope returns none,
// see Closable). t.Scope diff with t.BaseRev is a diff scope; every other
// scope is a full scan.
func (d *Driver) ScanFiles(ctx context.Context, t secscan.Target) (secscan.Result, Scanned, error) {
	ident := secscan.EngineIdentity{Name: DriverID}
	if d.env.Pack == nil || d.env.PackDir == "" || d.env.CacheDir == "" || d.env.OutDir == "" || d.env.ReadFile == nil {
		return notScanned(ident, ReasonNoPack), Scanned{}, nil
	}
	ident.RulePackVersion = d.env.Pack.Version()
	mode, why := ModeFor(t)
	if why != "" {
		return failed(ident, why, nil), Scanned{}, nil
	}
	// dir is the checkout the run reads; findings stay keyed on the project
	// (lane SEC-G1 audit finding 2: in a linked worktree the two differ).
	dir := t.ProjectRoot
	if t.CheckoutRoot != "" {
		dir = t.CheckoutRoot
	}
	rs, reason := d.resolve()
	switch reason {
	case "":
	case ReasonNotInstalled, ReasonNoGit:
		return notScanned(ident, reason), Scanned{}, nil
	default:
		return failed(ident, reason, nil), Scanned{}, nil
	}
	ident.Digest = rs.digest
	d.rememberRevocations(rs)
	if !rs.decision.Run() {
		return failed(ident, secengine.ReasonUnverified, nil), Scanned{}, nil
	}
	notes := unverifiedNotes(rs.decision)
	if mode == ModeDiff {
		if why := d.gitFilters(ctx, rs, dir); why != "" {
			return failed(ident, why, notes), Scanned{}, nil
		}
	}
	runner, isolated, err := d.runnerFor(dir, dir != t.ProjectRoot)
	if err != nil {
		return failed(ident, ReasonIsolation, notes), Scanned{}, nil
	}
	if !isolated {
		notes = append(notes, notIsolatedNoHost)
	}
	// The version, asked under the same digests as the scan.
	probeReq := d.request(rs, ModeSelfTest, dir, "")
	v, pr := runner.ProbeVersion(ctx, probeReq, extrun.VersionProbe{Args: []string{"--version"}, Pattern: versionPattern})
	if pr.Outcome == extrun.OutcomeRefused {
		return failed(ident, refusedReason(pr), notes), Scanned{}, nil
	}
	ident.Version = v.Version
	if again := secengine.Decide(secengine.Input{
		GOOS: d.env.GOOS, GOARCH: d.env.GOARCH, Digest: rs.digest, Version: v.Version,
		Managed: d.env.Managed, Manifest: rs.manifest, Tree: rs.tree,
	}); !again.Run() || v.Version == "" {
		return failed(ident, secengine.ReasonUnverified, notes), Scanned{}, nil
	}
	if !secengine.Tested(v.Version) {
		notes = append(notes, untestedNote)
	}
	selfTest, res := d.selfTest(ctx, runner, rs, dir, v.Version, mode)
	if res != nil {
		res.Engine, res.Coverage.Notes = ident, append(notes, res.Coverage.Notes...)
		return *res, Scanned{}, nil
	}
	req := d.request(rs, mode, dir, t.BaseRev, t.Paths...)
	run := runner.Run(ctx, req)
	if isolated && run.Isolation == "" && run.Outcome != extrun.OutcomeRefused {
		notes = append(notes, notIsolatedNoWrap)
	}
	if r := classify(run); r != "" {
		return failed(ident, r, notes), Scanned{}, nil
	}
	out, scanned, passed, why := d.read(run, t, dir, mode, ident, selfTest)
	if why != "" {
		return failed(ident, why, notes), Scanned{}, nil
	}
	out.Coverage.Notes = append(notes, out.Coverage.Notes...)
	if rs.decision.Status == secengine.StatusVerified {
		d.recordAfterVerifiedRun(rs, v.Version, passed)
	}
	if mode == ModeDiff || dir != t.ProjectRoot {
		// A diff scope suppresses what was already present at the base, so
		// a finding missing from it is not proven gone: it closes nothing.
		// Nor does a run of another checkout (a linked worktree): its files
		// say nothing about the project's own.
		scanned.Files = nil
	}
	return out, scanned, nil
}

// unverifiedNotes is the note a labelled (unverified) decision carries.
func unverifiedNotes(d secengine.Decision) []string {
	switch {
	case d.Status != secengine.StatusUnverifiedLabelled:
		return nil
	case d.Detail == secengine.DetailTreeChanged || d.Detail == secengine.DetailTreeUnreadable:
		return []string{unverifiedTreeNote}
	case d.Detail == secengine.DetailRecordUnreadable:
		return []string{unverifiedRecNote}
	}
	return []string{unverifiedNoMatch}
}

// GitFilterArgs are the git arguments of the filter-driver check: the
// repository's config entries under filter., include files followed, NUL
// separated so a value cannot forge an entry.
var GitFilterArgs = []string{"config", "--includes", "--null", "--get-regexp", `^filter\.`}

// gitFilters refuses a diff run in a repository whose own git config (its
// local config or a file that config includes) names a filter driver's
// smudge, process or clean command (lane SEC-G1 audit finding 3):
// --baseline-commit checks the base out into a temporary worktree, and a
// checkout starts those commands. git runs here through the plain runner
// under the git hardening, so only the repository's own config is read, and
// reading config starts no filter. A check that cannot finish refuses too.
func (d *Driver) gitFilters(ctx context.Context, rs resolved, dir string) string {
	r := d.env.Runner
	run := r.Run(ctx, extrun.Request{
		Component: ComponentID,
		Program:   extrun.Program{Path: rs.git, AllowSymlink: true},
		Args:      GitFilterArgs,
		Env:       extrun.EnvSpec{Set: extrun.GitHardeningEnv(r.GOOS)},
		Dir:       dir,
		Limits:    extrun.Limits{Wall: 10 * time.Second, StdoutBytes: 64 << 10, StderrBytes: 4 << 10},
	})
	switch {
	case run.Outcome == extrun.OutcomeExitNonZero && run.ExitCode == 1 && len(run.Stdout) == 0:
		return "" // git config --get-regexp exits 1 when nothing matches
	case run.Outcome == extrun.OutcomeOK && !run.StdoutTruncated:
		if FilterDriverSet(run.Stdout) {
			return ReasonGitFilter
		}
		return ""
	}
	return ReasonGitConfig
}

// FilterDriverSet reports whether `git config --null --get-regexp` output
// names a filter driver's smudge, process or clean command.
func FilterDriverSet(out []byte) bool {
	for _, e := range strings.Split(string(out), "\x00") {
		key, _, _ := strings.Cut(e, "\n")
		key = strings.ToLower(strings.TrimSpace(key))
		if !strings.HasPrefix(key, "filter.") {
			continue
		}
		for _, s := range []string{".smudge", ".process", ".clean"} {
			if strings.HasSuffix(key, s) {
				return true
			}
		}
	}
	return false
}

// runnerFor returns the runner of one run: isolated when the host has a
// provider, else the plain runner (the run is labelled "not isolated"). A
// provider that exists but cannot be prepared refuses the run.
func (d *Driver) runnerFor(root string, linked bool) (*extrun.Runner, bool, error) {
	if d.env.Isolate == nil || d.env.IsolatedRunner == nil {
		return d.env.Runner, false, nil
	}
	dirs := extrun.OneShotDirs{
		Project: root, Output: d.env.OutDir, Cache: d.env.CacheDir, ProgramDirs: []string{d.env.PackDir},
	}
	if linked && d.env.LinkedCommonDir != nil {
		// The one-shot binds program directories read-only: git in the box
		// reads the worktree's objects and refs, and writes none.
		if common := d.env.LinkedCommonDir(root); common != "" {
			dirs.ProgramDirs = append(dirs.ProgramDirs, common)
		}
	}
	prov, err := d.env.Isolate(dirs)
	switch {
	case err != nil:
		return nil, false, err
	case prov == nil:
		return d.env.Runner, false, nil
	}
	return d.env.IsolatedRunner(prov), true, nil
}

// request is the runner request of one run.
func (d *Driver) request(rs resolved, mode Mode, root, base string, paths ...string) extrun.Request {
	e := extrun.OpengrepEngine
	prog := extrun.Program{
		Path: rs.bin, AllowSymlink: true,
		CompanionExecs: []extrun.CompanionExec{{Path: rs.git, OnPath: true}},
	}
	expect := &extrun.Digests{Binary: rs.digest}
	// Every recorded file still present is handed to the runner with its
	// digest, whether or not a file was added or removed beside it (lane
	// SEC-G1 audit finding 4): a changed file refuses the run even when the
	// tree also gained one, never labelled and run unchecked.
	if rec := rs.state.Tree; rec != nil && rec.BinaryDigest == rs.digest && (rs.tree == secengine.TreeSame || rs.tree == secengine.TreeChanged) {
		dir := d.treeDir(rec.Version)
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
			p := d.join(dir, strings.ReplaceAll(n, "/", d.sep()))
			prog.Companions = append(prog.Companions, p)
			expect.Companions[p] = rec.Files[n]
		}
	}
	return extrun.Request{
		Component: ComponentID,
		Program:   prog,
		Args:      ArgsFor(mode, d.rulesDir(), d.canary(), d.join(strings.TrimRight(d.env.OutDir, `/\`), "opengrep.json"), base, paths, d.env.Jobs),
		Expect:    expect,
		Dir:       root,
		Limits:    LimitsFor(mode, d.env.Jobs),
		CacheDir:  d.env.CacheDir,
		Engine:    &e,
	}
}

// refusedReason maps a runner refusal.
func refusedReason(r extrun.Result) string {
	switch r.Reason {
	case extrun.RefuseDigestMismatch, extrun.RefuseDigestUnavailable:
		return secengine.ReasonUnverified
	case extrun.RefuseIsolationFailed, extrun.RefuseIsolationRequired:
		return ReasonIsolation
	}
	return ReasonRunner
}

// classify maps a finished run onto a failure reason, "" when its output
// is a result (an ordered table, CLAUDE.md module rule 5).
func classify(r extrun.Result) string {
	rows := []struct {
		when   func(extrun.Result) bool
		reason string
	}{
		{func(r extrun.Result) bool { return r.Outcome == extrun.OutcomeRefused }, refusedReason(r)},
		{func(r extrun.Result) bool {
			return r.Outcome == extrun.OutcomeTimeout || r.Outcome == extrun.OutcomeOutputCap || r.Outcome == extrun.OutcomeChildrenCap
		}, ReasonBudget},
		{func(r extrun.Result) bool { return r.Outcome == extrun.OutcomeCanceled }, ReasonCanceled},
		{func(r extrun.Result) bool { return r.ExitMeaning == extrun.ExitFailure && r.ExitCode == 7 }, ReasonConfig},
		{func(r extrun.Result) bool {
			return r.ExitMeaning != extrun.ExitResult && r.ExitMeaning != extrun.ExitFindings
		}, ReasonCrashed},
		{func(r extrun.Result) bool { return r.StdoutTruncated }, ReasonBudget},
	}
	for _, row := range rows {
		if row.when(r) {
			return row.reason
		}
	}
	return ""
}

// selfTest returns whether the canary has passed for the current binary,
// tree and pack. A full scan carries the canary itself, so it only reads
// the record; a diff scope runs the canary first when no record matches.
// A non-nil result is a self-test run that failed (the scan stops).
func (d *Driver) selfTest(ctx context.Context, runner *extrun.Runner, rs resolved, root, version string, mode Mode) (bool, *secscan.Result) {
	if st := rs.state.SelfTest; st != nil && st.BinaryDigest == rs.digest && st.PackDigest == d.env.Pack.Digest() && st.TreeDigest == treeDigest(rs.state.Tree, rs.digest) && rs.tree != secengine.TreeChanged {
		return true, nil
	}
	if carriesCanary(mode) {
		return false, nil
	}
	run := runner.Run(ctx, d.request(rs, ModeSelfTest, root, ""))
	if r := classify(run); r != "" {
		res := failed(secscan.EngineIdentity{}, r, nil)
		return false, &res
	}
	passed := d.canaryHit(run)
	if passed && rs.decision.Status == secengine.StatusVerified {
		d.recordAfterVerifiedRun(rs, version, true)
	}
	return passed, nil
}

// canaryHit reports whether a run's SARIF carries the canary result.
func (d *Driver) canaryHit(run extrun.Result) bool {
	log, err := sarif.Decode(run.Stdout)
	if err != nil || len(log.Runs) != 1 {
		return false
	}
	_, hit := splitCanary(log.Runs[0], d.env.Pack.Manifest.Canary.Rule, secrulepack.RulePrefix(d.rulesDir()), d.canary())
	return hit
}

// read turns a result run's SARIF and JSON copy into the driver result.
func (d *Driver) read(run extrun.Result, t secscan.Target, dir string, mode Mode, ident secscan.EngineIdentity, selfTest bool) (secscan.Result, Scanned, bool, string) {
	log, err := sarif.Decode(run.Stdout)
	if err != nil || len(log.Runs) != 1 {
		return secscan.Result{}, Scanned{}, false, ReasonOutput
	}
	jb, err := d.env.ReadFile(d.join(strings.TrimRight(d.env.OutDir, `/\`), "opengrep.json"), MaxJSONCopyBytes)
	if err != nil {
		return secscan.Result{}, Scanned{}, false, ReasonOutput
	}
	scanned, err := ParseJSONCopy(jb, dir, d.canary())
	if err != nil {
		return secscan.Result{}, Scanned{}, false, ReasonOutput
	}
	prefix := secrulepack.RulePrefix(d.rulesDir())
	project, hit := splitCanary(log.Runs[0], d.env.Pack.Manifest.Canary.Rule, prefix, d.canary())
	passed := selfTest
	if carriesCanary(mode) {
		passed = hit && scanned.Canary
	}
	row, _ := secscan.Adapter("opengrep")
	findings, cov := secscan.Adapt(row, project, secscan.AdaptOptions{
		ProjectRoot: dir, ProjectRootHash: secposture.ProjectRootHash(t.ProjectRoot),
		Scope: t.Scope, Engine: ident, RulePrefix: prefix, SelfTestPassed: passed,
	})
	pack := d.env.Pack
	for i := range findings {
		f := &findings[i]
		f.Rule.Pack, f.Rule.PackVersion = secrulepack.PackID, pack.Version()
		if r, ok := pack.Rule(f.Rule.ID); ok {
			// Confidence high only for a rule that cleared the precision bar
			// (PR7): none in G1, so every finding stays flag-only.
			if r.BlockingEligible() {
				f.Confidence = policy.FindingConfidenceHigh
			}
		}
	}
	findings, cov = excludeTestResults(pack, findings, cov, passed)
	cov.FilesScanned = len(scanned.Files)
	for _, p := range scanned.Partial {
		cov.Skipped = append(cov.Skipped, secscan.Skip{Path: p, Reason: skipPartial})
	}
	if cov.Outcome == secscan.OutcomeUnknown && !passed && cov.Reason == "no_self_test" {
		cov.Reason = "canary_not_reported"
	}
	if carriesCanary(mode) && !closable(passed, cov) {
		scanned.Files = nil
	}
	return secscan.Result{Findings: findings, Coverage: cov, Engine: ident}, scanned, passed, ""
}

// TestExcludedPrefix starts the note of a run that dropped results of
// exclude_tests rules in test paths.
const TestExcludedPrefix = "Test paths excluded"

// excludeTestResults is the per-rule test exclusion (lane SEC-G5): the
// results of a rule whose pack row sets exclude_tests in a test path class
// (secrulepack.TestPathClass) are dropped after the engine ran, counted in
// a note, never a skip (the file was read in full, so the run stays
// closable and an excluded rule's old finding there closes). A run left
// with no finding is clean only on the same terms as Adapt's.
func excludeTestResults(pack *secrulepack.Pack, fs []secfinding.Finding, cov secscan.Coverage, passed bool) ([]secfinding.Finding, secscan.Coverage) {
	kept := fs[:0]
	dropped := 0
	for _, f := range fs {
		if pack.TestExcluded(f.Rule.ID, f.Location.RelPath) {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	if dropped == 0 {
		return kept, cov
	}
	cov.Notes = append(cov.Notes, fmt.Sprintf("%s: %d result(s) of rules marked exclude_tests were in test paths and are not shown.", TestExcludedPrefix, dropped))
	if len(kept) == 0 && cov.Outcome == secscan.OutcomeFindings {
		if passed && len(cov.Skipped) == 0 && !cov.Truncated {
			cov.Outcome, cov.Reason = secscan.OutcomeClean, ""
		} else {
			cov.Outcome, cov.Reason = secscan.OutcomeUnknown, "results_refused"
		}
	}
	return kept, cov
}

// skipPartial is the skip reason of a file Opengrep did not read in full.
const skipPartial = "partially_parsed"

// closable reports whether a full run proved its read files complete (lane
// SEC-G1 audit finding 1): the canary passed in this run, nothing was cut
// at the output cap, and every skipped result is a partially parsed file
// (already left out of the read files). Any other drop, a result refused
// for its location or its rule id, leaves the whole run closing nothing.
func closable(passed bool, cov secscan.Coverage) bool {
	if !passed || cov.Truncated {
		return false
	}
	for _, s := range cov.Skipped {
		if s.Reason != skipPartial {
			return false
		}
	}
	return true
}

// treeDigest is a digest of a tree record's files (for the self-test key).
func treeDigest(rec *secengine.TreeRecord, binary string) string {
	if rec == nil || rec.BinaryDigest != binary {
		return ""
	}
	files := map[string][]byte{}
	for p, d := range rec.Files {
		files[p] = []byte(d)
	}
	return secrulepack.CanonicalDigest(files)
}

// recordAfterVerifiedRun records the companion tree after the first
// verified run (X9) and, when the canary passed, the self-test. The tree is
// hashed through the runner's own hasher, file by file.
func (d *Driver) recordAfterVerifiedRun(rs resolved, version string, canaryPassed bool) {
	if d.env.State == nil || d.env.ListTree == nil || d.env.Runner == nil || d.env.Runner.Hash == nil {
		return
	}
	st, err := d.env.State.Load()
	if err != nil {
		return // never a silent re-baseline over a record that did not load
	}
	if st.Tree == nil || st.Tree.BinaryDigest != rs.digest || rs.tree == secengine.TreeNone {
		dir := d.treeDir(version)
		l := d.env.ListTree(dir)
		if l.Err != "" || l.Irregular {
			return
		}
		sums := map[string]string{}
		for _, f := range l.Files {
			sum, err := d.env.Runner.Hash(d.join(dir, strings.ReplaceAll(f, "/", d.sep())))
			if err != nil {
				return
			}
			sums[f] = sum
		}
		rec, ok := secengine.NewTreeRecord(rs.digest, version, sums, d.now())
		if !ok {
			return
		}
		st.Tree = &rec
		st.SelfTest = nil
	}
	if canaryPassed {
		st.SelfTest = &SelfTest{BinaryDigest: rs.digest, TreeDigest: treeDigest(st.Tree, rs.digest), PackDigest: d.env.Pack.Digest(), PassedAt: d.now().UTC()}
	}
	_ = d.env.State.Save(st)
}

// Inspection is what status and doctor show about the engine.
type Inspection struct {
	Binary   string
	Digest   string
	Decision secengine.Decision
	// Tree compares the companion tree's file names with the record; the
	// file digests are compared by the runner before each scan, not here.
	Tree secengine.TreeState
	// TreeRecordedAt is when the tree was recorded (zero: no record).
	TreeRecordedAt time.Time
	// SelfTestAt is when the canary last passed for this binary, tree and
	// pack as recorded (zero: no record).
	SelfTestAt time.Time
	// Reason is a closed reason code when the engine could not be read.
	Reason string
}

// Inspect resolves and decides without starting anything and without
// writing anything (lane SEC-G1 audit finding 6): it hashes the binary,
// lists the tree and reads the record. It does not hash the unpacked tree
// (about 246 MB); it reports the recorded state and its age, and the next
// scan's runner compares the digests before Opengrep starts.
func (d *Driver) Inspect() Inspection {
	rs, reason := d.resolve()
	in := Inspection{Binary: rs.bin, Digest: rs.digest, Decision: rs.decision, Tree: rs.tree, Reason: reason}
	if rec := rs.state.Tree; rec != nil && rec.BinaryDigest == rs.digest {
		in.TreeRecordedAt = rec.RecordedAt
	}
	if st := rs.state.SelfTest; st != nil && st.BinaryDigest == rs.digest {
		in.SelfTestAt = st.PassedAt
	}
	return in
}
