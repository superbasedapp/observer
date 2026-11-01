package depdriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// ScalibrLimits are the scan child's caps: the match peaks at about 600 MB
// (JSP-9b section 4) and a background scan gets 600 s (JSP-8). GOMEMLIMIT
// in the child's environment keeps the Go heap under the cap.
var ScalibrLimits = extrun.Limits{
	Wall:        600 * time.Second,
	StdoutBytes: 64 << 20,
	StderrBytes: 1 << 20,
	MemoryBytes: 1536 << 20,
	Children:    64,
}

// ScalibrChildArgs are the arguments the scan child is started with.
var ScalibrChildArgs = []string{"security", "scan-child"}

// scalibrEnv is the child's whole environment: no PATH, no inherited
// variable; two Go runtime knobs only.
var scalibrEnv = extrun.EnvSpec{Set: []string{"GOMAXPROCS=2", "GOMEMLIMIT=1100MiB", "GOTRACEBACK=none"}}

// Env is what the SCALIBR driver needs from the caller.
type Env struct {
	// Runner is the shared runner (production: extrun/host.NewRunner).
	Runner *extrun.Runner
	// Executable is the absolute path of the caller's own binary.
	Executable string
	// Compiled is scalibrfacade.Compiled in the caller's build.
	Compiled bool
	// Extractors are the facade's extractor names (Platforms cells).
	Extractors []string
	// DBDir and Epochs are the local database store's directory and the
	// installed ecosystems' epochs (osvdb.Store).
	DBDir  string
	Epochs map[string]string
	// GOOS and GOARCH select the Platforms cells.
	GOOS, GOARCH string
	// Digest is the caller's binary digest, when known.
	Digest string
	// SkipDirs are absolute directories the walk skips.
	SkipDirs []string
	// Online, when set, matches an ecosystem the local database could not
	// (database_missing) against the OSV API; nil keeps matching local.
	Online OnlineMatcher
	// Isolate, when set, prepares one isolated run of the scan child for a
	// project root (lane SEC-D2B milestone 2d): the isolation provider, the
	// root and database directory the child reads inside it (outside
	// ~/.observer, which the isolation engine never binds) and a cleanup.
	// nil Isolate, or a nil provider with no error, means no isolation
	// provider is available on this host: the child runs unisolated and
	// the run's notes say so. An error refuses the scan.
	Isolate func(root string) (Isolated, error)
	// IsolatedRunner builds the runner that wraps the child in a provider
	// (production: extrun/host.NewRunner with Options.Isolation).
	IsolatedRunner func(extrun.IsolationProvider) *extrun.Runner
}

// Isolated is one prepared isolated run (Env.Isolate). A nil Provider
// with a nil error means no isolation provider exists on this host (the
// child then runs unisolated, labelled); an error means a provider exists
// but refused, and the scan is refused.
type Isolated struct {
	Provider extrun.IsolationProvider
	// Root is the project root as the isolated child sees it (resolved
	// through symlinks: the provider binds resolved paths only); empty
	// keeps the caller's root.
	Root string
	// DBDir is the database directory as the isolated child sees it,
	// resolved through symlinks for the same reason.
	DBDir string
	// Cleanup removes what Isolate prepared; nil when nothing.
	Cleanup func()
}

// The run notes of a SCALIBR child that was not isolated (ledger SECP-8:
// it then has the network, though it never opens a connection itself).
const (
	whyNoProvider = "no isolation provider is available on this host (the isolation component is off, or the host is not Linux with bwrap)"
	whyNotWrapped = "the runner did not wrap the run"
)

func notIsolated(why string) string {
	return depscan.NotIsolatedPrefix + ": the scan child ran with network access (ledger SECP-8): " + why + "."
}

// OnlineMatcher matches one ecosystem's packages online. ok false means it
// did not try (the ecosystem cannot be matched online), and the local
// result stands.
type OnlineMatcher func(ctx context.Context, eco string, pkgs []depscan.Package, idx []int) (depscan.EcoResult, bool)

// ApplyOnline replaces each ecosystem the local match left without a
// database with the online matcher's answer.
func ApplyOnline(ctx context.Context, resp depscan.ChildResponse, m OnlineMatcher) depscan.ChildResponse {
	if m == nil {
		return resp
	}
	keep, _ := depscan.Prepare(resp.Packages)
	out := resp
	out.Ecosystems = append([]depscan.EcoResult(nil), resp.Ecosystems...)
	for i, e := range out.Ecosystems {
		if e.Outcome == depscan.EcoScanned || e.Reason != depscan.ReasonNoDatabase {
			continue
		}
		if r, ok := m(ctx, e.Ecosystem, resp.Packages, keep[e.Ecosystem]); ok {
			out.Ecosystems[i] = r
		}
	}
	return out
}

// Scalibr is the linked driver.
type Scalibr struct{ env Env }

// NewScalibr returns the driver over env.
func NewScalibr(env Env) *Scalibr { return &Scalibr{env: env} }

// Row is the registry row.
func (d *Scalibr) Row() secscan.DriverRow { return depscan.ScalibrRow(d.env.Extractors) }

// Probe answers without scanning: compiled, platform cell, beta label,
// oldest database age.
func (d *Scalibr) Probe(context.Context) secscan.Probe {
	row := d.Row()
	p := secscan.Probe{
		Installed: d.env.Compiled, Version: depscan.SCALIBRVersion, Verified: d.env.Compiled,
		Platform: depscan.PlatformSupport(row, d.env.GOOS, d.env.GOARCH, ""),
		Beta:     depscan.Beta(row, d.env.GOOS, d.env.GOARCH),
	}
	switch {
	case !d.env.Compiled:
		p.Reason = depscan.ReasonNotCompiled
	case p.Platform == secscan.SupportUnsupported:
		p.Reason = depscan.ReasonUnsupported
	case len(d.env.Epochs) == 0:
		p.Reason = depscan.ReasonNoDatabase
	}
	return p
}

// Scan runs the child over t.ProjectRoot.
func (d *Scalibr) Scan(ctx context.Context, t secscan.Target) (secscan.Result, error) {
	engine := secscan.EngineIdentity{Name: depscan.ScalibrID, Version: depscan.SCALIBRVersion, Digest: d.env.Digest}
	if !d.env.Compiled {
		return Result(Input{DriverID: depscan.ScalibrID, Target: t, Engine: engine, RunReason: depscan.ReasonNotCompiled}), nil
	}
	if depscan.PlatformSupport(d.Row(), d.env.GOOS, d.env.GOARCH, "") == secscan.SupportUnsupported {
		return Result(Input{DriverID: depscan.ScalibrID, Target: t, Engine: engine, RunReason: depscan.ReasonUnsupported}), nil
	}
	if d.env.Runner == nil || d.env.Executable == "" {
		return secscan.Result{}, errors.New("depdriver.Scan: runner not wired")
	}
	run, notes, refused, err := d.runChild(ctx, t.ProjectRoot)
	if err != nil {
		return secscan.Result{}, err
	}
	if refused {
		return Result(Input{DriverID: depscan.ScalibrID, Target: t, Engine: engine, Failed: true, RunReason: depscan.ReasonIsolationRefused}), nil
	}
	resp, perr := ParseChild(run)
	if run.Digests.Binary != "" {
		engine.Digest = run.Digests.Binary
	}
	if perr != nil {
		return Result(Input{DriverID: depscan.ScalibrID, Target: t, Engine: engine, Failed: true, RunReason: failReason(run), Notes: notes}), nil
	}
	resp = ApplyOnline(ctx, resp, d.env.Online)
	return Result(Input{DriverID: depscan.ScalibrID, Target: t, Engine: engine, Response: resp, Notes: notes}), nil
}

// runChild starts the scan child, isolated when a provider is available.
// Only a host with no isolation provider at all (Env.Isolate nil, or an
// Isolated with neither a provider nor an error) runs the child
// unisolated, labelled by a fixed note (the SECP-8 residual). A provider
// that exists but cannot be prepared, or that the runner refuses to apply,
// refuses the scan: refused true, no child started (lane SEC-DEPS3 item 5).
// Notes carry fixed text only, never an error's or the engine's own text
// (item 6).
func (d *Scalibr) runChild(ctx context.Context, root string) (run extrun.Result, notes []string, refused bool, err error) {
	request := func(childRoot, dbDir string) (extrun.Request, error) {
		return ScalibrRequest(d.env.Executable, root, depscan.ChildRequest{
			Version: depscan.ProtocolVersion, Root: childRoot, DBDir: dbDir, Epochs: d.env.Epochs,
			SkipDirs: d.env.SkipDirs, GOOS: d.env.GOOS,
		})
	}
	plain := func() (extrun.Result, []string, bool, error) {
		req, err := request(root, d.env.DBDir)
		if err != nil {
			return extrun.Result{}, nil, false, err
		}
		return d.env.Runner.Run(ctx, req), []string{notIsolated(whyNoProvider)}, false, nil
	}
	if d.env.Isolate == nil || d.env.IsolatedRunner == nil {
		return plain()
	}
	iso, err := d.env.Isolate(root)
	if iso.Cleanup != nil {
		defer iso.Cleanup()
	}
	switch {
	case err != nil:
		return extrun.Result{}, nil, true, nil
	case iso.Provider == nil:
		return plain()
	}
	childRoot := root
	if iso.Root != "" {
		childRoot = iso.Root
	}
	req, err := request(childRoot, iso.DBDir)
	if err != nil {
		return extrun.Result{}, nil, false, err
	}
	run = d.env.IsolatedRunner(iso.Provider).Run(ctx, req)
	switch {
	case run.Outcome == extrun.OutcomeRefused && run.Reason == extrun.RefuseIsolationFailed:
		return extrun.Result{}, nil, true, nil
	case run.Isolation == "" && run.Outcome != extrun.OutcomeRefused:
		return run, []string{notIsolated(whyNotWrapped)}, false, nil
	}
	return run, nil, false, nil
}

// ScalibrRequest is the runner request that starts the scan child.
func ScalibrRequest(exe, root string, child depscan.ChildRequest) (extrun.Request, error) {
	body, err := json.Marshal(child)
	if err != nil {
		return extrun.Request{}, fmt.Errorf("depdriver.ScalibrRequest: %w", err)
	}
	return extrun.Request{
		Component: depscan.ScalibrComponent,
		Program:   extrun.Program{Path: exe},
		Args:      append([]string(nil), ScalibrChildArgs...),
		Env:       scalibrEnv,
		Dir:       root,
		Stdin:     body,
		Limits:    ScalibrLimits,
	}, nil
}

// ParseChild reads the child's answer from a finished run. A run that did
// not exit 0 with a well-formed response of this protocol version is an
// error.
func ParseChild(run extrun.Result) (depscan.ChildResponse, error) {
	if run.Outcome != extrun.OutcomeOK {
		return depscan.ChildResponse{}, fmt.Errorf("depdriver: scan child %s (%s) %s", run.Outcome, run.Reason, run.Detail)
	}
	if run.StdoutTruncated {
		return depscan.ChildResponse{}, errors.New("depdriver: scan child output passed its cap")
	}
	var resp depscan.ChildResponse
	if err := json.Unmarshal(run.Stdout, &resp); err != nil {
		return depscan.ChildResponse{}, fmt.Errorf("depdriver: scan child answer: %w", err)
	}
	if resp.Version != depscan.ProtocolVersion {
		return depscan.ChildResponse{}, fmt.Errorf("depdriver: scan child protocol %d, want %d", resp.Version, depscan.ProtocolVersion)
	}
	if resp.Error != "" {
		return resp, fmt.Errorf("depdriver: scan child: %s", resp.Error)
	}
	return resp, nil
}

// failReason is the closed reason for a run that did not answer.
func failReason(run extrun.Result) string {
	switch run.Outcome {
	case extrun.OutcomeTimeout, extrun.OutcomeOutputCap, extrun.OutcomeChildrenCap:
		return "budget_exceeded"
	case extrun.OutcomeRefused:
		return "driver_unverified"
	case extrun.OutcomeCanceled:
		return "canceled"
	}
	return depscan.ReasonEngineFailed
}

// Input is what Result needs from either driver.
type Input struct {
	DriverID string
	Target   secscan.Target
	Engine   secscan.EngineIdentity
	Response depscan.ChildResponse
	// RunReason, when set, is a run-level reason nothing was scanned.
	RunReason string
	// Failed: the engine failed.
	Failed bool
	// Notes are the run's notes (secscan.Coverage.Notes).
	Notes []string
}

// Result is the shared result path: the gaps (depscan.Finalize), grouped
// findings, coverage and engine identity.
func Result(in Input) secscan.Result {
	resp, gaps := depscan.Finalize(in.Response)
	epochs := map[string]string{}
	var advs []depscan.Advisory
	for _, e := range resp.Ecosystems {
		if e.Outcome != depscan.EcoScanned {
			continue
		}
		epochs[e.Ecosystem] = e.Epoch
		advs = append(advs, e.Advisories...)
	}
	row, _ := secscan.Adapter("osv")
	groups := depscan.GroupByAliases(advs, row.Default)
	findings, truncated := depscan.Findings(depscan.FindingInput{
		Packages: resp.Packages, Groups: groups, RootHash: secposture.ProjectRootHash(in.Target.ProjectRoot),
		Scope: scopeOr(in.Target.Scope), Engine: in.Engine, Epochs: epochs, DriverID: in.DriverID,
	})
	failures := 0
	for _, x := range resp.Extractors {
		if !x.OK {
			failures++
		}
	}
	cov := depscan.Coverage(depscan.RunFacts{
		Reason: in.RunReason, Failed: in.Failed, Ecosystems: resp.Ecosystems,
		ExtractorFailures: failures, Gaps: gaps, Findings: len(findings),
	})
	cov.Truncated = truncated
	cov.FilesScanned = filesOf(resp.Packages)
	cov.Notes = append([]string(nil), in.Notes...)
	in.Engine.DatabaseEpoch = EpochSummary(epochs)
	return secscan.Result{Findings: findings, Coverage: cov, Engine: in.Engine}
}

func scopeOr(s secfinding.Scope) secfinding.Scope {
	if s == "" {
		return "scheduled"
	}
	return s
}

// filesOf counts the distinct dependency files the inventory read.
func filesOf(pkgs []depscan.Package) int {
	seen := map[string]bool{}
	for _, p := range pkgs {
		seen[p.Path] = true
	}
	return len(seen)
}

// EpochSummary is the run's database epoch: "<eco>=<epoch>" pairs, sorted.
func EpochSummary(epochs map[string]string) string {
	keys := make([]string, 0, len(epochs))
	for k := range epochs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+epochs[k])
	}
	return strings.Join(parts, "; ")
}
