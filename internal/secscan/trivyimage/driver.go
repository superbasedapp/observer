package trivyimage

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// driver.go is the image driver's one run seam: ask the version and (once
// per binary digest) both subcommands' --help under the same digest, scan
// the canary, then the image, each through the shared runner under the
// driver's caps and only isolated, and turn the report into the run's
// result. Resolving and deciding the binary (the pinned guided install
// first, else the one on PATH, shims excluded) is the caller's, through the
// config driver's resolution (internal/seciac), so both Trivy drivers trust
// the same binary the same way.

// The run's reasons beside depscan's vocabulary.
const (
	// ReasonIsolationRequired: no isolation provider on this host; Trivy
	// runs only isolated (the config driver's rule).
	ReasonIsolationRequired = "isolation_required"
	// ReasonFlagsMissing: the binary's --help lacks a required flag.
	ReasonFlagsMissing = "engine_flags_missing"
	// ReasonUnverified: the binary is not covered by a verified pin, or it
	// changed under the run (the runner refused its digest).
	ReasonUnverified = "driver_unverified"
	// ReasonBudget, ReasonCanceled and ReasonOutput: a run past its caps,
	// canceled, or with an unreadable report.
	ReasonBudget   = "budget_exceeded"
	ReasonCanceled = "canceled"
	ReasonOutput   = "output_unreadable"
)

// The run notes' fixed prefixes.
const (
	// UntestedPrefix starts the note of a Trivy version other than the
	// tested one (depscan's label words).
	UntestedPrefix = "Untested engine version"
	// CoveragePrefix starts the note on what the canary proves.
	CoveragePrefix = "Self-test coverage"
	// EOSLPrefix starts the note of a release past its end of service life.
	EOSLPrefix = "End of service life"
	// NoFixPrefix starts the note counting findings with no fixed version.
	NoFixPrefix = "No fix available yet"
	// PreviousDriverPrefix starts the note on the other driver's open
	// findings after a switch.
	PreviousDriverPrefix = "Findings from the previous driver"
)

// Limits are one run's caps (the config driver's, with Trivy's report
// written to a file rather than stdout).
func Limits() extrun.Limits {
	return extrun.Limits{Wall: 600 * time.Second, StdoutBytes: 1 << 20, StderrBytes: 1 << 20, MemoryBytes: 2 << 30, Children: 64}
}

// ExtrunEngine is the run profile: its own HOME and cache inside the run's
// cache directory, a UTF-8 locale, and exit 0 as the only result (the run
// passes --exit-code 0; findings come from the report).
func ExtrunEngine() extrun.Engine {
	return extrun.Engine{Name: DriverID, OwnHome: true, Locale: "C.UTF-8", ExitCodes: []extrun.ExitCodeRow{{Code: 0, Meaning: extrun.ExitResult}}}
}

// Env is what one run needs; every I/O is injected.
type Env struct {
	// RunnerFor returns the isolated runner of a run whose read-only input
	// is project (the canary directory, or the image's input directory);
	// a nil runner comes with the reason it cannot be built
	// (ReasonIsolationRequired, depscan.ReasonIsolationRefused).
	RunnerFor func(project string) (*extrun.Runner, string)
	// Binary and Digest are the resolved and decided Trivy binary.
	Binary string
	Digest string
	// CacheDir is the run's Trivy cache directory (db/ inside it reaches
	// the installed database) and the engine's HOME; OutDir is the run's
	// output directory; CanaryDir holds CanaryFiles.
	CacheDir  string
	OutDir    string
	CanaryDir string
	// FlagsChecked: the caller's record says this digest's --help listed
	// every flag of both modes, so the help is not asked again.
	FlagsChecked bool
	// ReadFile reads a regular file of at most limit bytes (the reports).
	ReadFile func(path string, limit int64) ([]byte, error)
	// GOOS spells the paths.
	GOOS string
}

// ScanInput is one image run.
type ScanInput struct {
	Mode Mode
	// Target is the image tar (ModeImage) or root filesystem (ModeRootfs).
	Target string
	// Project is the run's read-only input directory: the directory that
	// holds the tar, or the root filesystem itself.
	Project string
	// Map carries the label, project, scope, engine identity, epoch and
	// location the findings take (its Report is filled in here).
	Map MapInput
	// Notes are the caller's notes (not isolated, previous driver).
	Notes []string
}

// ScanOutput is one run's answer.
type ScanOutput struct {
	Result secscan.Result
	// Packages are the image's OS packages (for the inventory record).
	Packages []depscan.Package
	// Version is the version Trivy reported.
	Version string
	// FlagsOK: this run checked both subcommands' --help and every flag was
	// listed (the caller records the digest).
	FlagsOK bool
}

func (e Env) sep() string {
	if e.GOOS == "windows" {
		return `\`
	}
	return "/"
}

func (e Env) path(dir, name string) string {
	return strings.TrimRight(dir, `/\`) + e.sep() + name
}

func (e Env) request(project string, args []string) extrun.Request {
	eng := ExtrunEngine()
	return extrun.Request{
		Component: ComponentID, Program: extrun.Program{Path: e.Binary, AllowSymlink: true}, Args: args,
		Expect: &extrun.Digests{Binary: e.Digest}, Dir: project, Limits: Limits(), CacheDir: e.CacheDir,
		Engine: &eng, RequireIsolation: true,
	}
}

// RunResult builds a run's result through depscan's coverage table: a release
// label with an outcome and reason, the findings, and the notes. failed
// marks a run the engine itself failed (a crash, a refused run, a budget).
func RunResult(label string, outcome depscan.EcoOutcome, reason string, failed bool, packages int, epoch string, findings MapOutput, engine secscan.EngineIdentity, notes []string) secscan.Result {
	facts := depscan.RunFacts{Failed: failed, Findings: len(findings.Findings)}
	if outcome == depscan.EcoNotScanned || failed {
		facts.Reason = reason
	}
	if label != "" {
		er := depscan.EcoResult{Ecosystem: label, Outcome: outcome, Reason: reason, Packages: packages}
		if outcome == depscan.EcoScanned {
			er.Epoch = epoch
		}
		facts.Ecosystems = []depscan.EcoResult{er}
	}
	cov := depscan.Coverage(facts)
	cov.Truncated = findings.Truncated
	if packages > 0 {
		cov.FilesScanned = 1
	}
	cov.Notes = append([]string(nil), notes...)
	if outcome == depscan.EcoScanned && label != "" && epoch != "" {
		engine.DatabaseEpoch = label + "=" + epoch
	}
	return secscan.Result{Findings: findings.Findings, Coverage: cov, Engine: engine}
}

// refusedReason maps a runner refusal onto the run's reason.
func refusedReason(r extrun.Result) string {
	switch r.Reason {
	case extrun.RefuseDigestMismatch, extrun.RefuseDigestUnavailable:
		return ReasonUnverified
	case extrun.RefuseIsolationRequired:
		return ReasonIsolationRequired
	case extrun.RefuseIsolationFailed:
		return depscan.ReasonIsolationRefused
	}
	return depscan.ReasonEngineFailed
}

// classify maps a finished run onto a failure reason, "" for a result
// (an ordered table, the config driver's).
var classifyRows = []struct {
	when   func(extrun.Result) bool
	reason func(extrun.Result) string
}{
	{func(r extrun.Result) bool { return r.Outcome == extrun.OutcomeRefused }, refusedReason},
	{func(r extrun.Result) bool {
		return r.Outcome == extrun.OutcomeTimeout || r.Outcome == extrun.OutcomeOutputCap || r.Outcome == extrun.OutcomeChildrenCap
	}, func(extrun.Result) string { return ReasonBudget }},
	{func(r extrun.Result) bool { return r.Outcome == extrun.OutcomeCanceled }, func(extrun.Result) string { return ReasonCanceled }},
	{func(r extrun.Result) bool { return r.ExitMeaning != extrun.ExitResult }, func(extrun.Result) string { return depscan.ReasonEngineFailed }},
}

func classify(r extrun.Result) string {
	for _, row := range classifyRows {
		if row.when(r) {
			return row.reason(r)
		}
	}
	return ""
}

// notRun reasons are runs that stopped before Trivy scanned anything
// (not scanned, never failed).
var notRun = map[string]bool{ReasonIsolationRequired: true}

// Scan runs the canary and the image (file comment).
func (e Env) Scan(ctx context.Context, in ScanInput) ScanOutput {
	ident := in.Map.Engine
	ident.Name, ident.Digest = DriverID, e.Digest
	label := in.Map.Label
	notes := append([]string(nil), in.Notes...)
	stop := func(reason string, out ScanOutput) ScanOutput {
		failed := !notRun[reason]
		out.Result = RunResult(label, depscan.EcoNotScanned, reason, failed, 0, "", MapOutput{}, ident, notes)
		return out
	}
	if e.RunnerFor == nil || e.ReadFile == nil || e.Binary == "" || e.CacheDir == "" || e.OutDir == "" || e.CanaryDir == "" {
		return stop(depscan.ReasonEngineFailed, ScanOutput{})
	}
	canaryRunner, why := e.RunnerFor(e.CanaryDir)
	if canaryRunner == nil {
		return stop(why, ScanOutput{})
	}
	var out ScanOutput
	v, pr := canaryRunner.ProbeVersion(ctx, e.request(e.CanaryDir, nil), extrun.VersionProbe{Args: VersionArgs(), Pattern: VersionPattern})
	if pr.Outcome == extrun.OutcomeRefused {
		return stop(refusedReason(pr), out)
	}
	if v.Version == "" {
		return stop(ReasonUnverified, out)
	}
	out.Version, ident.Version = v.Version, v.Version
	if v.Version != TestedVersion {
		notes = append(notes, UntestedPrefix+": this Trivy is "+v.Version+", not the tested "+TestedVersion+"; its results are shown, labelled untested.")
	}
	if !e.FlagsChecked {
		for _, m := range []Mode{ModeRootfs, ModeImage} {
			req := e.request(e.CanaryDir, HelpArgs(m))
			req.Limits = extrun.Limits{Wall: 20 * time.Second, StdoutBytes: 256 << 10, StderrBytes: 256 << 10, MemoryBytes: 1 << 30, Children: 64}
			run := canaryRunner.Run(ctx, req)
			if run.Outcome == extrun.OutcomeRefused {
				return stop(refusedReason(run), out)
			}
			help := append(append([]byte(nil), run.Stdout...), run.Stderr...)
			if len(MissingFlags(m, help)) > 0 {
				return stop(ReasonFlagsMissing, out)
			}
		}
		out.FlagsOK = true
	}
	canaryPaths := Paths{Target: e.CanaryDir, Cache: e.CacheDir, Report: e.path(e.OutDir, "canary.json"), Sep: e.sep()}
	if why := classify(canaryRunner.Run(ctx, e.request(e.CanaryDir, Args(ModeRootfs, canaryPaths)))); why != "" {
		return stop(why, out)
	}
	cb, err := e.ReadFile(canaryPaths.Report, MaxReportBytes)
	if err != nil {
		return stop(ReasonOutput, out)
	}
	canary, err := Parse(cb)
	if err != nil {
		return stop(ReasonOutput, out)
	}
	if !CanaryHit(canary) {
		notes = append(notes, CoveragePrefix+": the canary (Debian 12 libc6 "+CanaryVersion+", "+CanaryAdvisory+") was not flagged, so this database's silence cannot mean clean.")
		out.Result = RunResult(label, depscan.EcoNotScanned, depscan.ReasonSelfTestFailed, false, 0, "", MapOutput{}, ident, notes)
		return out
	}
	runner, why := e.RunnerFor(in.Project)
	if runner == nil {
		return stop(why, out)
	}
	paths := Paths{Target: in.Target, Cache: e.CacheDir, Report: e.path(e.OutDir, "report.json"), Sep: e.sep()}
	if why := classify(runner.Run(ctx, e.request(in.Project, Args(in.Mode, paths)))); why != "" {
		return stop(why, out)
	}
	b, err := e.ReadFile(paths.Report, MaxReportBytes)
	if err != nil {
		return stop(ReasonOutput, out)
	}
	rep, err := Parse(b)
	if err != nil {
		return stop(ReasonOutput, out)
	}
	m := in.Map
	m.Report, m.Engine = rep, ident
	mapped := Map(m)
	label = mapped.Label
	out.Packages = mapped.Packages
	switch {
	case !rep.Metadata.OS.Detected():
		out.Result = RunResult(label, depscan.EcoNotScanned, depscan.ReasonNoOSRelease, false, 0, "", MapOutput{}, ident, notes)
		return out
	case label == "":
		out.Result = RunResult("", depscan.EcoNotScanned, depscan.ReasonDistroNotSupported, false, 0, "", MapOutput{}, ident, notes)
		return out
	case len(mapped.Packages) == 0:
		out.Result = RunResult(label, depscan.EcoNotScanned, depscan.ReasonNoImagePackages, false, 0, "", MapOutput{}, ident, notes)
		return out
	}
	notes = append(notes, CoveragePrefix+": Trivy's database was proved by the Debian 12 canary in this run; "+label+" is reported scanned on that proof, since per-distribution canaries for Trivy are not built yet.")
	if rep.Metadata.OS.EOSL {
		notes = append(notes, EOSLPrefix+": Trivy reports "+label+" past its end of service life, so its advisories may stop.")
	}
	if mapped.KernelNote != "" {
		notes = append(notes, mapped.KernelNote)
	}
	if mapped.NoFix > 0 {
		notes = append(notes, NoFixPrefix+": "+strconv.Itoa(mapped.NoFix)+" finding(s) have no fixed version in the distribution yet.")
	}
	if mapped.Unreadable > 0 {
		notes = append(notes, "Unreadable advisories: "+strconv.Itoa(mapped.Unreadable)+" advisory row(s) carried an id or a package outside the accepted charset and were not recorded.")
	}
	out.Result = RunResult(label, depscan.EcoScanned, "", false, mapped.Matched, in.Map.Epoch, mapped, ident, notes)
	return out
}
