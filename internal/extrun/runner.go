package extrun

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// Runner runs external programs under the rules in the package doc. Every
// field except Isolation is required; internal/extrun/host.NewRunner builds
// the production one. A Runner is safe for concurrent use.
type Runner struct {
	// GOOS is the OS the programs run on (it selects the path, environment
	// and script rules).
	GOOS string
	// Resolve resolves a registry binary spec (production: toolresolve with
	// the shim exclusion of toolresolve/host.NewEnv).
	Resolve func(integration.BinaryResolveSpec) toolresolve.Resolution
	// Inspect reports what is at a path.
	Inspect func(path string) (FileFacts, error)
	// Hash returns the lowercase hex SHA-256 of the file at path.
	Hash func(path string) (string, error)
	// Getenv reads one variable of the daemon's environment.
	Getenv func(name string) (string, bool)
	// Exec is the one exec seam.
	Exec Executor
	// Isolation, when set, wraps every plan. nil runs programs directly.
	Isolation IsolationProvider

	mu       sync.Mutex
	versions map[string]VersionInfo
}

// prepared is a request that passed every check, ready to execute.
type prepared struct {
	plan Plan
	res  Result
}

// refuse fills res as a refusal.
func refuse(res Result, reason RefuseReason, detail string) Result {
	res.Outcome = OutcomeRefused
	res.Reason = reason
	res.Detail = detail
	return res
}

// prepare runs steps 1 to 6 of the package doc. ok is false when res is a
// refusal.
func (r *Runner) prepare(ctx context.Context, req Request) (prepared, bool) {
	res := Result{Component: req.Component, PeakChildren: -1}
	if req.Component == "" {
		return prepared{res: refuse(res, RefuseNoComponent, "every run must name the component that owns it")}, false
	}
	if r.Exec == nil || r.Inspect == nil || r.Hash == nil {
		return prepared{res: refuse(res, RefuseNoExecutor, "the runner is not wired")}, false
	}
	if (req.Program.Spec == nil) == (req.Program.Path == "") {
		return prepared{res: refuse(res, RefuseBadRequest, "set exactly one of Program.Spec and Program.Path")}, false
	}
	limits, ok := ResolveLimits(req.Limits)
	if !ok {
		return prepared{res: refuse(res, RefuseBadLimits, "a limit is negative")}, false
	}
	if req.Dir != "" && !IsAbs(r.GOOS, req.Dir) {
		return prepared{res: refuse(res, RefuseNotAbsolute, "the working directory is not absolute")}, false
	}

	// 1. Resolve.
	path := req.Program.Path
	if req.Program.Spec != nil {
		if r.Resolve == nil {
			return prepared{res: refuse(res, RefuseNoExecutor, "the runner has no resolver")}, false
		}
		rs := r.Resolve(*req.Program.Spec)
		res.Verdict = string(rs.Verdict)
		if !resolvableVerdicts[res.Verdict] || rs.Bin == "" {
			return prepared{res: refuse(res, RefuseNotFound, fmt.Sprintf("the program did not resolve to a launchable binary (verdict %s)", rs.Verdict))}, false
		}
		path = rs.Bin
	}

	// 2. Check the executable.
	run, reason, detail := r.checkPath(path, req.Program.AllowSymlink)
	if reason != RefuseNone {
		return prepared{res: refuse(res, reason, "program: "+detail)}, false
	}
	res.Path = run

	// 3. Digests.
	sum, err := r.Hash(run)
	if err != nil {
		return prepared{res: refuse(res, RefuseDigestUnavailable, "the program could not be hashed: "+err.Error())}, false
	}
	res.Digests.Binary = sum
	for _, c := range req.Program.Companions {
		real, reason, detail := r.checkPath(c, req.Program.AllowSymlink)
		if reason != RefuseNone {
			return prepared{res: refuse(res, reason, "companion "+c+": "+detail)}, false
		}
		sum, err := r.Hash(real)
		if err != nil {
			return prepared{res: refuse(res, RefuseDigestUnavailable, "companion "+c+" could not be hashed: "+err.Error())}, false
		}
		if res.Digests.Companions == nil {
			res.Digests.Companions = map[string]string{}
		}
		res.Digests.Companions[c] = sum
	}
	if mm := CompareDigests(req.Expect, res.Digests); len(mm) > 0 {
		res.Mismatches = mm
		return prepared{res: refuse(res, RefuseDigestMismatch, "a digest does not match the expected one")}, false
	}
	envSpec, mkdirs, reason, detail := r.runInputs(req, &res)
	if reason != RefuseNone {
		return prepared{res: refuse(res, reason, detail)}, false
	}

	// 4. Environment.
	env, err := BuildEnv(envSpec, r.GOOS, r.Getenv)
	if err != nil {
		return prepared{res: refuse(res, RefuseEnv, err.Error())}, false
	}
	res.EnvNames = EnvNames(env)

	// 5. Caps.
	res.Caps = PlanCaps(limits, r.Exec.Platform())

	plan := Plan{
		Component: req.Component,
		Path:      run,
		Program:   run,
		Args:      append([]string(nil), req.Args...),
		Env:       env,
		Dir:       req.Dir,
		Stdin:     req.Stdin,
		Limits:    limits,
		MakeDirs:  mkdirs,
	}

	// 6. Isolation.
	switch {
	case r.Isolation != nil:
		wrapped, err := r.Isolation.Wrap(ctx, plan)
		if err != nil {
			return prepared{res: refuse(res, RefuseIsolationFailed, "isolation could not be applied: "+err.Error())}, false
		}
		if !IsAbs(r.GOOS, wrapped.Path) {
			return prepared{res: refuse(res, RefuseIsolationFailed, "the isolation provider returned a launcher that is not an absolute path")}, false
		}
		res.Isolation = r.Isolation.Name()
		res.Launcher = wrapped.Path
		pidns := WrappedInPIDNamespace(r.Isolation, wrapped)
		plan = wrapped
		plan.Component = req.Component
		plan.Limits = limits
		plan.PIDNamespace = pidns
		plan.Program = run
		plan.MakeDirs = mkdirs
	case req.RequireIsolation:
		return prepared{res: refuse(res, RefuseIsolationRequired, "the request requires isolation and no isolation provider is wired")}, false
	}
	return prepared{plan: plan, res: res}, true
}

// runInputs checks and hashes the companion executables (putting their
// directories on PATH when asked), checks the cache directory and applies
// the engine profile. It returns the environment spec to build, the
// directories the executor must create, and a refusal when one applies.
func (r *Runner) runInputs(req Request, res *Result) (EnvSpec, []string, RefuseReason, string) {
	envSpec := req.Env
	envSpec.Set = append([]string(nil), req.Env.Set...)
	envSpec.PathDirs = append([]string(nil), req.Env.PathDirs...)
	for _, ce := range req.Program.CompanionExecs {
		real, reason, detail := r.checkPath(ce.Path, req.Program.AllowSymlink)
		if reason != RefuseNone {
			return envSpec, nil, reason, "companion executable " + ce.Path + ": " + detail
		}
		sum, err := r.Hash(real)
		if err != nil {
			return envSpec, nil, RefuseDigestUnavailable, "companion executable " + ce.Path + " could not be hashed: " + err.Error()
		}
		if res.Digests.Companions == nil {
			res.Digests.Companions = map[string]string{}
		}
		res.Digests.Companions[ce.Path] = sum
		res.Toolchain = append(res.Toolchain, ToolVersion{Path: real, Digest: sum})
		if ce.Expect != "" && ce.Expect != sum {
			res.Mismatches = append(res.Mismatches, Mismatch{Path: ce.Path, Expected: ce.Expect, Actual: sum})
		}
		if d := dirOf(r.GOOS, real); ce.OnPath && d != "" && !containsString(envSpec.PathDirs, d) {
			envSpec.PathDirs = append(envSpec.PathDirs, d)
		}
	}
	if len(res.Mismatches) > 0 {
		return envSpec, nil, RefuseDigestMismatch, "a companion executable's digest does not match the expected one"
	}
	if req.CacheDir != "" && !IsAbs(r.GOOS, req.CacheDir) {
		return envSpec, nil, RefuseNotAbsolute, "the cache directory is not absolute"
	}
	if req.Engine != nil && req.Engine.OwnHome && req.CacheDir == "" {
		return envSpec, nil, RefuseBadRequest, "the engine keeps its own home and cache, so the request needs a cache directory"
	}
	res.CacheDir = req.CacheDir
	if req.Engine != nil {
		res.Engine = req.Engine.Name
	}
	set, mkdirs := engineEnv(r.GOOS, req.Engine, req.CacheDir)
	envSpec.Set = append(envSpec.Set, set...)
	return envSpec, mkdirs, RefuseNone, ""
}

// checkPath inspects one path and walks the check table.
func (r *Runner) checkPath(path string, allowSymlink bool) (string, RefuseReason, string) {
	if !IsAbs(r.GOOS, path) {
		reason, detail, _ := CheckFile(r.GOOS, path, FileFacts{}, allowSymlink)
		return "", reason, detail
	}
	facts, err := r.Inspect(path)
	if err != nil {
		return "", RefuseNotFound, "the path could not be inspected: " + err.Error()
	}
	reason, detail, run := CheckFile(r.GOOS, path, facts, allowSymlink)
	return run, reason, detail
}

// Run runs one request and returns its full record. It never returns an
// error: a refusal or a failure is a Result outcome. Companion executables
// that carry a version probe are asked their version first (each probe is a
// run of its own under the same environment, cached per digest); a probe
// that fails leaves that version empty and does not stop the run.
func (r *Runner) Run(ctx context.Context, req Request) Result {
	p, ok := r.prepare(ctx, req)
	if !ok {
		return p.res
	}
	for i, ce := range req.Program.CompanionExecs {
		if ce.Version == nil || i >= len(p.res.Toolchain) {
			continue
		}
		probe := Request{
			Component: req.Component,
			Program:   Program{Path: ce.Path, AllowSymlink: req.Program.AllowSymlink},
			Expect:    &Digests{Binary: p.res.Toolchain[i].Digest},
			// The probe sees the run's own environment; PATH goes back
			// through PathDirs (BuildEnv refuses it in Set).
			Env: splitPath(r.GOOS, p.plan.Env),
			Dir: req.Dir,
		}
		v, _ := r.ProbeVersion(ctx, probe, *ce.Version)
		p.res.Toolchain[i].Version = v.Version
	}
	res := r.execute(ctx, p)
	res.ExitMeaning = ClassifyExit(req.Engine, res.Outcome, res.ExitCode)
	return res
}

// splitPath turns a built environment back into an EnvSpec: every entry
// but PATH as Set, PATH as PathDirs.
func splitPath(goos string, env []string) EnvSpec {
	sep := ":"
	if goos == "windows" {
		sep = ";"
	}
	var spec EnvSpec
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			if v != "" {
				spec.PathDirs = strings.Split(v, sep)
			}
			continue
		}
		spec.Set = append(spec.Set, kv)
	}
	return spec
}

// containsString reports whether list holds s.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// execute runs a prepared request through the Executor and classifies it.
func (r *Runner) execute(ctx context.Context, p prepared) Result {
	res := p.res
	facts := r.Exec.Exec(ctx, p.plan)
	res.Outcome = Classify(facts)
	if facts.StartErr != "" {
		res.Detail = "the program could not be started: " + facts.StartErr
	}
	res.ExitCode = facts.ExitCode
	res.Signal = facts.Signal
	res.Stdout = facts.Stdout
	res.Stderr = facts.Stderr
	res.StdoutTruncated = facts.StdoutTruncated
	res.StderrTruncated = facts.StderrTruncated
	res.Duration = facts.Duration
	res.PeakChildren = facts.PeakChildren
	res.Leftover = facts.Leftover
	res.Caps = applyApplied(res.Caps, facts.Applied)
	res.Trampoline = facts.Trampoline
	res.Containment = facts.Containment
	if res.Containment.Rung != "" {
		res.Containment.Contained, res.Containment.Label = ContainmentLabel(res.Containment)
	}
	return res
}
