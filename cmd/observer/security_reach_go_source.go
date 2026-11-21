//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_reach_go && !sbo_omit_security_scan_osv

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachgo"
	"github.com/marmutapp/superbased-observer/internal/secreachsvc"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvscanner"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// security_reach_go_source.go is the cmd seam of the Go source check, 3b-src
// (OS and CI vulnerability scanning plan section 14.5 item 3b, spike RG-0
// "Answer" item 2, component security.reach.go): osv-scanner with Go call
// analysis (--call-analysis=go --offline -L <go.mod>), ONE process per
// go.mod, never -r. It runs the project's own Go toolchain (go list, cgo and
// the C compiler for a cgo package) on project input, so:
//
//   - it runs only when the developer starts it (`observer security scan
//     --reach go-source`, or the Scanners card's button), never from the
//     daemon loop;
//   - it needs the project's signed opt-in (secreachsvc.ReadSourceOptIn),
//     which only the developer gives (guard rule R-165: the verbs, the
//     route and the record);
//   - it runs inside the isolation component's one-shot no-network run;
//     where that is not available it is refused, unless the developer's
//     override is on the opt-in or the run's --allow-unisolated flag
//     (R-165 too); such a run is labelled "not isolated";
//   - GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly GOWORK=off, its
//     own HOME, GOCACHE and telemetry directory (osvscanner.SourceEnv);
//   - the memory cap is the developer's ([security.reach.go]
//     source_memory_mib, default 12 GiB) with GOMEMLIMIT at 90 % of it.
//
// Each go.mod's answer is read by internal/secreachgo (Observer's own
// table, never osv-scanner's reading as is) and stored in the same reach
// record as 3b-bin (secreachsvc.ReplaceSymbolRuns, source
// govulncheck-source, the go.mod as Target), so it applies only to the
// findings from that go.mod.

// reachSourceCompiled reports that this build carries the Go source check.
const reachSourceCompiled = true

// goToolSpec is how the Go toolchain is found: the developer's own install,
// never a shim.
var goToolSpec = integration.BinaryResolveSpec{
	Names: integration.BinaryNames{Unix: []string{"go"}, Windows: []string{"go.exe"}},
}

// reachSourceCDirs are the C compiler's usual directories put on the run's
// PATH after GOROOT/bin (a cgo package runs cgo and gcc), each only when it
// exists.
var reachSourceCDirs = []string{"/usr/local/bin", "/usr/bin", "/bin"}

// reachSourceHooks are the run's host seams; a test swaps them.
var reachSourceHooks = struct {
	// newRunner builds the runner of one run, over the isolation provider
	// (nil: unisolated).
	newRunner func(extrun.IsolationProvider) *extrun.Runner
	// isolation returns the isolation factory (nil: none in this build or
	// on this OS) and whether the host has a provider at all.
	isolation func(e *depsScanEnv) (extrun.IsolationFactory, bool)
	// goRoot reads a resolved go binary's GOROOT and Go release.
	goRoot func(goBin string) (root, version string, ok bool)
	// modCache is the developer's module cache directory.
	modCache func() string
}{
	newRunner: func(p extrun.IsolationProvider) *extrun.Runner {
		return extrunhost.NewRunner(extrunhost.Options{Isolation: p})
	},
	isolation: func(e *depsScanEnv) (extrun.IsolationFactory, bool) {
		f := isolationFactoryFor(componentSnapshotForConfig(e.cfg), filepath.Dir(e.dir), nil)
		return f, f != nil && scanIsolationAvailable()
	},
	goRoot:   goRootOf,
	modCache: goModCacheDir,
}

// goRootOf reads the GOROOT of a go binary from its own layout, without
// running it: <GOROOT>/bin/go, with src/runtime beside it; the release is
// GOROOT/VERSION's first line.
func goRootOf(goBin string) (string, string, bool) {
	real, err := filepath.EvalSymlinks(goBin)
	if err != nil {
		return "", "", false
	}
	root := filepath.Dir(filepath.Dir(real))
	if fi, err := os.Stat(filepath.Join(root, "src", "runtime")); err != nil || !fi.IsDir() {
		return "", "", false
	}
	version := ""
	if f, err := os.Open(filepath.Join(root, "VERSION")); err == nil {
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			version = strings.TrimSpace(sc.Text())
		}
		_ = f.Close()
	}
	if len(version) > 32 {
		version = ""
	}
	return root, version, true
}

// goModCacheDir is the module cache the go command would use: GOMODCACHE,
// else the first GOPATH entry's pkg/mod, else ~/go/pkg/mod.
func goModCacheDir() string {
	if v := os.Getenv("GOMODCACHE"); v != "" && filepath.IsAbs(v) {
		return filepath.Clean(v)
	}
	if v := os.Getenv("GOPATH"); v != "" {
		if first := filepath.SplitList(v)[0]; filepath.IsAbs(first) {
			return filepath.Join(first, "pkg", "mod")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

// resolveBin resolves a spec through the runner's resolver (toolresolve,
// shims excluded).
func resolveBin(r *extrun.Runner, spec integration.BinaryResolveSpec) (string, bool) {
	if r == nil || r.Resolve == nil {
		return "", false
	}
	res := r.Resolve(spec)
	switch res.Verdict {
	case toolresolve.VerdictOK, toolresolve.VerdictOKOffPath, toolresolve.VerdictShadowed:
		return res.Bin, res.Bin != ""
	}
	return "", false
}

// The refusals of a source check that never started.
var (
	errReachSourceNotSelected = fmt.Errorf("the %s component is not selected: add it under [components] (observer components status)", reachGoComponent)
	errReachSourceNotOptedIn  = errors.New("this project is not opted in to the Go source check: you run `observer security scan reach enable` (or use the Scanners card); an agent cannot")
	errReachSourceNoDatabase  = errors.New("the Go OSV database is not installed: accept and refresh the databases first (`observer security scan db accept`, `observer security scan --refresh-db`)")
	errReachSourceNoScanner   = errors.New("osv-scanner is not installed: the Go source check runs osv-scanner's call analysis (`observer security scan install-osv-scanner` shows how to install it)")
)

// reachSourceIsolationRefusal is the refusal of a run with no isolation
// provider and no override.
const reachSourceIsolationRefusal = "the isolation component's no-network run is not available here (it needs the isolation component and bwrap, Linux only), so the Go source check, which runs this project's Go toolchain on its code, is refused; to run it unisolated anyway, pass --allow-unisolated or turn on \"run without isolation\" on the Scanners card"

// runReachSource is THE run seam of the Go source check.
func (e *depsScanEnv) runReachSource(ctx context.Context, opts reachSourceOptions) (reachSourceReport, error) {
	rep := reachSourceReport{Project: opts.Root}
	if !securitySelected(componentSnapshotForConfig(e.cfg), reachGoComponent) {
		return rep, errReachSourceNotSelected
	}
	realRoot, err := filepath.EvalSymlinks(opts.Root)
	if err != nil {
		return rep, fmt.Errorf("the project root could not be resolved: %w", err)
	}
	hash := secposture.ProjectRootHash(opts.Root)
	optin := secreachsvc.ReadSourceOptIn(e.dir, hash, depsRecordKey(e.dir))
	if !optin.OptedIn() {
		return rep, errReachSourceNotOptedIn
	}
	epochs, err := e.db.Installed()
	if err != nil {
		return rep, err
	}
	if epochs["Go"] == "" {
		return rep, errReachSourceNoDatabase
	}
	probe := reachSourceHooks.newRunner(nil)
	bin, ok := resolveBin(probe, osvscanner.Spec)
	if !ok {
		return rep, errReachSourceNoScanner
	}
	factory, isolated := reachSourceHooks.isolation(e)
	if !isolated && !opts.AllowUnisolated && !optin.UnisolatedAllowed() {
		return rep, errors.New(reachSourceIsolationRefusal)
	}
	rel, truncated := secreachsvc.FindGoMods(os.DirFS(realRoot), secreachsvc.DefaultGoModLimits)
	rep.Truncated = truncated
	cfg := e.cfg.Security.Reach.Go
	limit := cfg.MaxModules()

	release, err := e.acquireDepsScan(ctx, true, opts.OnWait)
	if err != nil {
		return rep, err
	}
	defer release()

	goBin, haveGo := resolveBin(probe, goToolSpec)
	goRoot, goVersion := "", ""
	if haveGo {
		goRoot, goVersion, haveGo = reachSourceHooks.goRoot(goBin)
	}
	rep.Toolchain = goVersion
	var runs []secreach.SymbolRun
	switch {
	case len(rel) == 0:
		rep.Notes = append(rep.Notes, "no go.mod in this project")
	case !haveGo:
		for _, t := range rel {
			runs = append(runs, secreach.SymbolRun{Source: secreach.SourceGovulncheckSource, Target: t, Reason: secreach.ReasonNoToolchain})
		}
	default:
		runs, err = e.reachSourceRunMods(ctx, &rep, reachSourceMods{
			root: realRoot, rel: rel, limit: limit, bin: bin, goBin: goBin, goRoot: goRoot,
			factory: factory, isolated: isolated, cfg: cfg, progress: opts.Progress,
		})
		if err != nil {
			return rep, err
		}
	}
	if err := secreachsvc.ReplaceSymbolRuns(e.dir, hash, secreach.SourceGovulncheckSource, nil, runs, time.Now()); err != nil {
		return rep, err
	}
	rep.Runs = runs
	if rep.Runs == nil {
		rep.Runs = []secreach.SymbolRun{}
	}
	return rep, nil
}

// reachSourceMods is the run list of one check.
type reachSourceMods struct {
	root, bin, goBin, goRoot string
	rel                      []string
	limit                    int
	factory                  extrun.IsolationFactory
	isolated                 bool
	cfg                      config.SecurityReachGoConfig
	progress                 func(string)
}

// reachSourceRunMods prepares the run directory and runs each go.mod.
func (e *depsScanEnv) reachSourceRunMods(ctx context.Context, rep *reachSourceReport, m reachSourceMods) ([]secreach.SymbolRun, error) {
	base, err := depsScanCacheRoot()
	if err != nil {
		return nil, err
	}
	runsDir := filepath.Join(base, "runs")
	if err := os.MkdirAll(runsDir, 0o700); err != nil {
		return nil, err
	}
	tmpRoot, err := os.MkdirTemp(runsDir, "reach-src-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpRoot) }()
	runRoot, err := filepath.EvalSymlinks(tmpRoot)
	if err != nil {
		return nil, err
	}
	db, etc, out, cache := filepath.Join(runRoot, "db"), filepath.Join(runRoot, "etc"), filepath.Join(runRoot, "out"), filepath.Join(runRoot, "cache")
	dirs := []string{db, etc, out, cache}
	for _, d := range osvscanner.SourceCacheDirs {
		dirs = append(dirs, filepath.Join(cache, d))
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	// osv-scanner v2.6 reads <dir>/osv-scalibr/<eco>/all.zip (osv-scalibr's
	// osvlocal matcher, live-checked 2026-11-05), the layout LinkInto makes.
	if err := e.db.LinkInto(db, []string{"Go"}); err != nil {
		return nil, fmt.Errorf("the Go OSV database could not be linked outside ~/.observer: %w", err)
	}
	cfgFile := filepath.Join(etc, osvscanner.ConfigFile)
	if err := os.WriteFile(cfgFile, []byte("# Observer's own osv-scanner config: empty, so a repository's osv-scanner.toml is never read.\n"), 0o600); err != nil {
		return nil, err
	}
	modCache := reachSourceHooks.modCache()
	if r, err := resolveThroughLinks(modCache); err == nil {
		modCache = r
	}
	var cdirs []string
	for _, d := range reachSourceCDirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() && d != filepath.Join(m.goRoot, "bin") {
			cdirs = append(cdirs, d)
		}
	}
	var prov extrun.IsolationProvider
	rep.Isolation = "not isolated"
	if m.isolated {
		p, err := m.factory(extrun.OneShotDirs{Project: m.root, Output: out, Cache: cache, ProgramDirs: []string{db, etc, m.goRoot, modCache}})
		switch {
		case err != nil && isolationMissingOnHost(err):
			return nil, errors.New(reachSourceIsolationRefusal)
		case err != nil:
			return nil, fmt.Errorf("the isolated run could not be prepared: %w", err)
		}
		prov, rep.Isolation = p, p.Name()
	}
	runner := reachSourceHooks.newRunner(prov)
	sep := string(filepath.Separator)
	var runs []secreach.SymbolRun
	for i, t := range m.rel {
		if i >= m.limit {
			runs = append(runs, secreach.SymbolRun{Source: secreach.SourceGovulncheckSource, Target: t, Reason: secreach.ReasonModuleCap})
			continue
		}
		if m.progress != nil {
			m.progress(t)
		}
		req := osvscanner.SourceRequest(osvscanner.SourceInput{
			Bin: m.bin, GoBin: m.goBin, GoRoot: m.goRoot, Root: m.root, GoMod: filepath.Join(m.root, filepath.FromSlash(t)),
			DBDir: db, ConfigFile: cfgFile, CacheDir: cache, ModCache: modCache, PathDirs: cdirs,
			MemoryBytes: m.cfg.MemoryBytes(), Wall: m.cfg.Timeout(), Sep: sep,
		})
		req.RequireIsolation = m.isolated
		if i == 0 {
			v, _ := runner.ProbeVersion(ctx, req, osvscanner.VersionProbe())
			rep.Engine = v.Version
			if osvscanner.Verdict(v.Version) == osvscanner.VersionRefused {
				return nil, errors.New("osv-scanner's version could not be read or is older than " + depscan.OSVScannerMinVersion + ": nothing was run")
			}
		}
		res := runner.Run(ctx, req)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if res.Outcome == extrun.OutcomeRefused {
			return nil, fmt.Errorf("the run was refused (%s): %s", res.Reason, res.Detail)
		}
		for _, c := range res.Caps {
			if c.Cap == extrun.CapMemory && rep.MemoryCap == "" {
				rep.MemoryCap = string(c.State)
				if c.Mechanism != "" {
					rep.MemoryCap += " (" + c.Mechanism + ")"
				}
			}
		}
		runs = append(runs, reachSourceAnswer(e.db.Dir(), t, res))
	}
	return runs, nil
}

// reachSourceAnswer reads one go.mod run into its stored answer.
func reachSourceAnswer(dbDir, target string, res extrun.Result) secreach.SymbolRun {
	run := secreach.SymbolRun{Source: secreach.SourceGovulncheckSource, Target: target}
	facts := secreachgo.RunFacts{
		TimedOut: res.Outcome == extrun.OutcomeTimeout,
		Killed:   res.Outcome == extrun.OutcomeSignaled,
		Capped:   res.Outcome == extrun.OutcomeOutputCap || res.Outcome == extrun.OutcomeChildrenCap || res.StdoutTruncated,
		Exited:   res.ExitMeaning == extrun.ExitClean || res.ExitMeaning == extrun.ExitFindings || res.ExitMeaning == extrun.ExitNoInput,
		Stderr:   string(res.Stderr),
	}
	if run.Reason = secreachgo.ClassifyRun(facts); run.Reason != "" {
		return run
	}
	if res.ExitMeaning == extrun.ExitNoInput {
		return run
	}
	groups, err := secreachgo.ParseScannerOutput(res.Stdout)
	if err != nil {
		run.Reason = secreach.ReasonSymbolCheckFailed
		return run
	}
	ids := secreachgo.GoModIDs(groups)
	if len(ids) > osvdb.MaxExportRecords {
		ids = ids[:osvdb.MaxExportRecords]
	}
	raw, err := osvdb.ExportRecords(dbDir, "Go", ids)
	if err != nil {
		run.Reason = secreach.ReasonSymbolCheckFailed
		return run
	}
	recs := make(map[string]secreachgo.RecordImports, len(raw))
	for id, b := range raw {
		if r, err := secreachgo.ParseRecord(b); err == nil {
			recs[id] = r
		}
	}
	run.Records = secreachgo.SourceVerdicts(secreachgo.SourceInput{Groups: groups, Records: recs})
	return run
}

// reachSourceIsolationAvailable reports whether this host can run the check
// isolated (for the status and the card).
func reachSourceIsolationAvailable(e *depsScanEnv) bool {
	_, ok := reachSourceHooks.isolation(e)
	return ok && runtime.GOOS == "linux"
}
