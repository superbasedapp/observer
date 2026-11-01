//go:build !sbo_omit_security

package seccustomsvc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seccustom"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// RunReport is what one driver run did, for the CLI, the Scanners tab and
// the sec_scan_runs record.
type RunReport struct {
	Driver  string            `json:"driver"`
	Verdict seccustom.Verdict `json:"verdict"`
	// Findings kept, results refused, targets skipped.
	Findings       int  `json:"findings"`
	Refused        int  `json:"refused"`
	Truncated      bool `json:"truncated,omitempty"`
	SkippedTargets int  `json:"skipped_targets,omitempty"`
	// Closed counts the driver's own earlier findings this run closed.
	Closed int `json:"closed"`
	// Isolation is the isolation provider that held the run, "" when it
	// ran unisolated; NotIsolatedWhy says why.
	Isolation      string `json:"isolation,omitempty"`
	NotIsolatedWhy string `json:"not_isolated_why,omitempty"`
	// Network says, for a manifest with declared hosts, that the hosts are
	// not enforced (seccustom.NetworkWords); "" for network none.
	Network string `json:"network,omitempty"`
	// ToolchainSkew says why the run is never complete when the scanner is
	// a Go program built with an older Go release than its go companion
	// (seccustom.CheckToolchainSkew); "" otherwise.
	ToolchainSkew string `json:"toolchain_skew,omitempty"`
	// Containment is the rung of the runner's containment table that held
	// the run (and its label: "not contained" on the third rung).
	Containment extrun.Containment      `json:"containment"`
	RunnerOut   extrun.Outcome          `json:"runner_outcome"`
	Detail      string                  `json:"detail,omitempty"`
	ExitCode    int                     `json:"exit_code"`
	ExitMeaning extrun.ExitMeaning      `json:"exit_meaning,omitempty"`
	Toolchain   []extrun.ToolVersion    `json:"toolchain,omitempty"`
	Caps        []extrun.CapResult      `json:"caps,omitempty"`
	Org         seccustom.OrgDecision   `json:"org"`
	Pin         seccustom.PinScope      `json:"pin"`
	SelfTest    seccustom.SelfTestState `json:"self_test"`
	Duration    time.Duration           `json:"duration"`
}

// execResult is one runner pass and what the strict adapter made of it.
type execResult struct {
	res            extrun.Result
	adapted        seccustom.Adapted
	noSARIF        bool
	skippedTargets int
	notIsolatedWhy string
	org            seccustom.OrgDecision
}

// Run scans projectRoot with driver id: the run is refused when the org
// forbids it, the digests are re-checked by the runner immediately before
// it starts, a stale self-test is re-run first, and the outcome is
// recorded. Runs are one at a time per machine.
func (s *Service) Run(ctx context.Context, id, projectRoot string, scope secfinding.Scope) (RunReport, error) {
	if !filepath.IsAbs(projectRoot) {
		return RunReport{}, errors.New("the project root is not absolute")
	}
	runMu.Lock()
	defer runMu.Unlock()
	rec, err := s.loadChecked(ctx, id)
	if err != nil {
		return RunReport{}, err
	}
	started := s.o.Now()
	rep := RunReport{Driver: rec.Driver(), Pin: rec.Pin}
	x, err := s.exec(ctx, rec, projectRoot, []string{projectRoot}, scope)
	if err != nil {
		return rep, err
	}
	digests, versions := toolchainMaps(x.res)
	skew := seccustom.CheckToolchainSkew(goBuildVersion(rec.Manifest.Executable), rec.Manifest, versions)
	current := rec.SelfTest.Current(x.res.Digests.Binary, digests, versions)
	if !current && rec.Manifest.SelfTest != nil && x.res.Outcome != extrun.OutcomeRefused {
		// A digest or companion version changed since the last self-test
		// (or it never ran): run it now, then judge this run.
		if st, err := s.selfTestLocked(ctx, &rec); err == nil {
			current = st.Current(x.res.Digests.Binary, digests, versions)
		}
	}
	facts := seccustom.RunFacts{
		Runner: x.res.Outcome, Refuse: x.res.Reason, Exit: x.res.ExitMeaning, NoSARIF: x.noSARIF,
		Findings: len(x.adapted.Findings), Refused: len(x.adapted.Refused), Truncated: x.adapted.Truncated,
		UnknownMarker:   seccustom.StderrMarksUnknown(rec.Manifest, x.res.Stderr),
		SelfTestCurrent: current,
		ToolchainSkew:   skew.Skewed,
	}
	rep.Verdict = seccustom.Classify(facts)
	rep.Findings, rep.Refused, rep.Truncated = facts.Findings, facts.Refused, facts.Truncated
	rep.SkippedTargets = x.skippedTargets
	rep.Isolation, rep.NotIsolatedWhy = x.res.Isolation, x.notIsolatedWhy
	rep.Network = seccustom.NetworkWords(rec.Manifest.Network)
	rep.ToolchainSkew = skew.Detail
	rep.Containment, rep.RunnerOut, rep.Detail = x.res.Containment, x.res.Outcome, x.res.Detail
	rep.ExitCode, rep.ExitMeaning = x.res.ExitCode, x.res.ExitMeaning
	rep.Toolchain, rep.Caps, rep.Org, rep.SelfTest = x.res.Toolchain, x.res.Caps, x.org, rec.SelfTest
	rep.Duration = s.o.Now().Sub(started)
	if s.o.Store != nil {
		if err := s.record(ctx, rec, projectRoot, scope, facts, x, &rep, started); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// exec runs one pass of rec over targets in projectRoot (isolated when the
// isolation component can hold it) and adapts its SARIF.
func (s *Service) exec(ctx context.Context, rec seccustom.Record, projectRoot string, targets []string, scope secfinding.Scope) (execResult, error) {
	var x execResult
	if s.o.NewRunner == nil {
		return x, errors.New("the runner is not wired")
	}
	if s.o.CacheRoot == "" || !filepath.IsAbs(s.o.CacheRoot) {
		return x, errors.New("no cache directory outside ~/.observer is configured")
	}
	runsDir := filepath.Join(s.o.CacheRoot, "runs")
	if err := os.MkdirAll(runsDir, 0o700); err != nil {
		return x, fmt.Errorf("seccustomsvc: %w", err)
	}
	runRoot, err := os.MkdirTemp(runsDir, rec.ID+"-")
	if err != nil {
		return x, fmt.Errorf("seccustomsvc: %w", err)
	}
	defer func() { _ = os.RemoveAll(runRoot) }()
	dirs := seccustom.RunDirs{Project: projectRoot, Output: filepath.Join(runRoot, "out"), Cache: filepath.Join(runRoot, "cache")}
	if rec.Manifest.Cache == seccustom.CachePerDriver {
		dirs.Cache = filepath.Join(s.o.CacheRoot, "drivers", rec.ID)
	}
	spec, err := seccustom.BuildRun(goos(), rec, dirs, targets)
	if err != nil {
		return x, err
	}
	x.skippedTargets = spec.SkippedTargets
	for _, d := range []string{dirs.Output, dirs.Cache, seccustom.HomeDir(goos(), dirs)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return x, fmt.Errorf("seccustomsvc: %w", err)
		}
	}
	if rec.Manifest.Input == seccustom.InputTargetsFile {
		if err := os.WriteFile(spec.TargetsFile, spec.TargetsBody, 0o600); err != nil {
			return x, fmt.Errorf("seccustomsvc: %w", err)
		}
	}
	var prov extrun.IsolationProvider
	switch {
	case !spec.Isolable:
		x.notIsolatedWhy = "the manifest declares network hosts, which are not enforced, and the isolated run has no network"
	case s.o.Isolation == nil:
		x.notIsolatedWhy = "the isolation component is not active in this build or on this host"
	default:
		p, err := s.o.Isolation(spec.OneShot)
		if err != nil {
			x.notIsolatedWhy = "the isolated run could not be prepared: " + err.Error()
		} else {
			prov = p
		}
	}
	pol, managed := s.org(ctx)
	x.org = seccustom.DecideOrg(pol, seccustom.OrgFacts{Managed: managed, Isolated: prov != nil}, rec)
	if !x.org.Run {
		return x, fmt.Errorf("the org's policy does not allow this scanner here (%s)", x.org.Reason)
	}
	x.res = s.o.NewRunner(prov).Run(ctx, spec.Request)
	if prov != nil && x.res.Isolation == "" && x.notIsolatedWhy == "" {
		x.notIsolatedWhy = "the run was not wrapped"
	}
	var raw []byte
	switch rec.Manifest.Output {
	case seccustom.OutputSARIFStdout:
		raw = x.res.Stdout
	default:
		raw, err = readCapped(spec.OutputFile, sarif.MaxBytes)
		if err != nil {
			raw = nil
		}
	}
	log, err := sarif.Decode(raw)
	x.noSARIF = len(raw) == 0 || err != nil
	if !x.noSARIF {
		x.adapted = seccustom.Adapt(seccustom.AdaptInput{
			Record: rec, ProjectRoot: projectRoot, ProjectRootHash: secposture.ProjectRootHash(projectRoot),
			Scope: scope, BlockingAllowed: x.org.BlockingRule,
		}, log)
	}
	return x, nil
}

// toolchainMaps returns the companion digests and versions a run recorded.
func toolchainMaps(res extrun.Result) (digests, versions map[string]string) {
	digests, versions = map[string]string{}, map[string]string{}
	for _, t := range res.Toolchain {
		digests[t.Path] = t.Digest
		versions[t.Path] = t.Version
	}
	return digests, versions
}

// SelfTest runs the driver's self-test now and stores the result.
func (s *Service) SelfTest(ctx context.Context, id string) (seccustom.SelfTestState, error) {
	runMu.Lock()
	defer runMu.Unlock()
	rec, err := s.loadChecked(ctx, id)
	if err != nil {
		return seccustom.SelfTestState{}, err
	}
	return s.selfTestLocked(ctx, &rec)
}

// selfTestLocked runs the self-test fixture through the same pass as a
// scan (the planted project copied into a fresh directory outside
// ~/.observer), checks the expected rules, and saves the state on the
// record. A driver with no self-test reports Ran=false: its runs are never
// clean.
func (s *Service) selfTestLocked(ctx context.Context, rec *seccustom.Record) (seccustom.SelfTestState, error) {
	st := rec.Manifest.SelfTest
	if st == nil {
		return seccustom.SelfTestState{}, errors.New("this scanner has no self-test, so its runs are never clean")
	}
	files, paths, ok := seccustom.FixtureFiles(st.Fixture)
	if !ok {
		return seccustom.SelfTestState{}, fmt.Errorf("the self-test fixture %s is missing", st.Fixture)
	}
	if err := os.MkdirAll(s.o.CacheRoot, 0o700); err != nil {
		return seccustom.SelfTestState{}, fmt.Errorf("seccustomsvc: %w", err)
	}
	proj, err := os.MkdirTemp(s.o.CacheRoot, "selftest-")
	if err != nil {
		return seccustom.SelfTestState{}, fmt.Errorf("seccustomsvc: %w", err)
	}
	defer func() { _ = os.RemoveAll(proj) }()
	for _, p := range paths {
		dst := filepath.Join(proj, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return seccustom.SelfTestState{}, err
		}
		if err := os.WriteFile(dst, files[p], 0o600); err != nil {
			return seccustom.SelfTestState{}, err
		}
	}
	x, err := s.exec(ctx, *rec, proj, seccustom.SelfTestTargets(goos(), proj, files), policy.FindingScopeManual)
	if err != nil {
		return seccustom.SelfTestState{}, err
	}
	digests, versions := toolchainMaps(x.res)
	v := seccustom.Classify(seccustom.RunFacts{
		Runner: x.res.Outcome, Refuse: x.res.Reason, Exit: x.res.ExitMeaning, NoSARIF: x.noSARIF,
		Findings: len(x.adapted.Findings), SelfTestCurrent: true,
	})
	check := seccustom.CheckSelfTest(st, v, x.adapted.Findings)
	state := seccustom.SelfTestState{
		Ran: true, Passed: check.Passed, At: s.o.Now().UTC(), BinaryDigest: x.res.Digests.Binary,
		Companions: digests, Versions: versions, Missing: check.Missing,
	}
	if !check.Passed {
		state.Detail = fmt.Sprintf("the self-test run was %s (%s)", v.Outcome, v.Reason)
		if len(check.Missing) > 0 {
			state.Detail = "the self-test did not report every planted finding"
		}
	}
	s.recMu.Lock()
	rec.SelfTest = state
	err = s.o.Layout.save(*rec)
	s.recMu.Unlock()
	if err != nil {
		return state, err
	}
	_ = s.o.Layout.appendAudit(AuditEntry{
		At: state.At, Action: AuditSelfTest, ID: rec.ID, ManifestSHA256: rec.ManifestSHA256,
		ExecutableSHA256: state.BinaryDigest, Detail: fmt.Sprintf("passed=%v missing=%v", state.Passed, state.Missing),
	})
	return state, nil
}

// scanRunEngine is the engine block of the sec_scan_runs row: which
// engine ran, how it was held, and what the org decided.
type scanRunEngine struct {
	Driver         string                `json:"driver"`
	Version        string                `json:"version"`
	Digest         string                `json:"digest"`
	Pin            seccustom.PinScope    `json:"pin"`
	Isolation      string                `json:"isolation"`
	NotIsolatedWhy string                `json:"not_isolated_why,omitempty"`
	Network        string                `json:"network,omitempty"`
	ToolchainSkew  string                `json:"toolchain_skew,omitempty"`
	Containment    extrun.Containment    `json:"containment"`
	Caps           []extrun.CapResult    `json:"caps,omitempty"`
	Toolchain      []extrun.ToolVersion  `json:"toolchain,omitempty"`
	Trampoline     bool                  `json:"trampoline"`
	Runner         extrun.Outcome        `json:"runner_outcome"`
	ExitCode       int                   `json:"exit_code"`
	ExitMeaning    extrun.ExitMeaning    `json:"exit_meaning,omitempty"`
	Org            seccustom.OrgDecision `json:"org"`
}

// scanRunCoverage is the coverage block of the row.
type scanRunCoverage struct {
	Outcome        secscan.Outcome `json:"outcome"`
	Reason         string          `json:"reason,omitempty"`
	Files          int             `json:"files"`
	Refused        int             `json:"refused"`
	Truncated      bool            `json:"truncated,omitempty"`
	SkippedTargets int             `json:"skipped_targets,omitempty"`
	SelfTest       bool            `json:"self_test_current"`
}

// record writes the findings, closes the driver's own missing findings
// when the run was complete, and inserts the scan-run row.
func (s *Service) record(ctx context.Context, rec seccustom.Record, projectRoot string, scope secfinding.Scope, facts seccustom.RunFacts, x execResult, rep *RunReport, started time.Time) error {
	now := s.o.Now()
	hash := secposture.ProjectRootHash(projectRoot)
	seen := map[string]bool{}
	for _, f := range x.adapted.Findings {
		if _, _, err := s.o.Store.UpsertSecFinding(ctx, f, now); err != nil {
			return err
		}
		seen[f.LocalKey] = true
	}
	if seccustom.CanCloseMissing(facts, rep.Verdict) {
		open, err := s.o.Store.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Limit: 1000})
		if err != nil {
			return err
		}
		for _, f := range open {
			// Only this driver's own findings: a custom driver never
			// closes a native or another driver's finding.
			if f.Engine.Driver != rec.Driver() || seen[f.LocalKey] {
				continue
			}
			// Hold-aware (lane sec-gate4 milestone 1c): a finding an
			// unpushed commit holds, or one that reached a remote, stays
			// open.
			closed, err := s.o.Store.CloseSecFindingNotReproduced(ctx, f.ID, now)
			if err != nil {
				return err
			}
			if closed {
				rep.Closed++
			}
		}
	}
	res := x.res
	return s.o.Store.InsertSecScanRun(ctx, store.SecScanRun{
		ProjectRootHash: hash, Driver: rec.Driver(), Scope: scope,
		Target: map[string]any{"targets": 1, "skipped": x.skippedTargets},
		Coverage: scanRunCoverage{
			Outcome: rep.Verdict.Outcome, Reason: rep.Verdict.Reason, Files: x.adapted.Files, Refused: facts.Refused,
			Truncated: facts.Truncated, SkippedTargets: x.skippedTargets, SelfTest: facts.SelfTestCurrent,
		},
		Engine: scanRunEngine{
			Driver: rec.Driver(), Version: rec.Manifest.Version, Digest: res.Digests.Binary, Pin: rec.Pin,
			Isolation: res.Isolation, NotIsolatedWhy: x.notIsolatedWhy, Network: rep.Network, ToolchainSkew: rep.ToolchainSkew, Containment: res.Containment, Caps: res.Caps,
			Toolchain: res.Toolchain, Trampoline: res.Trampoline, Runner: res.Outcome, ExitCode: res.ExitCode, ExitMeaning: res.ExitMeaning, Org: x.org,
		},
		Outcome: string(rep.Verdict.Outcome), Findings: facts.Findings, StartedAt: started, Duration: res.Duration,
	})
}
