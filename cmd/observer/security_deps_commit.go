//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_deps_commit.go is S-747 at commit and in the quick scan (lane
// SEC-D1FIX2 milestone 2f): the quick scan and the commit scanner hand the
// install gate the parsed diff of every changed manifest
// (secquickscan.Engine.Retain, the commit-step seam), and the dependencies
// a commit adds that the gate flags are recorded as findings of rule
// deps.s-747. They are flag-only (medium confidence, so never in the
// commit gate's blocking set), like S-747 on a manifest edit. Only the
// offline index and the online-answer cache decide here: nothing is asked
// online from a commit.

// depsActiveConfig is the config path of the running install gate (set by
// the ask loop while it runs); nil while security.deps does not run, and
// then nothing is recorded.
var depsActiveConfig atomic.Pointer[string]

// depsRetainPath reports a manifest the install gate reads.
func depsRetainPath(p string) bool {
	_, ok := secfeed.IsManifest(p)
	return ok
}

// depsCommitRule is the finding rule id of S-747 at commit.
const depsCommitRule = "deps.s-747"

// depsCommitDriver is the driver S-747 at commit records its findings and
// runs under (lane SEC-DEPS3 item 8): its own, so a run closes only its own
// findings, and a diff run (store.SecDiffDriverPrefix), so it never moves
// the project's last working-tree scan (store.SecLastScan).
const depsCommitDriver = store.SecDiffDriverPrefix + depsCommitRule

// depsCommitFlagged are the verdicts S-747 records at commit, with the
// finding's category and severity: a registry "not found" only (an index
// that cannot vouch is the index's state, never a finding per commit).
var depsCommitFlagged = map[policy.InstallVerdict]struct {
	cat policy.FindingCategory
	sev policy.FindingSeverity
}{
	policy.InstallMalicious:     {policy.FindingMaliciousPackage, policy.FindingSeverityHigh},
	policy.InstallListedVersion: {policy.FindingMaliciousPackage, policy.FindingSeverityMedium},
	policy.InstallNearMiss:      {policy.FindingMaliciousPackage, policy.FindingSeverityMedium},
	policy.InstallTooNew:        {policy.FindingProvenance, policy.FindingSeverityLow},
	policy.InstallUnknownName:   {policy.FindingHallucinatedPackage, policy.FindingSeverityMedium},
}

// recordDepsManifests records the flagged dependencies the diffs add, and
// closes, for the security.deps pack and this driver only, what the diffs
// prove gone: a dependency a manifest's diff removes (and does not add
// back), one it adds that the gate now answers known good, and every
// finding of a deleted manifest (lane SEC-DEPS3 item 8).
func recordDepsManifests(ctx context.Context, st *store.Store, root, sha string, scope policy.FindingScope, diffs []secdiffobs.FileDiff, logger *slog.Logger) {
	cfgPath := depsActiveConfig.Load()
	if cfgPath == nil || st == nil || root == "" || len(diffs) == 0 {
		return
	}
	run, ok := depsManifestRun(*cfgPath, root, sha, scope, diffs, time.Now())
	if !ok || (len(run.Findings) == 0 && len(run.Gone.Paths) == 0 && len(run.Gone.Removed) == 0) {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	cov := secscan.Coverage{Outcome: secscan.OutcomeClean, FilesScanned: len(diffs)}
	if len(run.Findings) > 0 {
		cov.Outcome = secscan.OutcomeFindings
	}
	res := secscan.Result{Findings: run.Findings, Coverage: cov, Engine: secscan.EngineIdentity{Name: depsCommitDriver, RulePackVersion: secrules.PackVersion}}
	if _, err := secsvc.RecordRun(ctx, st, secscan.Target{ProjectRoot: root, Scope: scope}, res, time.Now(), 0, run.Gone, securityRT.notify); err != nil {
		noteRecordFailure(ctx)
		logger.Warn("security: package findings not recorded", "scope", scope, "err", err)
	}
}

// depsManifestResult is one commit's (or staged change's) S-747 answer:
// the flagged findings and what the diffs prove gone.
type depsManifestResult struct {
	Findings []secfinding.Finding
	Gone     secsvc.Gone
}

// depsManifestFindings returns the flagged findings of depsManifestRun.
func depsManifestFindings(configPath, root, sha string, scope policy.FindingScope, diffs []secdiffobs.FileDiff, now time.Time) []secfinding.Finding {
	run, _ := depsManifestRun(configPath, root, sha, scope, diffs, now)
	return run.Findings
}

// depsManifestRun decides the dependencies each diff adds through the
// gate (offline index and cache, the project's classifier) and returns the
// flagged ones as findings, with what the diffs prove gone. ok is false
// when the gate is not set up here, and then nothing is decided or closed.
func depsManifestRun(configPath, root, sha string, scope policy.FindingScope, diffs []secdiffobs.FileDiff, now time.Time) (depsManifestResult, bool) {
	resolved := depsConfigPath(configPath)
	if resolved == "" {
		return depsManifestResult{}, false
	}
	cs := depsContentStore(resolved)
	if depsNotSetUp(cs, secposture.LayoutFor(resolved).Dir) {
		return depsManifestResult{}, false
	}
	ix, fresh := loadInstallIndexCached(cs, depsTrust())
	var cache secfeed.CacheLookup
	if b, err := readDepsFile(filepath.Join(secposture.LayoutFor(resolved).Dir, depsCacheFile), secfeed.MaxCacheFileBytes); err == nil {
		if c, err := secfeed.DecodeCacheFile(b, now); err == nil {
			cache = c.Lookup
		}
	}
	rootHash := secposture.ProjectRootHash(root)
	out := depsManifestResult{Gone: secsvc.Gone{Pack: securityDepsComponent}}
	for _, d := range diffs {
		if d.Deleted {
			out.Gone.Paths = append(out.Gone.Paths, d.Path)
			continue
		}
		removed, added := depsDiffText(d.Removed), depsDiffText(d.Added)
		for _, sp := range secfeed.ManifestAdditions(d.Path, added, removed) {
			out.Gone.Removed = append(out.Gone.Removed, store.SecSighting{Key: depsCommitKey(rootHash, d.Path, string(sp.Eco), secfeed.SafeName(sp.Name)), Path: d.Path})
		}
		specs := secfeed.ManifestAdditions(d.Path, removed, added)
		if len(specs) == 0 {
			continue
		}
		dir := filepath.Join(root, filepath.Dir(filepath.FromSlash(d.Path)))
		chain, ok := depsDirChain(dir, root)
		scopeOf := secfeed.Scope{ProjectRoot: root, Dirs: chain, Unknown: !ok}
		checks := secfeed.Gate(context.Background(), secfeed.GateInput{
			Specs: specs, Index: ix, IndexFreshness: fresh, Public: depsClassifier(scopeOf), Cache: cache,
			MinAge: depsDefaultMinAge, Now: now,
		})
		for _, c := range checks {
			if c.Verdict == policy.InstallKnownGood {
				out.Gone.Removed = append(out.Gone.Removed, store.SecSighting{Key: depsCommitKey(rootHash, d.Path, c.Ecosystem, c.Name), Path: d.Path})
				continue
			}
			if f, ok := depsCommitFinding(rootHash, sha, scope, d, c); ok {
				out.Findings = append(out.Findings, f)
			}
		}
	}
	return out, true
}

// depsCommitKey is the local key of one dependency in one manifest: a
// finding per manifest, so removing a dependency from one manifest closes
// that manifest's finding only.
func depsCommitKey(rootHash, relPath, eco, name string) string {
	return secfinding.LocalKey(rootHash, depsCommitRule, secfinding.TextIdentity(relPath+"\x00"+eco+":"+name))
}

// depsCommitFinding is one flagged check as a finding.
func depsCommitFinding(rootHash, sha string, scope policy.FindingScope, d secdiffobs.FileDiff, c policy.InstallCheck) (secfinding.Finding, bool) {
	row, flagged := depsCommitFlagged[c.Verdict]
	if !flagged || (c.Verdict == policy.InstallUnknownName && c.Reason != secfeed.ReasonNotFound) {
		return secfinding.Finding{}, false
	}
	line := 0
	for _, l := range d.Added {
		if strings.Contains(l.Text, c.Name) {
			line = l.N
			break
		}
	}
	msg := "S-747: " + d.Path + " adds " + c.Ecosystem + " \"" + c.Name + "\" (" + c.Reason + ")"
	if c.NearMiss != "" {
		msg += ", one edit from \"" + c.NearMiss + "\""
	}
	return secfinding.Normalize(secfinding.Finding{
		LocalKey:   depsCommitKey(rootHash, d.Path, c.Ecosystem, c.Name),
		Location:   secfinding.Location{RelPath: d.Path, StartLine: line, EndLine: line},
		Rule:       secfinding.Rule{ID: depsCommitRule, Pack: securityDepsComponent, PackVersion: secrules.PackVersion},
		Engine:     secfinding.Engine{Driver: depsCommitDriver},
		Category:   row.cat,
		Severity:   row.sev,
		Confidence: policy.FindingConfidenceMedium,
		Scope:      scope,
		Project:    secfinding.Project{RootHash: rootHash},
		Message:    msg,
		Baseline:   policy.FindingBaselineNew,
		Commit:     secfinding.Commit{SHA: sha},
		Status:     policy.FindingStatusOpen,
	}), true
}

// depsDiffText joins diff lines back into text.
func depsDiffText(ls []secdiffobs.Line) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Text)
		b.WriteByte('\n')
	}
	return b.String()
}
