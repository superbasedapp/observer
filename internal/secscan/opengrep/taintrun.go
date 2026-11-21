package opengrep

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// taintrun.go runs the intrafile taint pass (taintpass.go holds its rules)
// through the same runner, isolation and digests as the core pass, one
// batch at a time. Every batch is its own process tree under its own wall,
// memory, CPU and children caps; a cut kills the whole tree (the runner's
// cgroup, process group or job object) and only that batch is lost. Nothing
// here can change the core pass's results unless a batch finished with its
// canary reported, and then only for the files that batch read in full.

// TaintCacheStore loads and saves the pass's result cache. One owner
// writes it (the cmd layer's file).
type TaintCacheStore interface {
	Load() (TaintCache, error)
	Save(TaintCache) error
}

// coreRead is the core pass's decoded output, before the adapter.
type coreRead struct {
	project sarif.Run
	scanned Scanned
	passed  bool
	prefix  string
}

// taintOutcome is what the pass hands back to ScanFiles.
type taintOutcome struct {
	project sarif.Run
	status  secscan.PassStatus
	hold    []string
}

// taintPass runs the pass over a full scan's core read and returns the
// merged project run, the pass status and the targets whose taint-rule
// findings must not close in this run. On any failure the core run comes
// back unchanged.
func (d *Driver) taintPass(ctx context.Context, runner *extrun.Runner, rs resolved, dir, version string, mode Mode, cr coreRead) taintOutcome {
	started := d.now()
	pack := d.env.Pack
	rules := pack.TaintRules()
	out := taintOutcome{project: cr.project, status: secscan.PassStatus{Name: TaintPassName, Status: TaintSkipped}}
	gate := TaintGate{
		ConfigMode: strings.ToLower(strings.TrimSpace(d.env.Taint.Mode)), Mode: mode, TaintRules: len(rules),
		PackIntrafile: containsFlag(pack.EngineFlags(), secrulepack.FlagTaintIntrafile),
		CorePassed:    cr.passed, FileAccess: d.env.Stat != nil && d.env.Runner != nil && d.env.Runner.Hash != nil,
	}
	if why := TaintSkipReason(gate); why != "" {
		out.status.Reason = why
		return out
	}
	exts := TaintExtensions(rules)
	targets, unreadable := d.taintTargets(dir, append(append([]string(nil), cr.scanned.Files...), cr.scanned.Partial...), exts)
	out.status.Targets = len(targets) + len(unreadable)
	if out.status.Targets == 0 {
		out.status.Reason = TaintSkipNoTargets
		return out
	}
	isTaint := pack.IsTaintRule
	m := TaintMerge{Covered: map[string]bool{}, Partial: map[string]bool{}, Results: map[string][]sarif.Result{}}
	cache := d.loadTaintCache()
	dirty := false
	nowUnix := started.Unix()
	var misses []TaintTarget
	keys := map[string]string{}
	for _, t := range targets {
		k := TaintCacheKey(t.Rel, t.SHA256, pack.Digest(), version)
		keys[t.Rel] = k
		if e, ok := cache.Entries[k]; ok {
			m.Covered[t.Rel] = true
			m.Results[t.Rel] = TaintCacheResults(e, t.Rel)
			e.Used = nowUnix
			cache.Entries[k] = e
			out.status.Cached++
			dirty = true
			continue
		}
		misses = append(misses, t)
	}
	var missBytes int64
	for _, t := range misses {
		missBytes += t.Size
	}
	budget := TaintBudget(len(misses), missBytes, d.env.Taint.BudgetSeconds)
	batches := PlanTaintBatches(misses, TaintArgvCapFor(d.env.GOOS))
	outcomes := make([]TaintBatchOutcome, len(batches))
	remBytes := missBytes
	for i, b := range batches {
		remaining := budget - d.now().Sub(started)
		wall := TaintBatchWall(remaining, b.Bytes, remBytes)
		remBytes -= b.Bytes
		switch {
		case ctx.Err() != nil:
			outcomes[i] = TaintBatchOutcome{Status: BatchFailed, Reason: ReasonCanceled}
			continue
		case wall <= 0:
			outcomes[i] = TaintBatchOutcome{Status: BatchNotRun, Reason: TaintBudgetExhausted}
			continue
		}
		outcomes[i] = d.runTaintBatch(ctx, runner, rs, dir, i, b, wall, isTaint)
		if outcomes[i].Status != BatchCompleted {
			continue
		}
		out.status.Merged++
		for _, rel := range outcomes[i].Full {
			m.Covered[rel] = true
			got := outcomes[i].Results[rel]
			m.Results[rel] = got
			if len(got) <= TaintCacheMaxResults && keys[rel] != "" {
				cache.Entries[keys[rel]] = TaintCacheEntry{Results: got, Used: nowUnix}
				dirty = true
			}
		}
		for _, rel := range outcomes[i].Partial {
			m.Partial[rel] = true
			m.Results[rel] = outcomes[i].Results[rel]
		}
	}
	out.status.Status, out.status.Reason = TaintPassStatus(outcomes)
	out.status.Batches = len(batches)
	out.status.Covered, out.status.Partial = len(m.Covered), len(m.Partial)
	out.status.BudgetMS = budget.Milliseconds()
	out.status.TookMS = d.now().Sub(started).Milliseconds()
	out.project = MergeTaint(cr.project, isTaint, cr.prefix, dir, m)
	all := make([]string, 0, out.status.Targets)
	for _, t := range targets {
		all = append(all, t.Rel)
	}
	out.hold = TaintHold(append(all, unreadable...), m.Covered)
	if dirty && d.env.TaintCache != nil {
		_ = d.env.TaintCache.Save(PruneTaintCache(cache, started))
	}
	return out
}

func containsFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

// taintTargets stats and hashes the candidates (sorted, deduplicated): a
// regular file of the taint rules' languages within TaintMaxTargetBytes is
// a target; one that cannot be stat'ed or hashed is unreadable (the pass
// does not answer it, so its taint-rule findings are held).
func (d *Driver) taintTargets(dir string, rels []string, exts map[string]bool) ([]TaintTarget, []string) {
	sort.Strings(rels)
	var out []TaintTarget
	var bad []string
	last := ""
	for _, rel := range rels {
		if rel == last || !TaintCandidate(rel, exts) {
			continue
		}
		last = rel
		abs := d.join(strings.TrimRight(dir, `/\`), strings.ReplaceAll(rel, "/", d.sep()))
		size, regular, err := d.env.Stat(abs)
		switch {
		case err != nil:
			bad = append(bad, rel)
			continue
		case !regular || !TaintSizeOK(size):
			continue
		}
		sum, err := d.env.Runner.Hash(abs)
		if err != nil || sum == "" {
			bad = append(bad, rel)
			continue
		}
		out = append(out, TaintTarget{Rel: rel, Size: size, SHA256: sum})
	}
	return out, bad
}

// loadTaintCache loads the cache; a cache that does not load, or of
// another version, is empty (it only costs re-runs).
func (d *Driver) loadTaintCache() TaintCache {
	empty := TaintCache{Version: TaintCacheVersion, Entries: map[string]TaintCacheEntry{}}
	if d.env.TaintCache == nil {
		return empty
	}
	c, err := d.env.TaintCache.Load()
	if err != nil || c.Version != TaintCacheVersion || c.Entries == nil {
		return empty
	}
	return c
}

// taintConfigs returns the absolute rule files of the pass: every taint
// rule's file and the canary's.
func (d *Driver) taintConfigs() []string {
	base := strings.TrimRight(d.env.PackDir, `/\`)
	var out []string
	for _, r := range d.env.Pack.TaintRules() {
		out = append(out, d.join(base, strings.ReplaceAll(r.File, "/", d.sep())))
	}
	return append(out, d.join(base, strings.ReplaceAll(d.env.Pack.Manifest.Canary.RuleFile, "/", d.sep())))
}

// runTaintBatch runs one batch and reads its SARIF and JSON copy.
func (d *Driver) runTaintBatch(ctx context.Context, runner *extrun.Runner, rs resolved, dir string, i int, b TaintBatch, wall time.Duration, isTaint func(string) bool) TaintBatchOutcome {
	jsonOut := d.join(strings.TrimRight(d.env.OutDir, `/\`), "taint-"+strconv.Itoa(i)+".json")
	paths := make([]string, 0, len(b.Targets))
	for _, t := range b.Targets {
		paths = append(paths, t.Rel)
	}
	req := d.request(rs, ModeFull, dir, "")
	req.Args = ArgsForTaintBatch(d.taintConfigs(), d.canary(), jsonOut, paths, d.env.Taint.Jobs)
	req.Limits = TaintLimits(wall, d.env.Taint.Jobs, d.env.Taint.MemoryMiB)
	run := runner.Run(ctx, req)
	cls := classify(run)
	timedOut := run.Outcome == extrun.OutcomeTimeout
	canceled := run.Outcome == extrun.OutcomeCanceled || ctx.Err() != nil
	if cls != "" || timedOut || canceled {
		st, why := BatchStatusFor(cls, timedOut, canceled, false)
		return TaintBatchOutcome{Status: st, Reason: why}
	}
	log, err := sarif.Decode(run.Stdout)
	if err != nil || len(log.Runs) != 1 {
		return TaintBatchOutcome{Status: BatchFailed, Reason: ReasonOutput}
	}
	jb, err := d.env.ReadFile(jsonOut, MaxJSONCopyBytes)
	if err != nil {
		return TaintBatchOutcome{Status: BatchFailed, Reason: ReasonOutput}
	}
	scanned, err := ParseJSONCopy(jb, dir, d.canary())
	if err != nil {
		return TaintBatchOutcome{Status: BatchFailed, Reason: ReasonOutput}
	}
	prefix := secrulepack.RulePrefix(d.rulesDir())
	project, hit := splitCanary(log.Runs[0], d.env.Pack.Manifest.Canary.Rule, prefix, d.canary())
	if st, why := BatchStatusFor("", false, false, hit && scanned.Canary); st != BatchCompleted {
		return TaintBatchOutcome{Status: st, Reason: why}
	}
	if project.Dropped > 0 || project.RulesDropped > 0 {
		// A result cut at the decoder's cap: the batch cannot prove a file's
		// results complete, so it answers none.
		return TaintBatchOutcome{Status: BatchFailed, Reason: ReasonBudget}
	}
	inBatch := map[string]bool{}
	for _, p := range paths {
		inBatch[p] = true
	}
	o := TaintBatchOutcome{Status: BatchCompleted, Results: TaintResultsByFile(project, isTaint, prefix, dir)}
	for _, f := range scanned.Files {
		if inBatch[f] {
			o.Full = append(o.Full, f)
		}
	}
	for _, f := range scanned.Partial {
		if inBatch[f] {
			o.Partial = append(o.Partial, f)
		}
	}
	for rel := range o.Results {
		if !inBatch[rel] {
			delete(o.Results, rel)
		}
	}
	return o
}
