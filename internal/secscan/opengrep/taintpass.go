package opengrep

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// taintpass.go is the pure half of the intrafile taint pass (plan section
// 14.3 item 1a; operator ruling 2026-11-05 "1a pass", option (b)): on a
// FULL scan only, after the core pass, a second Opengrep pass runs the
// pack's taint-mode rules alone with --taint-intrafile, in batches, under
// its own budget and caps. Its results replace the core pass's taint-rule
// results only for the files a batch read in full with its canary
// reported; anything else leaves the core pass's results exactly as they
// were. Diff, commit and post-write scans stay one plain pass.
//
// Everything here is decision logic over plain values: the gate, the
// target rule, the budget table, the batch plan, the per-batch wall, the
// status table, the merge and the cache key and pruning. The runner half
// is taintrun.go.

// TaintPassName is the pass's secscan.PassStatus name.
const TaintPassName = "taint_intrafile" //nolint:gosec // G101: a pass name, not a credential.

// The [security.scan.opengrep] taint_pass values ("" reads as auto).
const (
	TaintModeAuto = "auto"
	TaintModeOff  = "off"
)

// TaintModes are the accepted taint_pass values.
var TaintModes = []string{"", TaintModeAuto, TaintModeOff}

// TaintConfig is the pass's configuration ([security.scan.opengrep]
// taint_pass, taint_pass_budget_seconds, taint_pass_jobs,
// taint_pass_memory_mib). The zero value is the default: auto, the scaled
// budget, TaintDefaultJobs and TaintDefaultMemoryMiB.
type TaintConfig struct {
	Mode          string
	BudgetSeconds int
	Jobs          int
	MemoryMiB     int
}

// The pass's status vocabulary (secscan.PassStatus.Status).
const (
	// TaintCompleted: every planned batch finished with its canary
	// reported (or every target came from the cache).
	TaintCompleted = "completed"
	// TaintTimedOut: a batch hit its wall, or the budget ran out before a
	// batch could start; the batches that finished are merged.
	TaintTimedOut = "timed_out"
	// TaintFailed: a batch crashed, was refused, hit a memory, output or
	// children cap, or finished without its canary; the batches that
	// finished are merged.
	TaintFailed = "failed"
	// TaintSkipped: the pass did not run (Reason says why); the core
	// pass's results stand unchanged.
	TaintSkipped = "skipped"
)

// The pass's own reasons (beside the driver's Reason* codes a failed batch
// carries).
const (
	TaintSkipOff            = "off"
	TaintSkipNotFull        = "not_full_scan"
	TaintSkipNoTaintRules   = "no_taint_rules"
	TaintSkipPackIntrafile  = "pack_runs_intrafile"
	TaintSkipCoreIncomplete = "core_pass_incomplete"
	TaintSkipNoFileAccess   = "no_file_access"
	TaintSkipNoTargets      = "no_targets"
	// TaintBudgetExhausted: the budget ran out before every batch started.
	TaintBudgetExhausted = "budget_exhausted"
	// TaintBatchTimedOut: a batch hit its own wall.
	TaintBatchTimedOut = "batch_timed_out"
	// TaintCanaryMissing: a batch finished without its canary reported.
	TaintCanaryMissing = "canary_not_reported"
)

// TaintGate is what the gate reads.
type TaintGate struct {
	ConfigMode string
	Mode       Mode
	// TaintRules is how many taint-mode rules the pack has; PackIntrafile
	// that the pack already runs --taint-intrafile in its core pass.
	TaintRules    int
	PackIntrafile bool
	// CorePassed: the core pass's canary passed in this run.
	CorePassed bool
	// FileAccess: the env can stat and hash project files.
	FileAccess bool
}

// taintGateRows is the ordered gate (CLAUDE.md module rule 5): the first
// row that matches skips the pass with its reason.
var taintGateRows = []struct {
	when   func(TaintGate) bool
	reason string
}{
	{func(g TaintGate) bool { return g.ConfigMode == TaintModeOff }, TaintSkipOff},
	{func(g TaintGate) bool { return g.Mode != ModeFull }, TaintSkipNotFull},
	{func(g TaintGate) bool { return g.TaintRules == 0 }, TaintSkipNoTaintRules},
	{func(g TaintGate) bool { return g.PackIntrafile }, TaintSkipPackIntrafile},
	{func(g TaintGate) bool { return !g.CorePassed }, TaintSkipCoreIncomplete},
	{func(g TaintGate) bool { return !g.FileAccess }, TaintSkipNoFileAccess},
}

// TaintSkipReason returns why the pass does not run, "" when it does.
func TaintSkipReason(g TaintGate) string {
	for _, r := range taintGateRows {
		if r.when(g) {
			return r.reason
		}
	}
	return ""
}

// TaintMaxTargetBytes is the pass's --max-target-bytes (the core pass's is
// 1 MB): the follow-up measurement (M3L-1 1a, section 2) found the flag
// times out at 1 MB on this repository and finishes at 250 KB.
const TaintMaxTargetBytes = 250000

// TaintExcludeMinified is the pass's name exclusion: minified JavaScript
// is where the flag's uncapped parse stage spends (13 KB ran 13 minutes),
// and no core result was ever found in one.
const TaintExcludeMinified = "*.min.js"

// taintLanguageExts maps a pack language to the file extensions Opengrep
// reads as that language.
var taintLanguageExts = map[string][]string{
	"go":         {".go"},
	"javascript": {".js", ".jsx", ".mjs", ".cjs"},
	"typescript": {".ts", ".tsx", ".mts", ".cts"},
	"python":     {".py", ".pyi"},
	"java":       {".java"},
	"csharp":     {".cs"},
}

// TaintExtensions returns the extensions of the taint rules' languages.
func TaintExtensions(rules []secrulepack.Rule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		for _, l := range r.Languages {
			for _, e := range taintLanguageExts[l] {
				out[e] = true
			}
		}
	}
	return out
}

// TaintCandidate reports whether a project file (relative, slash
// separated) is in a taint rule's language and not excluded by name.
func TaintCandidate(rel string, exts map[string]bool) bool {
	base := strings.ToLower(path.Base(rel))
	if strings.HasSuffix(base, ".min.js") {
		return false
	}
	return exts[strings.ToLower(path.Ext(base))]
}

// TaintSizeOK reports whether a candidate's size lets the pass read it.
func TaintSizeOK(size int64) bool { return size > 0 && size <= TaintMaxTargetBytes }

// TaintTarget is one file the pass reads.
type TaintTarget struct {
	Rel    string
	Size   int64
	SHA256 string
}

// The budget bounds.
const (
	// TaintMinBudget and TaintMaxBudget bound a configured budget.
	TaintMinBudget = 30 * time.Second
	TaintMaxBudget = time.Hour
)

// TaintBudgetRows scale the default budget by the work the pass has this
// time (the targets the cache does not answer): the first row whose file
// and byte bounds both hold. The 300 s row is the reference: this
// repository's 16,435 files and 142 MiB in the pack's languages took
// 104 to 130 s taint-only with the flag at 250 KB (M3L-1 1a follow-up,
// section 2). The first row is the floor, the last the ceiling.
var TaintBudgetRows = []struct {
	MaxFiles int
	MaxBytes int64
	Budget   time.Duration
}{
	{1000, 8 << 20, 60 * time.Second},
	{5000, 48 << 20, 150 * time.Second},
	{25000, 192 << 20, 300 * time.Second},
	{60000, 512 << 20, 600 * time.Second},
	{int(^uint(0) >> 1), 1<<63 - 1, 900 * time.Second},
}

// TaintBudget returns the pass's wall budget: the configured seconds
// (bounded by TaintMinBudget and TaintMaxBudget) when set, else the
// scaled row for files and bytes.
func TaintBudget(files int, bytes int64, configured int) time.Duration {
	if configured > 0 {
		b := time.Duration(configured) * time.Second
		return min(max(b, TaintMinBudget), TaintMaxBudget)
	}
	for _, r := range TaintBudgetRows {
		if files <= r.MaxFiles && bytes <= r.MaxBytes {
			return r.Budget
		}
	}
	return TaintBudgetRows[len(TaintBudgetRows)-1].Budget
}

// The pass's process caps.
const (
	// TaintDefaultJobs is the pass's -j: half the core pass's, so the
	// second pass never takes the whole machine.
	TaintDefaultJobs = 2
	// TaintDefaultMemoryMiB is the pass's memory cap (the core pass's).
	TaintDefaultMemoryMiB = 2048
	// TaintMinMemoryMiB and TaintMaxMemoryMiB bound a configured cap.
	TaintMinMemoryMiB = 512
	TaintMaxMemoryMiB = 8192
)

// ClampTaintJobs returns the pass's -j: 0 or less is TaintDefaultJobs,
// more than MaxJobs is MaxJobs.
func ClampTaintJobs(jobs int) int {
	switch {
	case jobs <= 0:
		return TaintDefaultJobs
	case jobs > MaxJobs:
		return MaxJobs
	}
	return jobs
}

// ClampTaintMemoryMiB returns the pass's memory cap in MiB.
func ClampTaintMemoryMiB(mib int) int {
	if mib <= 0 {
		return TaintDefaultMemoryMiB
	}
	return min(max(mib, TaintMinMemoryMiB), TaintMaxMemoryMiB)
}

// TaintLimits returns one batch's caps: its wall, the memory cap, a CPU
// cap of the wall times -j (per process on Linux and macOS, the job's
// total on Windows), and the core pass's output and children caps.
func TaintLimits(wall time.Duration, jobs, memoryMiB int) extrun.Limits {
	jobs = ClampTaintJobs(jobs)
	children := 16 * jobs
	if children < 64 {
		children = 64
	}
	return extrun.Limits{
		Wall:        wall,
		StdoutBytes: 32 << 20,
		StderrBytes: 4 << 20,
		MemoryBytes: int64(ClampTaintMemoryMiB(memoryMiB)) << 20,
		Children:    children,
		CPU:         wall * time.Duration(jobs),
	}
}

// The batch plan's bounds.
const (
	// TaintBatchTarget is how many batches a large target set is cut into,
	// so a killed batch loses at most about an eighth of the work.
	TaintBatchTarget = 8
	// TaintMinBatchFiles and TaintMaxBatchFiles bound one batch's files
	// (each Opengrep start costs a few seconds of rule loading).
	TaintMinBatchFiles = 100
	TaintMaxBatchFiles = 2000
	// TaintMaxBatchBytes bounds one batch's target bytes.
	TaintMaxBatchBytes = 32 << 20
	// TaintArgvCapWindows and TaintArgvCap bound one batch's target
	// arguments in bytes (Windows' command line is 32,767 characters, and
	// the rule configs and flags share it).
	TaintArgvCapWindows = 16000
	TaintArgvCap        = 256 << 10
)

// TaintArgvCapFor returns the target-argument cap of goos.
func TaintArgvCapFor(goos string) int {
	if goos == "windows" {
		return TaintArgvCapWindows
	}
	return TaintArgvCap
}

// TaintBatch is one Opengrep run of the pass.
type TaintBatch struct {
	Targets []TaintTarget
	Bytes   int64
}

// PlanTaintBatches cuts the targets (sorted by path) into batches of at
// most a per-batch file count (an eighth of the targets, bounded by
// TaintMinBatchFiles and TaintMaxBatchFiles), TaintMaxBatchBytes and
// argvCap bytes of "./path" arguments; a batch always holds at least one
// target.
func PlanTaintBatches(targets []TaintTarget, argvCap int) []TaintBatch {
	ts := slices.Clone(targets)
	sort.Slice(ts, func(i, j int) bool { return ts[i].Rel < ts[j].Rel })
	per := (len(ts) + TaintBatchTarget - 1) / TaintBatchTarget
	per = min(max(per, TaintMinBatchFiles), TaintMaxBatchFiles)
	var out []TaintBatch
	var cur TaintBatch
	argv := 0
	for _, t := range ts {
		a := len(t.Rel) + 3 // "./" and the separator
		if len(cur.Targets) > 0 && (len(cur.Targets) >= per || cur.Bytes+t.Size > TaintMaxBatchBytes || argv+a > argvCap) {
			out = append(out, cur)
			cur, argv = TaintBatch{}, 0
		}
		cur.Targets = append(cur.Targets, t)
		cur.Bytes += t.Size
		argv += a
	}
	if len(cur.Targets) > 0 {
		out = append(out, cur)
	}
	return out
}

// The per-batch wall bounds.
const (
	// TaintMinBatchWall is the least wall a batch is given while the budget
	// has it.
	TaintMinBatchWall = 30 * time.Second
	// TaintMinStart is the least budget left for a batch to start at all.
	TaintMinStart = 10 * time.Second
)

// TaintBatchWall returns one batch's wall: twice its byte share of what is
// left of the budget, at least TaintMinBatchWall and at most what is left,
// so one slow batch cannot spend the whole budget and the later batches
// still get their turn. 0 means the batch does not start (less than
// TaintMinStart left).
func TaintBatchWall(remaining time.Duration, batchBytes, remainingBytes int64) time.Duration {
	if remaining < TaintMinStart {
		return 0
	}
	share := remaining
	if remainingBytes > 0 && batchBytes < remainingBytes {
		share = time.Duration(float64(remaining) * 2 * float64(batchBytes) / float64(remainingBytes))
	}
	return min(max(share, TaintMinBatchWall), remaining)
}

// The per-batch statuses (TaintBatchOutcome.Status).
const (
	BatchCompleted = "completed"
	BatchTimedOut  = "timed_out"
	BatchFailed    = "failed"
	BatchNotRun    = "not_run"
)

// TaintBatchOutcome is what one batch came to.
type TaintBatchOutcome struct {
	Status string
	Reason string
	// Full are the targets the batch read in full, Partial those Opengrep
	// reported an error for (a per-file timeout, a parse error): both only
	// for a completed batch.
	Full    []string
	Partial []string
	// Results are the batch's taint-rule results by file, with their rule
	// id resolved and their location the project-relative path.
	Results map[string][]sarif.Result
}

// BatchStatusFor maps a batch's run onto its status: the driver's
// classify reason ("" for a result), then the canary.
func BatchStatusFor(classified string, timedOut, canceled, canary bool) (string, string) {
	rows := []struct {
		when   bool
		status string
		reason string
	}{
		{canceled, BatchFailed, ReasonCanceled},
		{timedOut, BatchTimedOut, TaintBatchTimedOut},
		{classified != "", BatchFailed, classified},
		{!canary, BatchFailed, TaintCanaryMissing},
	}
	for _, r := range rows {
		if r.when {
			return r.status, r.reason
		}
	}
	return BatchCompleted, ""
}

// taintStatusRows is the pass's status table, walked top down over its
// batches: a cancel fails the pass, every batch completed completes it, a
// timeout or a batch the budget never started times it out, anything else
// fails it with the first failed batch's reason.
var taintStatusRows = []struct {
	when   func([]TaintBatchOutcome) bool
	status string
	reason func([]TaintBatchOutcome) string
}{
	{func(bs []TaintBatchOutcome) bool { return anyReason(bs, ReasonCanceled) }, TaintFailed, func([]TaintBatchOutcome) string { return ReasonCanceled }},
	{func(bs []TaintBatchOutcome) bool { return allStatus(bs, BatchCompleted) }, TaintCompleted, func([]TaintBatchOutcome) string { return "" }},
	{func(bs []TaintBatchOutcome) bool { return anyStatus(bs, BatchNotRun) }, TaintTimedOut, func([]TaintBatchOutcome) string { return TaintBudgetExhausted }},
	{func(bs []TaintBatchOutcome) bool { return anyStatus(bs, BatchTimedOut) }, TaintTimedOut, func([]TaintBatchOutcome) string { return TaintBatchTimedOut }},
	{func([]TaintBatchOutcome) bool { return true }, TaintFailed, firstFailure},
}

// TaintPassStatus returns the pass's status and reason over its batches.
func TaintPassStatus(bs []TaintBatchOutcome) (string, string) {
	for _, r := range taintStatusRows {
		if r.when(bs) {
			return r.status, r.reason(bs)
		}
	}
	return TaintFailed, ""
}

func anyStatus(bs []TaintBatchOutcome, s string) bool {
	return slices.ContainsFunc(bs, func(b TaintBatchOutcome) bool { return b.Status == s })
}

func allStatus(bs []TaintBatchOutcome, s string) bool {
	return !slices.ContainsFunc(bs, func(b TaintBatchOutcome) bool { return b.Status != s })
}

func anyReason(bs []TaintBatchOutcome, r string) bool {
	return slices.ContainsFunc(bs, func(b TaintBatchOutcome) bool { return b.Reason == r })
}

func firstFailure(bs []TaintBatchOutcome) string {
	for _, b := range bs {
		if b.Status == BatchFailed {
			return b.Reason
		}
	}
	return ""
}

// TaintMerge is what the pass hands the merge.
type TaintMerge struct {
	// Covered are the files whose taint-rule results the pass answers in
	// full (a completed batch read them, or the cache holds them); Partial
	// those a completed batch read only in part.
	Covered map[string]bool
	Partial map[string]bool
	// Results are the pass's taint-rule results by file.
	Results map[string][]sarif.Result
}

// resultRuleID returns a result's rule id, prefix stripped.
func resultRuleID(run sarif.Run, r sarif.Result, rulePrefix string) string {
	id := r.RuleID
	if id == "" && r.RuleIndex >= 0 && r.RuleIndex < len(run.Tool.Rules) {
		id = run.Tool.Rules[r.RuleIndex].ID
	}
	if rulePrefix != "" {
		id = strings.TrimPrefix(strings.TrimPrefix(id, rulePrefix), ".")
	}
	return id
}

// resultRel returns a result's project-relative path ("" when it has none
// the adapter would accept).
func resultRel(r sarif.Result, root string) string {
	if len(r.Locations) == 0 {
		return ""
	}
	rel, why := secscan.NormalizeLocation(r.Locations[0].URI, root)
	if why != secscan.LocOK {
		return ""
	}
	return rel
}

// MergeTaint is the merge rule (operator ruling 2026-11-05):
//
//   - a core result of a taint rule in a Covered file is replaced: it is
//     dropped and the pass's results for that file are added;
//   - in a Partial file both stand: the core result is kept and the pass's
//     results are added, a pass result the core already reported (same
//     rule and lines) once;
//   - every other core result is kept as it was, and nothing is added for
//     a file the pass did not read.
//
// isTaint names the taint-mode rules; core is the core pass's project run
// (canary split off). The merged run keeps the core run's tool and rules.
func MergeTaint(core sarif.Run, isTaint func(string) bool, rulePrefix, root string, m TaintMerge) sarif.Run {
	out := core
	out.Results = nil
	seen := map[string]bool{}
	for _, r := range core.Results {
		id := resultRuleID(core, r, rulePrefix)
		rel := resultRel(r, root)
		if rel != "" && isTaint(id) && m.Covered[rel] {
			continue
		}
		out.Results = append(out.Results, r)
		if rel != "" {
			seen[resultKey(id, rel, r)] = true
		}
	}
	files := make([]string, 0, len(m.Results))
	for rel := range m.Results {
		if m.Covered[rel] || m.Partial[rel] {
			files = append(files, rel)
		}
	}
	sort.Strings(files)
	for _, rel := range files {
		for _, r := range m.Results[rel] {
			k := resultKey(r.RuleID, rel, r)
			if seen[k] {
				continue
			}
			seen[k] = true
			out.Results = append(out.Results, r)
		}
	}
	return out
}

func resultKey(id, rel string, r sarif.Result) string {
	start, end := 0, 0
	if len(r.Locations) > 0 {
		start, end = r.Locations[0].StartLine, r.Locations[0].EndLine
	}
	return id + "\x00" + rel + "\x00" + strconv.Itoa(start) + "\x00" + strconv.Itoa(end)
}

// TaintResultsByFile keeps a batch run's results of taint rules, each with
// its rule id resolved (RuleIndex cleared, so it reads the same in the
// merged run), its location's URI the project-relative path and its
// engine message dropped (SARIF messages are content-bearing and the
// adapter never reads them), grouped by file. A result of any other rule,
// or with a location the adapter would refuse, is dropped.
func TaintResultsByFile(run sarif.Run, isTaint func(string) bool, rulePrefix, root string) map[string][]sarif.Result {
	out := map[string][]sarif.Result{}
	for _, r := range run.Results {
		id := resultRuleID(run, r, rulePrefix)
		rel := resultRel(r, root)
		if rel == "" || !isTaint(id) {
			continue
		}
		c := r
		c.RuleID, c.RuleIndex, c.Message = id, -1, ""
		c.Locations = slices.Clone(r.Locations)
		c.Locations[0].URI, c.Locations[0].URIBaseID = rel, ""
		out[rel] = append(out[rel], c)
	}
	return out
}

// TaintHold returns the targets whose taint-rule findings this run must
// not close: the pass ran but did not answer them in full, so a finding
// the pass reported earlier (one the plain core pass cannot see) is not
// proven gone. Sorted.
func TaintHold(targets []string, covered map[string]bool) []string {
	var out []string
	for _, t := range targets {
		if !covered[t] {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// TaintCacheVersion is part of every cache key: a change to the pass's
// arguments (the byte limit, the flag set) or to what an entry holds bumps
// it, so no entry made under other arguments is ever read.
const TaintCacheVersion = "sbo-opengrep-taint-cache-v1"

// TaintCacheKey is the cache key of one file's intrafile taint results:
// the file's sha256, the pack digest and the engine version (intrafile
// taint results depend only on the file, the rules and the engine), and
// the file's project-relative path, because the engine's match
// fingerprint can include the path.
func TaintCacheKey(rel, fileSHA256, packDigest, engineVersion string) string {
	h := sha256.New()
	for _, s := range []string{TaintCacheVersion, rel, fileSHA256, packDigest, engineVersion} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TaintCache is the pass's node-local result cache: one entry per cache
// key, holding the file's taint-rule results (relative locations, no
// engine message) and when the entry was last used.
type TaintCache struct {
	Version string                     `json:"v"`
	Entries map[string]TaintCacheEntry `json:"entries"`
}

// TaintCacheEntry is one file's cached results.
type TaintCacheEntry struct {
	Results []sarif.Result `json:"r,omitempty"`
	// Used is when the entry was last written or read, in unix seconds.
	Used int64 `json:"u"`
}

// The cache's bounds.
const (
	// TaintCacheMaxEntries caps the entries kept (the oldest used go first).
	TaintCacheMaxEntries = 100000
	// TaintCacheMaxAge drops an entry unused this long.
	TaintCacheMaxAge = 30 * 24 * time.Hour
	// TaintCacheMaxResults caps one entry's results: a file with more is
	// not cached (it re-runs).
	TaintCacheMaxResults = 200
)

// PruneTaintCache drops entries unused for TaintCacheMaxAge, then the
// oldest used past TaintCacheMaxEntries (ties by key). A cache of another
// version is emptied.
func PruneTaintCache(c TaintCache, now time.Time) TaintCache {
	out := TaintCache{Version: TaintCacheVersion, Entries: map[string]TaintCacheEntry{}}
	if c.Version != TaintCacheVersion {
		return out
	}
	floor := now.Add(-TaintCacheMaxAge).Unix()
	keys := make([]string, 0, len(c.Entries))
	for k, e := range c.Entries {
		if e.Used >= floor {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := c.Entries[keys[i]], c.Entries[keys[j]]
		if a.Used != b.Used {
			return a.Used > b.Used
		}
		return keys[i] < keys[j]
	})
	if len(keys) > TaintCacheMaxEntries {
		keys = keys[:TaintCacheMaxEntries]
	}
	for _, k := range keys {
		out.Entries[k] = c.Entries[k]
	}
	return out
}

// TaintCacheResults returns an entry's results located at rel.
func TaintCacheResults(e TaintCacheEntry, rel string) []sarif.Result {
	out := make([]sarif.Result, 0, len(e.Results))
	for _, r := range e.Results {
		c := r
		c.Locations = slices.Clone(r.Locations)
		if len(c.Locations) > 0 {
			c.Locations[0].URI = rel
		}
		out = append(out, c)
	}
	return out
}

// ArgsForTaintBatch returns one batch's arguments: FlagsAlways with
// --max-target-bytes TaintMaxTargetBytes, --taint-intrafile, -j, one
// --config per taint rule file and the canary rule file (configs, absolute),
// the batch's JSON copy, --no-git-ignore with FullExcludes and the minified
// exclusion, each target as "./path", then the canary.
func ArgsForTaintBatch(configs []string, canary, jsonOut string, paths []string, jobs int) []string {
	args := []string{"scan"}
	for i := 0; i < len(FlagsAlways); i++ {
		args = append(args, FlagsAlways[i])
		if FlagsAlways[i] == "--max-target-bytes" && i+1 < len(FlagsAlways) {
			args = append(args, strconv.Itoa(TaintMaxTargetBytes))
			i++
		}
	}
	args = append(args, secrulepack.FlagTaintIntrafile, "-j", strconv.Itoa(ClampTaintJobs(jobs)))
	for _, c := range configs {
		args = append(args, "--config", c)
	}
	args = append(args, "--json-output="+jsonOut, "--no-git-ignore")
	args = append(args, FullExcludes...)
	args = append(args, "--exclude", TaintExcludeMinified)
	for _, p := range paths {
		args = append(args, "./"+p)
	}
	return append(args, canary)
}

// TaintStatusWords is how the CLI and the card name a pass status.
func TaintStatusWords(p secscan.PassStatus) string {
	s := p.Status
	if p.Reason != "" {
		s += " (" + p.Reason + ")"
	}
	switch p.Status {
	case TaintSkipped:
		return s + ": the core pass's taint-rule results stand"
	case TaintCompleted:
		return s + ": " + strconv.Itoa(p.Covered) + " files (" + strconv.Itoa(p.Cached) + " from the cache)" + partialWords(p)
	}
	return s + ": " + strconv.Itoa(p.Merged) + " of " + strconv.Itoa(p.Batches) + " batches merged, " + strconv.Itoa(p.Covered) + " of " + strconv.Itoa(p.Targets) +
		" files (" + strconv.Itoa(p.Cached) + " from the cache)" + partialWords(p) + "; the core pass's taint-rule results stand for the rest"
}

func partialWords(p secscan.PassStatus) string {
	if p.Partial == 0 {
		return ""
	}
	return ", " + strconv.Itoa(p.Partial) + " read in part"
}

// TaintPassOf returns a coverage's taint pass, ok false when it has none.
func TaintPassOf(c secscan.Coverage) (secscan.PassStatus, bool) {
	for _, p := range c.Passes {
		if p.Name == TaintPassName {
			return p, true
		}
	}
	return secscan.PassStatus{}, false
}

// HeldCloseRules returns the rule ids a held file (Scanned.TaintHold) may
// still close findings of: every rule of the pack that is not a taint
// rule. The store matches a close's rules by prefix, so ok is false (a
// held file closes nothing) when one such id is a prefix of a taint rule's
// id.
func HeldCloseRules(pack *secrulepack.Pack) ([]string, bool) {
	if pack == nil {
		return nil, false
	}
	taint := pack.TaintRules()
	var out []string
	for _, r := range pack.Manifest.Rules {
		if pack.IsTaintRule(r.ID) {
			continue
		}
		for _, t := range taint {
			if strings.HasPrefix(t.ID, r.ID) {
				return nil, false
			}
		}
		out = append(out, r.ID)
	}
	return out, len(out) > 0
}
