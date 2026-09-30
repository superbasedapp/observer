package projectroi

// Unit names a Proxy's Value's shape, for the caller's renderer.
const (
	UnitUSD          = "usd"
	UnitRatio        = "ratio"
	UnitCount        = "count"
	UnitUSDPerLine   = "usd_per_line"
	UnitUSDPerCommit = "usd_per_commit"
)

// Proxy is one ROI tile: a value, its unit, the formula that produced
// it in plain words, and an honesty caveat naming what it cannot see
// (R10). A Proxy that could not be computed reports Available=false and
// puts the reason in Caveat instead of the standing disclaimer.
type Proxy struct {
	Key     string
	Label   string
	Value   float64
	Unit    string
	Formula string
	Caveat  string
	// Available is false when the inputs cannot support this proxy —
	// no commits captured, commit capture unavailable, or zero spend
	// in the window. A false Proxy's Value is always 0; the reason is
	// in Caveat.
	Available bool
}

// ProxyInput is everything Proxies needs, already loaded and windowed
// by the caller.
type ProxyInput struct {
	WindowDays int
	Turns      []Turn
	Sessions   []Session
	Linkage    Linkage
	Spend      Spend
	Tasks      []Task
	// AIAdded and AIModified are the project's total AI-authored code
	// lines added/modified in the window (from internal/loc), for
	// proxies that need window-wide AI volume rather than only the
	// lines Linkage could trace to a prompt. Neither is read by the
	// eight proxies this version emits; they are threaded through for
	// a future line-survival-style metric.
	AIAdded, AIModified int
	// HumanCapture is "none" or "vscode" (docs/loc-tracking.md). It
	// gates no proxy Proxies emits today — see the package doc comment
	// on why a human_share proxy is out of scope for this version.
	HumanCapture string
	// CommitCapture is "ok", "no_git" or "never_scanned"
	// (docs/plans/.../2026-09-21.md §3.4's capture.commits enum). Any
	// proxy that reads Commits or Linkage is unavailable unless this
	// is "ok".
	CommitCapture string
	Commits       []Commit
	// TasksAvailable is false when the caller's task-lifecycle rollup
	// failed to load (2026-09-22 rework finding #11) — Tasks then holds
	// a raw task_items fallback, not the rollup's own lifecycle counts.
	// proxyUSDPerTaskDone must report itself Unavailable in that case
	// rather than compute a real-looking figure over the fallback rows:
	// the dashboard's own Tasks KPI already hides behind this same flag
	// (apiProjectDetail.Tasks.Available), and a "spend per completed
	// task" tile computed from the SAME failed rollup would otherwise
	// keep rendering a number the KPI right above it just said was
	// unavailable.
	TasksAvailable bool
}

const (
	commitCaptureOK = "ok"
	taskStatusDone  = "done"
)

// Proxies derives the fixed set of ROI tiles from in. The returned
// slice is always in the same order (the order below), regardless of
// map iteration inside this package, so a caller can render it
// positionally.
func Proxies(in ProxyInput) []Proxy {
	return []Proxy{
		proxyUSDPerReachedAILine(in),
		proxyAIFilesReachedShare(in),
		proxySessionsNoCommitUSD(in),
		proxyUSDPerCommit(in),
		proxyUSDPerTaskDone(in),
		proxyPromptsPerCommit(in),
		proxyTurnsPerCommit(in),
		proxyCacheReadShare(in),
	}
}

func totalSpend(turns []Turn) float64 {
	var total float64
	for _, t := range turns {
		total += t.CostUSD
	}
	return total
}

// reachedFiles walks in.Linkage and returns the number of distinct
// (prompt, path) pairs that reached a commit (linesAdded+linesModified
// summed alongside), and the number of distinct path hashes across
// every prompt's edits (reached or not) plus every orphan edit — the
// full AI-touched-file set.
func reachedFiles(l Linkage) (reachedLines int, reachedPaths map[string]bool, touchedPaths map[string]bool) {
	reachedPaths = make(map[string]bool)
	touchedPaths = make(map[string]bool)
	for _, chain := range l.Chains {
		for _, f := range chain.Files {
			touchedPaths[f.PathHash] = true
			if !f.Superseded && f.CommitID != 0 {
				reachedPaths[f.PathHash] = true
				reachedLines += f.Added + f.Modified
			}
		}
	}
	for _, e := range l.Orphans {
		touchedPaths[e.PathHash] = true
	}
	return reachedLines, reachedPaths, touchedPaths
}

func unavailable(key, label, unit, formula, reason string) Proxy {
	return Proxy{Key: key, Label: label, Unit: unit, Formula: formula, Caveat: reason, Available: false}
}

func proxyUSDPerReachedAILine(in ProxyInput) Proxy {
	const key = "usd_per_reached_ai_line"
	const label = "Spend per AI code line that reached a commit"
	const formula = "sum(spend attributed to commits) / (AI code lines added+modified, code files only, in files that reached a commit)"
	if in.CommitCapture != commitCaptureOK {
		return unavailable(key, label, UnitUSDPerLine, formula, "commit capture unavailable")
	}
	if len(in.Commits) == 0 {
		return unavailable(key, label, UnitUSDPerLine, formula, "no commits")
	}
	reachedLines, _, _ := reachedFiles(in.Linkage)
	if reachedLines == 0 {
		return unavailable(key, label, UnitUSDPerLine, formula, "no AI lines reached a commit in this window")
	}
	var byCommit float64
	for _, v := range in.Spend.ByCommit {
		byCommit += v
	}
	if byCommit == 0 && totalSpend(in.Turns) == 0 {
		return unavailable(key, label, UnitUSDPerLine, formula, "no spend in this window")
	}
	return Proxy{
		Key: key, Label: label, Unit: UnitUSDPerLine, Formula: formula,
		Value:     byCommit / float64(reachedLines),
		Caveat:    "file-level reach, not verified line survival",
		Available: true,
	}
}

func proxyAIFilesReachedShare(in ProxyInput) Proxy {
	const key = "ai_files_reached_share"
	const label = "AI-touched files that reached a commit"
	const formula = "distinct AI-touched files that reached a commit / distinct AI-touched files"
	if in.CommitCapture != commitCaptureOK {
		return unavailable(key, label, UnitRatio, formula, "commit capture unavailable")
	}
	_, reachedPaths, touchedPaths := reachedFiles(in.Linkage)
	if len(touchedPaths) == 0 {
		return unavailable(key, label, UnitRatio, formula, "no AI-touched files in this window")
	}
	return Proxy{
		Key: key, Label: label, Unit: UnitRatio, Formula: formula,
		Value:     float64(len(reachedPaths)) / float64(len(touchedPaths)),
		Caveat:    "counts a file once it reaches any commit in the window; does not confirm the AI's specific lines survived",
		Available: true,
	}
}

func proxySessionsNoCommitUSD(in ProxyInput) Proxy {
	const key = "sessions_no_commit_usd"
	const label = "Spend in sessions with no linked commit (yet)"
	const formula = "sum(session cost) over sessions with no prompt that reached a commit"
	const caveat = "may be research-only, work in progress, outside the link window, or due to commit capture being unavailable"
	if in.CommitCapture != commitCaptureOK {
		return unavailable(key, label, UnitUSD, formula, "commit capture unavailable")
	}
	if len(in.Sessions) == 0 {
		return unavailable(key, label, UnitUSD, formula, "no sessions in this window")
	}
	hasCommit := make(map[string]bool)
	for _, chain := range in.Linkage.Chains {
		for _, f := range chain.Files {
			if !f.Superseded && f.CommitID != 0 {
				hasCommit[chain.Prompt.SessionID] = true
				break
			}
		}
	}
	var noCommitUSD float64
	for _, s := range in.Sessions {
		if !hasCommit[s.ID] {
			noCommitUSD += s.CostUSD
		}
	}
	return Proxy{Key: key, Label: label, Unit: UnitUSD, Formula: formula, Value: noCommitUSD, Caveat: caveat, Available: true}
}

func proxyUSDPerCommit(in ProxyInput) Proxy {
	const key = "usd_per_commit"
	const label = "Spend per commit"
	const formula = "sum(turn cost) / count(commits in the window)"
	if in.CommitCapture != commitCaptureOK {
		return unavailable(key, label, UnitUSDPerCommit, formula, "commit capture unavailable")
	}
	n := countCommits(in.Commits)
	if n == 0 {
		return unavailable(key, label, UnitUSDPerCommit, formula, "no commits")
	}
	total := totalSpend(in.Turns)
	if total == 0 {
		return unavailable(key, label, UnitUSDPerCommit, formula, "no spend in this window")
	}
	return Proxy{
		Key: key, Label: label, Unit: UnitUSDPerCommit, Formula: formula,
		Value: total / float64(n), Caveat: "spend covers the whole window; a commit may draw on work from several sessions", Available: true,
	}
}

func proxyUSDPerTaskDone(in ProxyInput) Proxy {
	const key = "usd_per_task_done"
	const label = "Spend per completed task"
	const formula = "sum(turn cost) / count(tasks with status=done)"
	if !in.TasksAvailable {
		return unavailable(key, label, UnitUSD, formula, "task rollup unavailable")
	}
	done := 0
	for _, t := range in.Tasks {
		if t.Status == taskStatusDone {
			done++
		}
	}
	if done == 0 {
		return unavailable(key, label, UnitUSD, formula, "no completed tasks in this window")
	}
	total := totalSpend(in.Turns)
	if total == 0 {
		return unavailable(key, label, UnitUSD, formula, "no spend in this window")
	}
	return Proxy{
		Key: key, Label: label, Unit: UnitUSD, Formula: formula,
		Value: total / float64(done), Caveat: "task tracking is opt-in; an unmeasured project reads as zero tasks, not zero spend", Available: true,
	}
}

func proxyPromptsPerCommit(in ProxyInput) Proxy {
	const key = "prompts_per_commit"
	const label = "Prompts per commit"
	const formula = "count(prompts) / count(commits in the window)"
	if in.CommitCapture != commitCaptureOK {
		return unavailable(key, label, UnitCount, formula, "commit capture unavailable")
	}
	n := countCommits(in.Commits)
	if n == 0 {
		return unavailable(key, label, UnitCount, formula, "no commits")
	}
	return Proxy{
		Key: key, Label: label, Unit: UnitCount, Formula: formula,
		Value: float64(len(in.Linkage.Chains)) / float64(n), Caveat: "counts every prompt in the window, linked or not", Available: true,
	}
}

func proxyTurnsPerCommit(in ProxyInput) Proxy {
	const key = "turns_per_commit"
	const label = "Turns per commit"
	const formula = "count(turns) / count(commits in the window)"
	if in.CommitCapture != commitCaptureOK {
		return unavailable(key, label, UnitCount, formula, "commit capture unavailable")
	}
	n := countCommits(in.Commits)
	if n == 0 {
		return unavailable(key, label, UnitCount, formula, "no commits")
	}
	return Proxy{
		Key: key, Label: label, Unit: UnitCount, Formula: formula,
		Value: float64(len(in.Turns)) / float64(n), Caveat: "counts every turn in the window, linked or not", Available: true,
	}
}

func proxyCacheReadShare(in ProxyInput) Proxy {
	const key = "cache_read_share"
	const label = "Cache-read share of input tokens"
	const formula = "sum(cache_read) / sum(input + cache_read)"
	var input, cacheRead int64
	for _, t := range in.Turns {
		input += t.Input
		cacheRead += t.CacheRead
	}
	denom := input + cacheRead
	if denom == 0 {
		return unavailable(key, label, UnitRatio, formula, "no token usage in this window")
	}
	return Proxy{
		Key: key, Label: label, Unit: UnitRatio, Formula: formula,
		Value: float64(cacheRead) / float64(denom), Caveat: "prompt-cache observation, not a savings guarantee", Available: true,
	}
}

// CountsAsCommit is the ONE predicate for "does this commit count toward
// count(commits)" (R4.4 of docs/plans/projects-page-roi-and-commit-
// alignment-plan-2026-09-21.md, restated in docs/projects-page.md:
// "a merge commit is counted toward count(commits) proxies (when
// reachable) but never links a prompt to itself as though it authored
// the merged files"). A commit counts iff it is Reachable — IsMerge is
// irrelevant to COUNTING (a merge counts; it just carries no files, a
// separate rule enforced by Link). Exported so the list
// (store.LoadProjectListExtras' Commits30d), the detail panel
// (ComposeProjectDetail's Commits.Count) and this package's own
// usd_per_commit/prompts_per_commit/turns_per_commit proxies can never
// drift onto three different counts of the same window's commits (F17
// of the 2026-09-22 arc review: pre-fix, detail counted every commit
// unconditionally, the list and the proxies both excluded merges too).
func CountsAsCommit(c Commit) bool {
	return c.Reachable
}

// CountCommits applies CountsAsCommit across a commit slice.
func CountCommits(commits []Commit) int {
	n := 0
	for _, c := range commits {
		if CountsAsCommit(c) {
			n++
		}
	}
	return n
}

func countCommits(commits []Commit) int {
	return CountCommits(commits)
}
