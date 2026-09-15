// report.go builds the Phase-2 session task report and project/tool/
// window rollup — see the package doc comment (doc.go) for the
// import-cycle reason this is its own leaf package.
package taskreport

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskflow"
)

// TaskTokenTotals is the token-count shape shared by every bucket in a
// task report — one struct so the JSON key set never drifts between a
// per-task row, the between_tasks/shared buckets, the sidechain total,
// and the project/tool/window rollup.
type TaskTokenTotals struct {
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`
	ReasoningTokens  int64 `json:"reasoning_tokens"`
}

func (t *TaskTokenTotals) add(o TaskTokenTotals) {
	t.InputTokens += o.InputTokens
	t.OutputTokens += o.OutputTokens
	t.CacheReadTokens += o.CacheReadTokens
	t.CacheWriteTokens += o.CacheWriteTokens
	t.ReasoningTokens += o.ReasoningTokens
}

// TaskCostBucket bundles a bucket's tokens/actions with its priced
// cost and the "don't lie about precision" flag: Unpriced is true when
// at least one row in this bucket had NEITHER a recorded provider cost
// NOR a pricing-table entry for its model — the bucket's CostUSD is
// then a known UNDER-count, and a surface must render "unpriced"
// rather than implying $0.00 is the true cost (§R2.3.6/caveat #5).
type TaskCostBucket struct {
	Tokens       TaskTokenTotals `json:"tokens"`
	ActionsCount int             `json:"actions_count"`
	CostUSD      float64         `json:"cost_usd"`
	Unpriced     bool            `json:"unpriced"`
}

func (b *TaskCostBucket) addRow(tot TaskTokenTotals, rowCost float64, unpriced bool) {
	b.Tokens.add(tot)
	b.CostUSD += rowCost
	if unpriced {
		b.Unpriced = true
	}
}

// ReportItem is one task's full Phase-2 row: taskflow.TaskSummary's
// lifecycle facts layered with its attributed tokens/cost/action-count.
type ReportItem struct {
	Key        string `json:"key"`
	KeyKind    string `json:"key_kind"`
	Content    string `json:"content"`
	ActiveForm string `json:"active_form,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Status     string `json:"status"`
	RawStatus  string `json:"raw_status,omitempty"`
	Order      int    `json:"order"`
	Unmatched  bool   `json:"unmatched"`
	// NeverActivated / StillOpen / ElapsedSeconds / TerminalStatus /
	// FirstInProgressUnix / TerminalAtUnix mirror taskflow.TaskSummary
	// (§R2.3.3) — see its doc comment for the "never fabricate a
	// completion" / "never backfill a synthetic start" rules these
	// encode.
	NeverActivated      bool    `json:"never_activated"`
	StillOpen           bool    `json:"still_open"`
	ElapsedSeconds      float64 `json:"elapsed_seconds"`
	TerminalStatus      string  `json:"terminal_status,omitempty"`
	FirstInProgressUnix *int64  `json:"first_in_progress_unix,omitempty"`
	TerminalAtUnix      *int64  `json:"terminal_at_unix,omitempty"`
	TaskCostBucket
}

// SessionTaskReport is GET /api/session/<id>/tasks's payload — also the
// substrate `observer tasks <id>` and the MCP get_session_tasks tool
// render from directly.
type SessionTaskReport struct {
	SessionID string `json:"session_id"`
	// HasTasks gates the calm empty state a surface MUST show instead
	// of an empty table — 80% of sessions never used a task tool at all
	// (§R2.3.7 caveat #6).
	HasTasks bool         `json:"has_tasks"`
	Items    []ReportItem `json:"items,omitempty"`
	// TokenUsageAvailable is populated when HasTasks is true and applies to
	// the main attribution scope. A separate
	// sidechain bucket can still carry usage when this is false.
	TokenUsageAvailable bool   `json:"token_usage_available"`
	TokensNote          string `json:"tokens_note,omitempty"`
	// BetweenTasks / Shared are the two non-per-task buckets §R2.3.2
	// requires as first-class rows, never a rounding residual — only
	// ~52% of a session's tokens are attributable to one specific task
	// on average (caveat #1).
	BetweenTasks TaskCostBucket `json:"between_tasks"`
	Shared       TaskCostBucket `json:"shared"`
	// Sidechain is populated only when a sub-agent (is_sidechain=1)
	// contributed usage AND include_sidechains is false (the default) —
	// reported as the session's own separate total, never silently
	// dropped and never folded into whichever task happened to be open
	// (§3.3 option (a)).
	Sidechain *TaskCostBucket `json:"sidechain,omitempty"`
	// UnmatchedCount is the §R2.3.7 caveat #4 substrate. AllKeysNative
	// tells a surface whether to suppress the "N items could not be
	// matched across updates" sentence entirely — content-hash-matched
	// tools are the ones that can lose an item to a wording change;
	// a session whose task tool mints real ids never needs the caveat.
	UnmatchedCount int  `json:"unmatched_count"`
	AllKeysNative  bool `json:"all_keys_native"`
	// MatchMode / ConcurrentAttribution / IncludeSidechains echo the
	// [tasks] config this report was computed under (the opts argument
	// LoadSessionTaskReport was called with), so a UI need not fetch
	// config separately to label "which mode produced these
	// keys/buckets".
	MatchMode             string `json:"match_mode"`
	ConcurrentAttribution string `json:"concurrent_attribution"`
	IncludeSidechains     bool   `json:"include_sidechains"`
	// CostNote is the fixed §R2.3.7 caveat #5 disclaimer, populated
	// whenever this report carries any cost figure at all: "list
	// pricing at each turn's timestamp, never a billed amount" — always
	// true for this feature, so it's a static sentence, not a flag a
	// caller has to interpret.
	CostNote string `json:"cost_note,omitempty"`
}

const taskCostNote = "Costs are list pricing at each token row's own timestamp — never a billed amount."

// LoadSessionTaskReport builds the complete Phase-2 report for one
// session: taskflow.LoadTaskItems' lifecycle rows, joined with
// taskflow.Summarize's elapsed/never-activated/still-open facts, and
// every token_usage/actions row attributed via taskflow.NewAttributor.At
// (configured from the explicit opts argument — see its doc comment on
// why this is NOT read from st.TasksOptions()) and priced through
// costEngine — the one function a session-detail surface, the CLI, and
// the MCP tool all build on (docs/task-tracking.md "Store API (phase 2
// surface)"). costEngine may be nil (an install with no pricing
// configured at all); every row is then Unpriced rather than the
// function failing.
//
// opts carries [tasks].match_mode/.concurrent_attribution/
// .include_sidechains. It is an explicit parameter, NOT read off st via
// Store.TasksOptions(), because every read surface (the dashboard HTTP
// handlers, `observer tasks`, the MCP get_session_tasks tool) builds a
// FRESH store.New(db) per request/invocation that never had
// SetTasksOptions called on it — Store.TasksOptions() would silently
// return the zero value there, making concurrent_attribution and
// include_sidechains inert on every read surface even though the write
// (ingest-decode) path applies match_mode correctly on the daemon's
// long-lived store instance. Callers build opts from the config.TasksConfig
// they already hold (dashboard.Options.Tasks / the loaded CLI config /
// the MCP server's own config) — see each call site.
func LoadSessionTaskReport(ctx context.Context, st *store.Store, costEngine *cost.Engine, sessionID string, opts taskflow.Options) (SessionTaskReport, error) {
	rep := SessionTaskReport{
		SessionID:             sessionID,
		MatchMode:             opts.MatchMode,
		ConcurrentAttribution: opts.ConcurrentAttribution,
		IncludeSidechains:     opts.IncludeSidechains,
	}

	items, err := st.LoadTaskItems(ctx, sessionID)
	if err != nil {
		return rep, fmt.Errorf("taskreport.LoadSessionTaskReport: %w", err)
	}
	if len(items) == 0 {
		return rep, nil // HasTasks stays false — the calm empty state.
	}
	rep.HasTasks = true

	unmatchedCount, err := st.LoadTaskUnmatchedCount(ctx, sessionID)
	if err != nil {
		return rep, fmt.Errorf("taskreport.LoadSessionTaskReport: %w", err)
	}
	rep.UnmatchedCount = unmatchedCount

	rep.AllKeysNative = true
	for _, it := range items {
		if it.KeyKind != taskflow.KeyNative {
			rep.AllKeysNative = false
			break
		}
	}

	transitions, err := st.LoadTaskTransitions(ctx, sessionID)
	if err != nil {
		return rep, fmt.Errorf("taskreport.LoadSessionTaskReport: %w", err)
	}

	intervals := taskflow.BuildOpenIntervals(transitions)
	attributor := taskflow.NewAttributor(intervals).SetConcurrentAttribution(opts.ConcurrentAttribution)

	tokenRows, err := st.LoadTaskTokenRows(ctx, sessionID, opts.IncludeSidechains)
	if err != nil {
		return rep, fmt.Errorf("taskreport.LoadSessionTaskReport: %w", err)
	}
	rep.TokenUsageAvailable = len(tokenRows) > 0
	rep.TokensNote, err = st.CursorUsageNote(ctx, sessionID)
	if err != nil {
		return rep, fmt.Errorf("taskreport.LoadSessionTaskReport: %w", err)
	}
	actionTs, err := st.LoadTaskActionTimestamps(ctx, sessionID, opts.IncludeSidechains)
	if err != nil {
		return rep, fmt.Errorf("taskreport.LoadSessionTaskReport: %w", err)
	}

	// asOf ("as of when do we measure a still-open task's elapsed time")
	// is the latest activity this seam can observe — never wall-clock
	// now (§3.5): a session abandoned months ago must not report an
	// ever-growing elapsed time for its last open task.
	asOf := lastTransitionTs(transitions)
	if t := lastTokenTs(tokenRows); t.After(asOf) {
		asOf = t
	}
	if len(actionTs) > 0 && actionTs[len(actionTs)-1].After(asOf) {
		asOf = actionTs[len(actionTs)-1]
	}

	summaries := taskflow.Summarize(transitions, asOf)
	summaryByKey := make(map[string]taskflow.TaskSummary, len(summaries))
	for _, s := range summaries {
		summaryByKey[s.Key] = s
	}

	perTask := buildTaskReportItems(&rep, items, summaryByKey)

	anyPriced := attributeTokenRows(&rep, perTask, attributor, tokenRows, costEngine)
	attributeActionTimestamps(&rep, perTask, attributor, actionTs)

	if !opts.IncludeSidechains {
		sideRows, serr := st.LoadSidechainOnlyTaskTokenRows(ctx, sessionID)
		if serr != nil {
			return rep, fmt.Errorf("taskreport.LoadSessionTaskReport: %w", serr)
		}
		if len(sideRows) > 0 {
			var side TaskCostBucket
			for _, tr := range sideRows {
				tot, rowCost, unpriced := priceTaskTokenRow(costEngine, tr)
				side.addRow(tot, rowCost, unpriced)
				if !unpriced {
					anyPriced = true
				}
			}
			rep.Sidechain = &side
		}
	}

	sort.SliceStable(rep.Items, func(i, j int) bool { return rep.Items[i].Order < rep.Items[j].Order })

	if anyPriced {
		rep.CostNote = taskCostNote
	}
	return rep, nil
}

// buildTaskReportItems populates rep.Items from task_items rows layered
// with their taskflow.Summarize lifecycle facts, and returns a
// key->*ReportItem index into rep.Items' backing array — valid
// because that slice is never appended to again after this call.
func buildTaskReportItems(rep *SessionTaskReport, items []store.TaskItemRow, summaryByKey map[string]taskflow.TaskSummary) map[string]*ReportItem {
	rep.Items = make([]ReportItem, 0, len(items))
	for _, it := range items {
		ri := ReportItem{
			Key: it.Key, KeyKind: it.KeyKind, Content: it.Content, ActiveForm: it.ActiveForm,
			Owner: it.Owner, Status: it.Status, RawStatus: it.RawStatus, Order: it.Order,
			Unmatched: it.Unmatched,
		}
		if sum, ok := summaryByKey[it.Key]; ok {
			ri.NeverActivated = sum.NeverActivated
			ri.StillOpen = sum.StillOpen
			ri.ElapsedSeconds = sum.Elapsed.Seconds()
			ri.TerminalStatus = sum.TerminalStatus
			if sum.FirstInProgress != nil {
				u := sum.FirstInProgress.Unix()
				ri.FirstInProgressUnix = &u
			}
			if sum.TerminalAt != nil {
				u := sum.TerminalAt.Unix()
				ri.TerminalAtUnix = &u
			}
		}
		rep.Items = append(rep.Items, ri)
	}
	perTask := make(map[string]*ReportItem, len(rep.Items))
	for i := range rep.Items {
		perTask[rep.Items[i].Key] = &rep.Items[i]
	}
	return perTask
}

// attributeTokenRows classifies every token_usage row through attributor
// and folds it into the matching per-task item or the between_tasks/
// shared bucket on rep, pricing each row via priceTaskTokenRow. Returns
// whether at least one row was successfully priced (for CostNote).
func attributeTokenRows(rep *SessionTaskReport, perTask map[string]*ReportItem, attributor *taskflow.Attributor, tokenRows []store.TaskTokenRow, costEngine *cost.Engine) bool {
	var anyPriced bool
	for _, tr := range tokenRows {
		tot, rowCost, unpriced := priceTaskTokenRow(costEngine, tr)
		if !unpriced {
			anyPriced = true
		}
		switch a := attributor.At(tr.Ts); a.Bucket {
		case taskflow.BucketSingle:
			if ri, ok := perTask[a.Key]; ok {
				ri.addRow(tot, rowCost, unpriced)
			}
		case taskflow.BucketShared:
			rep.Shared.addRow(tot, rowCost, unpriced)
		default:
			rep.BetweenTasks.addRow(tot, rowCost, unpriced)
		}
	}
	return anyPriced
}

// attributeActionTimestamps is attributeTokenRows' action-count sibling
// — no tokens/cost, just a per-bucket count.
func attributeActionTimestamps(rep *SessionTaskReport, perTask map[string]*ReportItem, attributor *taskflow.Attributor, actionTs []time.Time) {
	for _, ts := range actionTs {
		switch a := attributor.At(ts); a.Bucket {
		case taskflow.BucketSingle:
			if ri, ok := perTask[a.Key]; ok {
				ri.ActionsCount++
			}
		case taskflow.BucketShared:
			rep.Shared.ActionsCount++
		default:
			rep.BetweenTasks.ActionsCount++
		}
	}
}

// priceTaskTokenRow implements the exact "recorded cost wins, else
// price at the row's own timestamp" rule internal/intelligence/
// dashboard/live.go:203-214 already established for the session-level
// cost summary — one row, priced honestly. unpriced=true means the row
// contributed ZERO tokens' worth of cost information (no recorded cost
// AND no pricing-table entry for its model): the caller must not treat
// that 0.0 as a real cost.
func priceTaskTokenRow(costEngine *cost.Engine, tr store.TaskTokenRow) (tot TaskTokenTotals, rowCost float64, unpriced bool) {
	tot = TaskTokenTotals{
		InputTokens:      tr.InputTokens,
		OutputTokens:     tr.OutputTokens,
		CacheReadTokens:  tr.CacheReadTokens,
		CacheWriteTokens: tr.CacheWriteTokens + tr.CacheWrite1hTokens,
		ReasoningTokens:  tr.ReasoningTokens,
	}
	if tr.RecordedCostUSD > 0 {
		return tot, tr.RecordedCostUSD, false
	}
	if costEngine == nil {
		return tot, 0, true
	}
	bundle := cost.TokenBundle{
		Input: tr.InputTokens, Output: tr.OutputTokens, CacheRead: tr.CacheReadTokens,
		CacheCreation: tr.CacheWriteTokens, CacheCreation1h: tr.CacheWrite1hTokens,
		Reasoning: tr.ReasoningTokens, WebSearchRequests: tr.WebSearchRequests,
	}
	p, ok := costEngine.LookupAt(tr.Model, tr.Ts)
	if !ok {
		return tot, 0, true
	}
	return tot, cost.Compute(p, bundle), false
}

func lastTransitionTs(transitions []taskflow.Transition) time.Time {
	var latest time.Time
	for _, tr := range transitions {
		if tr.Ts.After(latest) {
			latest = tr.Ts
		}
	}
	return latest
}

func lastTokenTs(rows []store.TaskTokenRow) time.Time {
	var latest time.Time
	for _, r := range rows {
		if r.Ts.After(latest) {
			latest = r.Ts
		}
	}
	return latest
}

// ToolTaskRollup is one tool's slice of a TaskRollup — the "which AI
// tool's task tracking is actually costing me" breakdown a Tasks page
// needs beside the session-scoped detail.
type ToolTaskRollup struct {
	Tool     string  `json:"tool"`
	Sessions int     `json:"sessions"`
	Tasks    int     `json:"tasks"`
	CostUSD  float64 `json:"cost_usd"`
	// Unpriced mirrors TaskCostBucket.Unpriced at tool granularity: true
	// when at least one row folded into this tool's CostUSD (any task's
	// attributed_single row, or its sessions' between_tasks/shared
	// buckets) had neither a recorded provider cost nor a pricing-table
	// entry for its model. CostUSD is then a known UNDER-count for this
	// tool — a surface must render "unpriced" rather than implying
	// CostUSD (possibly $0.00) is the true total.
	Unpriced bool `json:"unpriced"`
}

// TaskLifecycleCounts tallies task_items across every session the
// rollup covers, by taskflow.TaskSummary's own lifecycle facts —
// Created is simply len(items) per session, summed.
type TaskLifecycleCounts struct {
	Created        int `json:"created"`
	Completed      int `json:"completed"`
	Cancelled      int `json:"cancelled"`
	NeverActivated int `json:"never_activated"`
	StillOpen      int `json:"still_open"`
	// Unmatched is the §R2.3.7 caveat #4 substrate, rollup-wide.
	// AllSessionsKeysNative mirrors SessionTaskReport.AllKeysNative —
	// true only when EVERY session in the rollup used a genuinely
	// keyed tool, letting a rollup surface suppress the caveat exactly
	// like the session-detail one does.
	Unmatched             int  `json:"unmatched"`
	AllSessionsKeysNative bool `json:"all_sessions_keys_native"`
}

// TaskRollup is GET /api/tasks's payload — a project/tool/window
// aggregate built by folding LoadSessionTaskReport across every
// session SessionsWithTasksInWindow returns. See that function's doc
// comment for why this is a per-session fold rather than a single SQL
// aggregation: pricing needs the ladder applied per token_usage row at
// the row's own timestamp, which only LoadSessionTaskReport already
// knows how to do correctly.
type TaskRollup struct {
	SinceUnix *int64 `json:"since_unix,omitempty"`
	UntilUnix *int64 `json:"until_unix,omitempty"`
	ProjectID int64  `json:"project_id,omitempty"`
	// ProjectRoot / Tool echo the string-keyed filters a caller passed
	// in (the dashboard's global Analysis-page project/tool filters,
	// which key on a project's root_path and a session's tool string —
	// NOT the numeric ProjectID above, which nothing in the frontend
	// resolves to; see LoadTaskRollup's doc comment).
	ProjectRoot       string `json:"project_root,omitempty"`
	Tool              string `json:"tool,omitempty"`
	SessionsWithTasks int    `json:"sessions_with_tasks"`

	AttributedSingle TaskCostBucket `json:"attributed_single"`
	BetweenTasks     TaskCostBucket `json:"between_tasks"`
	Shared           TaskCostBucket `json:"shared"`

	Counts TaskLifecycleCounts `json:"counts"`
	ByTool []ToolTaskRollup    `json:"by_tool"`

	CostNote string `json:"cost_note,omitempty"`
}

// LoadTaskRollup builds the project/tool/window rollup for GET
// /api/tasks. since/until zero means "no bound" on that side
// (windowRange's own convention); projectID<=0 means "every project".
// projectRoot/tool are the same string-keyed filters every other
// Analysis-page endpoint accepts (analysisScopeClause's `project`/`tool`
// query params — the dashboard's global project filter is a root-path
// STRING, it never resolves to a numeric project id) — empty means "no
// filter" on that dimension; they compose with projectID (AND, not
// OR) when a caller happens to pass both. opts carries
// [tasks].match_mode/.concurrent_attribution/.include_sidechains,
// threaded into every LoadSessionTaskReport call this fold makes — see
// that function's doc comment for why it is an explicit parameter
// rather than read off st.
func LoadTaskRollup(ctx context.Context, st *store.Store, costEngine *cost.Engine, since, until time.Time, projectID int64, projectRoot, tool string, opts taskflow.Options) (TaskRollup, error) {
	rollup := TaskRollup{ProjectID: projectID, ProjectRoot: projectRoot, Tool: tool}
	if !since.IsZero() {
		u := since.Unix()
		rollup.SinceUnix = &u
	}
	if !until.IsZero() {
		u := until.Unix()
		rollup.UntilUnix = &u
	}

	refs, err := st.SessionsWithTasksInWindow(ctx, since, until, projectID, projectRoot, tool)
	if err != nil {
		return rollup, fmt.Errorf("taskreport.LoadTaskRollup: %w", err)
	}
	rollup.SessionsWithTasks = len(refs)
	if len(refs) == 0 {
		return rollup, nil
	}

	byTool := make(map[string]*ToolTaskRollup)
	rollup.Counts.AllSessionsKeysNative = true
	var anyPriced bool

	for _, ref := range refs {
		rep, err := LoadSessionTaskReport(ctx, st, costEngine, ref.SessionID, opts)
		if err != nil {
			return rollup, fmt.Errorf("taskreport.LoadTaskRollup: session %s: %w", ref.SessionID, err)
		}
		if !rep.HasTasks {
			continue // race: task_items existed at the SessionsWithTasksInWindow scan, gone since (pruned).
		}
		if rep.CostNote != "" {
			anyPriced = true
		}
		if !rep.AllKeysNative {
			rollup.Counts.AllSessionsKeysNative = false
		}
		rollup.Counts.Unmatched += rep.UnmatchedCount

		tr := byTool[ref.Tool]
		if tr == nil {
			tr = &ToolTaskRollup{Tool: ref.Tool}
			byTool[ref.Tool] = tr
		}
		tr.Sessions++
		tr.Tasks += len(rep.Items)

		for _, item := range rep.Items {
			rollup.Counts.Created++
			switch {
			case item.NeverActivated:
				rollup.Counts.NeverActivated++
			case item.StillOpen:
				rollup.Counts.StillOpen++
			case item.TerminalStatus == taskflow.StatusCompleted:
				rollup.Counts.Completed++
			case item.TerminalStatus == taskflow.StatusCancelled:
				rollup.Counts.Cancelled++
			}
			rollup.AttributedSingle.addRow(item.Tokens, item.CostUSD, item.Unpriced)
			rollup.AttributedSingle.ActionsCount += item.ActionsCount
			tr.CostUSD += item.CostUSD
			if item.Unpriced {
				tr.Unpriced = true
			}
		}
		rollup.BetweenTasks.addRow(rep.BetweenTasks.Tokens, rep.BetweenTasks.CostUSD, rep.BetweenTasks.Unpriced)
		rollup.BetweenTasks.ActionsCount += rep.BetweenTasks.ActionsCount
		rollup.Shared.addRow(rep.Shared.Tokens, rep.Shared.CostUSD, rep.Shared.Unpriced)
		rollup.Shared.ActionsCount += rep.Shared.ActionsCount
		tr.CostUSD += rep.BetweenTasks.CostUSD + rep.Shared.CostUSD
		if rep.BetweenTasks.Unpriced || rep.Shared.Unpriced {
			tr.Unpriced = true
		}
	}

	rollup.ByTool = make([]ToolTaskRollup, 0, len(byTool))
	for _, tr := range byTool {
		rollup.ByTool = append(rollup.ByTool, *tr)
	}
	// Cost descending, tool name as a stable tiebreak — the most
	// informative ordering first (the dashboard's per-task table sorts
	// the same way, TasksTab.tsx's own comment: "51% of tasks are
	// sub-minute flips, so cost is the more informative primary
	// ordering").
	sort.Slice(rollup.ByTool, func(i, j int) bool {
		if rollup.ByTool[i].CostUSD != rollup.ByTool[j].CostUSD {
			return rollup.ByTool[i].CostUSD > rollup.ByTool[j].CostUSD
		}
		return rollup.ByTool[i].Tool < rollup.ByTool[j].Tool
	})

	if anyPriced {
		rollup.CostNote = taskCostNote
	}
	return rollup, nil
}
