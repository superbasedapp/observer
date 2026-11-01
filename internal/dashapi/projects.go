package dashapi

import (
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

var PromptLinkCap = 10000

var EditLinkCap = 100000

var CommitLinkCap = 5000

// apiProjectCaptureInfo is the plan's `capture` shape - used both as
// ProjectDetail's required field and, as a pointer, ProjectRow's
// optional list-level field (dashboard.go's handleProjects).
type APIProjectCaptureInfo struct {
	Commits  string `json:"commits"`
	HumanLOC string `json:"human_loc"`
	// CommitsKind names the failure when Commits is "error" (timeout,
	// dubious_ownership, permission_denied, repo_unreadable,
	// output_too_large, other). Additive (2026-10-15).
	CommitsKind string `json:"commits_kind,omitempty"`
	// CommitScan is the detail surface's full scan health (the detail
	// response only; the list omits it).
	CommitScan *APICommitScanInfo `json:"commit_scan,omitempty"`
}

// APICommitScanInfo is one project's commit-scan health on the Project
// detail panel: what failed (Detail is git's own message), the root the
// scanner runs git in (ScanRoot differs from the stored root when a
// Windows path is translated for a WSL daemon), when the last attempt and
// the last success were, and whether "Rescan now" is available.
type APICommitScanInfo struct {
	Kind           string `json:"kind,omitempty"`
	Detail         string `json:"detail,omitempty"`
	ScanRoot       string `json:"scan_root,omitempty"`
	LastScanAt     string `json:"last_scan_at,omitempty"`
	LastSuccessAt  string `json:"last_success_at,omitempty"`
	Failures       int    `json:"failures"`
	HistoryPending bool   `json:"history_pending"`
	CanRescan      bool   `json:"can_rescan"`
}

type APIProjectCostBucketRow struct {
	Key     string  `json:"key"`
	Label   string  `json:"label,omitempty"`
	CostUSD float64 `json:"cost_usd"`
	Turns   int     `json:"turns,omitempty"`
	Count   int     `json:"count,omitempty"`
	// UnpricedTurns is how many of this bucket's turns carry NO price
	// (no recorded cost, no pricing entry for the model) - the bucket's
	// cost_usd is a floor, not an exact figure, whenever it is > 0
	// (SOL-R13). Omitted when every turn priced.
	UnpricedTurns int `json:"unpriced_turns,omitempty"`
	// AISplit is the session's AI-authored code-vs-comment split
	// (internal/loc.SplitAuthored over projectroi.Edit.CodeLines /
	// CommentLines), set ONLY on /cost?by=session rows and omitted when
	// the session authored no code or comment lines.
	AISplit *loc.AuthoredSplit `json:"ai_split,omitempty"`
}

type apiProjectSpendByDay struct {
	Day     string  `json:"day"`
	CostUSD float64 `json:"cost_usd"`
	// UnpricedTurns counts this day's turns with no recorded cost and no
	// pricing entry for their model (2026-09-22 rework finding S5): the
	// day's cost_usd is a floor, not an exact figure, whenever this is
	// nonzero. Omitted when every turn priced.
	UnpricedTurns int `json:"unpriced_turns,omitempty"`
}

type apiProjectSpendBySession struct {
	ID        string  `json:"id"`
	Tool      string  `json:"tool"`
	StartedAt string  `json:"started_at"`
	CostUSD   float64 `json:"cost_usd"`
	Turns     int     `json:"turns"`
	Prompts   int     `json:"prompts"`
	// AILines is this session's AI-authored CODE lines (added + modified,
	// code-category files only - projectroi.Edit.CodeLines). Before
	// 2026-09-28 it summed docs and config lines in too.
	AILines int `json:"ai_lines"`
	// AISplit is the code-vs-comment split of the same edits
	// (internal/loc.SplitAuthored, the one derivation).
	AISplit       loc.AuthoredSplit `json:"ai_split"`
	CommitsLinked int               `json:"commits_linked"`
	// UnpricedTurns counts this session's turns with no recorded cost and
	// no pricing entry for their model (2026-09-22 rework finding S5) -
	// same honesty contract as apiProjectSpendByDay.UnpricedTurns.
	UnpricedTurns int `json:"unpriced_turns,omitempty"`
}

type apiProjectDetailSpend struct {
	TotalUSD float64 `json:"total_usd"`
	// UnpricedTurns counts turns in the window with no recorded cost and
	// no pricing entry for their model (loadProjectSpend); omitted when
	// zero. The page names it so a low total is never mistaken for a
	// priced one.
	UnpricedTurns int                        `json:"unpriced_turns,omitempty"`
	ByTool        []APIProjectCostBucketRow  `json:"by_tool"`
	ByModel       []APIProjectCostBucketRow  `json:"by_model"`
	ByDay         []apiProjectSpendByDay     `json:"by_day"`
	BySession     []apiProjectSpendBySession `json:"by_session"`
}

type apiProjectRoiTile struct {
	Key       string  `json:"key"`
	Label     string  `json:"label"`
	Value     float64 `json:"value"`
	Unit      string  `json:"unit"`
	Formula   string  `json:"formula"`
	Caveat    string  `json:"caveat,omitempty"`
	Available bool    `json:"available"`
}

type apiProjectMeta struct {
	ID        int64    `json:"id"`
	RootPath  string   `json:"root_path"`
	GitRemote string   `json:"git_remote,omitempty"`
	Name      string   `json:"name,omitempty"`
	Tools     []string `json:"tools"`
	FirstSeen string   `json:"first_seen,omitempty"`
	LastSeen  string   `json:"last_seen,omitempty"`
}

type APIProjectDetail struct {
	Project apiProjectMeta        `json:"project"`
	Spend   apiProjectDetailSpend `json:"spend"`
	LOC     struct {
		// AIAdded / AIModified are AI-authored CODE lines (code-category
		// files only since 2026-09-28; docs/config lines used to be summed
		// in and dominated the figure on docs-heavy repositories).
		AIAdded    int `json:"ai_added"`
		AIModified int `json:"ai_modified"`
		// AIComment is the AI-added comment lines over the same rows, and
		// AISplit the code-vs-comment split (internal/loc.SplitAuthored).
		// Neither needs human measurement, so both are honest even where
		// HumanCapture is "none".
		AIComment    int               `json:"ai_comment"`
		AISplit      loc.AuthoredSplit `json:"ai_split"`
		HumanCapture string            `json:"human_capture"`
	} `json:"loc"`
	Commits struct {
		Count        int     `json:"count"`
		AITouched    int     `json:"ai_touched"`
		WithSpendUSD float64 `json:"with_spend_usd"`
	} `json:"commits"`
	Tasks struct {
		Total   int     `json:"total"`
		Done    int     `json:"done"`
		CostUSD float64 `json:"cost_usd"`
		// Available is false when the lifecycle task rollup could not be
		// loaded and the figures above fell back to the raw task_items
		// rows (a different count than the Tasks tab renders) with
		// cost_usd = 0 - an honest "degraded source" signal (SOL-F11),
		// never rendered as "zero tasks".
		Available bool `json:"available"`
	} `json:"tasks"`
	ROI        []apiProjectRoiTile   `json:"roi"`
	Capture    APIProjectCaptureInfo `json:"capture"`
	WindowDays int                   `json:"window_days"`
	Truncated  bool                  `json:"truncated,omitempty"`
}

func FmtProjectTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// commitAgg is the per-commit AI-attribution rollup handleProjectDetail/
// handleProjectCommits derive from a Linkage: the distinct AI-touched
// files that reached this commit, and the AI-authored CODE lines (added +
// modified, code files only) and comment lines carried with them.
type commitAgg struct {
	AIFiles   map[string]bool
	AILines   int
	AIComment int
}

func AggregateByCommit(linkage projectroi.Linkage) map[int64]*commitAgg {
	out := make(map[int64]*commitAgg)
	for _, chain := range linkage.Chains {
		for _, f := range chain.Files {
			if f.Superseded || f.CommitID == 0 {
				continue
			}
			a, ok := out[f.CommitID]
			if !ok {
				a = &commitAgg{AIFiles: map[string]bool{}}
				out[f.CommitID] = a
			}
			a.AIFiles[f.PathHash] = true
			a.AILines += f.Added + f.Modified
			a.AIComment += f.Comment
		}
	}
	return out
}

// bucketCost sums turn cost by an arbitrary key (tool or model),
// descending by cost - the most informative ordering first, same
// convention as taskreport.LoadTaskRollup's ByTool.
func BucketCost(turns []projectroi.Turn, keyFn func(projectroi.Turn) string) []APIProjectCostBucketRow {
	type agg struct {
		cost     float64
		turns    int
		unpriced int
	}
	m := make(map[string]*agg)
	var order []string
	for _, t := range turns {
		k := keyFn(t)
		if k == "" {
			k = "unknown"
		}
		a, ok := m[k]
		if !ok {
			a = &agg{}
			m[k] = a
			order = append(order, k)
		}
		a.cost += t.CostUSD
		a.turns++
		if !t.Priced {
			a.unpriced++
		}
	}
	rows := make([]APIProjectCostBucketRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, APIProjectCostBucketRow{Key: k, CostUSD: m[k].cost, Turns: m[k].turns, UnpricedTurns: m[k].unpriced})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CostUSD > rows[j].CostUSD })
	return rows
}

func BucketCostByDay(turns []projectroi.Turn) []apiProjectSpendByDay {
	m := make(map[string]float64)
	unpriced := make(map[string]int)
	for _, t := range turns {
		d := t.At.UTC().Format("2006-01-02")
		m[d] += t.CostUSD
		if !t.Priced {
			unpriced[d]++
		}
	}
	days := make([]string, 0, len(m))
	for d := range m {
		days = append(days, d)
	}
	sort.Strings(days)
	rows := make([]apiProjectSpendByDay, 0, len(days))
	for _, d := range days {
		rows = append(rows, apiProjectSpendByDay{Day: d, CostUSD: m[d], UnpricedTurns: unpriced[d]})
	}
	return rows
}

// buildBySession composes the by-session spend rows. promptsPerSession
// is the UNCAPPED per-session prompt count (store.LoadProjectPromptCounts),
// deliberately not derived from the capped newest-500 prompt slice the
// chains use, so an older session in a busy window shows its real count
// rather than 0 (F5 of the 2026-09-22 arc review); commits_linked and
// ai_lines still come from the capped slices, as the page's truncation
// banner states.
func buildBySession(sessions []projectroi.Session, turns []projectroi.Turn, promptsPerSession map[string]int, edits []projectroi.Edit, linkage projectroi.Linkage) []apiProjectSpendBySession {
	turnsPerSession := make(map[string]int)
	unpricedPerSession := make(map[string]int)
	for _, t := range turns {
		if t.SessionID != "" {
			turnsPerSession[t.SessionID]++
			if !t.Priced {
				unpricedPerSession[t.SessionID]++
			}
		}
	}
	// Edit.CodeLines / CommentLines, never AddedCode+ModifiedCode: a docs
	// or config file's lines are not code (the pre-2026-09-28 sum here
	// counted them, so a docs-heavy session's "AI lines" was mostly prose).
	aiLinesPerSession := make(map[string]int)
	aiCommentPerSession := make(map[string]int)
	for _, e := range edits {
		aiLinesPerSession[e.SessionID] += e.CodeLines()
		aiCommentPerSession[e.SessionID] += e.CommentLines()
	}
	commitsPerSession := make(map[string]map[int64]bool)
	for _, chain := range linkage.Chains {
		for _, cc := range chain.Commits {
			set := commitsPerSession[chain.Prompt.SessionID]
			if set == nil {
				set = make(map[int64]bool)
				commitsPerSession[chain.Prompt.SessionID] = set
			}
			set[cc.ID] = true
		}
	}

	out := make([]apiProjectSpendBySession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, apiProjectSpendBySession{
			ID:            sess.ID,
			Tool:          sess.Tool,
			StartedAt:     FmtProjectTime(sess.StartedAt),
			CostUSD:       sess.CostUSD,
			Turns:         turnsPerSession[sess.ID],
			Prompts:       promptsPerSession[sess.ID],
			AILines:       aiLinesPerSession[sess.ID],
			AISplit:       loc.SplitAuthored(int64(aiLinesPerSession[sess.ID]), int64(aiCommentPerSession[sess.ID])),
			CommitsLinked: len(commitsPerSession[sess.ID]),
			UnpricedTurns: unpricedPerSession[sess.ID],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CostUSD > out[j].CostUSD })
	return out
}

// toRoiTiles maps internal/projectroi.Proxies' output onto the wire
// shape, translating the pure package's "ratio" unit to the tile
// renderer's "pct" (web/src/components/projectdetail/OverviewTab.tsx's
// fmtRoiValue: `unit === "pct"` multiplies the value by 100 itself via
// fmtPct's default fromFraction=true - so the VALUE here stays the raw
// [0,1] fraction; it must NOT be pre-multiplied by 100, or the tile
// would render 100x too large).
func toRoiTiles(proxies []projectroi.Proxy) []apiProjectRoiTile {
	out := make([]apiProjectRoiTile, 0, len(proxies))
	for _, p := range proxies {
		unit := p.Unit
		if unit == projectroi.UnitRatio {
			unit = "pct"
		}
		out = append(out, apiProjectRoiTile{
			Key: p.Key, Label: p.Label, Value: p.Value, Unit: unit,
			Formula: p.Formula, Caveat: p.Caveat, Available: p.Available,
		})
	}
	return out
}
