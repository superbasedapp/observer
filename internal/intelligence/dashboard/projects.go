package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/taskreport"
)

// projects.go serves the Projects-page ROI + commit-alignment detail
// surfaces (docs/plans/projects-page-roi-and-commit-alignment-plan-
// 2026-09-21.md §3.4, wave W3): GET /api/project/{id}[/commits|/prompts|
// /cost] and POST /api/project/{id}/prompts/{action_id}/grade. The list
// endpoint (/api/projects, secNone) is extended additively in
// dashboard.go's handleProjects; everything here is secProjects.
//
// Every handler composes plain rows loaded by internal/store/
// projectroi.go into internal/projectroi's pure Link/AttributeSpend/
// Proxies pipeline, then shapes the result into the frozen wire types
// web/src/lib/types.ts already codes against (ProjectDetail,
// ProjectCommitRow, ProjectPromptRow, ProjectCostBucketRow, the grade
// types). Wire types are declared here as apiProject* structs with
// explicit json tags — snake_case throughout, nil slices/maps are never
// serialized (every list field is initialized non-nil so it encodes as
// `[]`, never `null`).

// Request-time caps (plan R11). The LINK caps bound what feeds
// projectroi.Link (a map-keyed join: 5k x 5k x 20k ran in ~53 ms, so
// these are memory bounds, not CPU ones); the ROWS caps bound what one
// ledger request RETURNS. Raised from 500/20,000/500 on 2026-09-22 after
// the live corpus showed this repository alone has ~7k prompts in 30 days
// - the newest-500 slice covered two of the thirty days and made every
// linkage-dependent ROI proxy a cap artifact. When a cap is still hit
// the response says so (`truncated`) and the affected tiles carry the
// caveat.
//
// var, not const: projects_test.go overrides these (save/restore around
// one test) to force a cap hit deterministically without seeding
// thousands of rows — the 2026-09-22 rework's SOL-F10 regression
// coverage. Production code never mutates them.
var (
	promptRowsCap = 500
	commitRowsCap = 500
)

// apiTruncationMeta is the additive truncation signal every secondary
// Projects-page endpoint (/commits, /prompts, /cost?by=commit) embeds
// into its `{rows: [...]}` payload when one or more of the capped
// loaders feeding it (promptLinkCap/editLinkCap/commitLinkCap) actually
// hit their cap (SOL-F10, 2026-09-22 rework: these endpoints used to
// discard the store loaders' own `truncated` bool and return only
// `rows`, so a tab could present partial prompt-to-commit linkage as
// complete with no signal at all — OverviewTab's `truncated` banner
// only ever covered GET /api/project/{id} itself, never these three).
// Anonymously embedded so its fields flatten into the parent JSON object
// (encoding/json promotes an embedded struct's exported fields) — the
// wire shape stays additive, never a nested object callers must unwrap.
// Zero value serializes to nothing (every field is `omitempty`), so an
// untruncated response is byte-identical to before this fix.
type apiTruncationMeta struct {
	Truncated bool `json:"truncated,omitempty"`
	// TruncatedInputs names which capped loader(s) actually hit their
	// cap — e.g. ["prompts","edits"] — never a blanket "something was
	// capped" flag; a caller/operator can tell exactly which slice to
	// distrust.
	TruncatedInputs []string `json:"truncated_inputs,omitempty"`
	// Affects names which OUTPUT fields on this response's rows are a
	// known undercount/partial view as a result — e.g. ["ai_lines",
	// "spend_usd"] — so a tab can caveat exactly those columns rather
	// than a generic "some data may be missing" sentence.
	Affects []string `json:"affects,omitempty"`
}

// truncatedInput names one capped loader this endpoint called, and
// whether IT actually hit its cap — the input to buildTruncationMeta.
type truncatedInput struct {
	name      string
	truncated bool
}

// buildTruncationMeta composes apiTruncationMeta from the set of capped
// loaders one handler called: empty (the zero value, which omits every
// field) when none of them actually truncated, so an untruncated
// response's JSON is unchanged.
func buildTruncationMeta(affects []string, inputs ...truncatedInput) apiTruncationMeta {
	var names []string
	for _, in := range inputs {
		if in.truncated {
			names = append(names, in.name)
		}
	}
	if len(names) == 0 {
		return apiTruncationMeta{}
	}
	return apiTruncationMeta{Truncated: true, TruncatedInputs: names, Affects: affects}
}

// --- wire types (web/src/lib/types.ts §"Projects ROI + commit-alignment") ---

type apiProjectCommitPrompt struct {
	ActionID  int64  `json:"action_id"`
	SessionID string `json:"session_id"`
	At        string `json:"at"`
	Preview   string `json:"preview"`
}

type apiProjectCommitRow struct {
	ID          int64  `json:"id"`
	SHA         string `json:"sha"`
	Subject     string `json:"subject"`
	CommittedAt string `json:"committed_at"`
	AuthorHash  string `json:"author_hash"`
	IsMerge     bool   `json:"is_merge"`
	Reachable   bool   `json:"reachable"`
	Files       int    `json:"files"`
	Added       int    `json:"added"`
	Deleted     int    `json:"deleted"`
	AIFiles     int    `json:"ai_files"`
	// AILines is the AI-authored CODE lines (added + modified, code files
	// only) this commit carried; AICommentLines the added comment lines
	// over the same carried pairs, and AISplit their split
	// (internal/loc.SplitAuthored).
	AILines        int                      `json:"ai_lines"`
	AICommentLines int                      `json:"ai_comment_lines"`
	AISplit        loc.AuthoredSplit        `json:"ai_split"`
	SpendUSD       float64                  `json:"spend_usd"`
	Prompts        []apiProjectCommitPrompt `json:"prompts"`
	// Owner is the commit's owning session (docs/projects-page.md "Commit
	// ownership"), always present: a commit with no owner carries an
	// empty session_id and a none reason, never a guessed session.
	Owner apiCommitOwner `json:"owner"`
}

// apiCommitContributor is one session's contribution to one commit
// (projectroi.CommitContributor on the wire).
type apiCommitContributor struct {
	SessionID string `json:"session_id"`
	// Share is this session's share of the commit on the owner's
	// share_basis; a commit's contributors sum to 1.
	Share         float64           `json:"share"`
	CodeLines     int               `json:"code_lines"`
	CommentLines  int               `json:"comment_lines"`
	Split         loc.AuthoredSplit `json:"split"`
	Files         int               `json:"files"`
	Prompts       int               `json:"prompts"`
	FirstPromptAt string            `json:"first_prompt_at,omitempty"`
}

// apiCommitOwner is projectroi.CommitOwnership on the wire. Reason and
// ShareBasis carry the projectroi constants verbatim (OwnerNone*/Owner*,
// ShareBasis*).
type apiCommitOwner struct {
	SessionID    string                 `json:"session_id,omitempty"`
	Reason       string                 `json:"reason"`
	ShareBasis   string                 `json:"share_basis,omitempty"`
	Contributors []apiCommitContributor `json:"contributors"`
}

// toAPICommitOwner shapes one ownership outcome for the wire.
func toAPICommitOwner(o projectroi.CommitOwnership) apiCommitOwner {
	out := apiCommitOwner{
		SessionID: o.OwnerSessionID, Reason: o.Reason, ShareBasis: o.ShareBasis,
		Contributors: make([]apiCommitContributor, 0, len(o.Contributors)),
	}
	for _, c := range o.Contributors {
		out.Contributors = append(out.Contributors, apiCommitContributor{
			SessionID: c.SessionID, Share: c.Share, CodeLines: c.CodeLines, CommentLines: c.CommentLines,
			Split: loc.SplitAuthored(int64(c.CodeLines), int64(c.CommentLines)),
			Files: c.Files, Prompts: c.Prompts, FirstPromptAt: dashapi.FmtProjectTime(c.FirstPromptAt),
		})
	}
	return out
}

// apiProjectPromptEdits is one prompt's post-supersede reach set. Files
// counts every AI-touched file (docs and config included - file-level
// reach); Added / Modified / Comment are CODE-file lines only
// (projectroi.ChainFile), and Split their code-vs-comment split.
type apiProjectPromptEdits struct {
	Files    int               `json:"files"`
	Added    int               `json:"added"`
	Modified int               `json:"modified"`
	Comment  int               `json:"comment"`
	Split    loc.AuthoredSplit `json:"split"`
}

type apiProjectPromptCommitRef struct {
	ID          int64   `json:"id"`
	SHA         string  `json:"sha"`
	Subject     string  `json:"subject"`
	CommittedAt string  `json:"committed_at"`
	Share       float64 `json:"share"`
}

type apiProjectPromptAlignment struct {
	Tier       string   `json:"tier"`
	Delivered  []string `json:"delivered"`
	Missed     []string `json:"missed"`
	Extra      []string `json:"extra"`
	Confidence float64  `json:"confidence,omitempty"`
	GradedAt   string   `json:"graded_at,omitempty"`
	Model      string   `json:"model,omitempty"`
}

type apiProjectPromptGradeAvailable struct {
	Judge  bool   `json:"judge"`
	Cloud  bool   `json:"cloud"`
	Reason string `json:"reason,omitempty"`
}

type apiProjectPromptRow struct {
	ActionID  int64                       `json:"action_id"`
	SessionID string                      `json:"session_id"`
	Tool      string                      `json:"tool"`
	At        string                      `json:"at"`
	Preview   string                      `json:"preview"`
	Edits     apiProjectPromptEdits       `json:"edits"`
	Commits   []apiProjectPromptCommitRef `json:"commits"`
	Status    string                      `json:"status"`
	// StatusUncertain is true when the edits and/or commits inputs
	// Link ran over this window were themselves capped (editLinkCap /
	// commitLinkCap) — Status is computed correctly over what THIS
	// request loaded, but a missing edit or commit outside the cap
	// could have changed it (most visibly: a real "committed"/"partial"
	// prompt reading as "uncommitted" because its carrying commit fell
	// outside commitLinkCap). SOL-F10, 2026-09-22 rework: the status
	// enum itself is left alone (its four other values are a closed set
	// the frontend keys UI off of) rather than inventing a fifth
	// "unknown (caps)" status string that would need threading through
	// every STATUS_VARIANT/STATUS_LABEL consumer.
	StatusUncertain bool                            `json:"status_uncertain,omitempty"`
	Alignment       *apiProjectPromptAlignment      `json:"alignment"`
	GradeAvailable  *apiProjectPromptGradeAvailable `json:"grade_available,omitempty"`
}

// --- secondary-endpoint response wrappers (SOL-F10, 2026-09-22 rework) ---
//
// Each embeds apiTruncationMeta anonymously so its truncated/
// truncated_inputs/affects fields flatten into the top-level `{rows:
// ...}` object — additive, and a no-op on the wire when nothing
// truncated (every field on the zero value is omitempty).

type apiProjectCommitsResponse struct {
	Rows []apiProjectCommitRow `json:"rows"`
	apiTruncationMeta
}

type apiProjectPromptsResponse struct {
	Rows []apiProjectPromptRow `json:"rows"`
	apiTruncationMeta
}

type apiProjectCostRowsResponse struct {
	Rows []dashapi.APIProjectCostBucketRow `json:"rows"`
	apiTruncationMeta
}

// --- helpers ---

// projectAuthoredSplit is internal/loc.AuthoredSplit, aliased so the
// /api/projects list row (declared in dashboard.go) can carry it without
// that file importing internal/loc for one field.
type projectAuthoredSplit = loc.AuthoredSplit

// optionalAuthoredSplit is an omitempty split (the list row's ai_split_30d,
// a /cost?by=session row's ai_split): nil when the scope holds no
// AI-authored code or comment lines, never a fabricated zero split (R7).
func optionalAuthoredSplit(codeLines, commentLines int) *projectAuthoredSplit {
	if codeLines <= 0 && commentLines <= 0 {
		return nil
	}
	split := loc.SplitAuthored(int64(codeLines), int64(commentLines))
	return &split
}

// parseProjectID reads the {id} path value as a positive numeric
// project id. Route ids are always numeric (plan §3.4); a non-numeric
// or non-positive value is treated as unknown (404), never a 400 — the
// wire contract has no other shape a caller could confuse this with.
func parseProjectID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// projectDetailWindow resolves the shared days/since/until triple every
// Projects-page detail route uses. It follows the page's global window
// through windowRange (since / hours / days, and a closed range's until;
// REVIEW-3 P3-25, T-485): `days` defaults to 30, capped at 365 (plan
// §3.4); an absent or malformed `until` means now. days is the window's
// whole-day span, for the responses that still report one.
func projectDetailWindow(r *http.Request) (since, until time.Time, days int) {
	since, until = windowRange(r, 30, 1, 365)
	if until.IsZero() {
		until = time.Now().UTC()
	}
	if since.IsZero() {
		since = until.Add(-30 * 24 * time.Hour)
	}
	days = windowSpanDays(since, until, 30)
	return since, until, days
}

// commitLinkWindow resolves the [projects].commit_link_window_days
// tunable this Server was constructed with, falling back to
// internal/projectroi.DefaultLinkWindow when unset — the same fallback
// projectroi.Options.window() applies internally, kept explicit here so
// every Link call site in this file agrees.
func (s *Server) commitLinkWindow() time.Duration {
	if s.opts.Projects.CommitLinkWindowDays <= 0 {
		return projectroi.DefaultLinkWindow
	}
	return time.Duration(s.opts.Projects.CommitLinkWindowDays) * 24 * time.Hour
}

// requireProject 404s the request when projectID is not a known
// project, otherwise returns silently (the caller proceeds). It is
// shared by every detail route so a bad/expired project id behaves
// identically everywhere.
func requireProject(ctx context.Context, w http.ResponseWriter, r *http.Request, st *store.Store, projectID int64) (store.ProjectMeta, bool) {
	meta, ok, err := st.LoadProjectMeta(ctx, projectID)
	if err != nil {
		writeErr(w, err)
		return store.ProjectMeta{}, false
	}
	if !ok {
		http.NotFound(w, r)
		return store.ProjectMeta{}, false
	}
	return meta, true
}

// commitOwnershipForRows folds commit ownership (projectroi.Ownership)
// over the SAME Linkage and link set the ledger already linked against -
// never a second link set, so a commit's owner can never disagree with its
// ai_files / ai_lines / prompts on the same row. A displayed commit that is
// outside the link set (possible only when the link cap sits below the row
// cap) is appended to the fold input as a commit Link never saw: the O1-O3
// gates decide its reason and it has no contributors, and the response's
// truncation meta names "owner" as affected whenever a link cap fired.
func commitOwnershipForRows(linkage projectroi.Linkage, linkCommits []projectroi.Commit, rows []store.ProjectCommitRow) map[int64]projectroi.CommitOwnership {
	in := make([]projectroi.Commit, len(linkCommits), len(linkCommits)+len(rows))
	copy(in, linkCommits)
	seen := make(map[int64]bool, len(linkCommits))
	for _, c := range linkCommits {
		seen[c.ID] = true
	}
	for _, r := range rows {
		if !seen[r.ID] {
			in = append(in, projectroi.Commit{ID: r.ID, SHA: r.SHA, CommittedAt: r.CommittedAt, IsMerge: r.IsMerge, Reachable: r.Reachable})
		}
	}
	return projectroi.Ownership(linkage, in)
}

func indexPromptsByAction(prompts []projectroi.Prompt) map[int64]projectroi.Prompt {
	out := make(map[int64]projectroi.Prompt, len(prompts))
	for _, p := range prompts {
		out[p.ActionID] = p
	}
	return out
}

// --- handlers ---

// handleProjectDetail serves GET /api/project/{id}?days=N — the
// OverviewTab/SpendTab landing payload (plan §3.4).
func (s *Server) handleProjectDetail(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
		return
	}
	since, until, days := projectDetailWindow(r)

	detail, err := ComposeProjectDetail(ctx, st, ProjectDetailInput{
		ProjectID: projectID, Days: days, Since: since, Until: until,
		LinkWindow: s.commitLinkWindow(), CostEngine: s.opts.CostEngine, Taskflow: s.taskflowOptions(),
		CanRescan: s.opts.CommitRescan != nil,
	})
	if err != nil {
		writeErr(w, err)
		return
	}

	writeJSON(w, detail)
}

// commitRescanWait is how long POST /api/project/{id}/commit-scan waits
// for the scan before answering "still running" (202); the scan keeps
// going on a detached context bounded by commitRescanLimit, and the page
// polls the detail endpoint until last_scan_at moves.
const (
	commitRescanWait  = 20 * time.Second
	commitRescanLimit = 5 * time.Minute
)

// commitRescanResponse is POST /api/project/{id}/commit-scan's body: Done
// is false when the scan is still running after commitRescanWait; Capture
// is the project's capture health as of the answer; Error is the scan's
// own error text when it failed (Capture then names the classified kind).
type commitRescanResponse struct {
	Done    bool                          `json:"done"`
	Error   string                        `json:"error,omitempty"`
	Capture dashapi.APIProjectCaptureInfo `json:"capture"`
}

// handleProjectCommitScan serves POST /api/project/{id}/commit-scan: the
// Projects page's "Rescan now", the dashboard twin of `observer backfill
// --commits --commits-project <id>`. It runs one read-only scan through
// Options.CommitRescan (the daemon's own scanner, so it never overlaps a
// tick) and answers with the fresh capture health. Local-only with the
// confirm token: it runs git on this machine.
func (s *Server) handleProjectCommitScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	st := store.New(s.db())
	meta, ok := requireProject(r.Context(), w, r, st, projectID)
	if !ok {
		return
	}
	if s.opts.CommitRescan == nil {
		http.Error(w, "commit scanning is not running in this process ([projects].commit_scan is off)", http.StatusServiceUnavailable)
		return
	}

	scanCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), commitRescanLimit)
	done := make(chan error, 1)
	go func() {
		defer cancel()
		done <- s.opts.CommitRescan(scanCtx, projectID)
	}()

	resp := commitRescanResponse{}
	timer := time.NewTimer(commitRescanWait)
	defer timer.Stop()
	select {
	case err := <-done:
		resp.Done = true
		if err != nil {
			resp.Error = err.Error()
		}
	case <-timer.C:
	case <-r.Context().Done():
		return
	}
	health, err := st.CommitScanHealth(r.Context(), projectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	resp.Capture = dashapi.APIProjectCaptureInfo{
		Commits:     health.State,
		CommitsKind: dashapi.CommitsKindFor(health),
		CommitScan:  dashapi.CommitScanInfo(health, meta.RootPath, true),
	}
	if !resp.Done {
		w.WriteHeader(http.StatusAccepted)
	}
	writeJSON(w, resp)
}

// handleProjectCommits serves GET /api/project/{id}/commits?days=&limit=
// — the commit ledger (plan §3.4).
func (s *Server) handleProjectCommits(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
		return
	}
	since, until, _ := projectDetailWindow(r)
	limit := intArg(r, "limit", commitRowsCap, 1, commitRowsCap)

	rawCommits, err := st.LoadProjectCommits(ctx, projectID, since, until, limit+1)
	if err != nil {
		writeErr(w, err)
		return
	}
	// commitRowsTruncated is the OUTPUT row cap (commitRowsCap, distinct
	// from the LINK caps below): the `limit+1` probe fetched one row past
	// what this response returns, so seeing more than `limit` rows back
	// means real commits in the window were left off this response
	// entirely — not just an undercount of a derived figure on the rows
	// that ARE shown. Before this fix (SOL-P2/F10 residue, 2026-09-22
	// rework) this fact was detected and silently discarded.
	commitRowsTruncated := len(rawCommits) > limit
	if commitRowsTruncated {
		rawCommits = rawCommits[:limit]
	}
	prompts, promptsTruncated, err := st.LoadProjectPrompts(ctx, projectID, since, until, dashapi.PromptLinkCap)
	if err != nil {
		writeErr(w, err)
		return
	}
	edits, editsTruncated, err := st.LoadProjectAIEdits(ctx, projectID, since, until, dashapi.EditLinkCap)
	if err != nil {
		writeErr(w, err)
		return
	}
	// The LINK set is the same newest-commitLinkCap slice every other view
	// links against (overview / prompts / cost?by=commit) - never the
	// displayed page's limit+1 - so a commit's attribution on this tab
	// cannot disagree with the same commit elsewhere (supersession and
	// per-file carrying depend on which OTHER commits are in the set).
	linkCommits, linkCommitsTruncated, err := st.LoadProjectCommitsForLink(ctx, projectID, since, until, dashapi.CommitLinkCap)
	if err != nil {
		writeErr(w, err)
		return
	}
	priced, err := dashapi.LoadProjectSpend(ctx, st, s.opts.CostEngine, projectID, since, until)
	if err != nil {
		writeErr(w, err)
		return
	}
	turns := priced.Turns

	linkage := projectroi.Link(prompts, edits, linkCommits, projectroi.Options{LinkWindow: s.commitLinkWindow()})
	spend := projectroi.AttributeSpend(linkage, turns, prompts)
	agg := dashapi.AggregateByCommit(linkage)
	promptByAction := indexPromptsByAction(prompts)
	ownership := commitOwnershipForRows(linkage, linkCommits, rawCommits)

	rows := make([]apiProjectCommitRow, 0, len(rawCommits))
	for _, c := range rawCommits {
		row := apiProjectCommitRow{
			ID: c.ID, SHA: c.SHA, Subject: c.Subject, CommittedAt: dashapi.FmtProjectTime(c.CommittedAt),
			AuthorHash: c.AuthorHash, IsMerge: c.IsMerge, Reachable: c.Reachable,
			Files: c.FilesCount, Added: c.Added, Deleted: c.Deleted,
			SpendUSD: spend.ByCommit[c.ID],
			Prompts:  []apiProjectCommitPrompt{},
		}
		if a := agg[c.ID]; a != nil {
			row.AIFiles = len(a.AIFiles)
			row.AILines = a.AILines
			row.AICommentLines = a.AIComment
		}
		row.AISplit = loc.SplitAuthored(int64(row.AILines), int64(row.AICommentLines))
		row.Owner = toAPICommitOwner(ownership[c.ID])
		for _, actionID := range linkage.ByCommit[c.ID] {
			p, ok := promptByAction[actionID]
			if !ok {
				continue
			}
			row.Prompts = append(row.Prompts, apiProjectCommitPrompt{
				ActionID: p.ActionID, SessionID: p.SessionID, At: dashapi.FmtProjectTime(p.At), Preview: p.Preview,
			})
		}
		sort.Slice(row.Prompts, func(i, j int) bool { return row.Prompts[i].At < row.Prompts[j].At })
		rows = append(rows, row)
	}

	// affects is built conditionally, not a fixed list — "commit_rows"
	// (the OUTPUT cap, commitRowsCap) is added only when it actually
	// fired, so it never falsely claims rows are missing when only a
	// LINK cap (feeding projectroi.Link) truncated. The web side
	// (TruncationBanner's describeTruncation) renders the two with
	// different copy: a row cap means rows are missing from this
	// response entirely, a link cap means a row that IS shown may carry
	// an undercounted figure.
	affects := []string{"prompts", "ai_files", "ai_lines", "spend_usd", "owner"}
	if commitRowsTruncated {
		affects = append(affects, "commit_rows")
	}
	resp := apiProjectCommitsResponse{Rows: rows}
	resp.apiTruncationMeta = buildTruncationMeta(
		affects,
		truncatedInput{"prompts", promptsTruncated},
		truncatedInput{"edits", editsTruncated},
		truncatedInput{"commits", linkCommitsTruncated},
		truncatedInput{"commit_rows", commitRowsTruncated},
	)
	writeJSON(w, resp)
}

// handleProjectPrompts serves GET /api/project/{id}/prompts?days=&limit=
// — the prompt-to-commit chain table (plan §3.4).
func (s *Server) handleProjectPrompts(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
		return
	}
	since, until, _ := projectDetailWindow(r)
	limit := intArg(r, "limit", promptRowsCap, 1, promptRowsCap)

	// promptRowsTruncated is the OUTPUT row cap (promptRowsCap): `limit`
	// here IS that cap (or the caller's smaller override), so the
	// loader's own truncated signal tells us directly whether real
	// prompts in the window were left off this response entirely. Before
	// this fix (SOL-P2/F10 residue, 2026-09-22 rework) it was discarded
	// via `_`.
	prompts, promptRowsTruncated, err := st.LoadProjectPrompts(ctx, projectID, since, until, limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	edits, editsTruncated, err := st.LoadProjectAIEdits(ctx, projectID, since, until, dashapi.EditLinkCap)
	if err != nil {
		writeErr(w, err)
		return
	}
	commits, commitsTruncated, err := st.LoadProjectCommitsForLink(ctx, projectID, since, until, dashapi.CommitLinkCap)
	if err != nil {
		writeErr(w, err)
		return
	}
	rawCommits, err := st.LoadProjectCommits(ctx, projectID, since, until, dashapi.CommitLinkCap)
	if err != nil {
		writeErr(w, err)
		return
	}
	subjectByCommit := make(map[int64]string, len(rawCommits))
	for _, c := range rawCommits {
		subjectByCommit[c.ID] = c.Subject
	}

	linkage := projectroi.Link(prompts, edits, commits, projectroi.Options{LinkWindow: s.commitLinkWindow()})

	actionIDs := make([]int64, 0, len(prompts))
	for _, p := range prompts {
		actionIDs = append(actionIDs, p.ActionID)
	}
	grades, err := st.LoadPromptGrades(ctx, projectID, actionIDs)
	if err != nil {
		writeErr(w, err)
		return
	}

	judgeAvailable := s.opts.JudgeGrade != nil
	judgeReason := s.opts.JudgeGradeReason
	cloudAvailable, cloudReason := false, "cloud grading is not available"
	if s.opts.CloudGradeAvailability != nil {
		cloudAvailable, cloudReason = s.opts.CloudGradeAvailability()
	}

	// A capped edits/commits input can make Status wrong for EVERY row
	// in this response, not just some of them — a chain's `committed`
	// vs `uncommitted` determination reads the whole (capped) edits and
	// commits slices Link was given, so there is no way from here to
	// say which specific rows a missing edit/commit would have changed.
	// The honest, cheap answer is to flag every row rather than none
	// (SOL-F10).
	statusUncertain := editsTruncated || commitsTruncated

	rows := make([]apiProjectPromptRow, 0, len(linkage.Chains))
	for _, chain := range linkage.Chains {
		p := chain.Prompt
		fileset := make(map[string]bool)
		var added, modified, comment int
		for _, f := range chain.Files {
			fileset[f.PathHash] = true
			added += f.Added
			modified += f.Modified
			comment += f.Comment
		}
		row := apiProjectPromptRow{
			ActionID: p.ActionID, SessionID: p.SessionID, Tool: p.Tool,
			At: dashapi.FmtProjectTime(p.At), Preview: p.Preview,
			Edits: apiProjectPromptEdits{
				Files: len(fileset), Added: added, Modified: modified, Comment: comment,
				Split: loc.SplitAuthored(int64(added+modified), int64(comment)),
			},
			Commits:         []apiProjectPromptCommitRef{},
			Status:          string(chain.Status),
			StatusUncertain: statusUncertain,
		}
		for _, cc := range chain.Commits {
			row.Commits = append(row.Commits, apiProjectPromptCommitRef{
				ID: cc.ID, SHA: cc.SHA, Subject: subjectByCommit[cc.ID],
				CommittedAt: dashapi.FmtProjectTime(cc.CommittedAt), Share: cc.Share,
			})
		}

		if grade, ok := grades[p.ActionID]; ok {
			row.Alignment = &apiProjectPromptAlignment{
				Tier: grade.Tier, Delivered: nonNilStrings(grade.Result.Delivered),
				Missed: nonNilStrings(grade.Result.Missed), Extra: nonNilStrings(grade.Result.Extra),
				Confidence: grade.Result.Confidence, GradedAt: dashapi.FmtProjectTime(grade.GradedAt), Model: grade.Model,
			}
		}
		avail := &apiProjectPromptGradeAvailable{Judge: judgeAvailable, Cloud: cloudAvailable}
		switch {
		case !judgeAvailable && !cloudAvailable:
			if judgeReason != "" {
				avail.Reason = judgeReason
			} else {
				avail.Reason = cloudReason
			}
		case !judgeAvailable:
			avail.Reason = judgeReason
		case !cloudAvailable:
			avail.Reason = cloudReason
		}
		row.GradeAvailable = avail

		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].At > rows[j].At })

	// affects is built conditionally, not a fixed list — same reasoning
	// as handleProjectCommits above: "prompt_rows" (the OUTPUT cap,
	// promptRowsCap) is added only when it actually fired, so it never
	// falsely claims prompts are missing when only a LINK cap
	// (edits/commits feeding projectroi.Link, which instead makes an
	// already-returned row's Status uncertain — see statusUncertain)
	// truncated.
	affects := []string{"edits", "commits", "status"}
	if promptRowsTruncated {
		affects = append(affects, "prompt_rows")
	}
	resp := apiProjectPromptsResponse{Rows: rows}
	resp.apiTruncationMeta = buildTruncationMeta(
		affects,
		truncatedInput{"edits", editsTruncated},
		truncatedInput{"commits", commitsTruncated},
		truncatedInput{"prompt_rows", promptRowsTruncated},
	)
	writeJSON(w, resp)
}

// handleProjectCost serves GET /api/project/{id}/cost?by=session|tool|
// model|day|task|commit&days=N — the SpendTab's segmented-control
// breakdowns (plan §3.4).
func (s *Server) handleProjectCost(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
		return
	}
	since, until, _ := projectDetailWindow(r)

	priced, err := dashapi.LoadProjectSpend(ctx, st, s.opts.CostEngine, projectID, since, until)
	if err != nil {
		writeErr(w, err)
		return
	}
	turns := priced.Turns

	var rows []dashapi.APIProjectCostBucketRow
	var meta apiTruncationMeta
	switch r.URL.Query().Get("by") {
	case "tool":
		rows = dashapi.BucketCost(turns, func(t projectroi.Turn) string { return t.Tool })
	case "model":
		rows = dashapi.BucketCost(turns, func(t projectroi.Turn) string { return t.Model })
	case "day":
		for _, d := range dashapi.BucketCostByDay(turns) {
			rows = append(rows, dashapi.APIProjectCostBucketRow{Key: d.Day, CostUSD: d.CostUSD, UnpricedTurns: d.UnpricedTurns})
		}
	case "session":
		turnsPerSession := make(map[string]int)
		unpricedPerSession := make(map[string]int)
		for _, t := range turns {
			turnsPerSession[t.SessionID]++
			if !t.Priced {
				unpricedPerSession[t.SessionID]++
			}
		}
		// The per-session AI code/comment split rides on the same capped
		// edits loader every other Projects view uses; a cap hit is named
		// in the truncation meta (affects ai_split), never silent.
		edits, editsTruncated, err := st.LoadProjectAIEdits(ctx, projectID, since, until, dashapi.EditLinkCap)
		if err != nil {
			writeErr(w, err)
			return
		}
		codePerSession := make(map[string]int)
		commentPerSession := make(map[string]int)
		for _, e := range edits {
			codePerSession[e.SessionID] += e.CodeLines()
			commentPerSession[e.SessionID] += e.CommentLines()
		}
		for _, sess := range priced.Sessions {
			row := dashapi.APIProjectCostBucketRow{Key: sess.ID, Label: sess.Tool, CostUSD: sess.CostUSD, Turns: turnsPerSession[sess.ID], UnpricedTurns: unpricedPerSession[sess.ID]}
			row.AISplit = optionalAuthoredSplit(codePerSession[sess.ID], commentPerSession[sess.ID])
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].CostUSD > rows[j].CostUSD })
		meta = buildTruncationMeta([]string{"ai_split"}, truncatedInput{"edits", editsTruncated})
	case "task":
		refs, err := st.SessionsWithTasksInWindow(ctx, since, until, projectID, "", "")
		if err != nil {
			writeErr(w, err)
			return
		}
		// One batched sweep (SOL-F18(b), 2026-09-22 rework) rather than a
		// LoadSessionTaskReport call per session — this loop used to issue
		// 6-7 queries per task-bearing session in the window.
		sessionIDs := make([]string, len(refs))
		for i, ref := range refs {
			sessionIDs[i] = ref.SessionID
		}
		reports, err := taskreport.LoadSessionTaskReportsBatch(ctx, st, s.opts.CostEngine, sessionIDs, s.taskflowOptions())
		if err != nil {
			writeErr(w, err)
			return
		}
		for _, ref := range refs {
			rep, ok := reports[ref.SessionID]
			if !ok {
				continue
			}
			for _, item := range rep.Items {
				// item.UnpricedTurns (taskreport.TaskCostBucket, embedded
				// on ReportItem) is the exact count of this task's own
				// attributed turns that had neither a recorded cost nor a
				// pricing-table entry — the SAME signal every other
				// bucket here carries as unpriced_turns. 2026-09-22 review
				// round 4 finding #9: this used to collapse to item.
				// Unpriced ? 1 : 0, so a task with 40 unpriced turns and a
				// task with 1 rendered identically; UnpricedTurns removes
				// that collapse at the source.
				rows = append(rows, dashapi.APIProjectCostBucketRow{Key: item.Key, Label: item.Content, CostUSD: item.CostUSD, Count: 1, UnpricedTurns: item.UnpricedTurns})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].CostUSD > rows[j].CostUSD })
	case "commit":
		rawCommits, err := st.LoadProjectCommits(ctx, projectID, since, until, dashapi.CommitLinkCap)
		if err != nil {
			writeErr(w, err)
			return
		}
		prompts, promptsTruncated, err := st.LoadProjectPrompts(ctx, projectID, since, until, dashapi.PromptLinkCap)
		if err != nil {
			writeErr(w, err)
			return
		}
		edits, editsTruncated, err := st.LoadProjectAIEdits(ctx, projectID, since, until, dashapi.EditLinkCap)
		if err != nil {
			writeErr(w, err)
			return
		}
		linkCommits, linkCommitsTruncated, err := st.LoadProjectCommitsForLink(ctx, projectID, since, until, dashapi.CommitLinkCap)
		if err != nil {
			writeErr(w, err)
			return
		}
		linkage := projectroi.Link(prompts, edits, linkCommits, projectroi.Options{LinkWindow: s.commitLinkWindow()})
		spend := projectroi.AttributeSpend(linkage, turns, prompts)
		for _, c := range rawCommits {
			// 2026-09-22 review round 4 finding #9: commit buckets used
			// to omit unpriced-turn coverage entirely, unlike every other
			// by= mode above (day/session/task all set UnpricedTurns).
			// spend.UnpricedTurnsByCommit carries the same honesty signal
			// projectroi.AttributeSpend now derives alongside the dollar
			// split.
			rows = append(rows, dashapi.APIProjectCostBucketRow{Key: c.SHA, Label: c.Subject, CostUSD: spend.ByCommit[c.ID], UnpricedTurns: spend.UnpricedTurnsByCommit[c.ID]})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].CostUSD > rows[j].CostUSD })
		meta = buildTruncationMeta(
			[]string{"cost_usd"},
			truncatedInput{"prompts", promptsTruncated},
			truncatedInput{"edits", editsTruncated},
			truncatedInput{"commits", linkCommitsTruncated},
		)
	default:
		http.Error(w, `by must be one of "session","tool","model","day","task","commit"`, http.StatusBadRequest)
		return
	}
	if rows == nil {
		rows = []dashapi.APIProjectCostBucketRow{}
	}
	resp := apiProjectCostRowsResponse{Rows: rows}
	resp.apiTruncationMeta = meta
	writeJSON(w, resp)
}

// handleProjectGrade serves POST /api/project/{id}/prompts/{action_id}/
// grade — the §3.6 J/C alignment-grading trigger (plan §3.4).
func (s *Server) handleProjectGrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	actionID, err := strconv.ParseInt(r.PathValue("action_id"), 10, 64)
	if err != nil || actionID <= 0 {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Tier string `json:"tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	st := store.New(s.db())
	if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
		return
	}

	switch body.Tier {
	case "judge":
		s.handleProjectGradeJudge(ctx, w, st, projectID, actionID)
	case "cloud":
		// Cloud tier: honest not_available until a hosted commit-alignment
		// executor ships (plan §3.6 tier C / W5c dropped, review F21).
		//
		// TODO(post-W5c): once the hosted commit-alignment kind exists and
		// CloudGradeAvailability reports true, spawn
		// `observer cloud grade-commit --prompt <action_id> --yes` here —
		// the same "the dashboard spawns the CLI, never links the cloud
		// network/credential packages itself" pattern
		// cloudautoenrich.go/cloudautosync.go already use for the daemon's
		// opt-in tickers. Do NOT import internal/cloudclient/cloudcred/
		// cloudpop into this package directly:
		// tests/invariant/cloud_egress_test.go pins the zero-egress
		// boundary to cmd/observer/cloud.go's CLI process alone.
		reason := "cloud grading is not available"
		if s.opts.CloudGradeAvailability != nil {
			_, reason = s.opts.CloudGradeAvailability()
		}
		writeJSON(w, map[string]any{"status": "not_available", "reason": reason})
	default:
		http.Error(w, `tier must be "judge" or "cloud"`, http.StatusBadRequest)
	}
}

func (s *Server) handleProjectGradeJudge(ctx context.Context, w http.ResponseWriter, st *store.Store, projectID, actionID int64) {
	if s.opts.JudgeGrade == nil {
		reason := s.opts.JudgeGradeReason
		if reason == "" {
			reason = "the judge tier is not configured"
		}
		writeJSON(w, map[string]any{"status": "not_available", "reason": reason})
		return
	}
	in, _, err := st.LoadPromptChainInput(ctx, projectID, actionID)
	if err != nil {
		writeErr(w, err)
		return
	}
	result, model, err := s.opts.JudgeGrade(ctx, in)
	if err != nil {
		writeJSON(w, map[string]any{"status": "not_available", "reason": err.Error()})
		return
	}
	gradedAt := time.Now().UTC()
	if err := st.SavePromptGrade(ctx, store.PromptGradeRow{
		ProjectID: projectID, ActionID: actionID, Tier: "judge", Model: model, Result: result, GradedAt: gradedAt,
	}); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"status": "ok",
		"alignment": apiProjectPromptAlignment{
			Tier: "judge", Delivered: nonNilStrings(result.Delivered), Missed: nonNilStrings(result.Missed),
			Extra: nonNilStrings(result.Extra), Confidence: result.Confidence, GradedAt: dashapi.FmtProjectTime(gradedAt), Model: model,
		},
	})
}
