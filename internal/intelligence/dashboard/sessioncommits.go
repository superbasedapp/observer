package dashboard

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// sessioncommits.go serves GET /api/session/{id}/commits: the session
// detail's "Commits" section (operator ask 2026-09-28, "track which session
// owned a git commit"). It is the session-side view of the SAME ownership
// fold the Projects commit ledger shows (projectroi.Ownership, docs/
// projects-page.md "Commit ownership"), composed through the one store
// seam store.LoadCommitOwnership over the window store.SessionOwnershipSpan
// derives, then inverted per session by projectroi.CommitsBySession. No
// rule lives here: this file only shapes the result for the wire.
//
// A sub-route of /api/session/ (handleSessionDetail's suffix dispatch), so
// it inherits that route's View capability and Sessions section exactly as
// /api/session/{id}/loc does. Because it discloses commit subjects - the
// Projects section's data - it additionally refuses when an org has hidden
// the Projects section on this node, the same refusal the governance guard
// gives /api/project/{id}/commits.

// apiSessionCommitRow is one commit this session contributed to, from the
// session's side.
type apiSessionCommitRow struct {
	ID          int64  `json:"id"`
	SHA         string `json:"sha"`
	Subject     string `json:"subject"`
	CommittedAt string `json:"committed_at"`
	Reachable   bool   `json:"reachable"`
	IsMerge     bool   `json:"is_merge"`
	// Owner is true when THIS session owns the commit.
	Owner bool `json:"owner"`
	// OwnerSessionID is the commit's owner - this session or another one.
	OwnerSessionID string `json:"owner_session_id,omitempty"`
	// Reason / ShareBasis carry the projectroi constants verbatim.
	Reason     string `json:"reason"`
	ShareBasis string `json:"share_basis,omitempty"`
	// Share is this session's share of the commit on ShareBasis.
	Share float64 `json:"share"`
	// Files / CodeLines / CommentLines are what THIS session's carried
	// (prompt, path) pairs contributed: code lines are added + modified,
	// code-category files only; Split is their code-vs-comment split.
	Files        int               `json:"files"`
	CodeLines    int               `json:"code_lines"`
	CommentLines int               `json:"comment_lines"`
	Split        loc.AuthoredSplit `json:"split"`
	// Prompts is how many of this session's prompts reached the commit.
	Prompts int `json:"prompts"`
}

// apiSessionCommitsResponse is GET /api/session/{id}/commits.
type apiSessionCommitsResponse struct {
	SessionID string `json:"session_id"`
	// ProjectID is omitted for a session that belongs to no project.
	ProjectID      int64 `json:"project_id,omitempty"`
	LinkWindowDays int   `json:"link_window_days"`
	// CommitCapture is the project's commit-capture state ("ok", "no_git",
	// "never_scanned", "error" - store.CommitCaptureState), so an empty
	// list can say WHY it is empty. Omitted with no project.
	CommitCapture string                `json:"commit_capture,omitempty"`
	Rows          []apiSessionCommitRow `json:"rows"`
	apiTruncationMeta
}

// sessionCommitsAffects names the per-row fields a capped loader makes a
// known partial view on this endpoint.
var sessionCommitsAffects = []string{"rows", "owner", "share", "files", "code_lines", "comment_lines", "prompts"}

// handleSessionCommits serves GET /api/session/{id}/commits.
func (s *Server) handleSessionCommits(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		http.Error(w, "session id required", http.StatusBadRequest)
		return
	}
	if s.opts.Governance != nil {
		if eff := s.opts.Governance(r.Context()); eff.Active && eff.IsNavSectionHidden(string(SectionProjects)) {
			writeGovernanceRefusal(w, http.StatusNotFound, "governance_hidden", string(SectionProjects), eff,
				"This page is managed by your organization and is not available on this machine.")
			return
		}
	}

	ctx := r.Context()
	st := store.New(s.db())
	now := time.Now().UTC()
	linkWindow := s.commitLinkWindow()
	resp := apiSessionCommitsResponse{
		SessionID:      id,
		LinkWindowDays: int(linkWindow / (24 * time.Hour)),
		Rows:           []apiSessionCommitRow{},
	}

	win, exists, err := st.LookupSessionWindow(ctx, id, now)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !exists {
		http.NotFound(w, r)
		return
	}
	if win.ProjectID <= 0 {
		writeJSON(w, resp)
		return
	}
	resp.ProjectID = win.ProjectID
	capture, err := st.CommitCaptureState(ctx, win.ProjectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	resp.CommitCapture = capture

	since, until := store.SessionOwnershipSpan(win, linkWindow, now)
	res, err := st.LoadCommitOwnership(ctx, win.ProjectID, since, until, linkWindow, store.OwnershipCaps{
		Prompts: promptLinkCap, Edits: editLinkCap, Commits: commitLinkCap,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	resp.Rows = buildSessionCommitRows(id, res)
	resp.apiTruncationMeta = buildTruncationMeta(
		sessionCommitsAffects,
		truncatedInput{"prompts", res.PromptsTruncated},
		truncatedInput{"edits", res.EditsTruncated},
		truncatedInput{"commits", res.CommitsTruncated},
	)
	writeJSON(w, resp)
}

// buildSessionCommitRows inverts one ownership fold to sessionID's side,
// newest committed_at first (ties by commit id, newest first). A commit
// id the fold names but the row set lacks cannot happen (the fold ran
// over exactly those rows) and is skipped rather than rendered blank.
func buildSessionCommitRows(sessionID string, res store.CommitOwnershipResult) []apiSessionCommitRow {
	byID := make(map[int64]store.ProjectCommitRow, len(res.Commits))
	for _, c := range res.Commits {
		byID[c.ID] = c
	}
	mine := projectroi.CommitsBySession(res.Ownership)[sessionID]
	kept := mine[:0:0]
	for _, sc := range mine {
		if _, ok := byID[sc.CommitID]; ok {
			kept = append(kept, sc)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		ti, tj := byID[kept[i].CommitID].CommittedAt, byID[kept[j].CommitID].CommittedAt
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return kept[i].CommitID > kept[j].CommitID
	})
	out := make([]apiSessionCommitRow, 0, len(kept))
	for _, sc := range kept {
		c := byID[sc.CommitID]
		con := sc.Contribution
		out = append(out, apiSessionCommitRow{
			ID: c.ID, SHA: c.SHA, Subject: c.Subject, CommittedAt: fmtProjectTime(c.CommittedAt),
			Reachable: c.Reachable, IsMerge: c.IsMerge,
			Owner: sc.Owner, OwnerSessionID: sc.OwnerSessionID, Reason: sc.Reason, ShareBasis: sc.ShareBasis,
			Share: con.Share, Files: con.Files, CodeLines: con.CodeLines, CommentLines: con.CommentLines,
			Split:   loc.SplitAuthored(int64(con.CodeLines), int64(con.CommentLines)),
			Prompts: con.Prompts,
		})
	}
	return out
}
