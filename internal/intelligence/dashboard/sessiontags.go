package dashboard

// sessiontags.go — the session-classification API surface
// (docs/plans/session-classification-tags-plan-2026-07-31.md §4):
//
//	GET  /api/sessions/tags          → vocabulary + per-tag cost/token rollup (V)
//	POST /api/sessions/tags/manage   → rename / delete a tag globally (Execute)
//	GET  /api/session/<id>/tags      → read-only snapshot of one session's
//	                                   tags/favorite/note/rating/title (View —
//	                                   the base /api/session/ route's GET tier)
//	POST /api/session/<id>/tags      → per-session add/remove/favorite/note/
//	                                   rating/title (Execute, dispatched from
//	                                   handleSessionDetail's suffix table +
//	                                   sessionSubRouteCapabilities; the
//	                                   method-aware View→Execute escalation in
//	                                   requiredCapability is what actually
//	                                   protects the POST)
//
// Execute (not Local) is deliberate: tagging from a phone during remote review
// is a primary flow, and the Execute class already covers strictly more
// powerful actions (/handoff, /launch, /resume). Annotation content is
// user-authored review metadata, not machine-reaching config.
//
// All storage goes through the single internal/store/sessiontags.go seam.

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// maxSessionTagFilters caps how many DISTINCT `tag=` filters one
// GET /api/sessions request may carry (handleSessions). Each accepted tag
// appends a correlated EXISTS subquery to the shared WHERE clause, which is
// executed by the page query, the pagination COUNT and scored_count — so an
// uncapped repeatable param lets one authenticated request cost an unbounded
// amount of work. 8 is well past any real "filter by a few labels" use and far
// below anything expensive; the per-session tag cap (store.MaxTagsPerSession,
// 16) bounds what an AND-filter could ever usefully match anyway.
const maxSessionTagFilters = 8

// tagRollupRow is one row of the GET /api/sessions/tags response: a tag, how
// many sessions carry it, and the summed cost/tokens of those sessions.
type tagRollupRow struct {
	Tag      string  `json:"tag"`
	Sessions int     `json:"sessions"`
	CostUSD  float64 `json:"cost_usd"`
	Tokens   int64   `json:"tokens"`
}

// sessionTagsRequest is the POST /api/session/<id>/tags body. Favorite, Note,
// Rating and Title are POINTERS so an omitted (or null) field means "leave
// unchanged" — the star toggle, the note editor, the rating control and the
// title editor each write independently. Rating 0 clears (unrated); 1-10 is a
// score. Title "" clears the developer's own title (falling back to the AI
// title, if any, on every rendering surface); <= store.MaxTitleLen chars,
// no newline.
type sessionTagsRequest struct {
	Add      []string `json:"add"`
	Remove   []string `json:"remove"`
	Favorite *bool    `json:"favorite"`
	Note     *string  `json:"note"`
	Rating   *int     `json:"rating"`
	Title    *string  `json:"title"`
}

// sessionTagsResponse is the current state of one session's classification —
// echoed by POST /api/session/<id>/tags so the caller never has to re-fetch,
// and returned as-is by GET /api/session/<id>/tags for a component that only
// needs to DISPLAY it (SessionEnrichmentHeader). Rating and Title carry
// omitempty so a session with neither emits the byte-identical payload it did
// before those fields existed.
type sessionTagsResponse struct {
	SessionID string   `json:"session_id"`
	Tags      []string `json:"tags"`
	Favorite  bool     `json:"favorite"`
	Note      string   `json:"note"`
	Rating    int      `json:"rating,omitempty"`
	Title     string   `json:"title,omitempty"`
}

// tagsManageRequest is the POST /api/sessions/tags/manage body. Exactly one of
// Rename / Delete must be set.
type tagsManageRequest struct {
	Rename *struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"rename"`
	Delete string `json:"delete"`
}

// tagRollup computes the per-tag session/cost/token rollup with ONE cost-engine
// PASS (not one query per tag): every tagged session id is scoped into a
// GroupBySession summary and the resulting rows are folded tag-wise in Go.
//
// The pass runs through cost.Engine.SessionRowsByID, which chunks the id set at
// cost.MaxSessionIDsPerScope — a single IN list of every tagged session blows
// SQLite's 32766 bind-variable ceiling once the vocabulary covers enough
// sessions, and because the cost error is swallowed as an enrichment failure
// (below) the symptom was silently ZEROED cost/token columns, not an error.
//
// Shared by the dashboard handler and (in spirit) `observer tags`; rows come
// back sorted by cost desc, then session count desc, then tag asc.
func (s *Server) tagRollup(r *http.Request) ([]tagRollupRow, error) {
	st := store.New(s.db())
	assignments, err := st.TagAssignments(r.Context())
	if err != nil {
		return nil, err
	}
	rows := []tagRollupRow{}
	if len(assignments) == 0 {
		return rows, nil
	}
	ids := make([]string, 0, len(assignments))
	for id := range assignments {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	byID := map[string]cost.Row{}
	if s.opts.CostEngine != nil {
		priced, cErr := s.opts.CostEngine.SessionRowsByID(r.Context(), s.db(), cost.Options{
			Days:   36500,
			Source: cost.SourceAuto,
		}, ids)
		if cErr != nil {
			// Cost is an ENRICHMENT of the vocabulary, not its substance —
			// degrade to counts rather than failing the whole surface.
			s.opts.Logger.Warn("sessions/tags: per-tag cost rollup failed", "err", cErr)
		} else {
			byID = priced
		}
	}

	agg := map[string]*tagRollupRow{}
	for _, id := range ids {
		row, hasCost := byID[id]
		for _, tag := range assignments[id] {
			e, ok := agg[tag]
			if !ok {
				e = &tagRollupRow{Tag: tag}
				agg[tag] = e
			}
			e.Sessions++
			if hasCost {
				e.CostUSD += row.CostUSD
				e.Tokens += row.Tokens.Input + row.Tokens.Output +
					row.Tokens.CacheRead + row.Tokens.CacheCreation
			}
		}
	}
	for _, e := range agg {
		rows = append(rows, *e)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CostUSD != rows[j].CostUSD {
			return rows[i].CostUSD > rows[j].CostUSD
		}
		if rows[i].Sessions != rows[j].Sessions {
			return rows[i].Sessions > rows[j].Sessions
		}
		return rows[i].Tag < rows[j].Tag
	})
	return rows, nil
}

// handleSessionsTags serves GET /api/sessions/tags — the tag vocabulary with
// its per-tag session/cost/token rollup. Drives the Sessions page Tags panel
// (analysis-by-label) and doubles as the TagEditor combobox vocabulary.
func (s *Server) handleSessionsTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.tagRollup(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"tags": rows})
}

// handleSessionsTagsManage serves POST /api/sessions/tags/manage — vocabulary
// management without a defs table: {"rename":{"from","to"}} merges the source
// into the destination across every session; {"delete":"tag"} drops every
// assignment. Responds {"affected": N} (assignment rows touched).
func (s *Server) handleSessionsTagsManage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body tagsManageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	hasRename := body.Rename != nil
	hasDelete := body.Delete != ""
	if hasRename == hasDelete {
		http.Error(w, `body must carry exactly one of {"rename":{"from","to"}} or {"delete":"tag"}`, http.StatusBadRequest)
		return
	}

	st := store.New(s.db())
	var (
		affected int64
		err      error
	)
	if hasRename {
		affected, err = st.RenameTag(r.Context(), body.Rename.From, body.Rename.To)
	} else {
		affected, err = st.DeleteTag(r.Context(), body.Delete)
	}
	if err != nil {
		if errors.Is(err, store.ErrInvalidTag) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"affected": affected})
}

// handleSessionTags serves /api/session/<id>/tags. POST is the per-session
// classification mutation: body {"add":[],"remove":[],"favorite":bool|null,
// "note":string|null,"rating":int|null,"title":string|null} — a null/absent
// field leaves it untouched. GET is a read-only snapshot of the same shape
// (handleSessionTagsGet), for a caller that only needs to DISPLAY the current
// annotation rather than parse it out of the larger session detail payload.
// Both respond with the session's current tags/favorite/note/rating/title.
func (s *Server) handleSessionTags(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		s.handleSessionTagsGet(w, r, sessionID)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body sessionTagsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate EVERYTHING before the first write. The tag write and the
	// annotation write are two store calls, so a body whose tags are valid but
	// whose note is over-long would otherwise commit the tags and then 400 —
	// a partial write indistinguishable, to the caller, from a total failure.
	if err := store.ValidateClassificationInput(body.Add, body.Remove, body.Note, body.Rating, body.Title); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	st := store.New(s.db())
	if len(body.Add) > 0 || len(body.Remove) > 0 {
		if err := st.MutateSessionTags(r.Context(), sessionID, body.Add, body.Remove); err != nil {
			switch {
			case errors.Is(err, store.ErrInvalidTag), errors.Is(err, store.ErrTooManyTags):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				writeErr(w, err)
			}
			return
		}
	}
	if body.Favorite != nil || body.Note != nil || body.Rating != nil || body.Title != nil {
		if err := st.SetSessionAnnotation(r.Context(), sessionID, body.Favorite, body.Note, body.Rating, body.Title); err != nil {
			if errors.Is(err, store.ErrNoteTooLong) || errors.Is(err, store.ErrInvalidRating) ||
				errors.Is(err, store.ErrTitleTooLong) || errors.Is(err, store.ErrInvalidTitle) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeErr(w, err)
			return
		}
	}

	s.writeSessionTagsState(w, r, sessionID)
}

// handleSessionTagsGet serves GET /api/session/<id>/tags: the same response
// shape POST returns, with no write. Never fails on an unclassified session —
// it degrades to the zero annotation like GetSessionAnnotation does.
func (s *Server) handleSessionTagsGet(w http.ResponseWriter, r *http.Request, sessionID string) {
	s.writeSessionTagsState(w, r, sessionID)
}

// writeSessionTagsState loads and writes one session's current
// tags/favorite/note/rating/title — the shared tail of both the GET read and
// the POST mutation's response.
func (s *Server) writeSessionTagsState(w http.ResponseWriter, r *http.Request, sessionID string) {
	st := store.New(s.db())
	tags, err := st.SessionTags(r.Context(), sessionID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if tags == nil {
		tags = []string{}
	}
	annot, err := st.GetSessionAnnotation(r.Context(), sessionID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, sessionTagsResponse{
		SessionID: sessionID,
		Tags:      tags,
		Favorite:  annot.Favorite,
		Note:      annot.Note,
		Rating:    annot.Rating,
		Title:     annot.Title,
	})
}
