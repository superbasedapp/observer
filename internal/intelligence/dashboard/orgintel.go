package dashboard

import (
	"fmt"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// orgintel.go serves GET /api/session/<id>/org-intel — a read-only view of the
// org-served Cloud Intelligence result the node last pulled back for this
// session (org-served-cloud-intelligence plan §3.5, W8b). It reads the
// NODE-LOCAL org_intel_cache (store.OrgIntelResultsForSession) and renders the
// newest result; a session with no cached result answers an honest
// {"enriched":false,...}, never an error.
//
// This is the node drawer's sibling of the org drawer's
// GET /api/org/sessions/{id}/intel. It adds NO org-push wire column and reads
// only data the node already holds locally, so there is nothing to audit on the
// node's own dashboard (the disclosure audit lives on the org server's route).

// orgIntelResultWire is one cached enrichment result on the wire. The node
// cache carries no provider / model / tokens / cost — only the content the org
// derived — so those fields are absent here by construction (the shared
// IntelResultCard omits what is absent rather than zeroing it).
type orgIntelResultWire struct {
	SessionID     string   `json:"session_id"`
	JobID         string   `json:"job_id"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	TaxonomyTags  []string `json:"taxonomy_tags"`
	SuggestedTags []string `json:"suggested_tags"`
	Limitations   []string `json:"limitations"`
	// The five NARRATIVE lists the org derived (agent migration 124): what the
	// session did, whether the stated plans landed, what issues were found,
	// what failed, what to do next. omitempty, so a row cached before 124 — or
	// pulled from a server predating server migration 156 — renders as absence
	// in the shared IntelResultCard rather than as five empty headings.
	WorkDone         []string `json:"work_done,omitempty"`
	PlansImplemented []string `json:"plans_implemented,omitempty"`
	IssuesFound      []string `json:"issues_found,omitempty"`
	Failures         []string `json:"failures,omitempty"`
	NextSteps        []string `json:"next_steps,omitempty"`
	Confidence       string   `json:"confidence"`
	SchemaVersion    string   `json:"schema_version"`
	FetchedAt        string   `json:"fetched_at"`
}

// orgIntelWire is the GET /api/session/<id>/org-intel body. `enriched` is the
// discriminator: false with a `reason` is the honest empty (no result cached),
// true carries the newest `result`.
type orgIntelWire struct {
	Enriched bool                `json:"enriched"`
	Reason   string              `json:"reason,omitempty"`
	Result   *orgIntelResultWire `json:"result,omitempty"`
}

// handleSessionOrgIntel serves the org-served enrichment for one session.
func (s *Server) handleSessionOrgIntel(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	st := store.New(s.opts.DB)
	results, err := st.OrgIntelResultsForSession(r.Context(), sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load org intel: %v", err), http.StatusInternalServerError)
		return
	}
	if len(results) == 0 {
		writeJSON(w, orgIntelWire{Enriched: false, Reason: "not yet enriched"})
		return
	}
	// OrgIntelResultsForSession orders newest pull first, so the head is the
	// result the card should render.
	writeJSON(w, orgIntelWire{Enriched: true, Result: newOrgIntelResultWire(results[0])})
}

// newOrgIntelResultWire maps a stored cache row onto the wire shape, formatting
// the node's pull time as RFC3339.
func newOrgIntelResultWire(res store.OrgIntelResult) *orgIntelResultWire {
	return &orgIntelResultWire{
		SessionID:     res.SessionID,
		JobID:         res.JobID,
		Title:         res.Title,
		Description:   res.Description,
		TaxonomyTags:  res.TaxonomyTags,
		SuggestedTags: res.SuggestedTags,
		Limitations:   res.Limitations,
		// The narrative half, carried straight through: the store seam already
		// decoded each NULLABLE column into a nil slice when it held no prose.
		WorkDone:         res.WorkDone,
		PlansImplemented: res.PlansImplemented,
		IssuesFound:      res.IssuesFound,
		Failures:         res.Failures,
		NextSteps:        res.NextSteps,
		Confidence:       res.Confidence,
		SchemaVersion:    res.SchemaVersion,
		FetchedAt:        res.FetchedAt.UTC().Format(time.RFC3339),
	}
}
