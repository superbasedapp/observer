package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud_digests.go serves GET /api/cloud/digests (value-upgrade plan §W5
// "digests + plan on the node",
// docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md): the
// weekly project digests `observer cloud sync` has pulled back, read-only
// over internal/store.ListCloudDigests (the FF1 "one store seam per
// database" seam — this file never selects against cloud_digests directly).
// Class V (a store-derived read), same as GET /api/cloud/status and GET
// /api/cloud/session/{id}.
//
// The `project` query parameter follows the SAME convention every other
// dashboard filter uses — a project ROOT PATH, not the internal numeric
// projects.id (which never leaves internal/store) — resolved here through
// store.ProjectIDForRoot, the same helper the LOC-tracking surfaces use for
// the identical resolution. An unrecognized root or an absent parameter both
// degrade to an honest empty/all-projects result, never an error.

// CloudDigestView is one weekly project digest GET /api/cloud/digests
// reports. Result is the validated cloudcontract.DigestResult body passed
// through as raw JSON so this handler stays agnostic of the digest schema —
// the same pattern CloudResultView uses for a session-enrichment result.
type CloudDigestView struct {
	ID             string          `json:"id"`
	LocalProjectID string          `json:"local_project_id"`
	CloudProjectID string          `json:"cloud_project_id"`
	PeriodStart    string          `json:"period_start"`
	PeriodEnd      string          `json:"period_end"`
	ReceivedAt     string          `json:"received_at"`
	Result         json.RawMessage `json:"result"`
}

// CloudDigestsResponse is GET /api/cloud/digests's payload.
type CloudDigestsResponse struct {
	Digests []CloudDigestView `json:"digests"`
}

// cloudDigestsDefaultLimit / cloudDigestsMaxLimit bound the `limit` query
// parameter — a project's digests are weekly, so even a generous limit is a
// tiny result set; the ceiling exists purely against a malformed request.
const (
	cloudDigestsDefaultLimit = 12
	cloudDigestsMaxLimit     = 200
)

// handleCloudDigests serves GET /api/cloud/digests?project=<root path>&limit=N.
// `project` absent lists digests across every project on this device;
// present, it scopes to one project (resolved via store.ProjectIDForRoot —
// an unrecognized root degrades to an empty list, not an error, since a
// project with no digests yet is the routine common case).
func (s *Server) handleCloudDigests(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := store.New(s.db())

	limit := cloudDigestsDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > cloudDigestsMaxLimit {
		limit = cloudDigestsMaxLimit
	}

	localProjectID := ""
	if root := strings.TrimSpace(r.URL.Query().Get("project")); root != "" {
		id, err := st.ProjectIDForRoot(ctx, root)
		if err != nil {
			http.Error(w, "resolve project: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if id == 0 {
			// Unrecognized root: an honest empty list, not an error — the
			// common case for a project no agent has ever run in yet.
			writeJSON(w, CloudDigestsResponse{Digests: []CloudDigestView{}})
			return
		}
		localProjectID = strconv.FormatInt(id, 10)
	}

	digests, err := st.ListCloudDigests(ctx, localProjectID, limit)
	if err != nil {
		http.Error(w, "list cloud digests: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := CloudDigestsResponse{Digests: []CloudDigestView{}}
	for _, d := range digests {
		resp.Digests = append(resp.Digests, CloudDigestView{
			ID:             d.ID,
			LocalProjectID: d.LocalProjectID,
			CloudProjectID: d.CloudProjectID,
			PeriodStart:    d.PeriodStart,
			PeriodEnd:      d.PeriodEnd,
			ReceivedAt:     cloudRFC3339(d.ReceivedAt),
			Result:         json.RawMessage(d.ResultJSON),
		})
	}
	writeJSON(w, resp)
}
