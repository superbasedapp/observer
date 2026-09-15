package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// corrections.go is the W6c API surface (divergence-remediation plan §3 W6c;
// operator ruling R6, closing D4/D12/D21):
//
//   PATCH /v1/results/{id}/correction              — device PoP; source=node
//   GET   /portal/api/sessions                     — portal; paginated list
//   GET   /portal/api/sessions/{id}                — portal; detail + revisions
//   POST  /portal/api/results/{id}/correction      — portal; source=portal
//
// A correction is an ETag-guarded, idempotent, append-only user edit; the store
// keeps the immutable AI original and every revision (R6). The device and portal
// correction paths share one applier and differ only in the recorded source.

// maxCorrectionBodyBytes bounds a correction body. A real correction is a title
// plus maybe a description and a few tags; 16 KiB is generous headroom and
// matches the column CHECK on result_revisions.correction.
const maxCorrectionBodyBytes = 16 << 10

// handleResultCorrection is the DEVICE correction path (PoP-authenticated). The
// node calls it to sync a local override up as a revision (R6), so the recorded
// source is "node".
func (s *Server) handleResultCorrection(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	s.applyResultCorrection(w, r, p.AccountID, r.PathValue("id"), store.CorrectionSourceNode)
}

// handlePortalResultCorrection is the PORTAL correction path (session cookie +
// CSRF via portalAuth). A developer editing on the Sessions page records
// source "portal".
func (s *Server) handlePortalResultCorrection(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	s.applyResultCorrection(w, r, p.AccountID, r.PathValue("id"), store.CorrectionSourcePortal)
}

// correctionResponse is the success/replay body.
type correctionResponse struct {
	ResultID    string `json:"result_id"`
	RevisionSeq int    `json:"revision_seq"`
	ETag        string `json:"etag"`
	Replayed    bool   `json:"replayed"`
}

// applyResultCorrection is the shared correction applier for both planes.
func (s *Server) applyResultCorrection(w http.ResponseWriter, r *http.Request, accountID, resultID string, source store.CorrectionSource) {
	ctx := r.Context()
	if resultID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "missing result id")
		return
	}

	// If-Match is REQUIRED (fail-closed): a blind correction cannot win over a
	// concurrent editor. The tag must be the strong ResultETag for THIS result.
	rawIfMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if rawIfMatch == "" {
		writeErr(w, http.StatusPreconditionRequired, "missing_if_match",
			"an If-Match header carrying the result's current ETag is required")
		return
	}
	etagResultID, ifMatchSeq, ok := cloudcontract.ParseResultETag(rawIfMatch)
	if !ok || etagResultID != resultID {
		writeErr(w, http.StatusBadRequest, "bad_if_match",
			"the If-Match header is not a valid ETag for this result")
		return
	}

	// Idempotency-Key is required so a retried correction replays instead of
	// appending a duplicate revision.
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeErr(w, http.StatusBadRequest, "missing_idempotency_key",
			"an Idempotency-Key header is required on a correction")
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCorrectionBodyBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "could not read body")
		return
	}
	if len(raw) > maxCorrectionBodyBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "correction exceeds the size bound")
		return
	}
	var corr cloudcontract.ResultCorrection
	if err := json.Unmarshal(raw, &corr); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "correction is not valid JSON")
		return
	}
	norm, err := corr.Normalize()
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invalid_correction", err.Error())
		return
	}
	normJSON, err := json.Marshal(norm)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not encode correction")
		return
	}

	out, err := s.store.ApplyResultCorrection(ctx, accountID, resultID, ifMatchSeq, idemKey, normJSON, source, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "result_not_found", "no such result")
		return
	case errors.Is(err, store.ErrResultTombstoned):
		writeErr(w, http.StatusGone, "result_tombstoned", "this result has been deleted and cannot be corrected")
		return
	case errors.Is(err, store.ErrResultNotCorrectable):
		writeErr(w, http.StatusConflict, "not_correctable", "this result cannot be corrected")
		return
	case errors.Is(err, store.ErrResultETagMismatch):
		// Hand back the current ETag so the caller can re-read and retry.
		w.Header().Set("ETag", cloudcontract.ResultETag(resultID, out.CorrectionSeq))
		s.audit(ctx, accountID, "result_correction_conflict")
		writeErr(w, http.StatusPreconditionFailed, "etag_mismatch",
			"the result changed since you last read it; re-fetch and retry")
		return
	case err != nil:
		s.log.Error("cloudserver/api: apply correction", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not apply correction")
		return
	}

	newETag := cloudcontract.ResultETag(resultID, out.CorrectionSeq)
	w.Header().Set("ETag", newETag)
	// Content-free audit: names the branch, never the corrected text.
	if out.Replayed {
		s.audit(ctx, accountID, "result_correction_replayed_"+string(source))
	} else {
		s.audit(ctx, accountID, "result_correction_applied_"+string(source))
	}
	writeJSON(w, http.StatusOK, correctionResponse{
		ResultID:    resultID,
		RevisionSeq: out.RevisionSeq,
		ETag:        newETag,
		Replayed:    out.Replayed,
	})
}

// --- Portal Sessions read surface -----------------------------------------

// sessionSummaryDTO is one Sessions-list row on the wire.
type sessionSummaryDTO struct {
	CloudSessionID string    `json:"cloud_session_id"`
	Tool           string    `json:"tool"`
	ModelFamily    string    `json:"model_family"`
	CreatedAt      time.Time `json:"created_at"`
	ResultCount    int       `json:"result_count"`
	Edited         bool      `json:"edited"`
	EffectiveTitle string    `json:"effective_title"`
	Tombstoned     bool      `json:"tombstoned"`
}

// handlePortalSessions serves one page of the account's enriched sessions,
// newest-first, with an opaque `next_cursor` for the following page.
func (s *Server) handlePortalSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := portalPrincipalFrom(ctx)

	limit := 25
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := parsePositiveInt(l); err == nil {
			limit = v
		}
	}
	var afterCreated time.Time
	var afterID string
	if cur := r.URL.Query().Get("after"); cur != "" {
		t, id, ok := decodeSessionsCursor(cur)
		if !ok {
			writeErr(w, http.StatusBadRequest, "bad_cursor", "after is not a valid sessions cursor")
			return
		}
		afterCreated, afterID = t, id
	}

	page, err := s.store.ListAccountSessions(ctx, p.AccountID, limit, afterCreated, afterID)
	if err != nil {
		s.log.Error("cloudserver/api: list sessions", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not list sessions")
		return
	}
	out := make([]sessionSummaryDTO, 0, len(page.Sessions))
	for _, it := range page.Sessions {
		out = append(out, sessionSummaryDTO{
			CloudSessionID: it.CloudSessionID, Tool: it.Tool, ModelFamily: it.ModelFamily,
			CreatedAt: it.CreatedAt, ResultCount: it.ResultCount, Edited: it.Edited,
			EffectiveTitle: it.EffectiveTitle, Tombstoned: it.Tombstoned,
		})
	}
	resp := map[string]any{"sessions": out, "has_more": page.HasMore}
	if page.HasMore {
		resp["next_cursor"] = encodeSessionsCursor(page.NextCreatedAt, page.NextCloudSessionID)
	}
	writeJSON(w, http.StatusOK, resp)
}

// sessionResultDTO is one result within the detail, its body rendered to safe
// bytes and its revisions attached.
type sessionResultDTO struct {
	ResultID     string                 `json:"result_id"`
	CreatedAt    time.Time              `json:"created_at"`
	AISource     bool                   `json:"ai_source"`
	Superseded   bool                   `json:"superseded"`
	SupersededBy string                 `json:"superseded_by,omitempty"`
	ETag         string                 `json:"etag"`
	Tombstoned   bool                   `json:"tombstoned"`
	Result       *cloudcontract.Result  `json:"result,omitempty"`
	Revisions    []store.ResultRevision `json:"revisions"`
}

// handlePortalSessionDetail serves one session's results + revision history.
func (s *Server) handlePortalSessionDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := portalPrincipalFrom(ctx)
	cloudSessionID := r.PathValue("id")

	det, err := s.store.GetAccountSession(ctx, p.AccountID, cloudSessionID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "session_not_found", "no such session")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: session detail", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not load session")
		return
	}

	results := make([]sessionResultDTO, 0, len(det.Results))
	for _, rd := range det.Results {
		dto := sessionResultDTO{
			ResultID:     rd.ResultID,
			CreatedAt:    rd.CreatedAt,
			AISource:     rd.AISource,
			Superseded:   rd.Superseded,
			SupersededBy: rd.SupersededBy,
			ETag:         cloudcontract.ResultETag(rd.ResultID, rd.CorrectionSeq),
			Tombstoned:   rd.Tombstoned,
			Revisions:    rd.Revisions,
		}
		if len(dto.Revisions) == 0 {
			dto.Revisions = []store.ResultRevision{}
		}
		if !rd.Tombstoned {
			safe, err := safeResult(rd.Result)
			if err != nil {
				// A stored result that cannot re-normalize is a server invariant
				// break (Normalize ran before insert). Fail loud rather than serve
				// unsafe bytes.
				writeErr(w, http.StatusInternalServerError, "internal", "corrupt result row")
				return
			}
			dto.Result = &safe
		}
		results = append(results, dto)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cloud_session_id": det.CloudSessionID,
		"tool":             det.Tool,
		"model_family":     det.ModelFamily,
		"created_at":       det.CreatedAt,
		"head_result_id":   det.HeadResultID,
		"results":          results,
	})
}

// safeResult re-normalizes a stored result body to its safe wire form (mirroring
// toResultRecord): the served bytes are the promised NFC/control-stripped form,
// never the raw stored bytes.
func safeResult(raw json.RawMessage) (cloudcontract.Result, error) {
	var result cloudcontract.Result
	if err := json.Unmarshal(raw, &result); err != nil {
		return cloudcontract.Result{}, err
	}
	norm, err := result.Normalize()
	if err != nil {
		return cloudcontract.Result{}, err
	}
	nb, err := json.Marshal(norm)
	if err != nil {
		return cloudcontract.Result{}, err
	}
	var safe cloudcontract.Result
	if err := json.Unmarshal(nb, &safe); err != nil {
		return cloudcontract.Result{}, err
	}
	return safe, nil
}

// parsePositiveInt parses a strictly-positive decimal; anything else errors so
// the caller keeps its default.
func parsePositiveInt(s string) (int, error) {
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return 0, errors.New("not a positive integer")
	}
	return v, nil
}

// encodeSessionsCursor packs the keyset (created_at, cloud_session_id) of the
// last row into an opaque base64url token. created_at is carried as UnixNano so
// the round-trip is exact.
func encodeSessionsCursor(createdAt time.Time, cloudSessionID string) string {
	raw := strconv.FormatInt(createdAt.UnixNano(), 10) + "|" + cloudSessionID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeSessionsCursor reverses encodeSessionsCursor. A malformed token is
// rejected (ok=false) rather than silently treated as "from the start".
func decodeSessionsCursor(cur string) (createdAt time.Time, cloudSessionID string, ok bool) {
	b, err := base64.RawURLEncoding.DecodeString(cur)
	if err != nil {
		return time.Time{}, "", false
	}
	sep := strings.IndexByte(string(b), '|')
	if sep <= 0 {
		return time.Time{}, "", false
	}
	nanos, err := strconv.ParseInt(string(b[:sep]), 10, 64)
	if err != nil {
		return time.Time{}, "", false
	}
	return time.Unix(0, nanos).UTC(), string(b[sep+1:]), true
}
