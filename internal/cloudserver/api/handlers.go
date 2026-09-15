package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// --- devices ---

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	devices, err := s.store.ListDevices(r.Context(), p.AccountID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not list devices")
		return
	}
	type dev struct {
		ID         string `json:"id"`
		Thumbprint string `json:"thumbprint"`
		Label      string `json:"label"`
		CreatedAt  string `json:"created_at"`
		Revoked    bool   `json:"revoked"`
	}
	out := make([]dev, 0, len(devices))
	for _, d := range devices {
		out = append(out, dev{
			ID: d.ID, Thumbprint: d.Thumbprint, Label: d.Label,
			CreatedAt: d.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Revoked:   d.RevokedAt != nil,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	id := r.PathValue("id")
	err := s.store.RevokeDevice(r.Context(), p.AccountID, id, s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "device not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not revoke device")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// --- consents ---

func (s *Server) handleGetConsents(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	st, err := s.store.CurrentConsent(r.Context(), p.AccountID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read consents")
		return
	}
	purposes := st.Purposes
	if purposes == nil {
		purposes = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"purposes": purposes, "generation": st.Generation})
}

func (s *Server) handlePutConsents(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var body struct {
		Purposes []string `json:"purposes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if !purposesValid(body.Purposes) {
		writeErr(w, http.StatusBadRequest, "invalid_purpose", "one or more purposes are outside the vocabulary")
		return
	}
	gen, err := s.store.SetConsent(r.Context(), p.AccountID, body.Purposes, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not set consents")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"purposes": body.Purposes, "generation": gen})
}

func (s *Server) handlePreviewConfirmation(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	var body struct {
		Purposes        []string `json:"purposes"`
		FieldClasses    []string `json:"field_classes"`
		EvidenceSchema  string   `json:"evidence_schema"`
		ScrubberVersion string   `json:"scrubber_version"`
		RetentionPolicy string   `json:"retention_policy"`
		Endpoint        string   `json:"endpoint"`
		Subprocessors   []string `json:"subprocessors"`
		UploadDigest    string   `json:"upload_digest"`
		ContentDigest   string   `json:"evidence_content_digest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if body.UploadDigest == "" || body.EvidenceSchema == "" || body.ScrubberVersion == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "upload_digest, evidence_schema, scrubber_version are required")
		return
	}
	if !purposesValid(body.Purposes) {
		writeErr(w, http.StatusBadRequest, "invalid_purpose", "one or more purposes are outside the vocabulary")
		return
	}
	rp := body.RetentionPolicy
	if rp == "" {
		rp = "temp_1h"
	}
	rid, gen, err := s.store.RecordPreviewConfirmation(r.Context(), p.AccountID, store.PreviewConfirmationInput{
		DeviceID: p.DeviceID, Purposes: body.Purposes, FieldClasses: body.FieldClasses,
		EvidenceSchema: body.EvidenceSchema, ScrubberVersion: body.ScrubberVersion,
		RetentionPolicy: rp, Endpoint: body.Endpoint, Subprocessors: body.Subprocessors,
		UploadDigest: body.UploadDigest, ContentDigest: body.ContentDigest, Now: s.now(),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not record confirmation")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"receipt_id": rid, "generation": gen})
}

// --- results / usage ---

// accountCursorPrefix marks a per-account (E1 / W6b) pull cursor on the wire.
// `?after=v2:<n>` (and the emitted next_cursor "v2:<n>") take the account path;
// a bare decimal takes the LEGACY global-seq path so an in-flight node keeps
// working. Retired with the global cursor one release later.
const accountCursorPrefix = "v2:"

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())

	// Dual-read cursor parse (E1 / W6b):
	//   empty          ⇒ account path from 0 (the new default)
	//   "v2:<decimal>" ⇒ account path from that account_seq
	//   "<decimal>"    ⇒ LEGACY global-seq path (unchanged back-compat)
	//   anything else  ⇒ 400 bad_cursor
	after := r.URL.Query().Get("after")
	accountPath := true
	var cursor int64
	switch {
	case after == "":
		// account path from 0
	case strings.HasPrefix(after, accountCursorPrefix):
		v, err := strconv.ParseInt(strings.TrimPrefix(after, accountCursorPrefix), 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_cursor", "after must be an integer cursor")
			return
		}
		cursor = v
	default:
		v, err := strconv.ParseInt(after, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_cursor", "after must be an integer cursor")
			return
		}
		accountPath = false
		cursor = v
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil {
			limit = v
		}
	}

	var rows []store.ResultRow
	var err error
	if accountPath {
		rows, err = s.store.ListResultsAfterAccountSeq(r.Context(), p.AccountID, cursor, limit)
	} else {
		rows, err = s.store.ListResultsAfter(r.Context(), p.AccountID, cursor, limit)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not list results")
		return
	}

	// next tracks the cursor of the LAST row on whichever path we took; with no
	// rows it stays the input cursor so the caller re-polls from the same place.
	next := cursor
	records := make([]cloudcontract.ResultRecord, 0, len(rows))
	for _, row := range rows {
		rec, err := toResultRecord(row)
		if err != nil {
			// A stored result that cannot re-parse is a server-side invariant
			// break (Validate ran before insert). Fail loudly rather than emit a
			// malformed wire record.
			writeErr(w, http.StatusInternalServerError, "internal", "corrupt result row")
			return
		}
		records = append(records, rec)
		if accountPath {
			next = row.AccountSeq
		} else {
			next = row.Cursor
		}
	}

	// next_cursor is documented (internal/cloudclient/doc.go) and consumed
	// (ResultsPage.NextCursor) as an opaque STRING. On the account path it is
	// "v2:<n>" (so the node round-trips it back onto the account path); on the
	// legacy path it stays a bare decimal (so a legacy caller keeps getting
	// legacy cursors). Always present, including the empty-page case.
	nextCursor := strconv.FormatInt(next, 10)
	if accountPath {
		nextCursor = accountCursorPrefix + nextCursor
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": records, "next_cursor": nextCursor})
}

// toResultRecord maps a store row to the wire ResultRecord (plan §6 CI-P4):
// the typed result the node decodes, carrying cloud_session_id + provenance.
func toResultRecord(row store.ResultRow) (cloudcontract.ResultRecord, error) {
	// FE6: a deleted result is stored as the tombstone marker, which is NOT a
	// valid enrichment. Emit it as a TYPED deletion marker (Tombstoned=true, no
	// Result) rather than decoding it into a title-less zero-value result the
	// node would persist as an empty, schema-inconsistent enrichment.
	var marker struct {
		Tombstoned bool `json:"tombstoned"`
	}
	if err := json.Unmarshal(row.Result, &marker); err == nil && marker.Tombstoned {
		return cloudcontract.ResultRecord{
			CloudSessionID: row.CloudSessionID,
			ResultID:       row.ID,
			Cursor:         row.Cursor,
			AccountCursor:  accountCursorPrefix + strconv.FormatInt(row.AccountSeq, 10),
			SchemaVersion:  row.SchemaVersion,
			AISource:       row.AISource,
			Superseded:     row.Superseded,
			CreatedAt:      row.CreatedAt,
			ReceivedAt:     row.CreatedAt,
			Tombstoned:     true,
			Kind:           row.Kind,
			CloudProjectID: row.CloudProjectID,
			PeriodStart:    row.PeriodStart,
			PeriodEnd:      row.PeriodEnd,
		}, nil
	}
	// A project-digest row's body is DigestResult-shaped (headline/themes/...),
	// not Result-shaped (title/tags/...): decoding it through Result would
	// silently drop every digest field (the json tags don't overlap beyond
	// schema_version/confidence) and then fail Result.Normalize's
	// schema_version check outright. Branch on kind and carry the digest body
	// in its own typed field.
	if row.Kind == store.ResultKindProjectDigest {
		return toDigestResultRecord(row)
	}

	var result cloudcontract.Result
	if err := json.Unmarshal(row.Result, &result); err != nil {
		return cloudcontract.ResultRecord{}, err
	}
	// FE1/FE6: NORMALIZE at the server read boundary, don't merely Validate. A
	// stored row that cannot re-normalize is a server-side invariant break
	// (Normalize ran before insert) — fail loud. And Normalize TRANSFORMS text to
	// its safe form (NFC, control/bidi-stripped), so emitting the raw stored bytes
	// would put un-normalized text on the wire even though it "validated". Re-
	// materialize the wire Result from the normalized value (NormalizedResult
	// marshals wire-identically to Result) so the bytes the node and any HTML/JSX
	// sink receive are the promised safe form, never the raw stored bytes.
	norm, err := result.Normalize()
	if err != nil {
		return cloudcontract.ResultRecord{}, err
	}
	nb, err := json.Marshal(norm)
	if err != nil {
		return cloudcontract.ResultRecord{}, err
	}
	var safe cloudcontract.Result
	if err := json.Unmarshal(nb, &safe); err != nil {
		return cloudcontract.ResultRecord{}, err
	}
	return cloudcontract.ResultRecord{
		CloudSessionID: row.CloudSessionID,
		ResultID:       row.ID,
		Cursor:         row.Cursor,
		AccountCursor:  accountCursorPrefix + strconv.FormatInt(row.AccountSeq, 10),
		SchemaVersion:  row.SchemaVersion,
		AISource:       row.AISource,
		Superseded:     row.Superseded,
		ETag:           cloudcontract.ResultETag(row.ID, row.CorrectionSeq),
		CreatedAt:      row.CreatedAt,
		ReceivedAt:     row.CreatedAt,
		Result:         safe,
		Kind:           row.Kind,
		CloudProjectID: row.CloudProjectID,
		PeriodStart:    row.PeriodStart,
		PeriodEnd:      row.PeriodEnd,
		Provenance: cloudcontract.ResultProvenance{
			ModelRouteID:  row.Provenance.ModelRouteID,
			RouteVersion:  row.Provenance.RouteVersion,
			PromptVersion: row.Provenance.PromptVersion,
			PriceVersion:  row.Provenance.PriceVersion,
			PromptHash:    row.Provenance.PromptHash,
			TokensIn:      row.Provenance.TokensIn,
			TokensOut:     row.Provenance.TokensOut,
			CostUSD:       row.Provenance.CostUSD,
			RetryCount:    row.Provenance.RetryCount,
		},
	}, nil
}

// toDigestResultRecord maps a project_digest store row to the wire
// ResultRecord, re-normalizing the stored DigestResult body (mirroring
// toResultRecord's FE1/FE6 discipline: NORMALIZE at the read boundary, don't
// merely Validate) and carrying it in the additive DigestResult field — the
// strongly-typed Result field stays a session-enrichment shape and is left
// zero-valued for a digest record.
func toDigestResultRecord(row store.ResultRow) (cloudcontract.ResultRecord, error) {
	var digest cloudcontract.DigestResult
	if err := json.Unmarshal(row.Result, &digest); err != nil {
		return cloudcontract.ResultRecord{}, err
	}
	norm, err := digest.Normalize()
	if err != nil {
		return cloudcontract.ResultRecord{}, err
	}
	nb, err := json.Marshal(norm)
	if err != nil {
		return cloudcontract.ResultRecord{}, err
	}
	var safe cloudcontract.DigestResult
	if err := json.Unmarshal(nb, &safe); err != nil {
		return cloudcontract.ResultRecord{}, err
	}
	return cloudcontract.ResultRecord{
		CloudSessionID: row.CloudSessionID,
		ResultID:       row.ID,
		Cursor:         row.Cursor,
		AccountCursor:  accountCursorPrefix + strconv.FormatInt(row.AccountSeq, 10),
		SchemaVersion:  row.SchemaVersion,
		AISource:       row.AISource,
		Superseded:     row.Superseded,
		ETag:           cloudcontract.ResultETag(row.ID, row.CorrectionSeq),
		CreatedAt:      row.CreatedAt,
		ReceivedAt:     row.CreatedAt,
		Kind:           row.Kind,
		CloudProjectID: row.CloudProjectID,
		PeriodStart:    row.PeriodStart,
		PeriodEnd:      row.PeriodEnd,
		DigestResult:   &safe,
		Provenance: cloudcontract.ResultProvenance{
			ModelRouteID:  row.Provenance.ModelRouteID,
			RouteVersion:  row.Provenance.RouteVersion,
			PromptVersion: row.Provenance.PromptVersion,
			PriceVersion:  row.Provenance.PriceVersion,
			PromptHash:    row.Provenance.PromptHash,
			TokensIn:      row.Provenance.TokensIn,
			TokensOut:     row.Provenance.TokensOut,
			CostUSD:       row.Provenance.CostUSD,
			RetryCount:    row.Provenance.RetryCount,
		},
	}, nil
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	snap, err := s.store.Usage(r.Context(), p.AccountID, store.FeatureSessionEnrichment, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read usage")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// --- logout ---

// handleLogout is the device-initiated sign-out (plan §3 W1, D17): it revokes
// the PRESENTED API token server-side, so a copy of that bearer stops working
// the moment the node clears its local credential — the gap that made
// `observer cloud logout` a purely local act.
//
// It revokes the TOKEN, never the device: the same device may log in again with
// a fresh exchange. Revoking the device instead would be a much stronger,
// unasked-for act (a revoked device may never re-exchange, per §3.3).
//
// It is idempotent at the store seam (an already-revoked row is a no-op, not an
// error). Note that a SECOND HTTP call with the same bearer never reaches this
// handler at all: the authenticate middleware introspects a revoked token as
// invalid and answers 401 — a stronger outcome than a repeated 200, and the
// proof that the revocation took effect.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	if err := s.store.RevokeAPIToken(r.Context(), p.AccountID, p.TokenID, s.now()); err != nil {
		s.log.Error("cloudserver/api: revoke api token", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not revoke this device token")
		return
	}
	s.audit(r.Context(), p.AccountID, "device_logout")
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

// --- deletion ---

func (s *Server) handleDeletionRequest(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	req, err := s.store.CreateDeletionRequest(r.Context(), p.AccountID, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not record deletion request")
		return
	}
	s.audit(r.Context(), p.AccountID, "deletion_requested")
	writeJSON(w, http.StatusAccepted, req)
}
