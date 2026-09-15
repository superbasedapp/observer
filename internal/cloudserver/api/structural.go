package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// structural.go is POST /v1/structural-insights — the hosted half of the
// structural-insights rail (divergence remediation plan rev 4.1 §3 W2 "Server
// half"). It mirrors handleSubmitJob's discipline: the request body IS the
// exact canonical bytes the node digested and stored, the digest is RECOMPUTED
// here from what arrived (a client-declared digest is never trusted), account
// and DEVICE come from the verified proof-of-possession principal, and the
// standing grant is validated against a server-side registration.
//
// It differs from the evidence path in one structural way, and deliberately: a
// session envelope's authorization is a receipt bound to ONE byte-string, so
// the check is "do these exact bytes have a confirmed preview". A standing
// grant authorizes a SCHEMA for an open-ended series of future windows, so the
// check is "does this account's registered grant for this purpose still cover
// this schema, at this consent generation" (R1).

const (
	// maxStructuralBodyBytes bounds a snapshot upload. The schema's own limits
	// (<=64 entries per mix, <=64-byte keys, a fixed set of scalar fields) put a
	// real snapshot near 10 KiB; 64 KiB is generous headroom and a hard wall,
	// well under the 2 MiB evidence ceiling the middleware already applies. The
	// same bound is a CHECK constraint on the column, so an oversized snapshot
	// cannot reach storage by any other route either.
	maxStructuralBodyBytes = 64 << 10

	// headerConsentGeneration carries the monotonic consent generation the
	// developer's standing grant was recorded at.
	headerConsentGeneration = "SBO-Consent-Generation"
	// headerDataDictionaryDigest carries the schema-level digest the standing
	// grant bound (cloudcontract.StructuralDataDictionaryDigest).
	headerDataDictionaryDigest = "SBO-Data-Dictionary-Digest"
	// headerSourceWindowRule carries the versioned rule naming WHICH activity
	// the grant covers. It is recorded on the registration (R1's binding set),
	// not gated on: a developer re-declaring a rule is a terms change, and terms
	// changes are gated by the consent generation.
	headerSourceWindowRule = "SBO-Source-Window-Rule"

	// maxGrantHeaderBytes bounds each grant-binding header so a hostile client
	// cannot push unbounded strings into a registration row.
	maxGrantHeaderBytes = 256
)

// structuralPurpose is the consent purpose POST /v1/structural-insights
// authorizes. It is a property of the ROUTE, derived server-side, and is
// deliberately NOT read from a request header: the endpoint serves exactly one
// purpose, so letting the caller name it would add a client-controlled input
// with no upside (a mismatch could only ever be a rejection).
//
// Note on authority: this route validates an upload against the account's
// server-side REGISTRATION of the node's standing grant. Consent itself stays
// NODE-authoritative — the registration follows the generation the node
// declares, monotonically, and the server never mints one. The PORTAL consent
// screen (portalconsent.go) is a separate, browser-plane preference store that
// this path deliberately does not consult.
const structuralPurpose = cloudcontract.PurposeStructuralInsights

// handleStructuralInsights stores one immutable snapshot window.
func (s *Server) handleStructuralInsights(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)

	// 1) Size cap + read. The middleware already bounded the body at the
	// evidence ceiling and handed back a re-readable reader; this narrows it to
	// the structural bound.
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxStructuralBodyBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "could not read body")
		return
	}
	if len(raw) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "empty snapshot body")
		return
	}
	if len(raw) > maxStructuralBodyBytes {
		s.audit(ctx, p.AccountID, "structural_rejected_too_large")
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large",
			"snapshot exceeds the structural-insights size bound")
		return
	}

	// 2) Parse + schema validation.
	var snap cloudcontract.StructuralSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "snapshot is not valid JSON")
		return
	}
	if err := snap.Validate(); err != nil {
		s.audit(ctx, p.AccountID, "structural_rejected_invalid")
		writeErr(w, http.StatusUnprocessableEntity, "invalid_snapshot", err.Error())
		return
	}

	// 3) Digest RECOMPUTED from the received bytes via the preimage rule, and
	// compared against the digest embedded in them. The client's declared value
	// is evidence of nothing; this is what proves the bytes were not edited
	// after they were digested.
	recomputed, err := cloudcontract.StructuralDigest(snap)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "digest recompute failed")
		return
	}
	if snap.Digest == "" || snap.Digest != recomputed {
		s.audit(ctx, p.AccountID, "structural_rejected_digest_tamper")
		writeErr(w, http.StatusUnprocessableEntity, "digest_mismatch",
			"the snapshot's embedded digest does not match a recomputation over the submitted bytes")
		return
	}
	// And the received bytes must BE the canonical serialization. Without this,
	// a re-framed body (different whitespace, reordered keys) could carry a
	// matching digest — the digest covers the VALUES, not the framing — and we
	// would then store bytes that are not the ones the node digested. Re-marshal
	// and compare: what we persist is provably canonical.
	canonical, err := cloudcontract.StructuralUploadBytes(snap)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "canonical re-serialization failed")
		return
	}
	if !bytes.Equal(canonical, raw) {
		s.audit(ctx, p.AccountID, "structural_rejected_noncanonical")
		writeErr(w, http.StatusUnprocessableEntity, "noncanonical_bytes",
			"the submitted bytes are not the canonical serialization of this snapshot")
		return
	}

	// 4) Standing-grant validation. The binding set rides as REQUEST HEADERS
	// because it describes the GRANT, not the window: putting it in the snapshot
	// would change what the digest covers (and therefore every existing
	// digest/receipt) for data that is not part of the window at all.
	gen, dict, rule, ok := s.structuralGrantHeaders(w, r)
	if !ok {
		return
	}
	// The server knows the schema it serves, so a dictionary digest that is not
	// the current one is refused before it can be registered. This is the wall
	// that stops a stale node re-registering an old schema's terms.
	if dict != cloudcontract.StructuralDataDictionaryDigest() {
		s.audit(ctx, p.AccountID, "structural_rejected_dictionary")
		writeErr(w, http.StatusForbidden, "data_dictionary_mismatch",
			"this snapshot's data dictionary is not the one this service currently accepts; re-confirm the standing grant")
		return
	}
	if snap.SchemaVersion != cloudcontract.StructuralSnapshotSchemaVersion {
		// Validate already enforces this; kept as the explicit statement that
		// the registration records the schema the service serves.
		writeErr(w, http.StatusUnprocessableEntity, "invalid_snapshot", "unsupported snapshot schema version")
		return
	}

	// 4) Rate limit before the registration write. The registration is an
	// admission-side mutation, so a limiter outage must not allow the request to
	// leave durable state behind while the caller receives a refusal.
	if s.rl != nil && s.rl.structural != nil && s.rl.structural.limit > 0 {
		ok, retry, err := s.rl.structural.allowContext(ctx, p.DeviceID)
		if err != nil {
			if s.log != nil {
				s.log.Error("cloudserver/api: structural rate limiter", "err", err)
			}
			writeRateLimitUnavailable(w)
			return
		}
		if !ok {
			s.audit(ctx, p.AccountID, "rate_limited_structural")
			writeRateLimited(w, retry)
			return
		}
	}

	_, action, err := s.store.RegisterStructuralGrant(ctx, p.AccountID, store.StructuralGrantInput{
		Purpose:              string(structuralPurpose),
		DataDictionaryDigest: dict,
		SchemaVersion:        snap.SchemaVersion,
		ConsentGeneration:    gen,
		DeclaredTimezone:     snap.DeclaredTimezone,
		SourceWindowRule:     rule,
		Now:                  s.now(),
	})
	if err != nil {
		writeStructuralGrantError(w, s, ctx, p.AccountID, err)
		return
	}

	// 5) One transaction: replay-ack / conflict / insert / supersede /
	// materialize.
	res, err := s.store.PutStructuralSnapshot(ctx, p.AccountID, store.StructuralSnapshotInput{
		DeviceID: p.DeviceID,
		// The purpose the insert REVALIDATES the grant under, from the route —
		// the same server-derived value the registration used (F7).
		Purpose:           string(structuralPurpose),
		Period:            snap.Period,
		PeriodRuleVersion: snap.PeriodRuleVersion,
		SchemaVersion:     snap.SchemaVersion,
		Revision:          snap.Revision,
		Digest:            recomputed,
		CanonicalBytes:    raw,
		DeclaredTimezone:  snap.DeclaredTimezone,
		SourceWatermark:   snap.SourceWatermark,
		ConsentGeneration: gen,
		Now:               s.now(),
	})
	if errors.Is(err, store.ErrStructuralDigestConflict) {
		s.audit(ctx, p.AccountID, "structural_rejected_revision_conflict")
		writeErr(w, http.StatusConflict, "revision_conflict",
			"a different snapshot is already stored for this window revision; a changed window is a new revision, never an overwrite")
		return
	}
	// F7: the insert re-checked the account and the registration inside its own
	// transaction. These refusals mean one of them changed between the
	// registration above and the write — an account deletion, or a grant
	// withdrawal — so NOTHING was stored.
	if errors.Is(err, store.ErrAccountClosed) {
		s.audit(ctx, p.AccountID, "structural_rejected_account_closed")
		writeErr(w, http.StatusForbidden, "account_closed",
			"this account no longer accepts uploads; nothing was stored")
		return
	}
	if errors.Is(err, store.ErrStructuralGrantRevoked) || errors.Is(err, store.ErrStructuralGrantMissing) ||
		errors.Is(err, store.ErrStructuralGenerationStale) {
		writeStructuralGrantError(w, s, ctx, p.AccountID, err)
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: store structural snapshot", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not store snapshot")
		return
	}

	// 7) Content-free audit: the event names the branch taken, never the data.
	s.audit(ctx, p.AccountID, "structural_snapshot_"+res.Status+"_grant_"+action)

	status := http.StatusAccepted
	if res.Replay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"snapshot_id": res.SnapshotID,
		"status":      res.Status,
		"replay":      res.Replay,
	})
}

// structuralGrantHeaders parses and bounds the three grant-binding headers,
// writing the refusal itself when one is missing or malformed.
func (s *Server) structuralGrantHeaders(w http.ResponseWriter, r *http.Request) (generation int64, dictionaryDigest, sourceWindowRule string, ok bool) {
	rawGen := strings.TrimSpace(r.Header.Get(headerConsentGeneration))
	if rawGen == "" {
		writeErr(w, http.StatusBadRequest, "missing_consent_generation",
			"the "+headerConsentGeneration+" header is required on a structural upload")
		return 0, "", "", false
	}
	gen, err := strconv.ParseInt(rawGen, 10, 64)
	if err != nil || gen < 1 {
		writeErr(w, http.StatusBadRequest, "invalid_consent_generation",
			"the "+headerConsentGeneration+" header must be a positive integer")
		return 0, "", "", false
	}
	dict := strings.TrimSpace(r.Header.Get(headerDataDictionaryDigest))
	if dict == "" {
		writeErr(w, http.StatusBadRequest, "missing_data_dictionary_digest",
			"the "+headerDataDictionaryDigest+" header is required on a structural upload")
		return 0, "", "", false
	}
	rule := strings.TrimSpace(r.Header.Get(headerSourceWindowRule))
	if rule == "" {
		// F5: the source-window rule is part of the binding the registration
		// records and compares, so an empty one cannot be stored. A registration
		// with a hole in it can never be checked against a later upload.
		writeErr(w, http.StatusBadRequest, "missing_source_window_rule",
			"the "+headerSourceWindowRule+" header is required on a structural upload")
		return 0, "", "", false
	}
	for name, v := range map[string]string{
		headerDataDictionaryDigest: dict,
		headerSourceWindowRule:     rule,
	} {
		if len(v) > maxGrantHeaderBytes {
			writeErr(w, http.StatusBadRequest, "header_too_long", "the "+name+" header is too long")
			return 0, "", "", false
		}
	}
	return gen, dict, rule, true
}

// writeStructuralGrantError maps a registration refusal to its honest status.
// Every branch is a REFUSAL of the upload: nothing is stored, and the node's
// classifier treats these 4xx codes as terminal so the window is not retried
// against terms that will keep refusing it.
func writeStructuralGrantError(w http.ResponseWriter, s *Server, ctx context.Context, accountID string, err error) {
	switch {
	case errors.Is(err, store.ErrStructuralGrantRevoked):
		s.audit(ctx, accountID, "structural_rejected_grant_revoked")
		writeErr(w, http.StatusForbidden, "grant_revoked",
			"the standing grant for this purpose has been withdrawn; re-grant it before syncing again")
	case errors.Is(err, store.ErrStructuralGenerationStale):
		s.audit(ctx, accountID, "structural_rejected_generation_stale")
		writeErr(w, http.StatusConflict, "consent_generation_stale",
			"this upload declares an older consent generation than the one registered; re-confirm the standing grant")
	case errors.Is(err, store.ErrStructuralDictionaryMismatch):
		s.audit(ctx, accountID, "structural_rejected_dictionary")
		writeErr(w, http.StatusForbidden, "data_dictionary_mismatch",
			"this upload's data dictionary differs from the registered grant at the same consent generation")
	case errors.Is(err, store.ErrStructuralGrantTermsMismatch):
		s.audit(ctx, accountID, "structural_rejected_grant_terms")
		writeErr(w, http.StatusForbidden, "grant_terms_mismatch",
			"this upload's grant terms (schema version, declared timezone, or source-window rule) differ from the ones "+
				"registered at the same consent generation; re-confirm the standing grant on this device — confirming it "+
				"raises the consent generation, and the new terms are recorded with it")
	case errors.Is(err, store.ErrStructuralBindingIncomplete):
		s.audit(ctx, accountID, "structural_rejected_binding_incomplete")
		writeErr(w, http.StatusBadRequest, "incomplete_grant_binding",
			"the declared standing-grant binding is missing its declared timezone or source-window rule; "+
				"a registration that does not record the full binding cannot be checked against later uploads")
	case errors.Is(err, store.ErrStructuralGrantMissing):
		s.audit(ctx, accountID, "structural_rejected_grant_missing")
		writeErr(w, http.StatusForbidden, "grant_missing",
			"no standing grant is registered for this purpose; re-grant it before syncing again")
	default:
		s.log.Error("cloudserver/api: register standing grant", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not validate the standing grant")
	}
}
