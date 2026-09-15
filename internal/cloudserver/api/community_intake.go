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
	"github.com/marmutapp/superbased-observer/internal/cloudserver/community"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// community_intake.go is POST /v1/community/contribution — the hosted half of
// the W5 contribution-upload path (divergence-remediation plan §3 W5). It is the
// leaner sibling of handleStructuralInsights and enforces the same discipline:
// the body IS the exact canonical bytes the node digested, the digest is
// RECOMPUTED from what arrived (a client-declared digest is never trusted),
// account + device come from the verified proof-of-possession principal, the
// four identifiers are validated against the compiled-in registry (an
// unregistered cohort/metric is a 400 — the forbidden-metric guard), and the
// standing grant is validated against a server-side registration.
//
// The actual value write goes through the already-hardened
// store.UpsertContribution, which rejects a write to an already-finalized window
// (ErrWindowFinalized) and to an unregistered cohort (ErrUnknownCohort) — so a
// published aggregate can never be moved by a late contribution.

const (
	// maxCommunityBodyBytes bounds a contribution upload. A contribution is four
	// short registry identifiers + one number + a digest; a real one is well
	// under 1 KiB. 4 KiB is generous headroom and a hard wall, far under the
	// 2 MiB middleware ceiling.
	maxCommunityBodyBytes = 4 << 10
)

// communityPurpose is the consent purpose POST /v1/community/contribution
// authorizes. It is a property of the ROUTE, derived server-side, never read
// from a client field: the endpoint serves exactly one purpose.
const communityPurpose = cloudcontract.PurposeCohortBenchmarking

// headerDeclaredTimezone carries the timezone the node's community standing
// grant declares. Community metric computation and window eligibility are
// UTC-only (the disclosure promises UTC), so this purpose is UTC-FIXED: the
// server accepts only "UTC" here (Sol N5). An absent header defaults to UTC; a
// present non-UTC value is refused so the recorded binding never contains a term
// that changes neither the bytes nor admission.
const headerDeclaredTimezone = "SBO-Declared-Timezone"

// communityFixedTimezone is the only declared timezone this purpose accepts and
// the exact value registered server-side (Sol N5).
const communityFixedTimezone = "UTC"

// communityExpectedSourceWindowRule is the versioned source-window rule the node
// must declare for this purpose (Sol N1/N5). v1 is the truthful rule the node
// adopts: the in-progress UTC month's scalar is re-sent on each sync until the
// month closes, then frozen. The header carrying it is headerSourceWindowRule
// (shared with the structural rail).
const communityExpectedSourceWindowRule = "in_progress_utc_month_after_grant"

// communityRequireSourceWindowRule gates whether SBO-Source-Window-Rule is
// MANDATORY on a community upload. It is a single documented toggle (Sol N5).
// The node CLI has sent the rule since the same release this landed in
// (cmd/observer/cloudcommunity.go, Sol N1), so a MISSING header is a clean 400;
// a PRESENT header is validated against communityExpectedSourceWindowRule
// regardless of this toggle. Set to false only to accept a pre-N1 node during a
// staged rollout (its uploads are then audited community_grant_rule_absent).
const communityRequireSourceWindowRule = true

// handleCommunityContribution stores (or upserts) one derived per-window value.
func (s *Server) handleCommunityContribution(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)

	// 1-3) Read + parse + digest/canonical-bytes proof.
	c, ok := s.decodeCommunityContribution(w, r, p.AccountID)
	if !ok {
		return
	}

	// 4) Registry validation — the forbidden-metric / unknown-cohort guard. Only
	// a registered cohort + metric may be contributed; anything else is a 400, not
	// a free-form write. (store.UpsertContribution re-checks the cohort as the DB
	// backstop, but validating here gives the honest 400 and never writes a grant
	// for an identifier that can never be aggregated.)
	if !community.ValidCohort(c.CohortKey) {
		s.audit(ctx, p.AccountID, "community_rejected_unknown_cohort")
		writeErr(w, http.StatusBadRequest, "unknown_cohort", "cohort is not a registered community cohort")
		return
	}
	metric, ok := community.LookupMetric(c.MetricID, c.MetricVersion)
	if !ok {
		s.audit(ctx, p.AccountID, "community_rejected_unknown_metric")
		writeErr(w, http.StatusBadRequest, "unknown_metric", "metric is not a registered community metric at this version")
		return
	}
	// Metric-specific value domain (Sol F12): cloudcontract.Validate already
	// rejected a non-finite/negative/absurd value against the shared,
	// data-independent sanity ceiling; this is the NARROWER per-metric range
	// (e.g. a percentage's [0,100]) that ceiling cannot express. Checked here,
	// before any grant mutation, so an out-of-domain value is a plain 400 and
	// never advances the standing grant's consent generation.
	if !metric.InDomain(c.Value) {
		s.audit(ctx, p.AccountID, "community_rejected_out_of_domain")
		writeErr(w, http.StatusBadRequest, "metric_out_of_domain",
			"value is outside this metric's valid range")
		return
	}
	// 5) Standing-grant binding headers (5 / 5b / 5c).
	gen, dict, okh := s.communityGrantBinding(w, r, p.AccountID)
	if !okh {
		return
	}

	// 6) ONE admission transaction (Sol N3 + N4): account fence → DB-authoritative
	// window → grant register → contribution upsert, all atomic. Any refusal rolls
	// the grant mutation back, so a rejected upload never advances the standing
	// grant.
	res, err := s.store.AdmitCommunityContribution(ctx, p.AccountID, store.AdmitCommunityContributionInput{
		Purpose:              string(communityPurpose),
		DeviceID:             p.DeviceID,
		DataDictionaryDigest: dict,
		SchemaVersion:        c.SchemaVersion,
		ConsentGeneration:    gen,
		DeclaredTimezone:     communityFixedTimezone,
		CohortKey:            c.CohortKey,
		MetricID:             metric.ID,
		MetricVersion:        metric.Version,
		WindowID:             c.WindowID,
		Value:                c.Value,
		Now:                  s.now(),
	})
	switch {
	case err == nil:
		// fallthrough to the success audit below.
	case errors.Is(err, store.ErrWindowNotCurrent):
		// Sol N7: past AND future both map here — 409 window_not_current — with
		// distinct copy. The DB-authoritative current window (res.CurrentWindow)
		// disambiguates: a lexicographic "YYYY-MM" compare is a chronological one.
		s.audit(ctx, p.AccountID, "community_rejected_window_not_current")
		msg := "this contribution window is not the current, in-progress window; only the in-progress window accepts writes"
		if res.CurrentWindow != "" && c.WindowID < res.CurrentWindow {
			msg = "this contribution window has already elapsed and is frozen; only the current in-progress window (" +
				res.CurrentWindow + ") accepts writes"
		} else if res.CurrentWindow != "" {
			msg = "this contribution window has not started yet; only the current in-progress window (" +
				res.CurrentWindow + ") accepts writes"
		}
		writeErr(w, http.StatusConflict, "window_not_current", msg)
		return
	case errors.Is(err, store.ErrCrossDeviceConflict):
		// Sol F9 interim honesty: the body states the recovery — the original
		// device must sync, or wait for the next writable window — and carries an
		// owner_device_hint (first 8 chars of the owning device id) + next_window.
		s.audit(ctx, p.AccountID, "community_rejected_cross_device_conflict")
		ownerHint := res.OwnerDeviceID
		if len(ownerHint) > 8 {
			ownerHint = ownerHint[:8]
		}
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this contribution window was already synced from a different device on this account; " +
				"the device that first synced this window (" + ownerHint + "…) must continue syncing it, " +
				"or contribute again from any device in the next window (" + res.NextWindow + ")",
			"code":              "cross_device_conflict",
			"owner_device_hint": ownerHint,
			"next_window":       res.NextWindow,
		})
		return
	case errors.Is(err, store.ErrUnknownCohort):
		s.audit(ctx, p.AccountID, "community_rejected_unknown_cohort")
		writeErr(w, http.StatusBadRequest, "unknown_cohort", "cohort is not a registered community cohort")
		return
	case errors.Is(err, store.ErrAccountClosed):
		// The admission fenced the account status FIRST inside its transaction
		// (Sol F5/N3): this account was deleted before/while this upload ran.
		// Nothing was stored and no grant was created — the whole tx rolled back.
		s.audit(ctx, p.AccountID, "community_rejected_account_closed")
		writeErr(w, http.StatusForbidden, "account_closed",
			"this account no longer accepts uploads; nothing was stored")
		return
	case errors.Is(err, store.ErrCommunityGrantRevoked),
		errors.Is(err, store.ErrCommunityGenerationStale),
		errors.Is(err, store.ErrCommunityDictionaryMismatch),
		errors.Is(err, store.ErrCommunityGrantTermsMismatch),
		errors.Is(err, store.ErrCommunityBindingIncomplete),
		errors.Is(err, store.ErrCommunityGrantMissing):
		writeCommunityGrantError(w, s, ctx, p.AccountID, err)
		return
	default:
		s.log.Error("cloudserver/api: admit community contribution", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not store contribution")
		return
	}

	// 8) Content-free audit: the event names the branch, never the value.
	s.audit(ctx, p.AccountID, "community_contribution_stored_grant_"+res.GrantAction)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "stored",
		"window": c.WindowID,
	})
}

// decodeCommunityContribution performs steps 1-3 of the community intake:
// size-capped read, parse + schema validation, and the digest / canonical-bytes
// proof. On a refusal it has already written the response (and audited the
// branch) and returns ok=false.
func (s *Server) decodeCommunityContribution(w http.ResponseWriter, r *http.Request, accountID string) (cloudcontract.CommunityContribution, bool) {
	ctx := r.Context()
	var c cloudcontract.CommunityContribution

	// 1) Size cap + read.
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCommunityBodyBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "could not read body")
		return c, false
	}
	if len(raw) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "empty contribution body")
		return c, false
	}
	if len(raw) > maxCommunityBodyBytes {
		s.audit(ctx, accountID, "community_rejected_too_large")
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large",
			"contribution exceeds the size bound")
		return c, false
	}

	// 2) Parse + schema validation.
	if err := json.Unmarshal(raw, &c); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "contribution is not valid JSON")
		return c, false
	}
	if err := c.Validate(); err != nil {
		s.audit(ctx, accountID, "community_rejected_invalid")
		writeErr(w, http.StatusUnprocessableEntity, "invalid_contribution", err.Error())
		return c, false
	}

	// 3) Digest RECOMPUTED from the received bytes and compared against the digest
	// embedded in them — proves the bytes were not edited after being digested.
	recomputed, err := cloudcontract.CommunityDigest(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "digest recompute failed")
		return c, false
	}
	if c.Digest == "" || c.Digest != recomputed {
		s.audit(ctx, accountID, "community_rejected_digest_tamper")
		writeErr(w, http.StatusUnprocessableEntity, "digest_mismatch",
			"the contribution's embedded digest does not match a recomputation over the submitted bytes")
		return c, false
	}
	// And the received bytes must BE the canonical serialization: a re-framed body
	// could carry a matching digest (the digest covers VALUES, not framing), and
	// we must never store bytes that are not the ones the node digested.
	canonical, err := cloudcontract.CommunityUploadBytes(c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "canonical re-serialization failed")
		return c, false
	}
	if !bytes.Equal(canonical, raw) {
		s.audit(ctx, accountID, "community_rejected_noncanonical")
		writeErr(w, http.StatusUnprocessableEntity, "noncanonical_bytes",
			"the submitted bytes are not the canonical serialization of this contribution")
		return c, false
	}
	return c, true
}

// communityGrantBinding performs step 5 (and 5b / 5c) of the community intake:
// the standing-grant binding that rides as request headers — it describes the
// GRANT, not the window. It returns the consent generation and the data
// dictionary digest; on a refusal it has already written the response (and
// audited the branch) and returns ok=false.
//
// Window currency is NO LONGER checked here (Sol N4): the current-window
// decision is DB-clock authoritative and lives inside the single
// AdmitCommunityContribution transaction, so the API Go clock, the store Go
// clock, and the DB trigger cannot disagree. Atomicity (Sol N3) replaces the
// old "check window before registering the grant" ordering: a doomed window
// rolls the grant mutation back rather than leaving it behind.
func (s *Server) communityGrantBinding(w http.ResponseWriter, r *http.Request, accountID string) (gen int64, dict string, ok bool) {
	ctx := r.Context()

	// 5) The dictionary digest must be the one this service currently serves.
	gen, dict, okh := s.communityGrantHeaders(w, r)
	if !okh {
		return 0, "", false
	}
	if dict != cloudcontract.CommunityDataDictionaryDigest() {
		s.audit(ctx, accountID, "community_rejected_dictionary")
		writeErr(w, http.StatusForbidden, "data_dictionary_mismatch",
			"this contribution's data dictionary is not the one this service currently accepts; re-confirm the standing grant")
		return 0, "", false
	}

	// 5b) Declared timezone (Sol N5): this purpose is UTC-fixed. An absent header
	// defaults to UTC; a present non-UTC value is refused, so the registered
	// binding always records exactly UTC and can never claim a window timezone it
	// does not use.
	if tz := strings.TrimSpace(r.Header.Get(headerDeclaredTimezone)); tz != "" && tz != communityFixedTimezone {
		s.audit(ctx, accountID, "community_rejected_grant_terms")
		writeErr(w, http.StatusForbidden, "grant_terms_mismatch",
			"the community benchmarking purpose is UTC-fixed; only a UTC declared timezone is accepted")
		return 0, "", false
	}

	// 5c) Source-window rule (Sol N1/N5), additive. A PRESENT header must name the
	// expected in-progress-UTC-month rule. A MISSING header is accepted today with
	// an audit tag (the node CLI does not send it yet); flip
	// communityRequireSourceWindowRule when the node ships the rule.
	if rule := strings.TrimSpace(r.Header.Get(headerSourceWindowRule)); rule != "" {
		if rule != communityExpectedSourceWindowRule {
			s.audit(ctx, accountID, "community_rejected_grant_terms")
			writeErr(w, http.StatusForbidden, "grant_terms_mismatch",
				"this contribution declares an unrecognized source-window rule for the community benchmarking purpose")
			return 0, "", false
		}
	} else if communityRequireSourceWindowRule {
		writeErr(w, http.StatusBadRequest, "missing_source_window_rule",
			"the "+headerSourceWindowRule+" header is required on a community contribution")
		return 0, "", false
	} else {
		s.audit(ctx, accountID, "community_grant_rule_absent")
	}
	return gen, dict, true
}

// communityGrantHeaders parses and bounds the two grant-binding headers,
// writing the refusal itself when one is missing or malformed. Community has no
// source-window rule (a contribution names its own UTC window), so only the
// consent generation and dictionary digest are read.
func (s *Server) communityGrantHeaders(w http.ResponseWriter, r *http.Request) (generation int64, dictionaryDigest string, ok bool) {
	rawGen := strings.TrimSpace(r.Header.Get(headerConsentGeneration))
	if rawGen == "" {
		writeErr(w, http.StatusBadRequest, "missing_consent_generation",
			"the "+headerConsentGeneration+" header is required on a community contribution")
		return 0, "", false
	}
	gen, err := strconv.ParseInt(rawGen, 10, 64)
	if err != nil || gen < 1 {
		writeErr(w, http.StatusBadRequest, "invalid_consent_generation",
			"the "+headerConsentGeneration+" header must be a positive integer")
		return 0, "", false
	}
	dict := strings.TrimSpace(r.Header.Get(headerDataDictionaryDigest))
	if dict == "" {
		writeErr(w, http.StatusBadRequest, "missing_data_dictionary_digest",
			"the "+headerDataDictionaryDigest+" header is required on a community contribution")
		return 0, "", false
	}
	if len(dict) > maxGrantHeaderBytes {
		writeErr(w, http.StatusBadRequest, "header_too_long", "the "+headerDataDictionaryDigest+" header is too long")
		return 0, "", false
	}
	return gen, dict, true
}

// writeCommunityGrantError maps a registration refusal to its honest status.
// Every branch is a REFUSAL of the upload: nothing is stored, and the node's
// classifier treats these 4xx codes as terminal so the contribution is not
// retried against terms that will keep refusing it.
func writeCommunityGrantError(w http.ResponseWriter, s *Server, ctx context.Context, accountID string, err error) {
	switch {
	case errors.Is(err, store.ErrCommunityGrantRevoked):
		s.audit(ctx, accountID, "community_rejected_grant_revoked")
		writeErr(w, http.StatusForbidden, "grant_revoked",
			"the standing grant for this purpose has been withdrawn; re-grant it before contributing again")
	case errors.Is(err, store.ErrCommunityGenerationStale):
		s.audit(ctx, accountID, "community_rejected_generation_stale")
		writeErr(w, http.StatusConflict, "consent_generation_stale",
			"this contribution declares an older consent generation than the one registered; re-confirm the standing grant")
	case errors.Is(err, store.ErrCommunityDictionaryMismatch):
		s.audit(ctx, accountID, "community_rejected_dictionary")
		writeErr(w, http.StatusForbidden, "data_dictionary_mismatch",
			"this contribution's data dictionary differs from the registered grant at the same consent generation")
	case errors.Is(err, store.ErrCommunityGrantTermsMismatch):
		s.audit(ctx, accountID, "community_rejected_grant_terms")
		writeErr(w, http.StatusForbidden, "grant_terms_mismatch",
			"this contribution's grant terms (schema version or declared timezone) differ from the ones registered at the "+
				"same consent generation; re-confirm the standing grant, which raises the consent generation")
	case errors.Is(err, store.ErrCommunityBindingIncomplete):
		s.audit(ctx, accountID, "community_rejected_binding_incomplete")
		writeErr(w, http.StatusBadRequest, "incomplete_grant_binding",
			"the declared standing-grant binding is missing its data dictionary digest or schema version")
	case errors.Is(err, store.ErrCommunityGrantMissing):
		s.audit(ctx, accountID, "community_rejected_grant_missing")
		writeErr(w, http.StatusForbidden, "grant_missing",
			"no standing grant is registered for this purpose; re-grant it before contributing again")
	default:
		s.log.Error("cloudserver/api: register community grant", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not validate the standing grant")
	}
}
