package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The WorkOS account-lifecycle webhook (plan §3 W1 "Lifecycle phase 1", D18).
//
// It is the ONE route on this server that is authenticated by neither a portal
// cookie nor a device bearer: WorkOS calls it, so the credential is an HMAC
// signature over the raw body. Three consequences shape the whole file:
//
//   - it is per-IP rate limited like the other unauthenticated endpoints;
//   - it is FAIL-CLOSED on configuration. With no signing secret configured the
//     route answers 501 and reads nothing. "No secret ⇒ verify nothing" would
//     turn an unauthenticated endpoint into an account-revocation lever for
//     anyone who can reach the origin, so it is not an option;
//   - the raw body is what the signature covers, so it is read (bounded) and
//     verified BEFORE any JSON decoding.
//
// Phase 1 handles four event types (Wave C, gap 2.6 — the original phase-1
// handler was `user.deleted` alone; this widens the table without changing
// its shape):
//
//   - `user.deleted` revokes every credential the linked account holds
//     (devices, API tokens, browser sessions) AND suspends the account —
//     ACCESS REVOCATION ONLY, never data deletion: the user-initiated
//     deletion path (POST /v1/deletion-requests, the portal deletion form) is
//     the only thing that removes data, and an identity provider saying "this
//     user is gone" is not the user asking us to erase their records.
//   - `user.updated` refreshes the linked account's DISPLAY profile
//     (account_profiles) from the event's email/name fields — the exact same
//     shape every sign-in already refreshes it with (accountprofile.go), just
//     triggered by the provider instead of a browser round-trip. It is
//     display data, never an identity or authorization decision.
//   - `session.revoked` revokes every LIVE browser session on the linked
//     account. WorkOS's own session-revocation (e.g. an admin ending a user's
//     SSO session at the IdP) carries no mapping from ITS session id to ours —
//     no WorkOS session id is stored on our side — so the honest response is
//     to revoke every browser session on the account rather than guess which
//     one. This is deliberately NOT a suspension: the identity is not gone,
//     only one session ended, and a fresh sign-in must keep working.
//   - `user.created` is recorded but never acts: WorkOS creating a user there
//     is not this product creating an account (the account is created on
//     first sign-in/device-exchange, never by a webhook).
//
// `organization_membership.*` and every OTHER event type — including any
// WorkOS adds later — are acknowledged and recorded, honestly unhandled,
// rather than pretended: see workOSEventDispatch.

const (
	// workOSSignatureHeader carries the timestamped HMAC WorkOS signs each
	// delivery with, in the form `t=<unix-ms>, v1=<hex hmac-sha256>`.
	workOSSignatureHeader = "WorkOS-Signature"
	// workOSSignatureTolerance bounds how far a delivery's signed timestamp may
	// be from our clock, in either direction. It is the replay window: a captured
	// delivery is useless once it lapses.
	workOSSignatureTolerance = 5 * time.Minute
	// WorkOS event type strings this phase names explicitly (see
	// workOSEventDispatch). Payload shapes verified against the WorkOS docs
	// 2026-09-11: user.* keys the affected user by `data.id`; session.* and
	// organization_membership.* key it by `data.user_id` instead (their own
	// `data.id` is the session/membership id, not the user).
	workOSEventUserDeleted    = "user.deleted"
	workOSEventUserUpdated    = "user.updated"
	workOSEventUserCreated    = "user.created"
	workOSEventSessionRevoked = "session.revoked"
	// workOSProvider is the identity-link provider label WorkOS subjects resolve
	// under — the same label identity.WorkOSVerifier reports, so a webhook and a
	// sign-in address the same account.
	workOSProvider = "workos"
)

// errWorkOSSignature wraps every signature-verification failure below, so the
// handler can answer one status with a specific, non-leaky code.
var errWorkOSSignature = errors.New("cloudserver/api: workos webhook signature invalid")

// workOSWebhookEvent is the slice of the provider's envelope this phase reads.
// The payload is NOT stored (migration 0010); it is decoded, acted on, and
// dropped.
type workOSWebhookEvent struct {
	ID    string `json:"id"`
	Event string `json:"event"`
	Data  struct {
		// ID is the WorkOS user id for a user.* event — the SUBJECT half of the
		// (provider, subject) identity link the device exchange and the portal
		// sign-in both key on. For a session.*/organization_membership.* event
		// this is that OBJECT's own id (a session or membership id), which is
		// why those handlers read UserID instead.
		ID string `json:"id"`
		// UserID is the affected user for session.* and
		// organization_membership.* events (WorkOS names it `user_id` on those
		// payloads, unlike a user.* event's own top-level `id`).
		UserID string `json:"user_id"`
		// Email/FirstName/LastName are user.updated's (and user.created's)
		// display fields — the same shape the browser sign-in's code-exchange
		// response already carries (portalauth.go's exchangeWorkOSCode).
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	} `json:"data"`
}

// workOSEventKind classifies how phase 1 handles one event TYPE — the shape
// applyWorkOSEvent needs, kept as a data table rather than a growing
// if/else-if ladder (CLAUDE.md #5: decision logic is table-driven).
type workOSEventKind int

const (
	// workOSEventRecordOnly is taken, recorded, and acknowledged, never acted
	// on. It is ALSO the zero value, so any event type absent from
	// workOSEventDispatch — every type WorkOS might add later, and everything
	// under organization_membership.* — falls through to it automatically,
	// with no explicit "ok" check required.
	workOSEventRecordOnly workOSEventKind = iota
	// workOSEventKindUserDeleted revokes and suspends the linked account (F8).
	workOSEventKindUserDeleted
	// workOSEventKindUserUpdated refreshes the linked account's display
	// profile.
	workOSEventKindUserUpdated
	// workOSEventKindSessionRevoked revokes every live browser session on the
	// linked account.
	workOSEventKindSessionRevoked
)

// workOSEventDispatch is the ONE table applyWorkOSEvent consults. A type named
// here gets the corresponding handling; every other type — present today
// (user.created, organization_membership.*) or added by WorkOS tomorrow —
// resolves to workOSEventRecordOnly via the map's zero-value default.
var workOSEventDispatch = map[string]workOSEventKind{
	workOSEventUserDeleted:    workOSEventKindUserDeleted,
	workOSEventUserUpdated:    workOSEventKindUserUpdated,
	workOSEventSessionRevoked: workOSEventKindSessionRevoked,
	// workOSEventUserCreated is named explicitly (rather than left to the
	// default) purely so a reader of this table does not wonder whether it was
	// forgotten — its handling IS record-only, on purpose (see the file
	// header).
	workOSEventUserCreated: workOSEventRecordOnly,
}

// verifyWorkOSSignature checks the `t=<unix-ms>, v1=<hex>` header against
// HMAC-SHA256("<t>.<raw body>") under secret, within the replay tolerance. The
// digest comparison is constant-time.
//
// UNITS (do not "fix" this to seconds): the `WorkOS-Signature` t= value is unix
// MILLISECONDS — the WorkOS SDK docs show a 13-digit example
// (t=1626125972272) — so it is parsed with time.UnixMilli. The tolerance itself
// is a time.Duration and the comparison is done on the resulting time.Time, so
// the unit lives in exactly one line and never leaks into the window math.
func verifyWorkOSSignature(header, secret string, body []byte, now time.Time) error {
	if strings.TrimSpace(header) == "" {
		return errWorkOSSignature
	}
	var rawTS, rawMAC string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			rawTS = v
		case "v1":
			rawMAC = v
		}
	}
	if rawTS == "" || rawMAC == "" {
		return errWorkOSSignature
	}
	ms, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return errWorkOSSignature
	}
	skew := now.Sub(time.UnixMilli(ms))
	if skew < 0 {
		skew = -skew
	}
	if skew > workOSSignatureTolerance {
		return errWorkOSSignature
	}
	presented, err := hex.DecodeString(rawMAC)
	if err != nil {
		return errWorkOSSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(rawTS))
	mac.Write([]byte("."))
	mac.Write(body)
	if !hmac.Equal(presented, mac.Sum(nil)) {
		return errWorkOSSignature
	}
	return nil
}

// handleWorkOSWebhook takes delivery of one provider lifecycle event.
//
// Order is deliberate: configuration gate → bounded raw read → signature →
// decode → idempotent intake → act → stamp processed. Nothing before the
// signature check touches the database, so an unsigned flood costs one bounded
// read and the per-IP cap, never a lookup or a write.
func (s *Server) handleWorkOSWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.workOSWebhookSecret == "" {
		writeErr(w, http.StatusNotImplemented, "webhook_not_configured",
			"WorkOS webhook intake is not configured on this deployment (WORKOS_WEBHOOK_SECRET is unset). Deliveries are refused rather than accepted unverified.")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		return
	}
	if err := verifyWorkOSSignature(r.Header.Get(workOSSignatureHeader), s.workOSWebhookSecret, body, s.now()); err != nil {
		s.audit(ctx, "", "workos_webhook_signature_invalid")
		writeErr(w, http.StatusUnauthorized, "signature_invalid",
			"the delivery signature was missing, malformed, stale, or did not verify")
		return
	}

	var ev workOSWebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil || ev.ID == "" || ev.Event == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid event envelope (id and event are required)")
		return
	}

	// Idempotent, RETRY-SAFE intake (F7). The question that decides whether to
	// act is "has this event's handling COMPLETED?", not "did this call insert
	// the row?". A delivery that was recorded and then failed mid-handling (or
	// whose process died) leaves a row with processed_at NULL, and WorkOS's
	// retry MUST re-run it. Acking on "not fresh" would drop exactly the events
	// the retry existed to save.
	intake, err := s.store.RecordWorkOSEvent(ctx, ev.ID, ev.Event, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: record workos event", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not record the event")
		return
	}
	if intake.Processed {
		// Settled. Re-running would emit duplicate audit rows and re-stamp a
		// finished event; revocation being idempotent is not a licence to.
		writeJSON(w, http.StatusOK, map[string]string{"status": "duplicate", "event_id": ev.ID})
		return
	}

	status, err := s.applyWorkOSEvent(r, ev)
	if err != nil {
		// A RECOGNIZED security event we could not carry out. Answer 5xx with NO
		// processed stamp so WorkOS redelivers and we try again: silently 200-ing
		// here is how a revocation gets lost forever.
		s.log.Error("cloudserver/api: apply workos event", "event_id", ev.ID, "event_type", ev.Event, "err", err)
		writeErr(w, http.StatusInternalServerError, "event_processing_failed",
			"the event was accepted but could not be processed; it will be retried on redelivery")
		return
	}

	if err := s.store.MarkWorkOSEventProcessed(ctx, ev.ID, s.now()); err != nil {
		// The work itself is already done and durable; failing to stamp the ledger
		// must not make us answer 5xx for an event we acted on. Log it and
		// acknowledge: the row stays processed_at NULL, which is the honest
		// investigate marker — and, since handling is now re-runnable, a
		// redelivery would simply redo idempotent work rather than break.
		s.log.Warn("cloudserver/api: mark workos event processed", "event_id", ev.ID, "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status, "event_id": ev.ID})
}

// applyWorkOSEvent runs the phase-1 handling for one pending event (a table
// lookup, then a dispatch to the one handler that kind names — see
// workOSEventDispatch) and returns the status word the acknowledgement
// carries, or an error when a RECOGNIZED security event could not be carried
// out.
//
// The error/no-error split is the retry contract, and it is deliberately
// asymmetric: an event type we do not act on can never "fail" (nil error ⇒
// stamped processed ⇒ never redelivered), whereas a handled event whose action
// errored returns an error (⇒ no stamp ⇒ redelivered ⇒ re-run).
func (s *Server) applyWorkOSEvent(r *http.Request, ev workOSWebhookEvent) (string, error) {
	ctx := r.Context()
	switch workOSEventDispatch[ev.Event] {
	case workOSEventKindUserDeleted:
		return s.applyUserDeleted(ctx, ev)
	case workOSEventKindUserUpdated:
		return s.applyUserUpdated(ctx, ev)
	case workOSEventKindSessionRevoked:
		return s.applySessionRevoked(ctx, ev)
	default:
		// workOSEventRecordOnly (the map's zero-value default too): taken,
		// recorded, not acted on. Phase 1 says so out loud rather than implying
		// a handler exists.
		return "acknowledged", nil
	}
}

// applyUserDeleted is the D18 phase-1 headline handler: revoke AND suspend, in
// one transaction (F8). Revocation alone is not durable — every credential is
// re-mintable from the same identity link, so a bare revocation lasts until
// the next sign-in — suspension is what makes the provider's "this user is
// gone" stick on our side.
func (s *Server) applyUserDeleted(ctx context.Context, ev workOSWebhookEvent) (string, error) {
	subject := strings.TrimSpace(ev.Data.ID)
	if subject == "" {
		// Nothing to resolve — a retry would be as empty as this attempt.
		s.audit(ctx, "", "workos_webhook_subject_missing")
		return "acknowledged", nil
	}
	accountID, err := s.store.AccountForIdentity(ctx, workOSProvider, subject)
	if errors.Is(err, store.ErrNotFound) {
		// A user we never linked (signed up with WorkOS, never used the product).
		// Nothing to revoke; not an error.
		return "no_account", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve workos subject for user.deleted: %w", err)
	}
	rev, err := s.store.RevokeAndSuspendAccount(ctx, accountID, s.now())
	if err != nil {
		return "", fmt.Errorf("revoke and suspend account: %w", err)
	}
	s.audit(ctx, accountID, "workos_account_access_revoked")
	s.log.Info("cloudserver/api: WorkOS lifecycle revocation applied",
		"event_type", ev.Event, "devices", rev.DevicesRevoked,
		"tokens", rev.TokensRevoked, "sessions", rev.SessionsRevoked,
		"suspended", rev.Suspended)
	return "revoked", nil
}

// applyUserUpdated refreshes the linked account's DISPLAY profile from a
// user.updated event, via the exact same seam every sign-in already uses
// (rememberProfile / newAccountProfile, accountprofile.go) — this is a cache
// refresh, never an identity or authorization decision. A user we never
// linked has nothing to refresh, and that is not an error: the same
// "nothing to do" shape user.deleted already returns for an unknown subject.
func (s *Server) applyUserUpdated(ctx context.Context, ev workOSWebhookEvent) (string, error) {
	subject := strings.TrimSpace(ev.Data.ID)
	if subject == "" {
		s.audit(ctx, "", "workos_webhook_subject_missing")
		return "acknowledged", nil
	}
	accountID, err := s.store.AccountForIdentity(ctx, workOSProvider, subject)
	if errors.Is(err, store.ErrNotFound) {
		return "no_account", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve workos subject for user.updated: %w", err)
	}
	// rememberProfile is itself best-effort (it swallows a storage failure —
	// see its doc comment), so this always succeeds once the account resolves;
	// a suspended account's fenced write is a silent no-op there, which is the
	// correct behaviour for a display-only cache on a non-active account.
	s.rememberProfile(ctx, accountID, newAccountProfile(ev.Data.Email, ev.Data.FirstName, ev.Data.LastName))
	s.audit(ctx, accountID, "workos_account_profile_refreshed")
	return "profile_refreshed", nil
}

// applySessionRevoked reacts to WorkOS's OWN session.revoked (distinct from
// user.deleted/D18 — the identity is not gone, only one provider session
// ended) by revoking every LIVE browser session on the linked account.
// WorkOS's payload carries no mapping from its session id to OUR opaque
// portal session (no WorkOS session id is ever stored on our side), so the
// honest response is to revoke every browser session on the account rather
// than guess which one — the device API and its tokens are untouched, since a
// WorkOS session is specifically the browser leg's own concept.
func (s *Server) applySessionRevoked(ctx context.Context, ev workOSWebhookEvent) (string, error) {
	subject := strings.TrimSpace(ev.Data.UserID)
	if subject == "" {
		s.audit(ctx, "", "workos_webhook_subject_missing")
		return "acknowledged", nil
	}
	accountID, err := s.store.AccountForIdentity(ctx, workOSProvider, subject)
	if errors.Is(err, store.ErrNotFound) {
		return "no_account", nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve workos subject for session.revoked: %w", err)
	}
	n, err := s.store.RevokeAllBrowserSessions(ctx, accountID, "", s.now())
	if err != nil {
		return "", fmt.Errorf("revoke browser sessions for session.revoked: %w", err)
	}
	s.audit(ctx, accountID, "workos_session_revoked")
	s.log.Info("cloudserver/api: WorkOS session.revoked applied", "sessions_revoked", n)
	return "sessions_revoked", nil
}
