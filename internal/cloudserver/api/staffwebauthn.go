package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The four WebAuthn ceremony routes of the staff console. The staff process
// wires the go-webauthn verifier (staffauth/passkey, ruling A2); a server
// with no verifier answers 501 not_available on each, before reading
// anything. Registration needs an operator-minted enrolment code (the only
// way any credential, the first included, comes to exist); a session comes
// only from an assertion.
//
//	register/begin   body {enrolment_code}: checks the operator-minted code,
//	                 records a challenge, sets the ceremony cookie, returns
//	                 {publicKey: creation options}.
//	register/finish  body {credential, label}: spends the ceremony, verifies,
//	                 stores the credential and spends the code in one
//	                 transaction. It does not sign in: a session comes only
//	                 from an assertion.
//	assert/begin     records a challenge, sets the ceremony cookie, returns
//	                 {publicKey: request options}.
//	assert/finish    body {credential}: spends the ceremony, finds the
//	                 credential, verifies, applies the counter rule, and
//	                 mints a NEW staff session (revoking any session cookie
//	                 the browser presented), returning its CSRF token.

// staffCredentialBody is a finish request.
type staffCredentialBody struct {
	Credential json.RawMessage `json:"credential"`
	Label      string          `json:"label"`
}

// staffWebAuthnReady answers 501 not_available or 503 and reports false
// when the ceremony routes cannot run.
func (s *Server) staffWebAuthnReady(w http.ResponseWriter) bool {
	if !s.staff.verifier.Available() {
		writeErr(w, http.StatusNotImplemented, "not_available",
			"staff WebAuthn is not available on this server (no passkey verifier is wired; the staff console runs as `observer-cloud staff serve`)")
		return false
	}
	if s.staff.db == nil {
		writeErr(w, http.StatusServiceUnavailable, "staff_unavailable", "the staff console has no store")
		return false
	}
	return true
}

// readStaffCredential decodes a finish body.
func readStaffCredential(w http.ResponseWriter, r *http.Request) (staffCredentialBody, bool) {
	var body staffCredentialBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, staffauth.MaxResponseBytes+4096)).Decode(&body); err != nil || len(body.Credential) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "a JSON body with a credential is required")
		return body, false
	}
	return body, true
}

// staffCeremonyFromCookie spends the ceremony the cookie names, clearing the
// cookie whatever the outcome (a challenge is answerable once).
func (s *Server) staffCeremonyFromCookie(w http.ResponseWriter, r *http.Request, kind store.StaffCeremonyKind, now time.Time) (store.StaffCeremony, bool) {
	c, err := r.Cookie(s.staffCeremonyCookieName())
	s.setStaffCookie(w, s.staffCeremonyCookieName(), "", time.Time{}, -1)
	if err != nil || c.Value == "" {
		writeErr(w, http.StatusBadRequest, "ceremony_missing", "no WebAuthn ceremony in progress")
		return store.StaffCeremony{}, false
	}
	cer, err := s.staff.db.ConsumeStaffCeremony(r.Context(), c.Value, kind, now)
	if err != nil {
		if !errors.Is(err, store.ErrStaffCeremonyInvalid) {
			s.log.Error("cloudserver/api: staff ceremony", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "could not read the ceremony")
			return store.StaffCeremony{}, false
		}
		writeErr(w, http.StatusBadRequest, "ceremony_invalid", "the WebAuthn ceremony expired or was already used")
		return store.StaffCeremony{}, false
	}
	return cer, true
}

// startStaffCeremony mints a challenge and a ceremony token and sets the
// ceremony cookie; record stores the ceremony.
func (s *Server) startStaffCeremony(w http.ResponseWriter, now time.Time, record func(raw string, challenge []byte) error) ([]byte, bool) {
	challenge, err := staffauth.NewChallenge(s.staff.random)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not mint a challenge")
		return nil, false
	}
	raw, err := s.staffToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not mint a ceremony")
		return nil, false
	}
	if err := record(raw, challenge); err != nil {
		if errors.Is(err, store.ErrStaffEnrolmentInvalid) {
			writeErr(w, http.StatusUnauthorized, "enrolment_invalid", "the enrolment code is invalid, used or expired")
			return nil, false
		}
		if errors.Is(err, staffauth.ErrPasskeyLimit) {
			writePasskeyLimit(w)
			return nil, false
		}
		s.log.Error("cloudserver/api: staff ceremony start", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start the ceremony")
		return nil, false
	}
	s.setStaffCookie(w, s.staffCeremonyCookieName(), raw, now.Add(store.StaffCeremonyTTL), int(store.StaffCeremonyTTL/time.Second))
	return challenge, true
}

// writePasskeyLimit answers a registration refused by the per-member passkey
// cap (staffauth.MaxActivePasskeys, ruling Staff 2): 409 passkey_limit, with
// what to do about it.
func writePasskeyLimit(w http.ResponseWriter) {
	writeErr(w, http.StatusConflict, "passkey_limit", fmt.Sprintf(
		"this staff member already holds %d active passkeys, the most allowed; ask the operator to revoke one "+
			"(observer-cloud staff revoke-credential) and register again with the same code", staffauth.MaxActivePasskeys))
}

func (s *Server) handleStaffRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if !s.staffWebAuthnReady(w) {
		return
	}
	var body struct {
		EnrolmentCode string `json:"enrolment_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil || strings.TrimSpace(body.EnrolmentCode) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "an enrolment_code is required")
		return
	}
	now := s.now()
	var start store.StaffRegistrationStart
	challenge, ok := s.startStaffCeremony(w, now, func(raw string, challenge []byte) error {
		var err error
		start, err = s.staff.db.BeginStaffRegistration(r.Context(), strings.TrimSpace(body.EnrolmentCode), raw, challenge, now)
		return err
	})
	if !ok {
		return
	}
	opts := staffauth.NewCreationOptions(staffauth.RegistrationCeremony{
		RPID: s.staff.rpID, Origin: s.staff.origin, Challenge: challenge,
		UserHandle: store.StaffUserHandle(start.Staff.StaffID),
	}, start.Staff.DisplayName, start.ExistingCredentialIDs, staffWebAuthnTimeout)
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": opts})
}

func (s *Server) handleStaffRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !s.staffWebAuthnReady(w) {
		return
	}
	body, ok := readStaffCredential(w, r)
	if !ok {
		return
	}
	now := s.now()
	cer, ok := s.staffCeremonyFromCookie(w, r, store.StaffCeremonyRegister, now)
	if !ok {
		return
	}
	cred, err := s.staff.verifier.VerifyRegistration(staffauth.RegistrationCeremony{
		RPID: s.staff.rpID, Origin: s.staff.origin, Challenge: cer.Challenge,
		UserHandle: store.StaffUserHandle(cer.StaffID),
	}, body.Credential)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "webauthn_failed", "the passkey registration did not verify")
		return
	}
	label := strings.TrimSpace(body.Label)
	if len([]rune(label)) > 100 {
		label = string([]rune(label)[:100])
	}
	switch err := s.staff.db.RegisterStaffCredential(r.Context(), cer, cred, label, now); {
	case err == nil:
	case errors.Is(err, store.ErrStaffEnrolmentInvalid):
		writeErr(w, http.StatusUnauthorized, "enrolment_invalid", "the enrolment code is invalid, used or expired")
		return
	case errors.Is(err, store.ErrStaffCredentialExists):
		writeErr(w, http.StatusConflict, "credential_exists", "this passkey is already registered")
		return
	case errors.Is(err, staffauth.ErrPasskeyLimit):
		writePasskeyLimit(w)
		return
	default:
		s.log.Error("cloudserver/api: staff register", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not store the passkey")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"registered": true, "staff_id": cer.StaffID})
}

func (s *Server) handleStaffAssertBegin(w http.ResponseWriter, r *http.Request) {
	if !s.staffWebAuthnReady(w) {
		return
	}
	now := s.now()
	challenge, ok := s.startStaffCeremony(w, now, func(raw string, challenge []byte) error {
		return s.staff.db.BeginStaffAssertion(r.Context(), raw, challenge, now)
	})
	if !ok {
		return
	}
	opts := staffauth.NewRequestOptions(staffauth.AssertionCeremony{
		RPID: s.staff.rpID, Origin: s.staff.origin, Challenge: challenge,
	}, staffWebAuthnTimeout)
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": opts})
}

func (s *Server) handleStaffAssertFinish(w http.ResponseWriter, r *http.Request) {
	if !s.staffWebAuthnReady(w) {
		return
	}
	body, ok := readStaffCredential(w, r)
	if !ok {
		return
	}
	now := s.now()
	cer, ok := s.staffCeremonyFromCookie(w, r, store.StaffCeremonyAssert, now)
	if !ok {
		return
	}
	// One answer for every failure below, so a caller cannot tell an unknown
	// credential from a bad signature or a replayed counter.
	refuse := func() {
		writeErr(w, http.StatusUnauthorized, "webauthn_failed", "the passkey assertion did not verify")
	}
	credID, err := staffauth.CredentialID(body.Credential)
	if err != nil {
		refuse()
		return
	}
	stored, user, err := s.staff.db.StaffCredentialForAssertion(r.Context(), credID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("cloudserver/api: staff credential", "err", err)
		}
		refuse()
		return
	}
	got, err := s.staff.verifier.VerifyAssertion(staffauth.AssertionCeremony{
		RPID: s.staff.rpID, Origin: s.staff.origin, Challenge: cer.Challenge,
	}, stored, body.Credential)
	if err != nil {
		refuse()
		return
	}
	if err := staffauth.CheckSignCount(stored.SignCount, got.SignCount); err != nil {
		s.log.Warn("cloudserver/api: staff passkey counter did not increase", "staff_id", user.StaffID)
		refuse()
		return
	}
	prior := ""
	if c, err := r.Cookie(s.staffCookieName()); err == nil {
		prior = c.Value
	}
	sess, err := s.staff.db.StartStaffSession(r.Context(), store.StartStaffSessionInput{
		StaffID: user.StaffID, CredentialID: stored.ID,
		StoredSignCount: stored.SignCount, NewSignCount: got.SignCount,
		PriorRawSession: prior, TTL: s.staff.sessionTTL, IdleTTL: s.staff.idleTTL, Now: now,
	})
	if err != nil {
		if !errors.Is(err, store.ErrStaffCredentialStale) {
			s.log.Error("cloudserver/api: staff session start", "err", err)
		}
		refuse()
		return
	}
	s.setStaffCookie(w, s.staffCookieName(), sess.RawSession, sess.ExpiresAt, 0)
	writeJSON(w, http.StatusOK, map[string]any{
		"staff_id":   sess.StaffID,
		"role":       sess.Role,
		"csrf_token": sess.RawCSRF,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}
