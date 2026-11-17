package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidchttp"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/portalmfa"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The portal's passkey second factor (managed-SaaS plan 07 tracker row "C2
// portal WebAuthn second factor"; lead decision L-92; wave 17 lane
// portal-guardrails; cloud 0131 / 0132; docs/security.md PLATRAIL-3).
//
// An account may register passkeys. Once it has one, every new portal
// session must use it (or a one-time recovery code) before it can do
// anything else: portalAuth answers 403 second_factor_required to every
// route outside portalmfa.AllowedWhilePending, and the platform OIDC issuer
// sends the browser to the second-factor page instead of issuing. A passkey
// sign-in is signed into the tenant's id_token as amr (portalmfa.AMRFor:
// "hwk" or "swk", with "mfa"); an org owner or admin may require it of every
// member (orgs.require_second_factor), which the issuer enforces at the
// tenant sign-in.
//
// WebAuthn verification is the staff console's verifier (staffauth.Verifier,
// wired from staffauth/passkey in serve), reused unchanged with the portal's
// own relying party: the portal host (never a parent domain, so a portal
// passkey is unusable on a tenant or staff host). Every decision is a
// portalmfa table; this file only reads, calls and answers.
//
// Routes (all behind portalAuth, so CSRF-checked on every POST, PUT, DELETE):
//
//	GET    /portal/api/mfa                              status: passkeys, codes left, this session
//	POST   /portal/api/mfa/passkeys/register/begin      {label}            -> {ceremony, options}
//	POST   /portal/api/mfa/passkeys/register/finish     {ceremony, credential} -> {passkey, recovery_codes?}
//	DELETE /portal/api/mfa/passkeys/{id}                remove one (id: base64url credential id)
//	POST   /portal/api/mfa/recovery-codes               a new batch -> {recovery_codes}
//	POST   /portal/api/mfa/assert/begin                 -> {ceremony, options}
//	POST   /portal/api/mfa/assert/finish                {ceremony, credential, return_to} -> {next}
//	POST   /portal/api/mfa/recover                      {code, return_to} -> {next, recovery_codes_left}
//	POST   /portal/api/mfa/devices/approve              {thumbprint} -> {expires_at} (passkey session only)
//	GET    /portal/api/orgs/{id}/signin-policy          {require_second_factor, can_change}
//	PUT    /portal/api/orgs/{id}/signin-policy          {require_second_factor}

// portalMFAConfig is the portal second factor's resolved configuration.
type portalMFAConfig struct {
	verifier staffauth.Verifier
	// rpID is the portal host, origin the portal origin.
	rpID, origin string
	random       io.Reader
	notifier     PortalSecurityNotifier
}

// initPortalMFA resolves the configuration from o and the portal origin.
func (s *Server) initPortalMFA(o Options) {
	c := portalMFAConfig{verifier: o.PortalWebAuthn, origin: s.portalBaseURL, random: rand.Reader, notifier: o.PortalSecurityNotifier}
	if c.verifier == nil {
		c.verifier = staffauth.Unavailable{}
	}
	if u, err := url.Parse(c.origin); err == nil {
		c.rpID = strings.ToLower(u.Hostname())
	}
	s.portalMFA = c
}

// secondFactorPagePath is the SPA's second-factor page, where the platform
// OIDC issuer sends an authorize that needs the passkey first
// (oidchttp.DefaultSecondFactorPath).
const secondFactorPagePath = oidchttp.DefaultSecondFactorPath

// portalWebAuthnTimeout is what the options ask the browser for.
const portalWebAuthnTimeout = 2 * time.Minute

// secondFactorStateKey carries the request's second-factor state, read once
// by portalAuth.
const secondFactorStateKey ctxKey = 9

func secondFactorFrom(ctx context.Context) (store.PortalSecondFactor, bool) {
	v, ok := ctx.Value(secondFactorStateKey).(store.PortalSecondFactor)
	return v, ok
}

// gateSecondFactor is portalAuth's last step: it reads the session's second
// factor, refuses a route the pending session may not reach, and carries the
// state on for the handlers. It reports whether the request may proceed
// (it has answered when it may not).
func (s *Server) gateSecondFactor(w http.ResponseWriter, r *http.Request, accountID, sessionID string) (context.Context, bool) {
	st, err := s.store.PortalSecondFactorState(r.Context(), accountID, sessionID)
	if errors.Is(err, store.ErrNotFound) {
		s.clearSessionCookie(w)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "session expired or invalid")
		return nil, false
	}
	if err != nil {
		s.log.Error("cloudserver/api: second factor state", "err", err)
		writeErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "could not check the sign-in")
		return nil, false
	}
	if st.Pending() && !portalmfa.AllowedWhilePending(r.Method, r.URL.Path) {
		writeErr(w, http.StatusForbidden, portalmfa.CodeSecondFactorRequired,
			"use your passkey to finish signing in")
		return nil, false
	}
	return context.WithValue(r.Context(), secondFactorStateKey, st), true
}

// secondFactorJSON is the session's second factor as the SPA reads it.
type secondFactorJSON struct {
	Enrolled    bool   `json:"enrolled"`
	Pending     bool   `json:"pending"`
	Method      string `json:"method,omitempty"`
	MultiFactor bool   `json:"multi_factor"`
}

func secondFactorView(st store.PortalSecondFactor) secondFactorJSON {
	return secondFactorJSON{Enrolled: st.Enrolled, Pending: st.Pending(), Method: string(st.Method), MultiFactor: st.MultiFactor()}
}

// portalPasskeyJSON is one passkey as the portal lists it.
type portalPasskeyJSON struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Synced     bool   `json:"synced"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

func passkeyJSON(p store.PortalPasskey) portalPasskeyJSON {
	v := portalPasskeyJSON{
		ID: base64.RawURLEncoding.EncodeToString(p.CredentialID), Label: p.Label, Synced: p.BackupEligible,
		CreatedAt: p.CreatedAt.UTC().Format(time.RFC3339),
	}
	if p.LastUsedAt != nil {
		v.LastUsedAt = p.LastUsedAt.UTC().Format(time.RFC3339)
	}
	return v
}

// handlePortalMFA is GET /portal/api/mfa.
func (s *Server) handlePortalMFA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	st, _ := secondFactorFrom(r.Context())
	out := map[string]any{
		"available":           s.portalMFA.verifier.Available(),
		"session":             secondFactorView(st),
		"recovery_codes_left": st.RecoveryCodesLeft,
		"passkeys":            []portalPasskeyJSON{},
	}
	if !st.Pending() {
		ps, err := s.store.ListPortalPasskeys(r.Context(), p.AccountID)
		if err != nil {
			s.log.Error("cloudserver/api: list passkeys", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "could not read your passkeys")
			return
		}
		list := make([]portalPasskeyJSON, len(ps))
		for i, pk := range ps {
			list[i] = passkeyJSON(pk)
		}
		out["passkeys"] = list
	}
	writeJSON(w, http.StatusOK, out)
}

// portalMFAReady answers 501 when no verifier is wired.
func (s *Server) portalMFAReady(w http.ResponseWriter) bool {
	if !s.portalMFA.verifier.Available() {
		writeErr(w, http.StatusNotImplemented, "not_available", "passkeys are not available on this server")
		return false
	}
	return true
}

// portalMFADecision applies portalmfa's action table, answering a refusal.
func (s *Server) portalMFADecision(w http.ResponseWriter, r *http.Request, a portalmfa.Action) bool {
	st, _ := secondFactorFrom(r.Context())
	code, rule := portalmfa.Decide(a, portalmfa.Facts{
		Session: st.SessionState, ActivePasskeys: st.ActivePasskeys, AuthTime: st.AuthTime, Now: s.now(),
	})
	if code == "" {
		return true
	}
	p, _ := portalPrincipalFrom(r.Context())
	s.audit(r.Context(), p.AccountID, "portal_mfa_refused_"+rule)
	writeErr(w, http.StatusForbidden, code, portalMFARefusalText[code])
	return false
}

// portalMFARefusalText words each refusal in plain language.
var portalMFARefusalText = map[string]string{
	portalmfa.CodeSecondFactorRequired:  "use your passkey (or a recovery code) first",
	portalmfa.CodeReauthRequired:        "sign in again to add your first passkey",
	portalmfa.CodePasskeyLimit:          "you have as many passkeys as an account can hold; remove one first",
	portalmfa.CodePasskeySignInRequired: "sign in with your passkey in this session to change this setting",
}

// portalCeremonyBody is a begin answer.
type portalCeremonyBody struct {
	Ceremony string `json:"ceremony"`
	Options  any    `json:"options"`
}

// newPortalCeremony mints a ceremony token and challenge.
func (s *Server) newPortalCeremony() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(s.portalMFA.random, b); err != nil {
		return "", nil, err
	}
	ch, err := staffauth.NewChallenge(s.portalMFA.random)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(b), ch, nil
}

// handlePortalPasskeyRegisterBegin is POST .../passkeys/register/begin.
func (s *Server) handlePortalPasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if !s.portalMFAReady(w) || !s.portalMFADecision(w, r, portalmfa.ActionEnrol) {
		return
	}
	p, _ := portalPrincipalFrom(r.Context())
	var req struct {
		Label string `json:"label"`
	}
	if !readSmallJSON(w, r, &req) {
		return
	}
	exclude, err := s.store.PortalPasskeyIDs(r.Context(), p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: passkey ids", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start")
		return
	}
	raw, challenge, err := s.newPortalCeremony()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not start")
		return
	}
	if err := s.store.BeginPortalPasskeyCeremony(r.Context(), p.AccountID, p.SessionID, raw, store.PortalCeremonyRegister, challenge, req.Label, s.now()); err != nil {
		s.log.Error("cloudserver/api: begin passkey registration", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start")
		return
	}
	name := "SuperBased account"
	if prof := s.lookupProfile(r.Context(), p.AccountID); prof.Email != "" {
		name = prof.Email
	}
	opts := staffauth.NewCreationOptionsNamed(portalmfa.RPName, staffauth.RegistrationCeremony{
		RPID: s.portalMFA.rpID, Origin: s.portalMFA.origin, Challenge: challenge, UserHandle: portalmfa.UserHandle(p.AccountID),
	}, name, exclude, portalWebAuthnTimeout)
	writeJSON(w, http.StatusOK, portalCeremonyBody{Ceremony: raw, Options: opts})
}

// portalCredentialBody is a finish body.
type portalCredentialBody struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	ReturnTo   string          `json:"return_to"`
}

func readPortalCredential(w http.ResponseWriter, r *http.Request) (portalCredentialBody, bool) {
	var body portalCredentialBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, staffauth.MaxResponseBytes+4096)).Decode(&body); err != nil ||
		len(body.Credential) == 0 || body.Ceremony == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "a JSON body with a ceremony and a credential is required")
		return body, false
	}
	return body, true
}

// handlePortalPasskeyRegisterFinish is POST .../passkeys/register/finish. The
// account's first passkey also mints its recovery codes (shown once) and
// counts as this session's second factor.
func (s *Server) handlePortalPasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !s.portalMFAReady(w) {
		return
	}
	body, ok := readPortalCredential(w, r)
	if !ok {
		return
	}
	// The table again: the session's state may have moved since begin.
	if !s.portalMFADecision(w, r, portalmfa.ActionEnrol) {
		return
	}
	p, _ := portalPrincipalFrom(r.Context())
	now := s.now()
	cer, err := s.store.ConsumePortalPasskeyCeremony(r.Context(), p.AccountID, p.SessionID, body.Ceremony, store.PortalCeremonyRegister, now)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ceremony_invalid", "that passkey request expired; start again")
		return
	}
	cred, err := s.portalMFA.verifier.VerifyRegistration(staffauth.RegistrationCeremony{
		RPID: s.portalMFA.rpID, Origin: s.portalMFA.origin, Challenge: cer.Challenge, UserHandle: portalmfa.UserHandle(p.AccountID),
	}, body.Credential)
	if err != nil {
		s.audit(r.Context(), p.AccountID, "portal_passkey_register_failed")
		writeErr(w, http.StatusBadRequest, "webauthn_failed", "the passkey could not be verified")
		return
	}
	codes, err := portalmfa.NewRecoveryCodes(s.portalMFA.random)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not add the passkey")
		return
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		if hashes[i], err = portalmfa.HashRecoveryCode(c); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "could not add the passkey")
			return
		}
	}
	res, err := s.store.RegisterPortalPasskey(r.Context(), store.RegisterPortalPasskeyInput{
		AccountID: p.AccountID, SessionID: p.SessionID, Cred: cred, Label: cer.Label, RecoveryHashes: hashes, Now: now,
	})
	switch {
	case errors.Is(err, store.ErrPortalPasskeyExists):
		writeErr(w, http.StatusConflict, "passkey_exists", "that passkey is already registered")
		return
	case errors.Is(err, store.ErrPortalPasskeyLimit):
		writeErr(w, http.StatusForbidden, portalmfa.CodePasskeyLimit, portalMFARefusalText[portalmfa.CodePasskeyLimit])
		return
	case errors.Is(err, store.ErrPortalSessionGone):
		writeErr(w, http.StatusUnauthorized, "unauthorized", "session expired or invalid")
		return
	case err != nil:
		s.log.Error("cloudserver/api: register passkey", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not add the passkey")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_passkey_registered")
	out := map[string]any{
		"passkey": passkeyJSON(store.PortalPasskey{CredentialID: cred.ID, Label: cer.Label, BackupEligible: cred.BackupEligible, CreatedAt: now}),
	}
	if res.First {
		out["recovery_codes"] = codes
	}
	writeJSON(w, http.StatusCreated, out)
}

// handlePortalPasskeyRemove is DELETE /portal/api/mfa/passkeys/{id}.
func (s *Server) handlePortalPasskeyRemove(w http.ResponseWriter, r *http.Request) {
	if !s.portalMFADecision(w, r, portalmfa.ActionManage) {
		return
	}
	p, _ := portalPrincipalFrom(r.Context())
	id, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil || len(id) == 0 || len(id) > staffauth.MaxCredentialIDBytes {
		writeErr(w, http.StatusNotFound, "not_found", "no such passkey")
		return
	}
	left, err := s.store.RevokePortalPasskey(r.Context(), p.AccountID, p.SessionID, id, s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such passkey")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: remove passkey", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not remove the passkey")
		return
	}
	event := "portal_passkey_removed"
	if left == 0 {
		event = "portal_passkey_removed_last"
	}
	s.audit(r.Context(), p.AccountID, event)
	writeJSON(w, http.StatusOK, map[string]any{"passkeys_left": left})
}

// handlePortalRecoveryCodes is POST /portal/api/mfa/recovery-codes: a new
// batch, the old one discarded.
func (s *Server) handlePortalRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if !s.portalMFADecision(w, r, portalmfa.ActionManage) {
		return
	}
	p, _ := portalPrincipalFrom(r.Context())
	codes, err := portalmfa.NewRecoveryCodes(s.portalMFA.random)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not make new codes")
		return
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		if hashes[i], err = portalmfa.HashRecoveryCode(c); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "could not make new codes")
			return
		}
	}
	if err := s.store.ReplacePortalRecoveryCodes(r.Context(), p.AccountID, hashes, s.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusConflict, "no_passkey", "add a passkey first")
			return
		}
		s.log.Error("cloudserver/api: recovery codes", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not make new codes")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_recovery_codes_replaced")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handlePortalAssertBegin is POST /portal/api/mfa/assert/begin.
func (s *Server) handlePortalAssertBegin(w http.ResponseWriter, r *http.Request) {
	if !s.portalMFAReady(w) {
		return
	}
	p, _ := portalPrincipalFrom(r.Context())
	allow, err := s.store.PortalPasskeyIDs(r.Context(), p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: passkey ids", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start")
		return
	}
	if len(allow) == 0 {
		writeErr(w, http.StatusConflict, "no_passkey", "this account has no passkey")
		return
	}
	raw, challenge, err := s.newPortalCeremony()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not start")
		return
	}
	if err := s.store.BeginPortalPasskeyCeremony(r.Context(), p.AccountID, p.SessionID, raw, store.PortalCeremonyAssert, challenge, "", s.now()); err != nil {
		s.log.Error("cloudserver/api: begin passkey assertion", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not start")
		return
	}
	opts := staffauth.NewRequestOptionsAllowing(staffauth.AssertionCeremony{
		RPID: s.portalMFA.rpID, Origin: s.portalMFA.origin, Challenge: challenge,
	}, allow, portalWebAuthnTimeout)
	writeJSON(w, http.StatusOK, portalCeremonyBody{Ceremony: raw, Options: opts})
}

// nextAfterSecondFactor validates where the SPA goes next: a safe return
// path (the OIDC authorize resume, or a portal page), else the portal root.
func nextAfterSecondFactor(raw string) string {
	if next, ok := safeReturnPath(raw); ok {
		return next
	}
	return defaultPortalReturnTo
}

// handlePortalAssertFinish is POST /portal/api/mfa/assert/finish.
func (s *Server) handlePortalAssertFinish(w http.ResponseWriter, r *http.Request) {
	if !s.portalMFAReady(w) {
		return
	}
	body, ok := readPortalCredential(w, r)
	if !ok {
		return
	}
	p, _ := portalPrincipalFrom(r.Context())
	now := s.now()
	// One answer for every failure, so a caller cannot tell an unknown
	// credential from a bad signature or a replayed counter.
	refuse := func(event string) {
		s.audit(r.Context(), p.AccountID, event)
		writeErr(w, http.StatusUnauthorized, "webauthn_failed", "the passkey could not be verified")
	}
	cer, err := s.store.ConsumePortalPasskeyCeremony(r.Context(), p.AccountID, p.SessionID, body.Ceremony, store.PortalCeremonyAssert, now)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ceremony_invalid", "that passkey request expired; start again")
		return
	}
	credID, err := staffauth.CredentialID(body.Credential)
	if err != nil {
		refuse("portal_passkey_assert_failed")
		return
	}
	stored, err := s.store.PortalPasskeyForAssertion(r.Context(), p.AccountID, credID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("cloudserver/api: passkey for assertion", "err", err)
		}
		refuse("portal_passkey_assert_failed")
		return
	}
	got, err := s.portalMFA.verifier.VerifyAssertion(staffauth.AssertionCeremony{
		RPID: s.portalMFA.rpID, Origin: s.portalMFA.origin, Challenge: cer.Challenge,
	}, stored, body.Credential)
	if err != nil {
		refuse("portal_passkey_assert_failed")
		return
	}
	if err := staffauth.CheckSignCount(stored.SignCount, got.SignCount); err != nil {
		refuse("portal_passkey_counter_regressed")
		return
	}
	amr := portalmfa.AMRFor(portalmfa.MethodPasskey, got.BackupEligible)
	if err := s.store.CompletePortalPasskeyAssertion(r.Context(), p.AccountID, p.SessionID, stored.ID, stored.SignCount, got.SignCount, amr, now); err != nil {
		if errors.Is(err, store.ErrPortalSessionGone) {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "session expired or invalid")
			return
		}
		if !errors.Is(err, store.ErrPortalPasskeyStale) {
			s.log.Error("cloudserver/api: complete passkey assertion", "err", err)
		}
		refuse("portal_passkey_assert_failed")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_second_factor_passkey")
	writeJSON(w, http.StatusOK, map[string]any{"next": nextAfterSecondFactor(body.ReturnTo), "amr": amr})
}

// handlePortalRecover is POST /portal/api/mfa/recover: a one-time recovery
// code completes the session's second factor (without an amr: an org that
// requires a second factor still asks for a passkey).
func (s *Server) handlePortalRecover(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	var req struct {
		Code     string `json:"code"`
		ReturnTo string `json:"return_to"`
	}
	if !readSmallJSON(w, r, &req) {
		return
	}
	st, err := s.store.RecoveryFailureState(r.Context(), p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: recovery failure state", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not check the code")
		return
	}
	if portalmfa.RecoveryLocked(st, s.now()) {
		s.audit(r.Context(), p.AccountID, "portal_recovery_code_locked_attempt")
		writeErr(w, http.StatusTooManyRequests, portalmfa.CodeRecoveryLocked,
			"too many wrong recovery codes; try again later or use your passkey")
		return
	}
	refuse := func() {
		s.audit(r.Context(), p.AccountID, "portal_recovery_code_refused")
		tripped, until, nerr := s.store.NoteRecoveryFailure(r.Context(), p.AccountID, s.now())
		if nerr != nil {
			s.log.Error("cloudserver/api: note recovery failure", "err", nerr)
		} else if tripped {
			s.audit(r.Context(), p.AccountID, "portal_recovery_code_lockout")
			if s.portalMFA.notifier != nil {
				s.portalMFA.notifier.RecoveryCodesLocked(r.Context(), p.AccountID, until)
			}
		}
		writeErr(w, http.StatusUnauthorized, "recovery_code_invalid", "that recovery code is not valid or was already used")
	}
	hash, err := portalmfa.HashRecoveryCode(req.Code)
	if err != nil {
		refuse()
		return
	}
	left, err := s.store.RedeemPortalRecoveryCode(r.Context(), p.AccountID, p.SessionID, hash, s.now())
	switch {
	case errors.Is(err, store.ErrRecoveryCodeInvalid):
		refuse()
		return
	case errors.Is(err, store.ErrPortalSessionGone):
		writeErr(w, http.StatusUnauthorized, "unauthorized", "session expired or invalid")
		return
	case err != nil:
		s.log.Error("cloudserver/api: recovery code", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not check the code")
		return
	}
	if cerr := s.store.ClearRecoveryFailures(r.Context(), p.AccountID); cerr != nil {
		s.log.Warn("cloudserver/api: clear recovery failures", "err", cerr)
	}
	if s.portalMFA.notifier != nil {
		s.portalMFA.notifier.RecoveryCodeUsed(r.Context(), p.AccountID, left)
	}
	s.audit(r.Context(), p.AccountID, "portal_second_factor_recovery_code")
	writeJSON(w, http.StatusOK, map[string]any{"next": nextAfterSecondFactor(req.ReturnTo), "recovery_codes_left": left})
}

// orgSigninPolicyJSON is an org's sign-in requirement as the console shows it.
type orgSigninPolicyJSON struct {
	RequireSecondFactor bool `json:"require_second_factor"`
	// CanChange: this caller is an owner or admin AND signed in with a
	// passkey in this session (portalmfa ActionOrgPolicy).
	CanChange bool `json:"can_change"`
	// Reason is the refusal code when CanChange is false for an admin.
	Reason string `json:"reason,omitempty"`
}

func (s *Server) orgSigninPolicyView(r *http.Request, accountID, orgID string, require bool) (orgSigninPolicyJSON, error) {
	v := orgSigninPolicyJSON{RequireSecondFactor: require}
	org, err := s.store.GetOrg(r.Context(), accountID, orgID)
	if err != nil {
		return v, err
	}
	if org.ConsoleRole != store.ConsoleOwner && org.ConsoleRole != store.ConsoleAdmin {
		return v, nil
	}
	st, _ := secondFactorFrom(r.Context())
	v.Reason, _ = portalmfa.Decide(portalmfa.ActionOrgPolicy, portalmfa.Facts{Session: st.SessionState, Now: s.now()})
	v.CanChange = v.Reason == ""
	return v, nil
}

// handlePortalOrgSigninPolicy is GET /portal/api/orgs/{id}/signin-policy.
func (s *Server) handlePortalOrgSigninPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, _ := portalPrincipalFrom(r.Context())
	orgID := r.PathValue("id")
	req, err := s.store.OrgSecondFactorRequired(r.Context(), p.AccountID, orgID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "org not found")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: org sign-in policy", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the setting")
		return
	}
	v, err := s.orgSigninPolicyView(r, p.AccountID, orgID, req)
	if err != nil {
		s.log.Error("cloudserver/api: org sign-in policy view", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the setting")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handlePortalSetOrgSigninPolicy is PUT /portal/api/orgs/{id}/signin-policy.
func (s *Server) handlePortalSetOrgSigninPolicy(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	var req struct {
		RequireSecondFactor *bool `json:"require_second_factor"`
	}
	if !readSmallJSON(w, r, &req) {
		return
	}
	if req.RequireSecondFactor == nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "require_second_factor (true or false) is required")
		return
	}
	orgID := r.PathValue("id")
	// Membership and role first, so a non-member learns nothing from the
	// second-factor refusal.
	org, err := s.store.GetOrg(r.Context(), p.AccountID, orgID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "org not found")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: org sign-in policy", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not change the setting")
		return
	}
	if org.ConsoleRole != store.ConsoleOwner && org.ConsoleRole != store.ConsoleAdmin {
		writeErr(w, http.StatusForbidden, "forbidden", "only an owner or admin can change how members sign in")
		return
	}
	if !s.portalMFADecision(w, r, portalmfa.ActionOrgPolicy) {
		return
	}
	prev, err := s.store.SetOrgSecondFactorRequired(r.Context(), p.AccountID, orgID, *req.RequireSecondFactor)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "org not found")
		return
	case errors.Is(err, store.ErrOrgPolicyForbidden):
		writeErr(w, http.StatusForbidden, "forbidden", "only an owner or admin can change how members sign in")
		return
	case err != nil:
		s.log.Error("cloudserver/api: set org sign-in policy", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not change the setting")
		return
	}
	if prev != *req.RequireSecondFactor {
		detail, _ := json.Marshal(map[string]any{"org_id": org.OrgID, "require_second_factor": *req.RequireSecondFactor})
		if err := s.store.RecordAudit(r.Context(), p.AccountID, "portal_org_second_factor_changed", string(detail)); err != nil {
			s.log.Warn("cloudserver/api: audit write failed", "event", "portal_org_second_factor_changed", "err", err)
		}
	}
	v, err := s.orgSigninPolicyView(r, p.AccountID, orgID, *req.RequireSecondFactor)
	if err != nil {
		s.log.Error("cloudserver/api: org sign-in policy view", "err", err)
	}
	writeJSON(w, http.StatusOK, v)
}

// PortalSecurityNotifier is the seam through which the portal tells an account
// holder about recovery-code events (FR-24). Both methods are best effort and
// must return quickly (hand the mail to a queue or goroutine).
type PortalSecurityNotifier interface {
	// RecoveryCodeUsed: a recovery code was redeemed; codesLeft remain.
	RecoveryCodeUsed(ctx context.Context, accountID string, codesLeft int)
	// RecoveryCodesLocked: too many wrong codes; entry is locked until the time.
	RecoveryCodesLocked(ctx context.Context, accountID string, until time.Time)
}

// handlePortalDeviceApprove is POST /portal/api/mfa/devices/approve
// {thumbprint} (FR-6): a session that signed in with a passkey approves one
// new device thumbprint for portalmfa.DeviceApprovalTTL; the device's next
// /v1/auth/exchange then registers it. The thumbprint is the one the refused
// exchange (device_approval_required) printed.
func (s *Server) handlePortalDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if !s.portalMFADecision(w, r, portalmfa.ActionApproveDevice) {
		return
	}
	p, _ := portalPrincipalFrom(r.Context())
	var req struct {
		Thumbprint string `json:"thumbprint"`
	}
	if !readSmallJSON(w, r, &req) {
		return
	}
	th := strings.TrimSpace(req.Thumbprint)
	if raw, err := base64.RawURLEncoding.DecodeString(th); err != nil || len(raw) != 32 {
		writeErr(w, http.StatusBadRequest, "bad_request", "that is not a device id")
		return
	}
	exp, err := s.store.ApproveDevice(r.Context(), p.AccountID, p.SessionID, th, portalmfa.DeviceApprovalTTL, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: approve device", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not approve the device")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_device_approved")
	writeJSON(w, http.StatusOK, map[string]any{"expires_at": exp.UTC().Format(time.RFC3339)})
}
