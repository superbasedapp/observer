package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// csrfHash reproduces the store's secret hashing (hex sha256) so the presented
// X-SBCI-CSRF header can be compared, in constant time, against the session's
// stored csrf_hash without the raw token ever leaving this process's memory.
func csrfHash(raw string) string {
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// The portal (app.superbased.app) is the signed-in-free BROWSER surface (plan
// §6 CI-P5 + the ZDR amendment §3.2). It shares this Server (one public
// ingress) with the device /v1 API but authenticates completely differently: a
// __Host-sbci session COOKIE (HttpOnly/Secure/SameSite=Strict), a double-submit
// CSRF token on every mutation, and NO bearer token in the browser at all. The
// device-API PoP/jti machinery is deliberately NOT reused here — a browser
// cannot hold a device private key.

const (
	// portalCookieSecure is the production cookie name. The __Host- prefix is a
	// browser-enforced hardening: the cookie MUST be Secure, Path=/, and carry
	// no Domain attribute, so it cannot be set over plain http or scoped to a
	// parent domain. We use it whenever the portal origin is https.
	portalCookieSecure = "__Host-sbci"
	// portalCookieDev is the plain-http DEV fallback. __Host- REQUIRES the
	// Secure attribute, and browsers reject a Secure cookie over http, so a
	// local `http://localhost` dev run cannot use the prefixed name at all.
	// This unprefixed, non-Secure cookie is the ONLY way dev-over-http works —
	// it is NEVER selected when the origin is https (see portalSecureCookie).
	portalCookieDev = "sbci_session"

	headerCSRF = "X-SBCI-CSRF"
)

// portalCookieName returns the cookie name for this deployment. The choice is a
// stable server-level property (derived from the external origin's scheme, not
// per-request r.TLS — behind Cloudflare, TLS terminates at the edge and r.TLS
// is nil even though the browser speaks https), so login (set), the middleware
// (read), and logout (clear) always agree.
func (s *Server) portalCookieName() string {
	if s.portalSecureCookie {
		return portalCookieSecure
	}
	return portalCookieDev
}

// portalPrincipal is the resolved identity behind a portal session cookie.
type portalPrincipal struct {
	AccountID string
	SessionID string
	CSRFHash  string
	Raw       string // the raw cookie value, so logout can revoke this exact row
}

const portalPrincipalKey ctxKey = 1

func portalPrincipalFrom(ctx context.Context) (portalPrincipal, bool) {
	p, ok := ctx.Value(portalPrincipalKey).(portalPrincipal)
	return p, ok
}

// setSessionCookie writes the session cookie. HttpOnly (no JS access — the token
// never enters browser storage), SameSite=Strict, Path=/. Secure is on whenever
// we use the __Host- name (required by the prefix).
func (s *Server) setSessionCookie(w http.ResponseWriter, raw string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.portalCookieName(),
		Value:    raw,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.portalSecureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie expires the session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.portalCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.portalSecureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

// portalDevAuth reports whether the configured broker verifier is the dev-auth
// stub. Branching on the verifier's capability (its provider label) rather than
// a separate flag keeps the 501-when-off decision in one place.
func (s *Server) portalDevAuth() bool { return s.verifier.Provider() == "dev" }

type portalLoginRequest struct {
	// BrokerToken is the dev-auth credential ("dev:<subject>"). This token-POST
	// endpoint is dev-auth ONLY: production WorkOS browser sign-in never posts a
	// token here — it uses the server-side OAuth redirect flow at
	// /portal/auth/workos/start (portalauth.go, gated by SBCI_PORTAL_WORKOS).
	BrokerToken string `json:"broker_token"`
}

// handlePortalLogin is the dev-auth browser sign-in (amendment §3.2). Under a
// production verifier it returns an honest 501 pointing at the WorkOS OAuth
// flow rather than a confusing 401. On success it opens a browser session, sets
// the cookie, and returns the CSRF token (for the double-submit header) — never
// a bearer token.
func (s *Server) handlePortalLogin(w http.ResponseWriter, r *http.Request) {
	if !s.portalDevAuth() {
		writeErr(w, http.StatusNotImplemented, "provider_not_configured",
			"This endpoint only supports the dev-auth build. Browser sign-in with WorkOS uses the OAuth flow at /portal/auth/workos/start (available when the deployment enables it).")
		return
	}
	var req portalLoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	id, err := s.verifier.Verify(r.Context(), req.BrokerToken)
	if err != nil {
		s.audit(r.Context(), "", "portal_login_identity_invalid")
		writeErr(w, http.StatusUnauthorized, "unauthorized", "broker credential invalid")
		return
	}
	sess, err := s.store.PortalLogin(r.Context(), id.Provider, id.Subject, s.portalSessionTTL, s.now(), store.WithIdleTTL(s.portalSessionIdleTTL))
	if errors.Is(err, store.ErrAccountSuspended) {
		s.audit(r.Context(), "", "portal_login_account_suspended")
		writeErr(w, http.StatusForbidden, "account_suspended",
			"this account is suspended and cannot sign in")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: portal login", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not sign in")
		return
	}
	// Dev-auth's own display identity: the "dev:<subject>:<email>" token form
	// carries an optional email, which the verifier already parsed into
	// Identity.Email. Same seam as the WorkOS leg, so a dev deployment renders
	// the same chip the production one will (and exercises the same path).
	profile := newAccountProfile(id.Email, "", "")
	s.rememberProfile(r.Context(), sess.AccountID, profile)
	s.audit(r.Context(), sess.AccountID, "portal_login_ok")
	s.setSessionCookie(w, sess.RawSession, sess.ExpiresAt)
	body := map[string]any{
		"account_id": sess.AccountID,
		"csrf_token": sess.RawCSRFToken,
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if prof := profileBody(store.AccountProfile{Email: profile.email, DisplayName: profile.displayName}); prof != nil {
		body["profile"] = prof
	}
	writeJSON(w, http.StatusOK, body)
}

// handlePortalLogout revokes the current session and clears the cookie. It runs
// behind portalAuth (so CSRF is enforced), but always clears the cookie.
func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	if err := s.store.RevokeBrowserSession(r.Context(), p.AccountID, p.Raw, s.now()); err != nil {
		s.log.Warn("cloudserver/api: portal logout revoke", "err", err)
	}
	s.audit(r.Context(), p.AccountID, "portal_logout")
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

// portalAuth is the cookie-auth middleware: resolve the session cookie to an
// account (fail-closed 401), then enforce the double-submit CSRF token on every
// mutating method (GET/HEAD exempt). It injects the portal principal and, like
// the device middleware, establishes account scope from the VERIFIED session,
// never a request field.
func (s *Server) portalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// Early per-IP abuse cap (FC2): runs BEFORE any cookie introspection so a
		// flood of invalid cookies cannot drive one SECURITY DEFINER session
		// lookup per request. An invalid cookie otherwise has no cap at all.
		if s.rl != nil && s.rl.ip != nil && s.rl.ip.limit > 0 {
			key, err := rateLimitKey(r)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "invalid_client_ip", "could not determine the client IP")
				return
			}
			ok, retry, err := s.rl.ip.allowContext(ctx, key)
			if err != nil {
				if s.log != nil {
					s.log.Error("cloudserver/api: IP rate limiter", "err", err)
				}
				writeRateLimitUnavailable(w)
				return
			}
			if !ok {
				writeRateLimited(w, retry)
				return
			}
		}
		c, err := r.Cookie(s.portalCookieName())
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "not signed in")
			return
		}
		bp, err := s.store.IntrospectBrowserSession(ctx, c.Value, s.now(), store.WithIdleTTL(s.portalSessionIdleTTL))
		if err != nil || !bp.Valid {
			s.clearSessionCookie(w) // a dead cookie should not linger
			writeErr(w, http.StatusUnauthorized, "unauthorized", "session expired or invalid")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Double-submit CSRF: the header must hash to the session's stored
			// csrf_hash. Constant-time compare of the hex digests.
			presented := csrfHash(r.Header.Get(headerCSRF))
			if bp.CSRFHash == "" || subtle.ConstantTimeCompare([]byte(presented), []byte(bp.CSRFHash)) != 1 {
				s.audit(ctx, bp.AccountID, "portal_csrf_failed")
				writeErr(w, http.StatusForbidden, "csrf_failed", "missing or invalid CSRF token")
				return
			}
		}
		// Per-account rate limit (plan §6 CI-P6). Portal and device routes share
		// ONE per-account budget (the same s.rl.account limiter), so a caller
		// cannot dodge the cap by alternating surfaces.
		if s.rl != nil && s.rl.account != nil && s.rl.account.limit > 0 {
			ok, retry, err := s.rl.account.allowContext(ctx, bp.AccountID)
			if err != nil {
				if s.log != nil {
					s.log.Error("cloudserver/api: account rate limiter", "err", err)
				}
				writeRateLimitUnavailable(w)
				return
			}
			if !ok {
				s.audit(ctx, bp.AccountID, "rate_limited_account")
				writeRateLimited(w, retry)
				return
			}
		}
		ctx = context.WithValue(ctx, portalPrincipalKey, portalPrincipal{
			AccountID: bp.AccountID, SessionID: bp.SessionID, CSRFHash: bp.CSRFHash, Raw: c.Value,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- portal read endpoints ---

// coverageDisclosure is the explicit, honest scoping string every Overview card
// must render (plan §4(c)): the numbers describe cloud enrichment-job coverage
// ONLY, not the whole observer corpus, and imply no trend.
const coverageDisclosure = "These figures cover cloud enrichment jobs only, not your whole Observer history. They are coverage counters, not a trend."

func (s *Server) handlePortalOverview(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	ov, err := s.store.OverviewStats(r.Context(), p.AccountID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read overview")
		return
	}
	usage, err := s.store.Usage(r.Context(), p.AccountID, store.FeatureSessionEnrichment, s.now())
	if err != nil && !errors.Is(err, store.ErrNoEntitlement) {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read allowance")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"coverage_disclosure": coverageDisclosure,
		"jobs_by_state":       ov.JobsByState,
		"jobs_total":          ov.JobsTotal,
		"results_total":       ov.ResultsTotal,
		"last_result_at":      ov.LastResultAt,
		"allowance":           usage,
	})
}

// portalUsageView is the Usage page's payload (D20). It EMBEDS the
// UsageSnapshot, so every field /v1/usage already publishes — including the W4
// plan / plan label / plan version / budget pool / warnings — keeps its exact
// name and meaning at the top level, and the page-specific additions (job
// states, window reset estimates) sit alongside them.
type portalUsageView struct {
	store.UsageSnapshot
	// JobsByState is the live job-state breakdown: what the allowance was
	// actually spent on.
	JobsByState map[string]int `json:"jobs_by_state"`
	JobsTotal   int            `json:"jobs_total"`
	// DailyResetsAt / MonthlyResetsAt are the window boundaries the counters
	// roll over at, in UTC — an ESTIMATE only in the sense that they are the
	// boundary, not a promise about when a queued job settles. The cycle keys
	// are UTC day / UTC calendar month (store.DailyWindowKey / MonthlyWindowKey),
	// so these are exactly when the counters start again.
	DailyResetsAt   string `json:"daily_resets_at"`
	MonthlyResetsAt string `json:"monthly_resets_at"`
	// ConcurrencyNote states honestly that concurrency has no clock: it frees as
	// jobs reach a terminal state, so there is no reset time to show.
	ConcurrencyNote string `json:"concurrency_note"`
}

const concurrencyResetNote = "Concurrency is not a timed window: it frees as your in-flight jobs finish, so it has no reset time."

func (s *Server) handlePortalUsage(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	now := s.now().UTC()
	snap, err := s.store.Usage(r.Context(), p.AccountID, store.FeatureSessionEnrichment, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read usage")
		return
	}
	view := portalUsageView{
		UsageSnapshot:   snap,
		JobsByState:     map[string]int{},
		DailyResetsAt:   nextUTCDay(now).Format(time.RFC3339),
		MonthlyResetsAt: nextUTCMonth(now).Format(time.RFC3339),
		ConcurrencyNote: concurrencyResetNote,
	}
	// The job-state breakdown is best-effort context for the bars, never the
	// allowance itself: a read failure degrades the page to the allowance rather
	// than failing it.
	if ov, oerr := s.store.OverviewStats(r.Context(), p.AccountID); oerr == nil {
		view.JobsByState = ov.JobsByState
		view.JobsTotal = ov.JobsTotal
	} else {
		s.log.Warn("cloudserver/api: portal usage job states", "err", oerr)
	}
	writeJSON(w, http.StatusOK, view)
}

// portalDigestDTO is one project's latest weekly digest on the wire.
type portalDigestDTO struct {
	CloudProjectID string   `json:"cloud_project_id"`
	PeriodStart    string   `json:"period_start"`
	PeriodEnd      string   `json:"period_end"`
	CreatedAt      string   `json:"created_at"`
	Headline       string   `json:"headline"`
	Themes         []string `json:"themes"`
}

// handlePortalDigests serves the account's latest project_digest result per
// project (W5), for the portal Overview "Project digests" section. Free
// accounts simply get an empty list — there is no locked/degraded shape to
// render, since a free account's plan never has digest_weekly=true and the
// scheduler never submits a digest job for it.
func (s *Server) handlePortalDigests(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	rows, err := s.store.ListLatestProjectDigests(r.Context(), p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: list project digests", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not list project digests")
		return
	}
	out := make([]portalDigestDTO, 0, len(rows))
	for _, d := range rows {
		out = append(out, portalDigestDTO{
			CloudProjectID: d.CloudProjectID, PeriodStart: d.PeriodStart, PeriodEnd: d.PeriodEnd,
			CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339), Headline: d.Headline, Themes: d.Themes,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"digests": out})
}

// nextUTCDay is the instant the UTC-day usage cycle key changes.
func nextUTCDay(now time.Time) time.Time {
	d := now.UTC()
	return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}

// nextUTCMonth is the instant the UTC calendar-month usage cycle key changes.
func nextUTCMonth(now time.Time) time.Time {
	d := now.UTC()
	return time.Date(d.Year(), d.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
}

func (s *Server) handlePortalDevices(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
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
			CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339),
			Revoked:   d.RevokedAt != nil,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (s *Server) handlePortalRevokeDevice(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	err := s.store.RevokeDevice(r.Context(), p.AccountID, r.PathValue("id"), s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "device not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not revoke device")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_device_revoked")
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handlePortalListBrowserSessions is the "sign out everywhere" surface's read
// half (Wave C, gap 2.4 residual (b)): every LIVE browser session on the
// account, with is_current computed HERE (comparing against the resolved
// principal's own session id) rather than in the store — the store has no
// concept of "this request's own session", only rows.
func (s *Server) handlePortalListBrowserSessions(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	sessions, err := s.store.ListBrowserSessions(r.Context(), p.AccountID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not list sessions")
		return
	}
	type browserSess struct {
		ID            string  `json:"id"`
		CreatedAt     string  `json:"created_at"`
		LastSeenAt    *string `json:"last_seen_at,omitempty"`
		ExpiresAt     string  `json:"expires_at"`
		IdleExpiresAt *string `json:"idle_expires_at,omitempty"`
		IsCurrent     bool    `json:"is_current"`
	}
	out := make([]browserSess, 0, len(sessions))
	for _, bs := range sessions {
		row := browserSess{
			ID:        bs.ID,
			CreatedAt: bs.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt: bs.ExpiresAt.UTC().Format(time.RFC3339),
			IsCurrent: bs.ID == p.SessionID,
		}
		if bs.LastSeenAt != nil {
			v := bs.LastSeenAt.UTC().Format(time.RFC3339)
			row.LastSeenAt = &v
		}
		if bs.IdleExpiresAt != nil {
			v := bs.IdleExpiresAt.UTC().Format(time.RFC3339)
			row.IdleExpiresAt = &v
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// portalRevokeAllSessionsRequest is the "sign out everywhere" POST body.
// keep_current=true preserves the session making THIS request (the "everywhere
// but here" shape); false (the default, and an empty `{}` body) revokes every
// session including this one, so the response clears the cookie too.
type portalRevokeAllSessionsRequest struct {
	KeepCurrent bool `json:"keep_current"`
}

// handlePortalRevokeAllBrowserSessions is "sign out everywhere"'s write half.
// It is CSRF-protected like every other portal mutation (the portalAuth
// middleware enforces the double-submit header on every non-GET before this
// handler runs at all).
func (s *Server) handlePortalRevokeAllBrowserSessions(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	var req portalRevokeAllSessionsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	except := ""
	if req.KeepCurrent {
		except = p.Raw
	}
	n, err := s.store.RevokeAllBrowserSessions(r.Context(), p.AccountID, except, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: revoke all browser sessions", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not revoke sessions")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_sessions_revoked_all")
	if !req.KeepCurrent {
		// This request's own session was revoked too — leaving the cookie set
		// would have the SPA hold a dead credential until its next 401.
		s.clearSessionCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "revoked": n})
}

func (s *Server) handlePortalConsents(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
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

type portalDeletionRequest struct {
	// BrokerToken re-presents the dev-auth credential (reauth, amendment §3.2).
	// In dev-auth mode reauth = re-presenting the credential in the body.
	BrokerToken string `json:"broker_token"`
	// StepUpAuthorizationID is the WorkOS-mode reauth: the one-use, ≤5-minute,
	// session-bound authorization minted by the /portal/auth/workos/callback
	// step-up leg. It is consumed transactionally WITH the deletion.
	StepUpAuthorizationID string `json:"step_up_authorization_id"`
}

// handlePortalDeletionRequest is CSRF-protected (by the middleware) AND requires
// reauth: the caller must re-present a broker credential that resolves to the
// SAME account as the session. This is the destructive-action step-up the
// amendment mandates for export/deletion.
func (s *Server) handlePortalDeletionRequest(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	var req portalDeletionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if !s.portalDevAuth() {
		// WorkOS mode. With the browser leg dark (R7) there is no way to
		// re-authenticate, so the honest 501 stands; with it active, deletion
		// requires a step-up authorization minted by the WorkOS callback. CSRF is
		// still enforced by the middleware — the step-up is an ADDITIONAL factor,
		// never a replacement for it.
		if !s.portalWorkOSEnabled {
			writeErr(w, http.StatusNotImplemented, "provider_not_configured",
				"Reauthentication for deletion is not available yet (the WorkOS step-up leg is not enabled on this deployment).")
			return
		}
		if req.StepUpAuthorizationID == "" {
			writeErr(w, http.StatusForbidden, "step_up_required",
				"re-authenticate at /portal/auth/workos/start?purpose=step_up&action=deletion before confirming deletion")
			return
		}
		dr, err := s.store.CreateDeletionRequestWithStepUp(r.Context(), p.AccountID, p.SessionID, req.StepUpAuthorizationID, s.now())
		if errors.Is(err, store.ErrStepUpInvalid) {
			s.audit(r.Context(), p.AccountID, "portal_step_up_invalid")
			writeErr(w, http.StatusForbidden, "step_up_invalid",
				"that re-authentication is expired, already used, or was not issued for this session")
			return
		}
		if err != nil {
			s.log.Error("cloudserver/api: deletion with step-up", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "could not record deletion request")
			return
		}
		s.audit(r.Context(), p.AccountID, "portal_deletion_requested")
		s.clearSessionCookie(w)
		writeJSON(w, http.StatusAccepted, dr)
		return
	}
	id, err := s.verifier.Verify(r.Context(), req.BrokerToken)
	if err != nil {
		s.audit(r.Context(), p.AccountID, "portal_reauth_failed")
		writeErr(w, http.StatusUnauthorized, "reauth_required", "re-enter your credential to confirm deletion")
		return
	}
	// The reauth credential must resolve to THIS account.
	reauthAccount, err := s.store.AccountForIdentity(r.Context(), id.Provider, id.Subject)
	if err != nil || reauthAccount != p.AccountID {
		s.audit(r.Context(), p.AccountID, "portal_reauth_account_mismatch")
		writeErr(w, http.StatusForbidden, "reauth_mismatch", "credential does not match the signed-in account")
		return
	}
	dr, err := s.store.CreateDeletionRequest(r.Context(), p.AccountID, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not record deletion request")
		return
	}
	s.audit(r.Context(), p.AccountID, "portal_deletion_requested")
	// The account's sessions were just revoked by the deletion skeleton; clear
	// this browser's cookie too so the UI returns to sign-in honestly.
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusAccepted, dr)
}
