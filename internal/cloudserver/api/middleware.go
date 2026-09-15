package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
)

// authenticate is the device-auth middleware: Bearer token introspection →
// per-request proof-of-possession → jti replay defense. Any failure is a 401
// (fail closed); a content-free audit event records the reason. On success it
// injects the verified principal into the request context and hands the handler
// a re-readable body.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		now := s.now()

		// 0) Early per-IP abuse cap (plan §6 CI-P6 / FC2). Runs BEFORE any bearer
		// introspection or PoP verification so a flood of invalid credentials
		// cannot drive one SECURITY DEFINER lookup + audit write per request. An
		// invalid bearer/cookie otherwise has no cap at all.
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

		// 1) Bearer token.
		token := bearerToken(r)
		if token == "" {
			s.audit(ctx, "", "auth_missing_bearer")
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}

		// 2) Introspect (unknown/org/opaque tokens resolve to not-found ⇒ 401,
		// which is how a cross-plane org token fails closed here).
		p, err := s.store.IntrospectToken(ctx, token, now)
		if err != nil || !p.Valid {
			s.audit(ctx, "", "auth_token_invalid")
			writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
			return
		}

		// 3) Read + bound the body (needed for the PoP body digest and by the
		// handler). Replace r.Body with a fresh reader afterwards.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		// 4) Proof of possession. The URL is reconstructed from the
		// server's own configured external origin + the request path —
		// NEVER from r.Host or X-Forwarded-* (those are client/proxy
		// controlled and would let an attacker forge a matching htu).
		res, err := s.pop.Verify(PoPRequest{
			ProofHeader:     r.Header.Get(headerPoP),
			Method:          r.Method,
			URL:             s.externalBaseURL + r.URL.EscapedPath(),
			Body:            body,
			AccessToken:     token,
			DevicePublicKey: p.PublicKey,
			Now:             now,
			MaxAge:          s.clockSkew,
			MaxSkew:         s.clockSkew,
		})
		if err != nil {
			s.audit(ctx, p.AccountID, "auth_pop_failed")
			writeErr(w, http.StatusUnauthorized, "unauthorized", "proof-of-possession failed")
			return
		}

		// 5) Verified-principal rate limits (plan §6 CI-P6): per-device AND
		// per-account on the authenticated surface. Checked AFTER the principal is
		// verified (so the keys are the real identities, never a spoofable
		// body/header field) but BEFORE the durable replay insert below (FC2) —
		// an over-limit valid proof must return 429 WITHOUT committing a
		// pop_replay row, so a device key holder cannot grow the database past
		// its cap.
		if s.rl != nil && s.rl.account != nil && s.rl.account.limit > 0 {
			ok, retry, err := s.rl.account.allowContext(ctx, p.AccountID)
			if err != nil {
				if s.log != nil {
					s.log.Error("cloudserver/api: account rate limiter", "err", err)
				}
				writeRateLimitUnavailable(w)
				return
			}
			if !ok {
				s.audit(ctx, p.AccountID, "rate_limited_account")
				writeRateLimited(w, retry)
				return
			}
		}
		if s.rl != nil && s.rl.device != nil && s.rl.device.limit > 0 {
			ok, retry, err := s.rl.device.allowContext(ctx, p.DeviceID)
			if err != nil {
				if s.log != nil {
					s.log.Error("cloudserver/api: device rate limiter", "err", err)
				}
				writeRateLimitUnavailable(w)
				return
			}
			if !ok {
				s.audit(ctx, p.AccountID, "rate_limited_device")
				writeRateLimited(w, retry)
				return
			}
		}

		// 6) jti replay defense (per-account) — the durable insert, now behind the
		// caps above.
		replay, err := s.store.RecordJTI(ctx, p.AccountID, res.JTI, res.JTIExpiry, now)
		if err != nil {
			// Log the cause: the client only ever sees the opaque 500, and a
			// silent failure here (2026-09-03 staging: every feature call 500'd
			// after the v6 roll) is undiagnosable from the outside.
			if s.log != nil {
				s.log.Error("cloudserver/api: jti replay record failed", "err", err)
			}
			writeErr(w, http.StatusInternalServerError, "internal", "replay check failed")
			return
		}
		if replay {
			s.audit(ctx, p.AccountID, "auth_pop_replay")
			writeErr(w, http.StatusUnauthorized, "unauthorized", "proof replay detected")
			return
		}

		ctx = context.WithValue(ctx, principalKey, principal{
			AccountID: p.AccountID, DeviceID: p.DeviceID,
			TokenID: p.TokenID, Thumbprint: p.Thumbprint,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// auditLogPrefixLen bounds the account-id fragment the stdout audit line
// carries — enough to correlate repeated events from the SAME account across
// a burst without logging a value that, by itself, identifies the account
// (content-free, matching the security_audit_events row it accompanies).
const auditLogPrefixLen = 8

// audit records a content-free security event; failures are swallowed (audit is
// best-effort and must never break the request path). It ALSO emits a
// structured stdout log line (gap 4.6 / D7's alerts.sh + webhook-5xx-and-
// audit-bursts.sql — both note this was the missing signal: the Postgres row
// exists but nothing reaches Log Analytics, so a burst of
// paddle_webhook_signature_invalid or portal_workos_state_mismatch could not
// be alerted on without an operator-scheduled SQL poll). Every Postgres write
// this function makes is now also observable through the same Log Analytics
// workspace revision-unhealthy.kql and healthz-and-restarts.kql already
// query, closing that gap for every event this function has ever recorded —
// not just those two.
func (s *Server) audit(ctx context.Context, accountID, event string) {
	if err := s.store.RecordAudit(ctx, accountID, event, ""); err != nil {
		s.log.Warn("cloudserver/api: audit write failed", "event", event, "err", err)
	}
	prefix := accountID
	if len(prefix) > auditLogPrefixLen {
		prefix = prefix[:auditLogPrefixLen]
	}
	s.log.Info("cloudserver/api: audit", "event", event, "account_id_prefix", prefix)
}
