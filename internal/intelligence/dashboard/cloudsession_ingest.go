package dashboard

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/shiptoken"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The INDIVIDUAL destination of Rail S on the node (cloud-agents arc, lane
// CA-B3, decision CA-D8, section 7.2 of the plan; ledger CLOUDSESS-3): a
// developer whose node a vendor cloud sandbox can reach (Tailscale, or a
// remote-exposed dashboard) mints a ship token here, and the sandbox's
// `observer cloud-session flush --destination node` posts its push envelope
// to POST /api/cloud-session/ingest with it.
//
// Off by default, by construction: the ingest route answers 404 while the
// node holds no active ship token, and minting one is an owner-local action
// (CapabilityLocal, confirm token). The ingest route itself is
// CapabilityPublic because a sandbox can hold no device session: it
// authenticates every request with the ship token, and on a non-loopback bind
// it is reachable only while the existing remote-access stack is Ready
// (auth configured, Host allow-list, rate limit), the same gate every other
// remotely reachable route sits behind.
//
// The rules are the pure internal/shiptoken package, the SQL the store's
// cloudsessiontokens.go / cloudsessionland.go.

const cloudSessionIngestRoute = "/api/cloud-session/ingest"

// registerCloudSessionRoutes registers the node's ship-token routes. reg is
// dashboard.go's registration closure.
func (s *Server) registerCloudSessionRoutes(reg func(pattern string, cap Capability, section Section, h http.HandlerFunc)) {
	// A literal, not cloudSessionIngestRoute: the component catalog's route
	// check (tests/invariant TestComponentsRoutesExist) reads reg("...")
	// literals, and core declares this route.
	reg("/api/cloud-session/ingest", CapabilityPublic, SectionNone, s.handleCloudSessionIngest)
	reg("/api/cloud-session/tokens", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudSessionTokens)
	reg("/api/cloud-session/tokens/", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudSessionToken)
}

// cloudSessionStore is the REAL node store (never the demo database: a
// sandbox's rows and the owner's tokens belong to the live node).
func (s *Server) cloudSessionStore() *store.Store {
	if s.opts.DB == nil {
		return nil
	}
	return store.New(s.opts.DB)
}

// writeShipError writes a typed refusal the flush reads.
func writeShipError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="cloud-session"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

// handleCloudSessionIngest is POST /api/cloud-session/ingest.
func (s *Server) handleCloudSessionIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.cloudSessionStore()
	if st == nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	now := time.Now().UTC()
	// No active token: the route does not exist (off by default).
	if on, err := st.HasActiveCloudSessionShipToken(ctx, now); err != nil || !on {
		http.NotFound(w, r)
		return
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		writeShipError(w, http.StatusUnauthorized, shiptoken.CodeMissing, "a cloud-session ship token is required")
		return
	}
	secret, err := shiptoken.FromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeShipError(w, http.StatusUnauthorized, shiptoken.CodeInvalid, "not a cloud-session ship token")
		return
	}
	tok, err := st.CloudSessionShipTokenByHash(ctx, shiptoken.Hash(secret))
	if errors.Is(err, store.ErrShipTokenNotFound) {
		writeShipError(w, http.StatusUnauthorized, shiptoken.CodeInvalid, "unknown cloud-session ship token")
		return
	}
	if err != nil {
		writeShipError(w, http.StatusServiceUnavailable, shiptoken.CodeUnavailable, "token store unavailable")
		return
	}
	if code := shiptoken.RefusalCode(tok.Status(now)); code != "" {
		writeShipError(w, http.StatusUnauthorized, code, "cloud-session ship token is "+tok.Status(now))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, shiptoken.MaxBodyBytes+1))
	if err != nil {
		writeShipError(w, http.StatusBadRequest, shiptoken.CodeBadEnvelope, "could not read body")
		return
	}
	env, err := shiptoken.DecodeBody(raw, r.Header.Get("Content-Encoding"), shiptoken.MaxBodyBytes)
	switch {
	case errors.Is(err, shiptoken.ErrTooLarge):
		writeShipError(w, http.StatusRequestEntityTooLarge, shiptoken.CodeTooLarge, "batch exceeds size limit")
		return
	case err != nil:
		writeShipError(w, http.StatusBadRequest, shiptoken.CodeBadEnvelope, "invalid push envelope")
		return
	}
	adm := shiptoken.Admit(env, shiptoken.Binding{})
	res, err := st.LandCloudSessionEnvelope(ctx, adm.Envelope, tok.TokenID)
	var exhausted store.ShipTokenVolumeExhaustedError
	switch {
	case errors.As(err, &exhausted):
		writeShipError(w, http.StatusForbidden, shiptoken.CodeVolumeExhausted,
			fmt.Sprintf("%s for %q; mint a new token for the environment", exhausted.Error(), tok.Label))
		return
	case err != nil:
		writeShipError(w, http.StatusServiceUnavailable, shiptoken.CodeUnavailable, "batch not stored")
		return
	}
	_ = st.TouchCloudSessionShipToken(ctx, tok.TokenID, now)
	dropped := adm.Dropped
	for family, n := range res.NotLanded {
		dropped[family] += n
	}
	// Rows of a session the token did not create (ledger CLOUDSESS-8).
	for family, n := range res.SkippedRows {
		dropped[family] += n
	}
	remaining := res.RowsRemaining
	writeJSON(w, shiptoken.Receipt{
		AcceptedRows:       int64(res.Ingest.ActionsInserted + res.Ingest.TokensInserted),
		AdmittedRows:       adm.Rows,
		DroppedRows:        nonEmptyCounts(dropped),
		Execution:          nonEmptyCounts(adm.Execution),
		NextCursor:         env.CursorTo,
		TokenExpiresAt:     tok.ExpiresAt.Format(time.RFC3339),
		TokenRowsRemaining: &remaining,
		Environment:        tok.Label,
		SkippedSessions:    nonEmptyCounts(res.SkippedSessions),
	})
}

// nonEmptyCounts drops an empty count map so the receipt omits it.
func nonEmptyCounts(m map[string]int) map[string]int {
	if len(m) == 0 {
		return nil
	}
	return m
}

// nodeShipTokenView is one node token on the wire: never the hash. Since
// decision CA-D18 a token is per cloud environment (Label names it) and its
// expiry is shown as a time left too.
type nodeShipTokenView struct {
	TokenID     string `json:"token_id"`
	Label       string `json:"label"`
	Environment string `json:"environment"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	RevokedAt   string `json:"revoked_at,omitempty"`
	LastUsedAt  string `json:"last_used_at,omitempty"`
	UseCount    int64  `json:"use_count"`
	Status      string `json:"status"`
	// ExpiresInSeconds is the time left at the read, 0 unless active.
	ExpiresInSeconds int64 `json:"expires_in_seconds"`
}

func nodeShipView(t store.CloudSessionShipToken, now time.Time) nodeShipTokenView {
	v := nodeShipTokenView{
		TokenID: t.TokenID, Label: t.Label, Environment: t.Label, UseCount: t.UseCount, Status: t.Status(now),
		CreatedAt: t.CreatedAt.Format(time.RFC3339), ExpiresAt: t.ExpiresAt.Format(time.RFC3339),
	}
	if v.Status == shiptoken.StatusActive {
		v.ExpiresInSeconds = int64(t.ExpiresAt.Sub(now) / time.Second)
	}
	if !t.RevokedAt.IsZero() {
		v.RevokedAt = t.RevokedAt.Format(time.RFC3339)
	}
	if !t.LastUsedAt.IsZero() {
		v.LastUsedAt = t.LastUsedAt.Format(time.RFC3339)
	}
	return v
}

// nodeShipMintRequest is the body of POST /api/cloud-session/tokens.
type nodeShipMintRequest struct {
	Label      string `json:"label"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

// handleCloudSessionTokens serves GET (list, plus the confirm token) and POST
// (mint; the secret is returned once) on /api/cloud-session/tokens.
func (s *Server) handleCloudSessionTokens(w http.ResponseWriter, r *http.Request) {
	st := s.cloudSessionStore()
	if st == nil {
		writeErrStatus(w, errors.New("no database"), http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	now := time.Now().UTC()
	if r.Method == http.MethodGet {
		ts, err := st.ListCloudSessionShipTokens(ctx)
		if err != nil {
			writeErrStatus(w, err, http.StatusInternalServerError)
			return
		}
		out := make([]nodeShipTokenView, 0, len(ts))
		for _, t := range ts {
			out = append(out, nodeShipView(t, now))
		}
		writeJSON(w, map[string]any{
			"ship_tokens":         out,
			"ingest_path":         cloudSessionIngestRoute,
			"default_ttl_seconds": int64(shiptoken.DefaultLifetime / time.Second),
			"max_ttl_seconds":     int64(shiptoken.MaxLifetime / time.Second),
			"confirm_token":       setConfirmCookie(w, r),
		})
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	var req nodeShipMintRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeErrStatus(w, errors.New("the request body is not valid JSON"), http.StatusBadRequest)
		return
	}
	minted, err := st.MintCloudSessionShipToken(ctx, rand.Reader, req.Label, time.Duration(req.TTLSeconds)*time.Second, now)
	var held store.ShipTokenEnvironmentHeldError
	switch {
	case errors.Is(err, store.ErrShipTokenBadLabel):
		writeErrStatus(w, err, http.StatusBadRequest)
		return
	case errors.As(err, &held), errors.Is(err, store.ErrShipTokenTooMany):
		writeErrStatus(w, err, http.StatusConflict)
		return
	case err != nil:
		writeErrStatus(w, err, http.StatusInternalServerError)
		return
	}
	tok := minted.Token
	s.recordManageAudit(r, "cloud_session_token_mint", fmt.Sprintf("token_id=%s expires_at=%s", tok.TokenID, tok.ExpiresAt.Format(time.RFC3339)))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"token":      minted.Secret,
		"ship_token": nodeShipView(tok, now),
		// CA-D19: the owner's own node receives full content by default (it
		// is the owner's own data); `init --destination node` bakes it in.
		"share_posture": shiptoken.PostureFullContent,
		"init_flag":     "--destination node --share " + shiptoken.PostureFullContent,
		"note":          "Shown once. Store it as a secret of this one cloud environment (never in the repository) and point the flush at " + cloudSessionIngestRoute + " on this node, or the environment's OTLP exporter at this node's receiver. It can only land cloud-session capture and telemetry into this node, until its expiry.",
	})
}

// handleCloudSessionToken serves POST /api/cloud-session/tokens/{id}/revoke.
func (s *Server) handleCloudSessionToken(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/cloud-session/tokens/"), "/")
	id, verb, _ := strings.Cut(rest, "/")
	if !shiptoken.ValidID(id) || verb != "revoke" {
		http.NotFound(w, r)
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	st := s.cloudSessionStore()
	if st == nil {
		writeErrStatus(w, errors.New("no database"), http.StatusServiceUnavailable)
		return
	}
	revoked, err := st.RevokeCloudSessionShipToken(r.Context(), id, time.Now().UTC())
	if errors.Is(err, store.ErrShipTokenNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeErrStatus(w, err, http.StatusInternalServerError)
		return
	}
	s.recordManageAudit(r, "cloud_session_token_revoke", "token_id="+id)
	writeJSON(w, map[string]any{"token_id": id, "revoked": true, "already_revoked": !revoked})
}
