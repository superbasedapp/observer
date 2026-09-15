package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

type nonceResponse struct {
	Nonce     string `json:"nonce"`
	ExpiresIn int    `json:"expires_in_seconds"`
}

// exchangeSigningContext + exchangeSigningInput mirror
// internal/cloudclient/device.go's exchangeSigningContext /
// ExchangeSigningInput byte-for-byte. internal/cloudserver may import ONLY
// internal/cloudpop (tests/invariant/cloud_egress_test.go), so the exchange
// signing-input format — a domain-separated construction distinct from
// cloudpop's own proof format — is duplicated here rather than imported.
// cloudclient's doc comment on ExchangeSigningInput states "The server
// recomputes and verifies this."; prior to this fix handleExchange verified
// the signature over the bare nonce bytes instead, which rejects every real
// client-minted exchange signature with "device signature invalid".
const exchangeSigningContext = "sbo-device-exchange.v1"

func exchangeSigningInput(nonce string, pub ed25519.PublicKey) []byte {
	return []byte(exchangeSigningContext + "\n" + nonce + "\n" + base64.RawURLEncoding.EncodeToString(pub))
}

// handleNonce mints a single-use exchange nonce (pre-auth).
func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := s.store.MintNonce(r.Context(), s.nonceTTL, s.now())
	if err != nil {
		s.log.Error("cloudserver/api: mint nonce", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not mint nonce")
		return
	}
	writeJSON(w, http.StatusOK, nonceResponse{Nonce: nonce, ExpiresIn: int(s.nonceTTL.Seconds())})
}

// exchangeRequest's JSON tags are the wire contract with internal/cloudclient
// (client.go's exchangeRequest). BrokerToken carries whatever the configured
// identity.Verifier expects (a WorkOS access token, or "dev:<subject>" under
// dev-auth) — the field name stays provider-agnostic even though the wire
// tag names the WorkOS shape the client was built against.
type exchangeRequest struct {
	BrokerToken     string `json:"workos_access_token"`
	DevicePublicKey string `json:"device_public_key"` // base64url, raw
	DeviceLabel     string `json:"device_label"`
	Nonce           string `json:"nonce"`
	Signature       string `json:"signature"` // base64url Ed25519 over the nonce string bytes
}

// exchangeResponse's JSON tags are the wire contract with internal/cloudclient
// (client.go's exchangeResponse expects api_token).
type exchangeResponse struct {
	Token      string `json:"api_token"`
	AccountID  string `json:"account_id"`
	DeviceID   string `json:"device_id"`
	Thumbprint string `json:"thumbprint"`
	ExpiresAt  string `json:"expires_at"`
}

// handleExchange validates the broker token + the device's proof of possession
// over the nonce, then mints a device-bound API token. Account scope is derived
// server-side (identity link), never from the request body.
func (s *Server) handleExchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req exchangeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}

	// 1) Broker identity.
	id, err := s.verifier.Verify(ctx, req.BrokerToken)
	if err != nil {
		s.audit(ctx, "", "exchange_identity_invalid")
		writeErr(w, http.StatusUnauthorized, "unauthorized", "broker token invalid")
		return
	}

	// 2) Device key + signature over the nonce (proof of possession at exchange).
	pub, err := base64.RawURLEncoding.DecodeString(req.DevicePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid device public key")
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid signature encoding")
		return
	}
	if req.Nonce == "" || !ed25519.Verify(ed25519.PublicKey(pub), exchangeSigningInput(req.Nonce, pub), sig) {
		s.audit(ctx, "", "exchange_bad_signature")
		writeErr(w, http.StatusUnauthorized, "unauthorized", "device signature invalid")
		return
	}

	// 3) Consume nonce + resolve/create account + register device + mint token.
	res, err := s.store.Exchange(ctx, store.ExchangeInput{
		Provider:  id.Provider,
		Subject:   id.Subject,
		PublicKey: pub,
		Label:     req.DeviceLabel,
		RawNonce:  req.Nonce,
		TokenTTL:  s.tokenTTL,
		Now:       s.now(),
	})
	switch {
	case errors.Is(err, store.ErrNonceInvalid):
		writeErr(w, http.StatusUnauthorized, "nonce_invalid", "nonce invalid, expired, or already used")
		return
	case errors.Is(err, store.ErrDeviceRevoked):
		s.audit(ctx, "", "exchange_device_revoked")
		writeErr(w, http.StatusForbidden, "device_revoked", "this device has been revoked")
		return
	case errors.Is(err, store.ErrAccountSuspended):
		// The broker token verified, but the account behind the identity has been
		// suspended here (D18: a user.deleted lifecycle event). Minting a token
		// would re-open access the revocation just closed.
		s.audit(ctx, "", "exchange_account_suspended")
		writeErr(w, http.StatusForbidden, "account_suspended",
			"this account is suspended and cannot obtain new credentials")
		return
	case err != nil:
		s.log.Error("cloudserver/api: exchange", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "exchange failed")
		return
	}

	s.audit(ctx, res.AccountID, "exchange_ok")
	writeJSON(w, http.StatusOK, exchangeResponse{
		Token:      res.Token,
		AccountID:  res.AccountID,
		DeviceID:   res.DeviceID,
		Thumbprint: res.Thumbprint,
		ExpiresAt:  res.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}
