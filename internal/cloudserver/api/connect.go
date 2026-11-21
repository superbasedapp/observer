package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/connectflow"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/portalmfa"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// connect.go is the machine side of the Getting started v2 connect flow
// (contract A, docs/plans/onboarding-v2-connect-flow.md; docs/security.md
// CONNECT-1):
//
//	POST /v1/connect/requests        create a request (unauthenticated, per-IP limits)
//	GET  /v1/connect/requests/{id}   poll it (proof of possession of the request's key)
//	GET  /connect/{id}               the approve_url: 302 into the console
//	GET  /connect                    the verify_url (code entry): 302 into the console
//
// The browser side is portal_connect.go. The decisions are connectflow's and
// the SQL is store/connect.go's; this file owns the HTTP shape only.

// connectPagePath and connectEntryPath are the console pages the approve and
// verify URLs land on (webcloud's /connect/:id and /connect routes).
const (
	connectPagePath  = portalRootPath + "connect/"
	connectEntryPath = portalRootPath + "connect"
)

// connectRequestIDMax bounds a request id in a path before any lookup (a
// UUID is 36 characters).
const connectRequestIDMax = 64

// mountConnect registers the connect flow's machine and browser routes.
func (s *Server) mountConnect(mux *http.ServeMux) {
	mux.Handle("POST /v1/connect/requests", s.rateLimitIP(http.HandlerFunc(s.handleConnectCreate)))
	mux.Handle("GET /v1/connect/requests/{id}", s.rateLimitIP(http.HandlerFunc(s.handleConnectPoll)))
	mux.Handle("GET /connect/{id}", s.rateLimitIP(http.HandlerFunc(s.handleConnectApprovePage)))
	mux.Handle("GET /connect", s.rateLimitIP(http.HandlerFunc(s.handleConnectEntryPage)))
	s.mountPortalConnect(mux)
}

// connectCreateJSON is the 201 body of a create.
type connectCreateJSON struct {
	RequestID  string `json:"request_id"`
	UserCode   string `json:"user_code"`
	ApproveURL string `json:"approve_url"`
	VerifyURL  string `json:"verify_url"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

// connectTargetJSON is the dashboard an approved request connects to.
type connectTargetJSON struct {
	OrgID       string `json:"org_id"`
	Slug        string `json:"slug"`
	Kind        string `json:"kind"`
	DisplayName string `json:"display_name"`
	ShareLevel  string `json:"share_level"`
}

// connectPollJSON is the 200 body of a poll. Target and ConsentReceiptID are
// JSON null until an approval sets them; SignIn is present only on a
// delivering poll and is exactly the /v1/auth/exchange body. AttachGrant
// rides only beside a delivered SignIn when the approval chose a target
// (connect_grant.go).
type connectPollJSON struct {
	Status           string             `json:"status"`
	Target           *connectTargetJSON `json:"target"`
	ConsentReceiptID *string            `json:"consent_receipt_id"`
	Interval         int                `json:"interval"`
	SignIn           *exchangeResponse  `json:"sign_in,omitempty"`
	AttachGrant      string             `json:"attach_grant,omitempty"`
}

// connectTarget maps a stored target to the wire (nil stays nil).
func connectTarget(t *store.ConnectTarget) *connectTargetJSON {
	if t == nil {
		return nil
	}
	return &connectTargetJSON{
		OrgID: t.OrgID, Slug: t.Slug, Kind: string(t.Kind),
		DisplayName: t.DisplayName, ShareLevel: string(t.ShareLevel),
	}
}

// allowConnectDimension applies one connect-flow rate-limit bucket to key. It
// reports whether the request may proceed (it has answered when it may not).
func (s *Server) allowConnectDimension(w http.ResponseWriter, r *http.Request, d func(*rateLimiters) *rateLimitDimension, key string) bool {
	if s.rl == nil {
		return true
	}
	ok, retry, err := d(s.rl).allowContext(r.Context(), key)
	if err != nil {
		s.log.Error("cloudserver/api: connect rate limiter", "err", err)
		writeRateLimitUnavailable(w)
		return false
	}
	if !ok {
		writeRateLimited(w, retry)
		return false
	}
	return true
}

// handleConnectCreate is POST /v1/connect/requests.
func (s *Server) handleConnectCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ip, err := edgeClientIP(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_client_ip", "could not determine the client IP")
		return
	}
	if !s.allowConnectDimension(w, r, func(l *rateLimiters) *rateLimitDimension { return l.connectCreate }, ip) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, connectflow.MaxCreateBodyBytes))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		return
	}
	var req connectflow.CreateRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	in, err := connectflow.ValidateCreate(req)
	var fe *connectflow.FieldError
	if errors.As(err, &fe) {
		writeErr(w, http.StatusBadRequest, fe.Code, fe.Field+" is not valid")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid request")
		return
	}
	c, err := s.store.CreateConnectRequest(r.Context(), store.CreateConnectInput{
		Request: in, OriginNetwork: connectflow.NetworkPrefix(ip), Now: s.now(),
	})
	if err != nil {
		s.log.Error("cloudserver/api: create connect request", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not create the connect request")
		return
	}
	s.audit(r.Context(), "", "connect_request_created")
	writeJSON(w, http.StatusCreated, connectCreateJSON{
		RequestID:  c.RequestID,
		UserCode:   c.UserCode,
		ApproveURL: s.portalBaseURL + "/connect/" + c.RequestID,
		VerifyURL:  s.portalBaseURL + "/connect",
		ExpiresIn:  int(connectflow.RequestTTL / time.Second),
		Interval:   int(connectflow.PollInterval / time.Second),
	})
}

// handleConnectPoll is GET /v1/connect/requests/{id}: the machine proves it
// holds the key it sent at create, and reads the request's status; an
// approved request hands over its sign-in (store.DeliverConnectSignIn).
func (s *Server) handleConnectPoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	now := s.now()
	id := r.PathValue("id")
	if id == "" || len(id) > connectRequestIDMax {
		writeErr(w, http.StatusNotFound, "not_found", "connect request not found")
		return
	}
	if !s.allowConnectDimension(w, r, func(l *rateLimiters) *rateLimitDimension { return l.connectPoll }, id) {
		return
	}
	c, err := s.store.ConnectRequestByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "connect request not found")
		return
	}
	if err != nil {
		s.log.Error("cloudserver/api: read connect request", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the connect request")
		return
	}

	// The proof binds the request's own key, this URL rebuilt from the
	// configured external origin (never Host or X-Forwarded-*), and the
	// request id as its bound "token".
	pop, err := s.pop.Verify(PoPRequest{
		ProofHeader:     r.Header.Get(headerPoP),
		Method:          r.Method,
		URL:             s.externalBaseURL + r.URL.EscapedPath(),
		AccessToken:     c.RequestID,
		DevicePublicKey: c.PublicKey,
		Now:             now,
		MaxAge:          s.clockSkew,
		MaxSkew:         s.clockSkew,
	})
	if err != nil {
		s.audit(ctx, "", "connect_poll_pop_failed")
		writeErr(w, http.StatusUnauthorized, "unauthorized", "proof-of-possession failed")
		return
	}
	replay, err := s.store.RecordConnectPollJTI(ctx, c.RequestID, pop.JTI, pop.JTIExpiry)
	if err != nil {
		s.log.Error("cloudserver/api: connect poll replay record", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "replay check failed")
		return
	}
	if replay {
		s.audit(ctx, "", "connect_poll_replay")
		writeErr(w, http.StatusUnauthorized, "unauthorized", "proof replay detected")
		return
	}

	out := connectPollJSON{Interval: int(connectflow.PollInterval / time.Second)}
	status := connectflow.EffectiveStatus(c.Status, c.ExpiresAt, now)
	if status == connectflow.StatusApproved {
		delivered, signIn, err := s.store.DeliverConnectSignIn(ctx, c.RequestID, c.MachineName, s.tokenTTL, now)
		if s.connectDeliveryRefused(w, r, c.AccountID, err) {
			return
		}
		c = delivered
		if signIn != nil {
			s.audit(ctx, signIn.AccountID, "connect_signin_delivered")
			out.SignIn = &exchangeResponse{
				Token: signIn.Token, AccountID: signIn.AccountID, DeviceID: signIn.DeviceID,
				Thumbprint: signIn.Thumbprint, ExpiresAt: signIn.ExpiresAt.UTC().Format(time.RFC3339),
			}
			// The attach grant follows sign_in's delivery rules exactly: it
			// is only ever on a delivering poll.
			if grant := s.connectAttachGrant(ctx, c, now); grant != "" {
				s.audit(ctx, signIn.AccountID, "connect_attach_grant_delivered")
				out.AttachGrant = grant
			}
		}
		out.Target = connectTarget(c.Target)
		if c.ConsentID != "" {
			rid := c.ConsentID
			out.ConsentReceiptID = &rid
		}
	}
	out.Status = string(status)
	writeJSON(w, http.StatusOK, out)
}

// connectDeliveryRule maps one store refusal of a sign-in delivery to its
// answer.
type connectDeliveryRule struct {
	err     error
	status  int
	code    string
	message string
}

// connectDeliveryRules are the delivery refusals, in the order checked.
var connectDeliveryRules = []connectDeliveryRule{
	{
		store.ErrConnectSignInDelivered, http.StatusConflict, "sign_in_already_delivered",
		"this machine already received its sign-in; run observer connect again",
	},
	{store.ErrNotFound, http.StatusNotFound, "not_found", "connect request not found"},
	{store.ErrDeviceRevoked, http.StatusForbidden, "device_revoked", "this machine was removed from the account"},
	{
		store.ErrDeviceApprovalRequired, http.StatusForbidden, portalmfa.CodeDeviceApprovalRequired,
		"approve this machine again with your passkey, then run observer connect again",
	},
	{store.ErrAccountSuspended, http.StatusForbidden, "account_suspended", "this account is suspended"},
}

// connectDeliveryRefused answers a failed delivery. It reports whether it
// answered (false: err is nil and the poll goes on).
func (s *Server) connectDeliveryRefused(w http.ResponseWriter, r *http.Request, accountID string, err error) bool {
	if err == nil {
		return false
	}
	for _, rule := range connectDeliveryRules {
		if errors.Is(err, rule.err) {
			s.audit(r.Context(), accountID, "connect_signin_refused")
			writeErr(w, rule.status, rule.code, rule.message)
			return true
		}
	}
	s.log.Error("cloudserver/api: deliver connect sign-in", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal", "could not complete the sign-in")
	return true
}

// handleConnectApprovePage is GET /connect/{id}, the approve_url: it sends the
// browser to the console's approval page. The id is re-escaped, never echoed
// raw into the Location header.
func (s *Server) handleConnectApprovePage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > connectRequestIDMax {
		http.Redirect(w, r, connectEntryPath, http.StatusFound)
		return
	}
	http.Redirect(w, r, connectPagePath+url.PathEscape(id), http.StatusFound)
}

// handleConnectEntryPage is GET /connect, the verify_url: it sends the
// browser to the console's code entry page, keeping a well-formed ?code= so a
// link that carries the code prefills it.
func (s *Server) handleConnectEntryPage(w http.ResponseWriter, r *http.Request) {
	target := connectEntryPath
	if code, err := connectflow.NormalizeUserCode(r.URL.Query().Get("code")); err == nil {
		target += "?code=" + url.QueryEscape(code)
	}
	http.Redirect(w, r, target, http.StatusFound)
}
