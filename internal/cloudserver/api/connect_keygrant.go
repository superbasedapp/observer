package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/connectflow"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/sdkkeygrant"
)

// connect_keygrant.go answers the poll of an SDK key connect request (the AI
// Apps SDK quickstart's device sign-in, plan
// docs/plans/sdk-quickstart-one-command-plan-2026-11-25.md section 3.6;
// sdk/contract/fixtures/setup/connect-poll.json; docs/security.md SDKQS-1
// and SDKQS-2).
//
// An SDK key poll never delivers a cloud sign-in or an attach grant: no
// cloud API token reaches an SDK. Once a signed-in person approved the
// request with a dashboard, the poll hands over a key grant
// (internal/sdkkeygrant) that the dashboard's own host redeems for the
// member's SDK key. The grant follows the sign-in's delivery rules: on at
// most three polls within ten minutes of the approval, anchored to the
// approval (issued at it, ten minutes of life, a jti derived from the
// request id), and Ed25519 is deterministic, so every delivery is the same
// bytes and the host mints one key per approval. A personal dashboard still
// being set up is waited for: the poll answers approved, target.ready false,
// no grant, and the wait uses no delivery (connectflow.KeyGrantDecision).
//
// The grant is signed with the SDK key grant key (Options.SDKKeyGrantKey),
// never the attach grant's: the second platform key of ruling R13.

// connectSDKTargetJSON is the dashboard an approved SDK key request chose,
// as the SDK reads it (the fixture's target_fields: no share level).
type connectSDKTargetJSON struct {
	OrgID       string `json:"org_id"`
	Slug        string `json:"slug"`
	Kind        string `json:"kind"`
	DisplayName string `json:"display_name"`
	// ServerURL is the dashboard's own host, where the SDK redeems the
	// grant; "" until Ready.
	ServerURL string `json:"server_url"`
	// Ready is true once the dashboard is active (a new account's personal
	// dashboard is set up after the approval).
	Ready bool `json:"ready"`
}

// connectSDKPollJSON is the 200 body of an SDK key poll.
type connectSDKPollJSON struct {
	Status           string                `json:"status"`
	Target           *connectSDKTargetJSON `json:"target"`
	ConsentReceiptID *string               `json:"consent_receipt_id"`
	Interval         int                   `json:"interval"`
	// KeyGrant is present only on a delivering poll.
	KeyGrant string `json:"key_grant,omitempty"`
}

// sdkKeyGrantClaims builds the grant's claims for an approved SDK key
// request and the approving account's membership of the chosen dashboard.
// It reports false when no grant may be minted (no dashboard, not approved,
// or an account the host could not bind: not a member, or no subject). Pure:
// time is the decision table's (connectflow.KeyGrantDecision), not this
// function's.
func sdkKeyGrantClaims(c store.ConnectRequest, m connectGrantMember) (sdkkeygrant.Claims, bool) {
	t := c.Target
	switch {
	case t == nil, c.AccountID == "", c.ResolvedAt.IsZero(), c.RedeemHash == "":
		return sdkkeygrant.Claims{}, false
	case !m.IsMember, m.Sub == "":
		return sdkkeygrant.Claims{}, false
	}
	iat := c.ResolvedAt.UTC().Truncate(time.Second)
	return sdkkeygrant.Claims{
		OrgID:      t.OrgID,
		Slug:       t.Slug,
		Kind:       string(t.Kind),
		AccountID:  c.AccountID,
		Subject:    m.Sub,
		RequestID:  c.RequestID,
		RedeemHash: c.RedeemHash,
		IssuedAt:   iat.Unix(),
		ExpiresAt:  iat.Add(sdkkeygrant.Lifetime).Unix(),
		JTI:        sdkkeygrant.JTIFor(c.RequestID),
	}, true
}

// connectTargetReady reports whether the dashboard an approval chose is
// active now (the cloud's own org state, read through the approver's
// membership; the SDK needs no GET /v1/orgs).
func (s *Server) connectTargetReady(ctx context.Context, c store.ConnectRequest) (bool, error) {
	if c.Target == nil || c.AccountID == "" {
		return false, nil
	}
	return s.store.ConnectTargetActive(ctx, c.AccountID, c.Target.OrgID)
}

// connectKeyGrantRefusals map a store refusal of a key grant delivery to its
// answer.
var connectKeyGrantRefusals = []connectDeliveryRule{
	{
		store.ErrConnectKeyGrantDelivered, http.StatusConflict, "key_grant_already_delivered",
		"the key grant for this request was already delivered; run setup again",
	},
	{
		store.ErrConnectKeyGrantWindowClosed, http.StatusConflict, "key_grant_window_closed",
		"the approval is more than 10 minutes old and no key grant was delivered; run setup again",
	},
	{store.ErrNotFound, http.StatusNotFound, "not_found", "connect request not found"},
}

// handleConnectKeyGrantPoll answers an authenticated poll of an SDK key
// request.
func (s *Server) handleConnectKeyGrantPoll(w http.ResponseWriter, r *http.Request, c store.ConnectRequest, now time.Time) {
	ctx := r.Context()
	out := connectSDKPollJSON{Interval: int(connectflow.PollInterval / time.Second)}
	status := connectflow.EffectiveStatus(c.Status, c.ExpiresAt, now)
	out.Status = string(status)
	if status != connectflow.StatusApproved {
		writeJSON(w, http.StatusOK, out)
		return
	}

	ready, err := s.connectTargetReady(ctx, c)
	if err != nil {
		s.log.Error("cloudserver/api: key grant: read dashboard state", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the dashboard")
		return
	}
	// The claims are built (and the member checked) before a delivery is
	// counted, so an account the host could not bind never uses one.
	var claims sdkkeygrant.Claims
	if ready {
		m, err := s.store.OIDC().Member(ctx, c.AccountID, c.Target.OrgID)
		if err != nil {
			s.log.Error("cloudserver/api: key grant: read membership", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "could not read the membership")
			return
		}
		var ok bool
		if claims, ok = sdkKeyGrantClaims(c, m); !ok {
			s.audit(ctx, c.AccountID, "connect_key_grant_refused")
			writeErr(w, http.StatusForbidden, "key_grant_refused", "this account cannot receive an SDK key for that dashboard")
			return
		}
	}

	d, err := s.store.DeliverConnectKeyGrant(ctx, c.RequestID, ready, now)
	for _, rule := range connectKeyGrantRefusals {
		if errors.Is(err, rule.err) {
			s.audit(ctx, c.AccountID, "connect_key_grant_refused")
			writeErr(w, rule.status, rule.code, rule.message)
			return
		}
	}
	if err != nil {
		s.log.Error("cloudserver/api: deliver key grant", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not deliver the key grant")
		return
	}
	c = d.Request
	if d.Decision == connectflow.KeyGrantDeliver {
		grant, err := sdkkeygrant.Sign(s.sdkKeyGrantKey, claims)
		if err != nil {
			s.log.Error("cloudserver/api: sign key grant", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal", "could not sign the key grant")
			return
		}
		s.audit(ctx, c.AccountID, "connect_key_grant_delivered")
		out.KeyGrant = grant
	}
	if t := c.Target; t != nil {
		target := &connectSDKTargetJSON{
			OrgID: t.OrgID, Slug: t.Slug, Kind: string(t.Kind), DisplayName: t.DisplayName,
			Ready: ready && d.Decision != connectflow.KeyGrantNotReady,
		}
		if target.Ready {
			target.ServerURL = s.tenantLink(t.Slug, tenantPageOrigin)
		}
		out.Target = target
	}
	if c.ConsentID != "" {
		rid := c.ConsentID
		out.ConsentReceiptID = &rid
	}
	writeJSON(w, http.StatusOK, out)
}
