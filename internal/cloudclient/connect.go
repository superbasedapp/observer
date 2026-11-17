package cloudclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/cloudpop"
)

// connect.go is the node half of the connect request (Getting started v2,
// shared contract A): one browser approval that signs this machine in AND
// picks where its data goes. It is the ONE seam that knows the wire shape;
// cmd/observer sees only the plain result types below, so a field rename on
// the hosted side is one edit here.
//
//   - CreateConnectRequest: POST /v1/connect/requests, unauthenticated
//     (the user is not signed in yet), carrying this machine's device public
//     key and a short description of the machine. The answer names the
//     browser approval page and a short code for machines with no browser.
//   - PollConnectRequest: GET /v1/connect/requests/{id}, with a
//     proof of possession for the device key (cloudpop) and no bearer. When
//     the request is approved the answer also completes device sign-in: the
//     API token it carries is stored through Cred exactly as Exchange stores
//     one, and is never returned to the caller.
//
// The poll proof binds its ath claim to the request id, because there is no
// API token yet to bind (cloudpop requires a non-empty binding). The hosted
// side verifies the proof against the device key the create call registered.
//
// Both answers are checked before use: an approve or verify URL that does not
// point at the configured cloud origin is refused, so a compromised or
// confused response can never send the user's browser somewhere else.

// Connect request paths, relative to the cloud base URL.
const pathConnectRequests = "/v1/connect/requests"

// Connect request statuses (contract A).
const (
	ConnectPending  = "pending"
	ConnectApproved = "approved"
	ConnectDeclined = "declined"
	ConnectExpired  = "expired"
)

// Connect target kinds and share levels (contract A).
const (
	ConnectKindPersonal = "personal"
	ConnectKindTeam     = "team"
	ConnectShareSummary = "summary"
	ConnectShareFull    = "full"
)

// ErrConnectRequestGone means the hosted side no longer knows the request
// (404 or 410): it expired or was withdrawn. The caller starts a new one.
var ErrConnectRequestGone = errors.New("cloudclient: connect request expired or not found")

// ErrConnectUnsupported means the cloud answered the create call with 404 or
// 405: it does not offer connect requests yet. The caller may fall back to
// the older sign-in and organization list.
var ErrConnectUnsupported = errors.New("cloudclient: this cloud does not offer connect requests")

// ErrConnectSlowDown means the hosted side rate-limited a poll (429). The
// caller waits longer before the next poll; it is not a failure.
var ErrConnectSlowDown = errors.New("cloudclient: connect request polled too fast")

// ConnectRequestInput describes this machine for the approval page. The
// device public key is added by the client from its own device key.
type ConnectRequestInput struct {
	MachineName     string
	OS              string
	Arch            string
	ObserverVersion string
	// TargetHint is a team slug to preselect on the approval page, or "".
	TargetHint string
}

// ConnectRequest is the hosted side's answer to CreateConnectRequest.
type ConnectRequest struct {
	RequestID  string `json:"request_id"`
	UserCode   string `json:"user_code"`
	ApproveURL string `json:"approve_url"`
	VerifyURL  string `json:"verify_url"`
	// ExpiresIn and Interval are seconds.
	ExpiresIn int `json:"expires_in"`
	Interval  int `json:"interval"`
}

// ConnectTarget is where an approved request sends this machine's data.
type ConnectTarget struct {
	OrgID       string `json:"org_id"`
	Slug        string `json:"slug"`
	Kind        string `json:"kind"`
	DisplayName string `json:"display_name"`
	ShareLevel  string `json:"share_level"`
	// ServerURL is the target's own address, when the hosted side sends it
	// (a contract addition; lane 2 handback). Empty means the caller looks
	// the org up by OrgID through the organization list.
	ServerURL string `json:"server_url,omitempty"`
	// DashboardURL is the target's online dashboard, when sent (addition).
	DashboardURL string `json:"dashboard_url,omitempty"`
}

// ConnectStatus is one poll's answer, with every credential removed.
type ConnectStatus struct {
	Status           string
	Target           *ConnectTarget
	ConsentReceiptID string
	// SignedIn is true when this answer completed device sign-in (an API
	// token was stored through Cred).
	SignedIn bool
	// EnrolCode is a one-time attach code for Target, when the hosted side
	// minted one at approval (a contract addition; lane 2 handback). It is a
	// secret: callers hand it to the attach step on standard input and never
	// print, log or serialize it (json:"-").
	EnrolCode string `json:"-"`
	// AttachGrant is the one-step attach grant for Target (contract A
	// section 11, internal/attachgrant), present beside a delivered sign-in
	// when the approval chose a dashboard. Callers hand it to the attach
	// step on standard input with a proof from this device key (AttachProof)
	// and never print, log or serialize it (json:"-").
	AttachGrant string `json:"-"`
}

// connectCreateWire is the create request body (contract A).
type connectCreateWire struct {
	DevicePublicKey string `json:"device_public_key"`
	MachineName     string `json:"machine_name"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	ObserverVersion string `json:"observer_version"`
	TargetHint      string `json:"target_hint"`
}

// connectPollWire is the poll answer (contract A, plus the device sign-in
// fields an approved answer carries: the same api_token / expires_at /
// device_id the exchange answer uses, and the optional one-time enrol_code).
type connectPollWire struct {
	Status           string         `json:"status"`
	Target           *ConnectTarget `json:"target"`
	ConsentReceiptID string         `json:"consent_receipt_id"`
	// SignIn is contract A's delivered sign-in: byte for byte the
	// /v1/auth/exchange answer, nested under "sign_in".
	SignIn *exchangeResponse `json:"sign_in,omitempty"`
	// APIToken, ExpiresAt and DeviceID are the flat spelling the CLI was
	// first written against (lane 2's reading of the brief); kept so an
	// answer in either shape signs the machine in. sign_in wins.
	APIToken    string `json:"api_token,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	EnrolCode   string `json:"enrol_code,omitempty"`
	AttachGrant string `json:"attach_grant,omitempty"`
}

// apiToken is the delivered API token: sign_in's, else the flat field.
func (w connectPollWire) apiToken() string {
	if w.SignIn != nil {
		if tok := strings.TrimSpace(w.SignIn.APIToken); tok != "" {
			return tok
		}
	}
	return strings.TrimSpace(w.APIToken)
}

// CreateConnectRequest registers a connect request for this machine's
// device key (POST /v1/connect/requests). Unauthenticated: no bearer and no
// proof, since the device key is being introduced, not used. Transport
// errors are not retried, because each attempt would create a second
// request; the caller simply runs the command again.
func (c *Client) CreateConnectRequest(ctx context.Context, in ConnectRequestInput) (ConnectRequest, error) {
	body, err := json.Marshal(connectCreateWire{
		DevicePublicKey: b64.EncodeToString(c.dev.pub),
		MachineName:     strings.TrimSpace(in.MachineName),
		OS:              in.OS,
		Arch:            in.Arch,
		ObserverVersion: in.ObserverVersion,
		TargetHint:      strings.TrimSpace(in.TargetHint),
	})
	if err != nil {
		return ConnectRequest{}, fmt.Errorf("cloudclient.CreateConnectRequest: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+pathConnectRequests, bytes.NewReader(body))
	if err != nil {
		return ConnectRequest{}, fmt.Errorf("cloudclient.CreateConnectRequest: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	raw, err := c.sendOnce(req)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed) {
			return ConnectRequest{}, ErrConnectUnsupported
		}
		return ConnectRequest{}, fmt.Errorf("cloudclient.CreateConnectRequest: %w", err)
	}
	var out ConnectRequest
	if err := json.Unmarshal(raw, &out); err != nil {
		return ConnectRequest{}, fmt.Errorf("cloudclient.CreateConnectRequest: decode response: %w", err)
	}
	if err := c.validateConnectRequest(out); err != nil {
		return ConnectRequest{}, fmt.Errorf("cloudclient.CreateConnectRequest: refused an invalid answer: %w", err)
	}
	return out, nil
}

// PollConnectRequest asks for the request's state (GET
// /v1/connect/requests/{id}) with a proof of possession for the device key.
// An approved answer that carries an API token completes device sign-in: the
// token is stored through Cred and the result reports SignedIn. A 404 or 410
// is ErrConnectRequestGone, a 429 is ErrConnectSlowDown.
func (c *Client) PollConnectRequest(ctx context.Context, requestID string) (ConnectStatus, error) {
	seg, err := pathSegment(requestID)
	if err != nil {
		return ConnectStatus{}, fmt.Errorf("cloudclient.PollConnectRequest: %w", err)
	}
	fullURL := c.baseURL + pathConnectRequests + "/" + seg
	raw, err := c.sendRetryable(ctx, nil, func(int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		proof, err := cloudpop.Create(cloudpop.CreateParams{
			PrivateKey:  c.dev.priv,
			Method:      http.MethodGet,
			URL:         fullURL,
			AccessToken: requestID,
			IssuedAt:    c.clock(),
		})
		if err != nil {
			return nil, fmt.Errorf("mint proof: %w", err)
		}
		req.Header.Set(headerPoP, proof)
		return req, nil
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			switch apiErr.StatusCode {
			case http.StatusNotFound, http.StatusGone:
				return ConnectStatus{}, ErrConnectRequestGone
			case http.StatusTooManyRequests:
				return ConnectStatus{}, ErrConnectSlowDown
			}
		}
		return ConnectStatus{}, fmt.Errorf("cloudclient.PollConnectRequest: %w", err)
	}
	var w connectPollWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return ConnectStatus{}, fmt.Errorf("cloudclient.PollConnectRequest: decode response: %w", err)
	}
	if err := validateConnectPoll(w); err != nil {
		return ConnectStatus{}, fmt.Errorf("cloudclient.PollConnectRequest: refused an invalid answer: %w", err)
	}
	out := ConnectStatus{Status: w.Status, Target: w.Target, ConsentReceiptID: w.ConsentReceiptID}
	if w.Status != ConnectApproved {
		return out, nil
	}
	out.EnrolCode = strings.TrimSpace(w.EnrolCode)
	// A grant is only meaningful for a target; one beside "Not now" is
	// dropped rather than handed to an attach that has nowhere to go.
	if w.Target != nil {
		out.AttachGrant = strings.TrimSpace(w.AttachGrant)
	}
	if tok := w.apiToken(); tok != "" {
		if err := c.cred.SaveAPIToken(tok); err != nil {
			return ConnectStatus{}, fmt.Errorf("cloudclient.PollConnectRequest: store token: %w", err)
		}
		out.SignedIn = true
	}
	return out, nil
}

// validateConnectRequest checks a create answer: a usable request id, a
// short code, and both URLs on the configured cloud origin.
func (c *Client) validateConnectRequest(r ConnectRequest) error {
	if _, err := pathSegment(r.RequestID); err != nil {
		return fmt.Errorf("request_id: %w", err)
	}
	if !validUserCode(r.UserCode) {
		return fmt.Errorf("user_code %q is not a short code", r.UserCode)
	}
	for name, u := range map[string]string{"approve_url": r.ApproveURL, "verify_url": r.VerifyURL} {
		if err := sameOrigin(c.baseURL, u); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if r.ExpiresIn < 0 || r.Interval < 0 {
		return errors.New("negative expires_in or interval")
	}
	return nil
}

// validUserCode accepts the short code shape (like KTRW-4821): 4 to 16
// characters of A-Z, 0-9 and '-'.
func validUserCode(code string) bool {
	if len(code) < 4 || len(code) > 16 {
		return false
	}
	for _, r := range code {
		if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' {
			return false
		}
	}
	return true
}

// sameOrigin reports whether raw is an absolute URL on base's scheme and
// host. A plain-http base is accepted only on loopback (local testing).
func sameOrigin(base, raw string) error {
	b, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("base url: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	if !strings.EqualFold(u.Scheme, b.Scheme) || !strings.EqualFold(u.Host, b.Host) {
		return fmt.Errorf("%q is not on %s://%s", raw, b.Scheme, b.Host)
	}
	if strings.EqualFold(u.Scheme, "http") {
		ip := net.ParseIP(u.Hostname())
		if !strings.EqualFold(u.Hostname(), "localhost") && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("%q is plain http off loopback", raw)
		}
	} else if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%q is not https", raw)
	}
	return nil
}

// validateConnectPoll checks a poll answer against the closed vocabularies.
// An approved answer with a target must name the org, a known kind and a
// known share level; approved with no target is "Not now" (signed in,
// nothing sent).
func validateConnectPoll(w connectPollWire) error {
	switch w.Status {
	case ConnectPending, ConnectDeclined, ConnectExpired:
		return nil
	case ConnectApproved:
	default:
		return fmt.Errorf("unknown status %q", w.Status)
	}
	t := w.Target
	if t == nil {
		return nil
	}
	if strings.TrimSpace(t.OrgID) == "" {
		return errors.New("target has no org_id")
	}
	switch t.Kind {
	case ConnectKindPersonal, ConnectKindTeam:
	default:
		return fmt.Errorf("target kind %q", t.Kind)
	}
	switch t.ShareLevel {
	case ConnectShareSummary, ConnectShareFull:
	default:
		return fmt.Errorf("target share_level %q", t.ShareLevel)
	}
	// The org's own address follows the organization list's rule
	// (cloudcontract.DeviceOrg.Validate): https and <slug>.<domain>.
	if t.ServerURL != "" {
		u, err := url.Parse(t.ServerURL)
		if err != nil || u.Scheme != "https" || !strings.Contains(u.Hostname(), ".") {
			return fmt.Errorf("target server_url %q must be https", t.ServerURL)
		}
		if label, _, _ := strings.Cut(u.Hostname(), "."); label != t.Slug {
			return fmt.Errorf("target server_url %q is not on <slug>.<domain>", t.ServerURL)
		}
	}
	if t.DashboardURL != "" {
		if u, err := url.Parse(t.DashboardURL); err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("target dashboard_url %q must be https", t.DashboardURL)
		}
	}
	return nil
}

// AttachProof signs the device proof that rides with an attach grant
// (attachgrant.SignProof): this machine's device key over the grant and the
// node key the attach enrols. The device key never leaves the client; the
// proof binds the exact grant and node key, so it can sign nothing else.
func (c *Client) AttachProof(grant, agentPublicKey string) (attachgrant.Proof, error) {
	if strings.TrimSpace(grant) == "" || strings.TrimSpace(agentPublicKey) == "" {
		return attachgrant.Proof{}, errors.New("cloudclient.AttachProof: grant and node key are required")
	}
	p, err := attachgrant.SignProof(c.dev.priv, grant, agentPublicKey)
	if err != nil {
		return attachgrant.Proof{}, fmt.Errorf("cloudclient.AttachProof: %w", err)
	}
	return p, nil
}
