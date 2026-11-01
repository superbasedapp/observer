package orgclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The project audience's resolve call, node sender side (security plan
// section 7.11 "Delivery" item 3, lane sec-p2a): POST
// /api/agent/project/resolve. The daemon's matcher (cmd/observer
// project_audience.go) calls it at launch and at session start, for a project
// root its cached mapping did not match, never on the hook path. This file
// sends the request and checks the answer's signature against the org policy
// key pinned at enrolment; the rest of the accept gate (org, member, epoch,
// bundle version, request digest, nonce, expiry, envelopes) is
// projectmatch.AcceptResolve, which the matcher runs against the composed
// bundle in force.

// projectResolveMaxReply bounds a resolve answer (a few envelopes).
const projectResolveMaxReply = 4 << 20

// Resolve call outcomes the matcher distinguishes.
var (
	// ErrProjectResolveUnavailable: the server has no resolve route (it
	// predates lane sec-p2a) or no project audience now (404).
	ErrProjectResolveUnavailable = errors.New("orgclient: project resolve unavailable on this org server")
	// ErrProjectResolveLimited: the server rate-limited this member (429).
	ErrProjectResolveLimited = errors.New("orgclient: project resolve rate-limited")
	// ErrProjectResolveKey: the answer verified under a key that is not the
	// org policy key pinned at enrolment (or no key is pinned).
	ErrProjectResolveKey = errors.New("orgclient: project resolve answer is not signed by the pinned org key")
)

// NewProjectResolveNonce returns a fresh random nonce for one request.
func NewProjectResolveNonce() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("orgclient.NewProjectResolveNonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ResolveProject sends one resolve request and returns the answer once its
// signature verifies under the org policy key pinned at enrolment. It makes
// exactly one attempt; the caller decides what a failure means (an unknown
// project layer only when the mapping cannot answer on its own).
func (c *Client) ResolveProject(ctx context.Context, req orgcontract.ProjectResolveRequest) (orgcontract.ProjectResolveAnswer, error) {
	var zero orgcontract.ProjectResolveAnswer
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return zero, fmt.Errorf("orgclient.ResolveProject: %w", err)
	}
	if enr == nil || c.bearers == nil {
		return zero, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return zero, ErrNotEnrolled
	}
	if err != nil {
		return zero, fmt.Errorf("orgclient.ResolveProject: load bearer: %w", err)
	}
	pinned, err := c.loadKeyPin(ctx, enr.OrgServerURL)
	if err != nil {
		return zero, fmt.Errorf("orgclient.ResolveProject: read key pin: %w", err)
	}
	if pinned == "" {
		return zero, ErrProjectResolveKey
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return zero, fmt.Errorf("orgclient.ResolveProject: marshal: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/project/resolve"
	if projectFamiliesAdvertised() {
		// The same tokens as the bundle GET (lane sec-p3): the answer's
		// envelopes then carry their family members.
		url += "?policy_caps=" + orgcontract.PolicyBindingV3Capability + "," + orgcontract.ProjectFamiliesCapability
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return zero, fmt.Errorf("orgclient.ResolveProject: new request: %w", err)
	}
	hreq.Header.Set("Authorization", "Bearer "+bearer)
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(hreq)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return zero, fmt.Errorf("orgclient.ResolveProject: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return zero, ErrProjectResolveUnavailable
	case http.StatusTooManyRequests:
		return zero, ErrProjectResolveLimited
	case http.StatusUnauthorized, http.StatusForbidden:
		return zero, fmt.Errorf("orgclient.ResolveProject: %w", ErrAuthFailed)
	default:
		return zero, fmt.Errorf("orgclient.ResolveProject: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, projectResolveMaxReply))
	if err != nil {
		return zero, fmt.Errorf("orgclient.ResolveProject: read: %w", err)
	}
	var ans orgcontract.ProjectResolveAnswer
	if err := json.Unmarshal(body, &ans); err != nil {
		return zero, fmt.Errorf("orgclient.ResolveProject: decode: %w", err)
	}
	pub, err := orgcontract.VerifyProjectResolveAnswer(ans)
	if err != nil || orgcontract.PublicKeyPinHash(pub) != pinned {
		return zero, ErrProjectResolveKey
	}
	return ans, nil
}
