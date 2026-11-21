package orgclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The SDK credential rail (Plane A W2-7, ruling D18): this machine, signed
// in to its org, asks for the member's own scoped SDK key, or revokes it.
// The org binds the key to the bearer's member. Over the existing org lane
// (this package); the caller (internal/sdkcredsvc) stores the key.

// ErrSDKCredentialNotSupported is the org's 404 not_supported: this org
// server (pooled, or older than the rail) offers no SDK keys.
var ErrSDKCredentialNotSupported = errors.New("orgclient: this organization does not offer SDK keys yet")

// ErrSDKCredentialNotMember is the org's 403: the sign-in names no active
// member.
var ErrSDKCredentialNotMember = errors.New("orgclient: this machine's sign-in names no active member of the organization")

// maxSDKCredentialBody bounds the org's answer.
const maxSDKCredentialBody = 64 << 10

// MintSDKCredential asks the org for this member's SDK key, replacing only
// the key this machine holds (in.KeyID). The returned Credential is the
// secret; the caller stores it and never logs it.
func (c *Client) MintSDKCredential(ctx context.Context, in orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialMinted, error) {
	var out orgcontract.SDKCredentialMinted
	err := c.sdkCredentialCall(ctx, http.MethodPost, in, &out)
	return out, err
}

// RevokeSDKCredential revokes this machine's SDK key (in.KeyID), or every
// live SDK key of the member when in.All is set; the org refuses a request
// that names neither (review E-28).
func (c *Client) RevokeSDKCredential(ctx context.Context, in orgcontract.SDKCredentialRequest) (orgcontract.SDKCredentialRevoked, error) {
	var out orgcontract.SDKCredentialRevoked
	err := c.sdkCredentialCall(ctx, http.MethodDelete, in, &out)
	return out, err
}

func (c *Client) sdkCredentialCall(ctx context.Context, method string, in orgcontract.SDKCredentialRequest, out any) error {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return fmt.Errorf("orgclient.SDKCredential: load enrolment: %w", err)
	}
	if enr == nil || c.bearers == nil {
		return ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return fmt.Errorf("orgclient.SDKCredential: load bearer: %w", err)
	}
	reqBody, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("orgclient.SDKCredential: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(enr.OrgServerURL, "/")+orgcontract.AgentSDKCredentialPath, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return fmt.Errorf("orgclient.SDKCredential: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSDKCredentialBody))
	if err != nil {
		return fmt.Errorf("orgclient.SDKCredential: read: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return ErrSDKCredentialNotSupported
	case http.StatusForbidden:
		return ErrSDKCredentialNotMember
	case http.StatusUnauthorized:
		return fmt.Errorf("orgclient.SDKCredential: the organization refused this machine's sign-in (401); sign in again with `observer org enroll`")
	default:
		return fmt.Errorf("orgclient.SDKCredential: the organization answered %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("orgclient.SDKCredential: decode: %w", err)
	}
	return nil
}
