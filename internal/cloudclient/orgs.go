package cloudclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// orgs.go is the node's organization discovery (managed SaaS plan 06 section
// 19.3 rows 7-9; plan 07 M8.7): the two device-authenticated calls `observer
// connect` makes when it is given no server address. Both ride the client's
// one authenticated send path (a fresh proof of possession per attempt, the
// one-shot token self-heal, transport retries only), and both refuse an
// answer that does not pass the shared wire contract's Validate: a node never
// attaches to an org whose shape it could not check.
//
// They are reached only through the consent gateway's Bootstrap family
// (internal/cloudgateway), because the user's own `observer connect` is the
// authorization, as for sign-in (R2 F10). No consent purpose of their own.

// Discovery paths, relative to the cloud base URL.
const (
	pathListOrgs          = "/v1/orgs"
	pathEnsurePersonalOrg = "/v1/orgs/personal:ensure"
)

// ListOrgs fetches the orgs the signed-in account belongs to (GET /v1/orgs),
// personal first. It returns ErrNotAuthenticated when no API token is stored.
// An answer that fails cloudcontract.DeviceOrgList.Validate is refused.
func (c *Client) ListOrgs(ctx context.Context) (cloudcontract.DeviceOrgList, error) {
	raw, err := c.sendAuthed(ctx, nil, nil, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodGet, pathListOrgs, nil, nil)
	})
	if err != nil {
		return cloudcontract.DeviceOrgList{}, fmt.Errorf("cloudclient.ListOrgs: %w", err)
	}
	var out cloudcontract.DeviceOrgList
	if err := json.Unmarshal(raw, &out); err != nil {
		return cloudcontract.DeviceOrgList{}, fmt.Errorf("cloudclient.ListOrgs: decode response: %w", err)
	}
	if err := out.Validate(); err != nil {
		return cloudcontract.DeviceOrgList{}, fmt.Errorf("cloudclient.ListOrgs: refused an invalid answer: %w", err)
	}
	return out, nil
}

// EnsurePersonalOrg returns the account's personal org, asking the service to
// create it when it has none (POST /v1/orgs/personal:ensure; 201 created, 200
// existing). The call is idempotent server-side, so a transport retry can
// never create a second org. An answer that fails
// cloudcontract.EnsurePersonalOrgResponse.Validate (including any org that
// is not personal) is refused.
func (c *Client) EnsurePersonalOrg(ctx context.Context) (cloudcontract.EnsurePersonalOrgResponse, error) {
	raw, err := c.sendAuthed(ctx, nil, nil, func(int) (*http.Request, error) {
		return c.buildAuthed(ctx, http.MethodPost, pathEnsurePersonalOrg, nil, nil)
	})
	if err != nil {
		return cloudcontract.EnsurePersonalOrgResponse{}, fmt.Errorf("cloudclient.EnsurePersonalOrg: %w", err)
	}
	var out cloudcontract.EnsurePersonalOrgResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return cloudcontract.EnsurePersonalOrgResponse{}, fmt.Errorf("cloudclient.EnsurePersonalOrg: decode response: %w", err)
	}
	if err := out.Validate(); err != nil {
		return cloudcontract.EnsurePersonalOrgResponse{}, fmt.Errorf("cloudclient.EnsurePersonalOrg: refused an invalid answer: %w", err)
	}
	return out, nil
}
