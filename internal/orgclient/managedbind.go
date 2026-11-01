package orgclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// ErrManagedBindRefused is returned by BindMachine when the server, under its
// enforce collision posture, refuses to bind this machine because it is already
// bound to another managed node (HTTP 409). The enrolment itself already
// succeeded; the caller surfaces this as a firm notice, not a failure.
var ErrManagedBindRefused = errors.New("managed machine binding refused: this machine is already bound to another managed node")

// ErrManagedBindNotManagedHere is returned when the server answers 403: it
// does not serve this node as managed (an older org server asked by a node
// its org switched to enterprise, or the window before the server recorded
// the node's adoption of the switch).
var ErrManagedBindNotManagedHere = errors.New("managed machine binding refused: the org server does not serve this node as managed")

// Client-only ManagedBindResponse.Status values that never come off the wire —
// they describe a locally-resolved outcome (no stable machine source, or a
// server too old to know the route).
const (
	ManagedBindUnbindable  = "unbindable"  // no stable machine identity on this host
	ManagedBindUnavailable = "unavailable" // server has no managed-bind route (older server)
)

// BindMachine performs the SECOND step of managed enrolment (Arc 4 P6a, plan
// §9): it presents this host's org-salted machine fingerprint so the server can
// bind one managed node to one machine. It is called ONLY for a managed
// node: a managed enrolment at enrolment time, or, once per process before
// its first integrity report, a node its org switched to enterprise (P-205).
// An individual/BYO node never computes or sends a fingerprint, so the
// individual plane emits no machine identity at all. A 403 (the server does
// not serve this node as managed) returns ErrManagedBindNotManagedHere.
//
// Best-effort by design: a host with no stable machine source yields an empty
// fingerprint and BindMachine returns ManagedBindUnbindable WITHOUT calling the
// server (the node then shows as "unbound" to the admin — itself a signal). An
// older server without the route returns ManagedBindUnavailable. A 409 under the
// server's enforce posture returns ErrManagedBindRefused. None of these fail the
// enrolment, which has already completed.
func (c *Client) BindMachine(ctx context.Context) (orgcontract.ManagedBindResponse, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return orgcontract.ManagedBindResponse{}, fmt.Errorf("orgclient.BindMachine: enrolment: %w", err)
	}
	if enr == nil {
		return orgcontract.ManagedBindResponse{}, ErrNotEnrolled
	}

	// Org-salted so the same machine yields unrelated identities across orgs and
	// the raw OS id never leaves the host.
	mid, err := machineid.ForOrg(enr.OrgID)
	if err != nil {
		// A merely-unusable source is not an error inside ForOrg; a non-nil err
		// is an unexpected I/O failure worth surfacing, but never fatal.
		return orgcontract.ManagedBindResponse{Status: ManagedBindUnbindable}, fmt.Errorf("orgclient.BindMachine: machine id: %w", err)
	}
	if mid == "" {
		return orgcontract.ManagedBindResponse{Status: ManagedBindUnbindable}, nil
	}

	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return orgcontract.ManagedBindResponse{}, fmt.Errorf("orgclient.BindMachine: bearer: %w", err)
	}

	body, err := json.Marshal(orgcontract.ManagedBindRequest{MachineIdentity: mid})
	if err != nil {
		return orgcontract.ManagedBindResponse{}, fmt.Errorf("orgclient.BindMachine: marshal: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/managed-bind"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return orgcontract.ManagedBindResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return orgcontract.ManagedBindResponse{}, fmt.Errorf("orgclient.BindMachine: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		var out orgcontract.ManagedBindResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return orgcontract.ManagedBindResponse{}, fmt.Errorf("orgclient.BindMachine: decode: %w", err)
		}
		return out, nil
	case http.StatusConflict:
		// enforce posture: the machine is bound elsewhere. Enrolment stands; the
		// binding was refused and (server-side) audited.
		return orgcontract.ManagedBindResponse{Status: orgcontract.ManagedBindCollision, Collision: true}, ErrManagedBindRefused
	case http.StatusNotFound:
		// Older server without the route — treat like "no managed binding".
		return orgcontract.ManagedBindResponse{Status: ManagedBindUnavailable}, nil
	case http.StatusForbidden:
		return orgcontract.ManagedBindResponse{}, ErrManagedBindNotManagedHere
	default:
		return orgcontract.ManagedBindResponse{}, fmt.Errorf("orgclient.BindMachine: server returned %d", resp.StatusCode)
	}
}
