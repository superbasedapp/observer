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

// ErrManagedIntegrityUnbound mirrors ErrManagedBindRefused's precedent: the
// server's ownership guard (managed_integrity.go::ManagedIntegrity, the
// `!bound || binding.UserID != userID` branch) returns 409 whenever this
// managed node's one-time P6a BindMachine step never completed or no longer
// matches. It is a firm, already-audited server-side notice (the server
// writes a managed_node_collision audit row on every occurrence), not a
// transient failure — so the caller should treat it as expected and not
// re-log it every push cycle until an admin re-binds the machine.
var ErrManagedIntegrityUnbound = errors.New("managed integrity report refused: machine is not bound to this node")

// ReportIntegrity performs the Arc 4 P6b managed-integrity probe report (plan
// §9): it presents this host's org-salted machine fingerprint plus coarse
// tamper-EVIDENCE labels (sibling-observer origins + drifted AI-tool names) so
// the admin Control Center can surface circumvention on the node's health. The
// counts are len(siblingLabels) / len(driftedTools); only labels cross the wire
// (no paths/usernames/config values — the §9 content-floor).
//
// Called ONLY under managed tenancy (the caller gates on enr.IsManaged()); an
// individual/BYO node never runs the probe, so the individual plane sends no
// integrity signal at all — the same by-construction guarantee as BindMachine.
//
// Best-effort by design: a host with no stable machine source (empty
// fingerprint) skips the call (nothing to correlate); an older server without
// the route (404) is a no-op; an unbound managed node (409) returns the named
// ErrManagedIntegrityUnbound sentinel rather than a generic error. None of
// these are failures the caller must act on beyond deciding how to log them.
func (c *Client) ReportIntegrity(ctx context.Context, report orgcontract.ManagedIntegrityReport) (orgcontract.ManagedIntegrityResponse, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return orgcontract.ManagedIntegrityResponse{}, fmt.Errorf("orgclient.ReportIntegrity: enrolment: %w", err)
	}
	if enr == nil {
		return orgcontract.ManagedIntegrityResponse{}, ErrNotEnrolled
	}

	mid, err := machineid.ForOrg(enr.OrgID)
	if err != nil {
		return orgcontract.ManagedIntegrityResponse{}, fmt.Errorf("orgclient.ReportIntegrity: machine id: %w", err)
	}
	if mid == "" {
		// No stable machine identity — nothing to correlate to a managed_node.
		return orgcontract.ManagedIntegrityResponse{}, nil
	}

	report.MachineIdentity = mid
	report = report.NormalizeLabels()
	if report.SiblingObservers < 0 {
		report.SiblingObservers = 0
	}
	if report.RouteDrift < 0 {
		report.RouteDrift = 0
	}
	body, err := json.Marshal(report)
	if err != nil {
		return orgcontract.ManagedIntegrityResponse{}, fmt.Errorf("orgclient.ReportIntegrity: marshal: %w", err)
	}

	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return orgcontract.ManagedIntegrityResponse{}, fmt.Errorf("orgclient.ReportIntegrity: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/managed-integrity"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return orgcontract.ManagedIntegrityResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return orgcontract.ManagedIntegrityResponse{}, fmt.Errorf("orgclient.ReportIntegrity: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		var out orgcontract.ManagedIntegrityResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return orgcontract.ManagedIntegrityResponse{}, fmt.Errorf("orgclient.ReportIntegrity: decode: %w", err)
		}
		return out, nil
	case http.StatusNotFound:
		// Older server without the route — treat as a no-op.
		return orgcontract.ManagedIntegrityResponse{}, nil
	case http.StatusConflict:
		// Not bound — a firm, already-audited notice, not a transient
		// failure. See ErrManagedIntegrityUnbound.
		return orgcontract.ManagedIntegrityResponse{}, ErrManagedIntegrityUnbound
	default:
		return orgcontract.ManagedIntegrityResponse{}, fmt.Errorf("orgclient.ReportIntegrity: server returned %d", resp.StatusCode)
	}
}
