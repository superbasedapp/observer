package cloudgateway

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// orgs.go is organization discovery on the BOOTSTRAP lane (managed SaaS plan
// 06 section 19.3 rows 7-9, plan 07 M8.7, design decision D-IND-2): the two
// calls `observer connect` makes when it is given no server address and no
// company pre-set.
//
// They are ungated by design, like sign-in itself: the user's own typed
// `observer connect` (or the dashboard Connect card's confirmed click) is the
// authorization (R2 disposition F10), and they send no session-derived data,
// only the device's own authenticated request. They are never called by a
// daemon loop, and never when a server address or a company pre-set is given,
// so an air-gapped private enrolment never touches them (rule 4). The lane
// rows in tests/invariant/egress_lanes_test.go (cloud.client, cloud.gateway)
// name them; docs/security.md ledger row IND-2.

// BootstrapListOrgs lists the orgs the signed-in account belongs to (GET
// /v1/orgs), personal first. The answer is validated against the shared wire
// contract; an invalid one is refused. Needs no consent grant: it is the
// user's own connect action, as for sign-in.
func (g *Gateway) BootstrapListOrgs(ctx context.Context) (cloudcontract.DeviceOrgList, error) {
	c, err := g.network()
	if err != nil {
		return cloudcontract.DeviceOrgList{}, err
	}
	return c.ListOrgs(ctx)
}

// BootstrapEnsurePersonalOrg returns the account's personal org, creating it
// lazily (POST /v1/orgs/personal:ensure). Idempotent server-side; an answer
// that is not a valid personal org is refused. Needs no consent grant: it is
// the user's own connect action, as for sign-in.
func (g *Gateway) BootstrapEnsurePersonalOrg(ctx context.Context) (cloudcontract.EnsurePersonalOrgResponse, error) {
	c, err := g.network()
	if err != nil {
		return cloudcontract.EnsurePersonalOrgResponse{}, err
	}
	return c.EnsurePersonalOrg(ctx)
}
