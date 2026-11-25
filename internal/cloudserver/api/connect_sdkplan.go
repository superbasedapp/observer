package api

import (
	"context"
	"errors"
	"net/url"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// connect_sdkplan.go decides, for the SDK key approval page, whether a
// dashboard's plan includes AI Apps (the SDK quickstart plan section 3.6 and
// ruling R14): a team whose plan does not is listed but disabled, with the
// plan refusal's message and link, so a person rarely approves a key its
// host would refuse (the host still refuses: 403 plan_required at the
// redeem). The entitlement read is the one the cloud issued last (it is the
// issuer, so it needs no signature check), else the kind's floor.

// sdkPlanVerdict is whether an org's plan admits AI Apps ingest, and how a
// refusal reads.
type sdkPlanVerdict struct {
	// Refused is true when the plan does not include AI Apps, or includes it
	// with no allowance.
	Refused bool
	// Message is the refusal for people ("" when not refused).
	Message string
	// UpgradeURL is where the billing owner changes the plan.
	UpgradeURL string
}

// sdkPlanVerdictFn decides from the org's entitlement in force.
// connect_sdkplan_refusal.go sets it at init to the org server's own refusal
// builder (internal/orgserver/gateway/planrefusal), so the page says exactly
// what the host's 403 plan_required says. The public tree has no such file
// (scripts/release.sh's import sweep drops a file importing
// internal/orgserver), and there this default answers from the entitlements
// catalog alone, in plainer words.
var sdkPlanVerdictFn = defaultSDKPlanVerdict

// defaultSDKPlanVerdict refuses when the plan does not list AI Apps ingest
// or allows 0 of it on either axis.
func defaultSDKPlanVerdict(e entitlements.Effective, consoleOrigin, orgID string) sdkPlanVerdict {
	zero := func(n entitlements.CapName) bool {
		l := e.Cap(n)
		return l.Set && !l.Unlimited && l.N == 0
	}
	if e.Has(entitlements.CapabilityPlaneAGateway) &&
		!zero(entitlements.CapPlaneAEventsMonthly) && !zero(entitlements.CapPlaneAGBMonthly) {
		return sdkPlanVerdict{}
	}
	upgrade := consoleOrigin + "/portal/orgs/" + url.PathEscape(orgID)
	return sdkPlanVerdict{
		Refused:    true,
		Message:    "This dashboard's plan does not include AI Apps. The organization's billing owner can change the plan at " + upgrade + ".",
		UpgradeURL: upgrade,
	}
}

// orgEntitlementInForce is the entitlement an org's host holds, as the
// caller (a member) may read it: the newest document the cloud issued for it
// (store.MyOrgEntitlementBody, through a view that answers only for the
// caller's own orgs), composed with its kind's floor (entitlements.Evaluate),
// or the floor alone when none was issued yet (a dashboard still being set
// up). A stored body that does not decode, or names another org or kind,
// counts as none (the host would refuse it the same).
func (s *Server) orgEntitlementInForce(ctx context.Context, accountID string, o store.MyOrg) (entitlements.Effective, error) {
	kind, _ := store.OrgEntitlementsKind(o.Kind)
	var doc *entitlements.Document
	version, raw, err := s.store.MyOrgEntitlementBody(ctx, accountID, o.OrgID)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return entitlements.Effective{}, err
	default:
		if body, derr := entitlements.Decode(raw); derr == nil && body.Org == o.OrgID && body.Kind == kind {
			doc = &entitlements.Document{Version: version, Body: body}
		}
	}
	return entitlements.Evaluate(kind, doc, s.now()), nil
}

// sdkPlanFor is the plan verdict of one of accountID's dashboards for an SDK
// key.
func (s *Server) sdkPlanFor(ctx context.Context, accountID string, o store.MyOrg) (sdkPlanVerdict, error) {
	e, err := s.orgEntitlementInForce(ctx, accountID, o)
	if err != nil {
		return sdkPlanVerdict{}, err
	}
	return sdkPlanVerdictFn(e, s.portalBaseURL, o.OrgID), nil
}
