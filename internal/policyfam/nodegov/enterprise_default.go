package nodegov

import "fmt"

// The DEFAULT node.governance body an org running the `enterprise` product
// posture publishes to its managed fleet (org-observer fundamentals plan
// 2026-09-13, ruling R3).
//
// WHY IT EXISTS. The org could already pin `guard.budget.from_org` and
// `guard.budget.hard` through this family, and could already raise the
// reporting tiers its grant authorizes — but nothing ever emitted such a body,
// so every enterprise fleet ran on the INDIVIDUAL defaults: `from_org` false,
// the org's signed budget fetched every cycle and discarded, and the coverage
// table telling an admin their cap was enforced by nobody. A capability no
// surface ever exercises is indistinguishable from a missing one.
//
// WHAT IT IS NOT. It is not a second enforcement mechanism and it is not a
// server-side override: it produces a BODY, which is published as an ordinary
// signed policy resource, compiled through the same vocabulary as an
// admin-authored one, and applied by the node through the same accept path
// with the same lowering-only algebra. The caller publishes it ONLY when the
// org has no node.governance resource of its own — an admin-authored body is
// never overwritten by a default.
//
// It lives in this package, not in the org server, for the reason every other
// table here does: the pin and share keys are a closed vocabulary this package
// owns, and a default body assembled anywhere else could name a key the
// compiler would then reject at publish time — a failure the org would
// discover in production rather than in this package's tests.

// EnterpriseDefaultInput is what the caller knows and this package does not.
type EnterpriseDefaultInput struct {
	// GrantedAuthority is the authority token set the enrolment actually
	// offers (govern.EnterpriseAuthoritySet on the posture-flip path). Only
	// the reporting tiers it authorizes are turned on: a share pin the grant
	// does not back would be a directive the node is right to refuse, and
	// publishing one would make the org's own body the thing that looks
	// broken.
	//
	// Authority tokens are compared as opaque strings. This package must not
	// import internal/govern (the resolver depends on THIS package, never the
	// reverse — see imports_test.go), so the tokens are named as literals in
	// enterpriseDefaultShares and checked against govern's own constants by
	// that package's tests.
	GrantedAuthority []string
	// ExtraPins are additional pinned keys the caller owns the definition of
	// — today the enterprise GUARD defaults
	// (internal/orgserver/posture.EnterpriseGuardDefaultsBody: guard.enabled,
	// guard.mode, guard.strict), which have a single owner over there and must
	// not be restated here. They are merged UNDER the budget pins below: a
	// caller cannot accidentally unset the two keys this helper exists to set.
	ExtraPins map[string]any
}

// enterpriseDefaultPin is one row of the default `pinned` block.
type enterpriseDefaultPin struct {
	Key   string
	Value any
	// Why is documentation, not wire: it explains the row to the next reader
	// and is asserted by the table test so a row can never be added without
	// one.
	Why string
}

// enterpriseDefaultPins is the settings.pin half of the default body. Both
// rows are PinnableKeys entries (TestEnterpriseDefaultBodyCompiles walks the
// produced body through the real compiler, so a key that left the vocabulary
// fails here rather than at an org's publish).
var enterpriseDefaultPins = []enterpriseDefaultPin{
	{
		Key: "guard.budget.from_org", Value: true,
		Why: "the node applies the organization's budget at all — with this false, " +
			"the signed per-caller body is fetched every push cycle and thrown away",
	},
	{
		Key: "guard.budget.hard", Value: true,
		Why: "a breach BLOCKS rather than flags. DirRestrictiveOnly, so this is the " +
			"only value the org may pin and a node that already blocks is unaffected",
	},
}

// enterpriseDefaultShare is one row of the default `share` block: a share key
// and the extraction authority that must be present for turning it on to be
// honest.
type enterpriseDefaultShare struct {
	Key       string
	Authority string
	Why       string
}

// enterpriseDefaultShares is the capture.pin half.
//
// WHAT IS DELIBERATELY ABSENT: every CONTENT-bearing tier — full_content,
// full_tool_bodies, the obs.* span bodies. The enterprise posture may well
// want them, and its grant authorizes them, but a DEFAULT body is the wrong
// instrument for a decision an admin should make deliberately and disclose to
// their developers. This table is the reporting floor that makes the org's own
// surfaces work; raising content collection stays an authored act.
//
// `admin_managed` is structurally absent from the pin vocabulary entirely
// (BootstrapEnvelopeKeys) and could not be named here even if it were wanted.
var enterpriseDefaultShares = []enterpriseDefaultShare{
	{
		Key: "routing_summary", Authority: "extract.routing",
		Why: "the per-day routing rollup, with no models and no content. Without it " +
			"the org's Routing surfaces are empty on an enterprise fleet",
	},
	{
		Key: "policy_state", Authority: "extract.policy_state",
		Why: "the node's effective-policy-state report: whether the org's own " +
			"directives actually landed. An org that cannot see this is governing blind",
	},
	{
		Key: "limit_gauge", Authority: "extract.predictions",
		Why: "the provider 5h/weekly usage-window gauge — quota headroom, not content",
	},
	{
		Key: "task_detail", Authority: "extract.tasks",
		Why: "task tracking counts",
	},
	{
		Key: "tool_account_detail", Authority: "extract.tool_accounts",
		Why: "which vendor account a tool is logged in as — the licence-compliance read",
	},
}

// authorityUmbrella is the legacy alias that stands in for every per-tier
// extraction token (govern.AuthorityExtractManaged). A grant carrying it
// authorizes each tier below, exactly as govern's own per-tier predicates
// treat it.
const authorityUmbrella = "extract.managed"

// EnterpriseDefaultBody assembles the default body and returns it together
// with the CANONICAL bytes a caller publishes.
//
// The bytes come back from CanonicalJSON, which compiles the body on the way
// through, so this function cannot hand back something the publish lint would
// reject: an unpinnable key, a value outside an enum, or a share key pinned in
// the wrong direction is an error HERE, in one place, rather than a 400 an
// admin sees while flipping their posture.
//
// A grant that authorizes none of the reporting tiers still produces a valid
// body — the budget pins are unconditional, because they are the point.
func EnterpriseDefaultBody(in EnterpriseDefaultInput) (Body, []byte, error) {
	granted := make(map[string]bool, len(in.GrantedAuthority)+1)
	for _, a := range in.GrantedAuthority {
		granted[a] = true
	}

	pinned := make(map[string]any, len(in.ExtraPins)+len(enterpriseDefaultPins))
	for k, v := range in.ExtraPins {
		pinned[k] = v
	}
	for _, p := range enterpriseDefaultPins {
		pinned[p.Key] = p.Value
	}

	var share map[string]any
	for _, s := range enterpriseDefaultShares {
		if !granted[s.Authority] && !granted[authorityUmbrella] {
			continue
		}
		if share == nil {
			share = make(map[string]any, len(enterpriseDefaultShares))
		}
		share[s.Key] = true
	}

	body := Body{Schema: MaxSchema, Pinned: pinned, Share: share}
	raw, err := CanonicalJSON(body)
	if err != nil {
		return Body{}, nil, fmt.Errorf("policyfam/nodegov.EnterpriseDefaultBody: %w", err)
	}
	return body, raw, nil
}

// EnterpriseDefaultDescription is the `description` a published default body
// carries, so an admin reading the policy-resource list can tell the org's
// automatic starting point from something a person wrote.
const EnterpriseDefaultDescription = "Default enterprise node governance (published automatically on the " +
	"posture flip because this organization had none; edit or replace it like any other policy resource)"
