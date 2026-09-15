package policyfam

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/egress"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/policyfam/planebadmission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/providers"
)

// Family identifiers for the v1 unified policy resource (design doc §3;
// docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md). This is the
// CLOSED set every publish/accept path validates a SignedPolicyResource.Family
// against. These are the SAME two literal strings
// internal/policystate/collector.go's FamilyAdmissionInput /
// FamilyEgressGuardrail constants carry — duplicated here as untyped string
// constants (rather than importing policystate) so this package's dependency
// graph stays exactly {admission, egress}: policystate is a P0-6 REPORTING
// concern, this is a COMPILER/dispatch concern, and a caller of one should
// never be forced to pull in the other.
const (
	FamilyAdmissionInput  = "admission.input"
	FamilyEgressGuardrail = "egress.routing_guardrail"
	// FamilyGatewayProviders is the Phase 3 dashboard-managed proxy lane
	// table (docs/plans/gateway-config-plane-spec-2026-08-15.md Phase 3).
	// Unlike the two families above it has no internal/obs evaluation
	// counterpart to mirror; it compiles straight into
	// internal/policyfam/providers.PolicySpec for the cmd/observer install
	// seam to apply to internal/proxy.Proxy.SetLaneTable.
	FamilyGatewayProviders = "gateway.providers"
	// FamilyNodeGovernance is the admin-controlled Plane-B node governance
	// family (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §3.1,
	// Phase 1a). Named node.* rather than planeb.* to match the existing
	// <subject>.<aspect> convention (the thing governed is the NODE's own
	// surface), leaving room for a later node.retention / node.telemetry.
	// It compiles into internal/policyfam/nodegov.PolicySpec, which
	// cmd/observer intersects with the machine's enrolment GRANT
	// (internal/govern) before anything is applied.
	FamilyNodeGovernance = "node.governance"
	// FamilyNodeFeatures is the org-parity W5.1 per-feature enable/disable
	// + limits family (docs/plans/org-parity-full-depth-plan-2026-08-24.md
	// §4 "W5.1"): the org DECIDES whether a dev's node may use embedded
	// terminals / remote / routing-apply / patterns-write, and with what
	// limits. It compiles into internal/policyfam/nodefeatures.PolicySpec,
	// which cmd/observer's four enforcement seams consult directly — there
	// is no grant-intersection with internal/govern (unlike
	// FamilyNodeGovernance) and no live-lane apply (unlike
	// FamilyGatewayProviders): the compiled spec is only ever READ at the
	// moment of a local action, never pushed into a running subsystem.
	FamilyNodeFeatures = "node.features"
)

// SupportedFamilies is the v1 closed enum, in a stable order. New families
// are appended last so an index into this slice stays stable across
// releases for any caller that persisted one.
var SupportedFamilies = []string{FamilyAdmissionInput, FamilyEgressGuardrail, FamilyGatewayProviders, FamilyNodeGovernance, FamilyNodeFeatures, FamilyPlaneBAdmission}

// FamilyPlaneBAdmission is the Plane-B judged-admission body (design §4.6,
// gap register G1-JUDGED-ADM): the inner admission spec + the gateway judge
// route + the default-OFF node-lane flip. See internal/policyfam/planebadmission.
const FamilyPlaneBAdmission = planebadmission.Family

// IsSupportedFamily reports whether family is one of the v1 closed set.
func IsSupportedFamily(family string) bool {
	for _, f := range SupportedFamilies {
		if f == family {
			return true
		}
	}
	return false
}

// CompileFamilyBody dispatches raw org-wire JSON to the correct family
// compiler by name, returning the compiled spec (as an `any` — callers
// downcast to admission.PolicySpec / egress.PolicySpec, or use
// SpecRequestsEnforce below for the one cross-family property the agent's
// accept gate needs generically) and the canonical body bytes to sign/hash.
// An unsupported family is a hard error so a malformed publish/accept never
// silently no-ops.
func CompileFamilyBody(family string, raw []byte, maxBytes int64) (spec any, canonicalBody []byte, err error) {
	switch family {
	case FamilyAdmissionInput:
		s, canon, cerr := admission.CompileBody(raw, maxBytes)
		if cerr != nil {
			return nil, nil, cerr
		}
		return s, canon, nil
	case FamilyEgressGuardrail:
		s, canon, cerr := egress.CompileBody(raw, maxBytes)
		if cerr != nil {
			return nil, nil, cerr
		}
		return s, canon, nil
	case FamilyGatewayProviders:
		s, canon, cerr := providers.CompileBody(raw, maxBytes)
		if cerr != nil {
			return nil, nil, cerr
		}
		return s, canon, nil
	case FamilyNodeGovernance:
		s, canon, cerr := nodegov.CompileBody(raw, maxBytes)
		if cerr != nil {
			return nil, nil, cerr
		}
		return s, canon, nil
	case FamilyNodeFeatures:
		s, canon, cerr := nodefeatures.CompileBody(raw, maxBytes)
		if cerr != nil {
			return nil, nil, cerr
		}
		return s, canon, nil
	case FamilyPlaneBAdmission:
		s, canon, cerr := planebadmission.CompileBody(raw, maxBytes)
		if cerr != nil {
			return nil, nil, cerr
		}
		return s, canon, nil
	default:
		return nil, nil, fmt.Errorf("policyfam.CompileFamilyBody: unsupported family %q", family)
	}
}

// SpecRequestsEnforceMode reports whether a compiled family spec (as
// returned by CompileFamilyBody) asks to run in its family's "enforce"
// posture. The agent's four-gate accept (plan §6.4) needs this ONE boolean,
// generically across families, to decide whether the preauthorize_enforce
// gate applies at all — a body in observe/advise/off mode never needs
// preauthorization. spec must be a value CompileFamilyBody actually
// returned for the matching family; any other type panics, since that is a
// caller bug (a family/spec mismatch), not a runtime condition to handle.
func SpecRequestsEnforceMode(family string, spec any) bool {
	switch family {
	case FamilyAdmissionInput:
		return spec.(admission.PolicySpec).Mode == admission.ModeEnforce //nolint:forcetypeassert // caller contract: spec came from CompileFamilyBody(family, ...)
	case FamilyEgressGuardrail:
		return spec.(egress.PolicySpec).Mode == egress.ModeEnforce //nolint:forcetypeassert // caller contract: spec came from CompileFamilyBody(family, ...)
	case FamilyGatewayProviders:
		// gateway.providers has no mode field at all — applying a remote
		// lane table always mutates live proxy routing the moment it is
		// accepted, unconditionally, so it unconditionally requires the
		// operator's preauthorize_enforce listing exactly as if every body
		// requested enforce mode. There is no "observe" posture for a lane
		// table: either the node's proxy routes through it or it doesn't.
		_ = spec.(providers.PolicySpec) //nolint:forcetypeassert // caller contract: spec came from CompileFamilyBody(family, ...)
		return true
	case FamilyNodeGovernance:
		// node.governance has no mode field either, and for the same
		// reason: hiding a page or locking a settings section always
		// mutates the node's live surface the moment it is accepted.
		// There is no "observe" posture for a hidden page. Note this is
		// the node's OWN preauthorize_enforce gate, which is INDEPENDENT
		// of (and additional to) the enrolment grant — a body must clear
		// both, and neither alone suffices (spec §1.3 Quote 6).
		_ = spec.(nodegov.PolicySpec) //nolint:forcetypeassert // caller contract: spec came from CompileFamilyBody(family, ...)
		return true
	case FamilyNodeFeatures:
		// node.features has no mode field either: disabling a local
		// capability always takes effect the moment the body is accepted —
		// there is no "observe" posture for "can this dev launch a
		// terminal right now." Same unconditional-enforce reasoning as
		// gateway.providers/node.governance above.
		_ = spec.(nodefeatures.PolicySpec) //nolint:forcetypeassert // caller contract: spec came from CompileFamilyBody(family, ...)
		return true
	case FamilyPlaneBAdmission:
		return planebadmission.Enforces(spec.(planebadmission.PolicySpec)) //nolint:forcetypeassert // caller contract: spec came from CompileFamilyBody(family, ...)
	default:
		panic(fmt.Sprintf("policyfam.SpecRequestsEnforceMode: unsupported family %q", family))
	}
}
