package policyfam

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/egress"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodecomponents"
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

// familyRow is one row of the family table: a family's name and whether
// its compiler is linked only through the seam in linked.go (a family whose
// compiler belongs to an optional component). The NAME is known in every
// build, so a body of a family whose compiler a build omits NACKs with
// ErrFamilyNotLinked instead of being unknown.
type familyRow struct {
	Name       string
	LinkedOnly bool
}

// familyTable is the v1 closed family table, in a stable order. New families
// are appended last so an index into SupportedFamilies stays stable across
// releases for any caller that persisted one.
var familyTable = []familyRow{
	{Name: FamilyAdmissionInput},
	{Name: FamilyEgressGuardrail},
	{Name: FamilyGatewayProviders},
	{Name: FamilyNodeGovernance},
	{Name: FamilyNodeFeatures},
	{Name: FamilyPlaneBAdmission},
	{Name: FamilyMCPAccess, LinkedOnly: true},
	{Name: FamilyNodeComponents},
	// The two module families of the security and sandbox tracks (roadmap
	// F0-9). Both are linked-only: until the security lane (phase E) and
	// the sandbox lane (P1b) add their pair files, every body of either
	// family NACKs with ErrFamilyNotLinked.
	{Name: FamilySecurityScanning, LinkedOnly: true},
	{Name: FamilyTerminalsIsolation, LinkedOnly: true},
}

// SupportedFamilies is the v1 closed enum, in a stable order: familyTable's
// names.
var SupportedFamilies = func() []string {
	out := make([]string, len(familyTable))
	for i, r := range familyTable {
		out[i] = r.Name
	}
	return out
}()

// FamilySecurityScanning is the security module's scanner-floor family
// (security plan 4.9): raise-only floors, linked from a security pair file.
const FamilySecurityScanning = "security.scanning"

// FamilyTerminalsIsolation is the sandbox module's isolation-floor family
// (b9 v2 plan 8.2): raise-only floors, linked from a sandbox pair file.
const FamilyTerminalsIsolation = "terminals.isolation"

// IsLinkedOnlyFamily reports whether a supported family's compiler is linked
// only through the seam in linked.go.
func IsLinkedOnlyFamily(family string) bool {
	for _, r := range familyTable {
		if r.Name == family {
			return r.LinkedOnly
		}
	}
	return false
}

// FamilyNodeComponents is the managed component-set family `node.components`
// (modular packaging plan 6.2, lane MP-GOV): which components an
// org-managed node may run (allow / require / typed deny / unlisted inert).
// It applies only under a live managed grant carrying components.govern; see
// internal/policyfam/nodecomponents.
const FamilyNodeComponents = nodecomponents.Family

// FamilyPlaneBAdmission is the Plane-B judged-admission body (design §4.6,
// gap register G1-JUDGED-ADM): the inner admission spec + the gateway judge
// route + the default-OFF node-lane flip. See internal/policyfam/planebadmission.
const FamilyPlaneBAdmission = planebadmission.Family

// FamilyMCPAccess is the Agent Access grant family `tools.mcp_access`
// (docs/plans/agent-access-implementation-plan-2026-09-23.md §11.4 W2b,
// D10): the registry view + grant rows that internal/mcpaccess compiles
// into the agentgateway mcpAuthorization CEL, the node decision table, the
// AuthZEN function and the PDP fast path. See internal/policyfam/mcpaccess.
// Its compiler is an optional component's (Agent Access), so it is linked
// through the seam in linked.go (family_mcpaccess.go) rather than imported
// here; the literal equals mcpaccess.Family, which the pair registers under.
const FamilyMCPAccess = "tools.mcp_access"

// IsSupportedFamily reports whether family is one of the v1 closed set.
func IsSupportedFamily(family string) bool {
	for _, r := range familyTable {
		if r.Name == family {
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
		// LENIENT on this, the agent accept path: a section id this build
		// does not know is dropped with a note (PolicySpec.IgnoredIDs)
		// rather than failing the body, so a newer org server naming a newer
		// page cannot stop every other directive reaching this node. The
		// publish lint compiles strictly (nodegov.CompileBody).
		s, canon, cerr := nodegov.CompileBodyLenient(raw, maxBytes)
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
	case FamilyNodeComponents:
		// LENIENT on this, the agent accept path (the node.governance
		// precedent): an exact component id this build does not know is
		// dropped into PolicySpec.IgnoredIDs, so a newer org server naming a
		// newer component cannot stop every other directive reaching an
		// older node. The publish path compiles strictly
		// (nodecomponents.CompileBody).
		s, canon, cerr := nodecomponents.CompileBodyLenient(raw, maxBytes)
		if cerr != nil {
			return nil, nil, cerr
		}
		return s, canon, nil
	default:
		// Every linked-only family (tools.mcp_access, security.scanning,
		// terminals.isolation) compiles through the seam (linked.go):
		// ErrFamilyNotLinked in a build without its compiler.
		if IsLinkedOnlyFamily(family) {
			return compileLinked(family, raw, maxBytes)
		}
		return nil, nil, fmt.Errorf("policyfam.CompileFamilyBody: unsupported family %q", family)
	}
}

// IgnoredDirectives returns the directives the agent's lenient compile
// dropped from a body because this build does not know them (as
// "<list>:<id>"), for the accept path to log. Empty for every family that
// compiles strictly.
func IgnoredDirectives(family string, spec any) []string {
	switch family {
	case FamilyNodeGovernance:
		if s, ok := spec.(nodegov.PolicySpec); ok {
			return s.IgnoredIDs
		}
	case FamilyNodeComponents:
		if s, ok := spec.(nodecomponents.PolicySpec); ok {
			return s.IgnoredIDs
		}
	}
	return nil
}

// IsServeTimeProjection reports whether held (the body a node holds at a
// version) is the server's vocabulary projection of served (a body delivered
// at the SAME version). That is the one equal-version, different-bytes
// delivery that is not a replay: the server stripped ids an older build did
// not know, the node upgraded and advertised the newer vocabulary, and is now
// served the full body. Only node.governance projects; every other family
// answers false, so its replay rule is unchanged.
func IsServeTimeProjection(family string, served, held []byte, maxBytes int64) bool {
	if family != FamilyNodeGovernance {
		return false
	}
	full, err := nodegov.DecodeBody(served, maxBytes)
	if err != nil {
		return false
	}
	prior, err := nodegov.DecodeBody(held, maxBytes)
	if err != nil {
		return false
	}
	return nodegov.IsVocabProjection(full, prior)
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
	case FamilyNodeComponents:
		// node.components has no mode field: blocking or requiring a
		// component changes what the node runs the moment it resolves, so
		// it needs the node's preauthorize_enforce consent exactly like
		// node.features (a managed enrolment holding components.govern
		// writes both lists).
		_ = spec.(nodecomponents.PolicySpec) //nolint:forcetypeassert // caller contract: spec came from CompileFamilyBody(family, ...)
		return true
	default:
		if IsLinkedOnlyFamily(family) {
			return linkedEnforces(family, spec)
		}
		panic(fmt.Sprintf("policyfam.SpecRequestsEnforceMode: unsupported family %q", family))
	}
}
