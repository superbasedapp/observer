package update

import "strings"

// skew.go is the version-skew decision layer of enterprise update management
// (docs/plans/enterprise-update-management-plan-2026-09-07.md §4 W5, ruling R3
// and open decision O5).
//
// It is PURE, like everything else in this package: an org server calls
// [EvaluateSkew] at the ingest boundary to decide whether a node's push is
// accepted-and-flagged or refused with a 426, and the fleet board calls
// [MinorDistance] to decide whether the skew banner has anything to say. No
// SQL, no HTTP, no clock — the same decision runs in a table-driven test.
//
// Two properties are load-bearing and are asserted by skew_test.go:
//
//   - An EMPTY MinVersion is today's behaviour, byte for byte. The feature
//     cannot change what a server does until an operator names a floor.
//   - A version this package cannot ORDER is never refused. A dev build, an
//     empty string and a malformed version are all "unknown", and refusing an
//     unknown strands a node the admin cannot even see the version of — the
//     precise failure mode O5 warns about, since a package-manager-owned
//     binary has no automatic remediation.

// SkewAction is what a server does with a push from a node below the floor.
// A closed vocabulary, so a typo in the TOML is a validation error rather than
// a silently permissive server.
type SkewAction string

const (
	// SkewActionWarn accepts the push and flags the node on the board. The
	// DEFAULT (O5): a refused node's sessions stop reaching the org entirely,
	// which is worst for exactly the nodes that cannot fix themselves.
	SkewActionWarn SkewAction = "warn"
	// SkewActionRefuse answers 426 Upgrade Required and ingests nothing.
	SkewActionRefuse SkewAction = "refuse"
)

// RefusalReasonAgentTooOld is the machine-readable `reason` a refused push
// receives. It is part of the wire contract: a node matches on this string to
// tell "your org requires a newer agent" apart from every other 4xx.
const RefusalReasonAgentTooOld = "agent_too_old"

// KnownSkewAction reports whether a is a value this server implements.
func KnownSkewAction(a SkewAction) bool {
	switch a {
	case SkewActionWarn, SkewActionRefuse:
		return true
	default:
		return false
	}
}

// DefaultMaxSkewMinors is how many MINOR releases a fleet may span before the
// board raises the skew banner.
//
// Two is the smallest number that is not noise: a fleet mid-rollout always
// spans at least one minor (the ring's baseline and its target), so a
// threshold of one would light the banner on every healthy rollout.
const DefaultMaxSkewMinors = 2

// SkewPolicy is the org server's [server].min_agent_version trio.
type SkewPolicy struct {
	// MinVersion is the floor, e.g. "v1.30.0". EMPTY DISABLES THE FEATURE.
	MinVersion string
	// Action is warn (default) or refuse.
	Action SkewAction
	// MaxSkewMinors bounds how far apart the fleet's oldest and newest agents
	// may be before the board says so. <= 0 uses DefaultMaxSkewMinors.
	MaxSkewMinors int
}

// Configured reports whether an operator has named a floor. When false every
// verdict is Allow and no surface renders a skew control — the honest
// disabled-copy discipline rather than a green "compliant" badge over a
// question nobody asked.
func (p SkewPolicy) Configured() bool { return strings.TrimSpace(p.MinVersion) != "" }

// EffectiveAction resolves the action, defaulting to warn. An UNKNOWN action
// resolves to warn too: config validation refuses it at authoring time, and if
// one ever reached a running server the safe reading of an unrecognised value
// is the less destructive one.
func (p SkewPolicy) EffectiveAction() SkewAction {
	if p.Action == SkewActionRefuse {
		return SkewActionRefuse
	}
	return SkewActionWarn
}

// EffectiveMaxSkewMinors resolves the banner threshold.
func (p SkewPolicy) EffectiveMaxSkewMinors() int {
	if p.MaxSkewMinors > 0 {
		return p.MaxSkewMinors
	}
	return DefaultMaxSkewMinors
}

// SkewVerdict is one node's standing against the policy.
type SkewVerdict struct {
	// BelowMin is true when the node's version is strictly below the floor.
	BelowMin bool
	// Refuse is true only when BelowMin AND the action is refuse. It is the
	// single boolean the ingest boundary branches on.
	Refuse bool
	// UnknownVersion is true when the node's version could not be ordered
	// (absent, a dev build, or malformed). Such a node is never refused; the
	// board shows it as unknown rather than as compliant.
	UnknownVersion bool
	// MinVersion and Version are echoed so the 426 body and the board row can
	// name both sides without re-reading the policy.
	MinVersion string
	Version    string
	// Rule names the table row that decided, so a surface can explain the
	// verdict instead of asserting it.
	Rule string
}

// skewRule is one row of the decision table. Rows are evaluated top-down and
// the first match wins; the ORDER is the specification (CLAUDE.md #5).
type skewRule struct {
	name    string
	matches func(p SkewPolicy, version string) bool
	verdict func(v *SkewVerdict)
}

// skewRules is the ordered decision table.
var skewRules = []skewRule{
	{
		// No floor named: the feature is inert and the server behaves exactly
		// as it did before this shipped. Acceptance 12's first clause.
		name:    "no-floor-configured",
		matches: func(p SkewPolicy, _ string) bool { return !p.Configured() },
		verdict: func(*SkewVerdict) {},
	},
	{
		// A dev build has no position in the ordering (semver.go's own rule),
		// so it is neither compliant nor behind. Never refused.
		name:    "dev-build",
		matches: func(_ SkewPolicy, version string) bool { return IsDevBuild(strings.TrimSpace(version)) },
		verdict: func(v *SkewVerdict) { v.UnknownVersion = true },
	},
	{
		// Unorderable on either side. Refusing here would strand a node over
		// a comparison that never happened.
		name: "unorderable",
		matches: func(p SkewPolicy, version string) bool {
			_, ok := CompareSemver(strings.TrimSpace(version), strings.TrimSpace(p.MinVersion))
			return !ok
		},
		verdict: func(v *SkewVerdict) { v.UnknownVersion = true },
	},
	{
		name: "below-floor",
		matches: func(p SkewPolicy, version string) bool {
			cmp, ok := CompareSemver(strings.TrimSpace(version), strings.TrimSpace(p.MinVersion))
			return ok && cmp < 0
		},
		verdict: func(v *SkewVerdict) { v.BelowMin = true },
	},
}

// EvaluateSkew judges one node's reported version against the policy.
//
// It is called at the ingest boundary BEFORE the ingest transaction opens, so
// a refusal ingests nothing at all — a partially-ingested refused push would
// be the worst of both answers.
func EvaluateSkew(p SkewPolicy, version string) SkewVerdict {
	v := SkewVerdict{
		MinVersion: strings.TrimSpace(p.MinVersion),
		Version:    strings.TrimSpace(version),
		Rule:       "compliant",
	}
	for _, r := range skewRules {
		if !r.matches(p, version) {
			continue
		}
		v.Rule = r.name
		r.verdict(&v)
		break
	}
	v.Refuse = v.BelowMin && p.EffectiveAction() == SkewActionRefuse
	return v
}

// MinorDistance returns how many MINOR releases separate two versions, and
// whether both could be ordered.
//
// A major bump counts as a large jump rather than as zero minors: the ordinal
// is Major*1000 + Minor, so 1.9.0 -> 2.0.0 is not "one minor closer than"
// 1.9.0 -> 1.10.0. 1000 is a bound no real minor series approaches, and the
// number is only ever compared against a small threshold.
//
// The result is the ABSOLUTE distance, so callers need not order the pair.
func MinorDistance(a, b string) (int, bool) {
	pa, oka := ParseSemver(a)
	pb, okb := ParseSemver(b)
	if !oka || !okb {
		return 0, false
	}
	d := (pa.Major*1000 + pa.Minor) - (pb.Major*1000 + pb.Minor)
	if d < 0 {
		d = -d
	}
	return d, true
}
