package policy

// Posture rules (spec §5.4, §13) — risky client-configuration states.
// G11 ships R-204 (native deny-rule drift, the §13.2 compile moat's
// detection half); G13 ships R-205 as the integrity-failure row, its
// first signal being an org policy bundle that failed signature/pin
// verification (§14.2 — the §5.4 hook-integrity signal joins the same
// row as another finding kind when that machinery promotes to guard
// events). R-201/R-202/R-203 stay unbuilt until their posture signals
// exist as data (session metadata capture for yolo flags and sandbox
// state) — recorded in the spec §22 tracker, never silently stubbed.
//
// R-204 follows the MCPFindings evaluation shape exactly: the drift
// computation lives at the owner (the cmd-layer dialect runner, which
// holds the compiled-entry tables via internal/guard/compile and the
// pin state via the store) and is stamped onto a KindConfigChange
// event as a PostureFinding. This package only matches on the stamped
// finding — it never reads native client configs itself (§17.1
// purity). The row is flag-in-both-modes: the drift scan observes
// config state after the fact, so there is nothing to block; the
// remediation surface is `observer guard compile`.

// PostureFinding kind vocabulary (PostureFinding.Kind values). Stable
// strings — they appear in verdict reasons and tests.
const (
	// PostureFindingDialectDrift fires R-204: a compiled native
	// guard-rule artifact (spec §13.2) no longer matches the effective
	// policy — entries the compiler would emit are missing from the
	// client's native config.
	PostureFindingDialectDrift = "dialect_drift"
	// PostureFindingBundleSignature fires R-205: an org policy bundle
	// failed integrity verification at the fetch seam (bad/missing
	// Ed25519 signature, public key not matching the enrolment pin, or
	// a version regression — spec §14.2) and was REJECTED. The
	// rejection itself is the enforcement; this row makes it auditable
	// and alertable. Client carries "org" (the subject is the org
	// server channel, not an AI client); Target is the bundle URL.
	PostureFindingBundleSignature = "bundle_signature"
)

// PostureFinding is one posture finding stamped onto an Event by the
// guard composition layer (the §13.2 dialect drift check today; later
// posture rows reuse the shape). It carries no config content —
// Client/Target name the subject, Detail is a bounded human-readable
// description for the verdict reason.
type PostureFinding struct {
	// Kind is one of the PostureFindingXxx constants.
	Kind string
	// Client is the AI client whose posture the finding concerns.
	Client string
	// Target is the native config file path the finding concerns.
	Target string
	// Detail is a bounded human-readable specifics string.
	Detail string
}

// matchPostureFinding builds an event-scoped matcher that hits when
// the stamped findings carry the given kind. The guard layer emits
// one event per finding, so a verdict's reason names exactly one
// subject (the matchMCPFinding contract).
func matchPostureFinding(kind string) MatchFn {
	return func(ctx *MatchContext) (bool, string) {
		for i := range ctx.Event.PostureFindings {
			f := &ctx.Event.PostureFindings[i]
			if f.Kind != kind {
				continue
			}
			detail := "client " + f.Client
			if f.Target != "" {
				detail += " (" + f.Target + ")"
			}
			if f.Detail != "" {
				detail += ": " + f.Detail
			}
			return true, detail
		}
		return false, ""
	}
}

// postureRules assembles the §5.4 table rows in catalog order (R-204
// + R-205 until the remaining posture signals exist). Both rows are
// flag-in-both-modes: posture scans observe state after the fact —
// R-204's remediation is `observer guard compile`, and R-205's
// enforcement already happened at the fetch seam (the bad bundle was
// rejected before any rule from it could load).
func postureRules() []Rule {
	cfgScan := []EventKind{KindConfigChange}
	return []Rule{
		{
			ID: "R-204", Category: CategoryPosture, Severity: SeverityHigh,
			AppliesTo: cfgScan, Match: matchPostureFinding(PostureFindingDialectDrift),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "compiled native guard rules drifted from the effective policy",
			Advice: "Inspect the divergence with Check for drift, then re-sync the client's native rules with Write native rules (Observer dashboard Security > Rules, Apply policy changes), or run `observer guard compile --diff` then `observer guard compile`.",
		},
		{
			ID: "R-205", Category: CategoryPosture, Severity: SeverityHigh,
			AppliesTo: cfgScan, Match: matchPostureFinding(PostureFindingBundleSignature),
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "org policy bundle failed integrity verification and was rejected",
			Advice: "Verify the org server's policy signing key with your org admin; if the key legitimately rotated, re-enrol (`observer enroll`) to pin the new key. The agent keeps running on its previous policy.",
		},
	}
}
