package openshellorg

import (
	"slices"
	"strings"
	"time"
)

// The gateway soundness table (g1-design.md section 7.1, lane G3). Each
// fact is marked api (the gateway's admin API reports it, and the sync reads
// it every interval) or deploy (only the rendered config shows it; the
// operator attests it once with `observer-org openshell attest <preflight
// receipt>`). The marks are G-L1's measured answer (receipts
// g-l-2026-11-03-b2, fact.api.* and fact.deploy_class): the admin API
// reports the gateway version, the compute drivers, the gateway settings
// (proposal approval mode and agent proposals) and the global policy
// revisions; the OIDC block, the roles and scope claims, the auth modes,
// bind mounts, driver config, telemetry and the image digests are deploy
// class.
//
// An api fact that is unsound refuses every mint (T8). A deploy fact is
// sound only while the attestation stands: the gateway reports its settings
// revision, and a change of it after the attestation marks the attestation
// stale and refuses mints until it is re-attested.

// FactClass is api or deploy.
type FactClass string

// The fact classes.
const (
	FactAPI    FactClass = "api"
	FactDeploy FactClass = "deploy"
)

// FactID names one soundness fact.
type FactID string

// The closed fact set.
const (
	FactReachable       FactID = "gateway_reachable"
	FactVersionTested   FactID = "version_tested"
	FactVersionDeclared FactID = "version_declared"
	FactDockerDriver    FactID = "docker_driver"
	FactProposalsOff    FactID = "agent_proposals_off"
	FactApprovalManual  FactID = "proposal_approval_manual"
	FactNoGlobalPolicy  FactID = "no_global_policy"
	// The deploy class, attested from the rendered config's digest.
	FactOIDC            FactID = "oidc_issuer_audience"
	FactRolesScope      FactID = "roles_and_scope_enforced"
	FactAuthModesOff    FactID = "mtls_unauth_edge_jwt_off"
	FactBindMountsOff   FactID = "bind_mounts_off"
	FactDriverConfigOff FactID = "driver_config_off"
	FactTelemetryOff    FactID = "telemetry_off"
	FactImagesPinned    FactID = "images_pinned"
	FactNoOperatorCert  FactID = "no_operator_certificate"
	FactFirewall        FactID = "front_only_firewall"
)

// FactVerdict is one fact's verdict.
type FactVerdict string

// The closed verdicts.
const (
	VerdictOK      FactVerdict = "ok"
	VerdictUnsound FactVerdict = "unsound"
	VerdictUnknown FactVerdict = "unknown"
	// VerdictAttested is a deploy fact under a standing attestation;
	// VerdictUnattested one with none; VerdictStale one whose attestation
	// the gateway's settings revision has moved past.
	VerdictAttested   FactVerdict = "attested"
	VerdictUnattested FactVerdict = "unattested"
	VerdictStale      FactVerdict = "stale"
)

// Sound reports whether a verdict lets mints through.
func (v FactVerdict) Sound() bool { return v == VerdictOK || v == VerdictAttested }

// Observed is what one sync pass read from the gateway, plus the
// attestation on file.
type Observed struct {
	// Reached is false when the admin API did not answer (every api fact is
	// then unknown, which is unsound).
	Reached         bool
	Version         string
	DeclaredVersion string
	TestedVersions  []string
	Drivers         []string
	// Settings are the gateway-global settings ("unset" or missing means
	// the default).
	Settings       map[string]string
	GlobalPolicies int
	// SettingsRevision is the gateway's settings revision ("" when it
	// reports none).
	SettingsRevision string
	// AttestedDigest and AttestedRevision are the attestation on file.
	AttestedDigest   string
	AttestedRevision string
}

// Fact is one row of a soundness report.
type Fact struct {
	ID      FactID      `json:"id"`
	Class   FactClass   `json:"class"`
	Verdict FactVerdict `json:"verdict"`
}

// SoundnessReport is a sync pass's soundness: enum-only, so it can be
// stored and shown as it is.
type SoundnessReport struct {
	Facts []Fact `json:"facts"`
	Sound bool   `json:"sound"`
	// ProviderProfiles are the provider profile ids the gateway listed on
	// this pass (ProfilesRead), not a soundness fact: the mint refuses a
	// private clone whose git_providers row names a profile not among them
	// (FX3 item 4, live finding F-L6P4-2). Profile names are the org's own
	// configuration, shown to the admin, never sent to a node.
	ProviderProfiles []string `json:"provider_profiles,omitempty"`
	ProfilesRead     bool     `json:"provider_profiles_read,omitempty"`
}

// Unsound lists the facts that refuse mints.
func (r SoundnessReport) Unsound() []FactID {
	var out []FactID
	for _, f := range r.Facts {
		if !f.Verdict.Sound() {
			out = append(out, f.ID)
		}
	}
	return out
}

// settingOff reports whether a gateway setting is at its safe value.
func settingOff(settings map[string]string, key string, safe ...string) FactVerdict {
	v := strings.ToLower(strings.TrimSpace(settings[key]))
	if v == "" || v == "unset" || slices.Contains(safe, v) {
		return VerdictOK
	}
	return VerdictUnsound
}

// soundnessRow is one row of the fact table.
type soundnessRow struct {
	ID    FactID
	Class FactClass
	Judge func(o Observed) FactVerdict
}

// soundnessTable is the fact table, in report order.
var soundnessTable = []soundnessRow{
	{FactReachable, FactAPI, func(o Observed) FactVerdict {
		if o.Reached {
			return VerdictOK
		}
		return VerdictUnsound
	}},
	{FactVersionTested, FactAPI, func(o Observed) FactVerdict {
		if slices.Contains(o.TestedVersions, o.Version) {
			return VerdictOK
		}
		return VerdictUnsound
	}},
	{FactVersionDeclared, FactAPI, func(o Observed) FactVerdict {
		if o.Version == o.DeclaredVersion {
			return VerdictOK
		}
		return VerdictUnsound
	}},
	{FactDockerDriver, FactAPI, func(o Observed) FactVerdict {
		for _, d := range o.Drivers {
			if strings.HasPrefix(strings.ToLower(d), "docker") {
				return VerdictOK
			}
		}
		return VerdictUnsound
	}},
	{FactProposalsOff, FactAPI, func(o Observed) FactVerdict {
		return settingOff(o.Settings, "agent_policy_proposals_enabled", "false", "0", "off")
	}},
	{FactApprovalManual, FactAPI, func(o Observed) FactVerdict {
		return settingOff(o.Settings, "proposal_approval_mode", "manual")
	}},
	{FactNoGlobalPolicy, FactAPI, func(o Observed) FactVerdict {
		if o.GlobalPolicies == 0 {
			return VerdictOK
		}
		return VerdictUnsound
	}},
}

// deployFacts are attested together from the rendered config's digest.
var deployFacts = []FactID{
	FactOIDC, FactRolesScope, FactAuthModesOff, FactBindMountsOff, FactDriverConfigOff,
	FactTelemetryOff, FactImagesPinned, FactNoOperatorCert, FactFirewall,
}

// attestationVerdict judges the deploy class.
func attestationVerdict(o Observed) FactVerdict {
	switch {
	case o.AttestedDigest == "":
		return VerdictUnattested
	case o.SettingsRevision != "" && o.AttestedRevision != o.SettingsRevision:
		return VerdictStale
	}
	return VerdictAttested
}

// EvaluateSoundness walks the fact table. An unreached gateway reports
// every api fact but reachability unknown.
func EvaluateSoundness(o Observed) SoundnessReport {
	rep := SoundnessReport{Sound: true}
	for _, row := range soundnessTable {
		v := VerdictUnknown
		if o.Reached || row.ID == FactReachable {
			v = row.Judge(o)
		}
		rep.Facts = append(rep.Facts, Fact{ID: row.ID, Class: row.Class, Verdict: v})
		if !v.Sound() {
			rep.Sound = false
		}
	}
	dv := attestationVerdict(o)
	for _, id := range deployFacts {
		rep.Facts = append(rep.Facts, Fact{ID: id, Class: FactDeploy, Verdict: dv})
	}
	if !dv.Sound() {
		rep.Sound = false
	}
	return rep
}

// SyncFactsOf turns a stored soundness row into mint rule T8's input.
func SyncFactsOf(present, sound bool, checked time.Time, interval time.Duration) SyncFacts {
	return SyncFacts{Present: present, Sound: sound, CheckedAt: checked, Interval: interval}
}
