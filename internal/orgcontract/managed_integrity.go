package orgcontract

import (
	"sort"
	"strings"
)

const maxManagedIntegrityLabels = 16

// NormalizeLabels reduces every managed-integrity detail array to the closed,
// content-free wire vocabulary. Both client and server call it so paths,
// usernames, commands, config values, and error strings cannot cross the wire
// through these fields or enter server persistence through a custom client.
func (r ManagedIntegrityReport) NormalizeLabels() ManagedIntegrityReport {
	r.SiblingDetail = normalizeManagedLabels(r.SiblingDetail, validManagedSiblingLabel)
	r.DriftedTools = normalizeManagedLabels(r.DriftedTools, validDriftedToolLabel)
	if r.CaptureCheckVersion != ManagedCaptureCheckVersion {
		r.CaptureCheckVersion = 0
		r.CaptureRisks = nil
		r.UnknownChecks = nil
		return r
	}
	r.CaptureCheckVersion = ManagedCaptureCheckVersion
	r.CaptureRisks = normalizeManagedLabels(r.CaptureRisks, validCaptureRisk)
	r.UnknownChecks = normalizeManagedLabels(r.UnknownChecks, validUnknownCheck)
	return r
}

func normalizeManagedLabels(labels []string, allowed func(string) bool) []string {
	seen := map[string]bool{}
	for _, raw := range labels {
		label := strings.TrimSpace(raw)
		if label != "" && allowed(label) {
			seen[label] = true
		}
	}
	out := make([]string, 0, len(seen))
	for label := range seen {
		out = append(out, label)
	}
	sort.Strings(out)
	if len(out) > maxManagedIntegrityLabels {
		out = out[:maxManagedIntegrityLabels]
	}
	return out
}

// driftedToolLabels is the CLOSED `drifted_tools` vocabulary: the adapter
// ids a node can report a proxy-route drift for.
//
// WIDENED ADDITIVELY by Track C item 2
// (docs/plans/org-guardrail-control-wave-2026-09-21.md) from the original
// claude-code/codex pair to every adapter whose PERSISTED proxy route
// internal/proxyroute owns a guarded writer for, because the route inspector
// now dispatches on the integration registry's RouteKind rather than on two
// hand-listed tools.
//
// ONE OWNER, two halves, held together by a test:
// proxyroute.InspectedTools() decides what a node CAN report, this table
// decides what the wire ACCEPTS, and
// proxyroute.TestInspectedToolsAreValidWireLabels fails if they diverge. The
// table lives here rather than being imported from proxyroute because
// orgcontract is the wire vocabulary and the org SERVER validates against it
// — the server must not have to link the node's config writers.
//
// Adding a row is safe in both directions: an older server drops a label it
// does not know (NormalizeLabels is applied on BOTH sides), and an older node
// simply never sends one.
var driftedToolLabels = map[string]bool{
	"claude-code": true,
	"codex":       true,
	"crush":       true,
	"kimi-code":   true,
	"qwen-code":   true,
}

// validDriftedToolLabel reports whether label is in the closed
// `drifted_tools` vocabulary.
func validDriftedToolLabel(label string) bool { return driftedToolLabels[label] }

// DriftedToolLabels returns the closed `drifted_tools` vocabulary, sorted —
// for surfaces (and tests) that need to enumerate it.
func DriftedToolLabels() []string {
	out := make([]string, 0, len(driftedToolLabels))
	for label := range driftedToolLabels {
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

func validManagedSiblingLabel(label string) bool {
	parts := strings.Split(label, "/")
	if len(parts) != 2 {
		return false
	}
	originOK := parts[0] == "native-alt" || parts[0] == "wsl-mnt" || parts[0] == "wslhost" || parts[0] == "other"
	osOK := parts[1] == "windows" || parts[1] == "linux" || parts[1] == "darwin" || parts[1] == "other"
	return originOK && osOK
}

func validCaptureRisk(label string) bool {
	switch label {
	case CaptureRiskHookRegistrationError,
		CaptureRiskHookBinaryMismatch,
		CaptureRiskHookConfigMissing,
		CaptureRiskCodexHookUntrusted,
		CaptureRiskHookConfigChanged:
		return true
	default:
		return false
	}
}

func validUnknownCheck(label string) bool {
	switch label {
	case CaptureUnknownRegistryMissing,
		CaptureUnknownRegistryUnreadable,
		CaptureUnknownRegistryInvalid,
		CaptureUnknownRegistryEmpty,
		CaptureUnknownConfigUnreadable,
		CaptureUnknownChecksumMissing,
		CaptureUnknownBinaryPath,
		CaptureUnknownRecordedBinary,
		CaptureUnknownCodexTrust:
		return true
	default:
		return false
	}
}
