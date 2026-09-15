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
	r.DriftedTools = normalizeManagedLabels(r.DriftedTools, func(label string) bool {
		return label == "claude-code" || label == "codex"
	})
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
