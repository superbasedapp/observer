package orgcontract

import "strings"

// managed_integrity_layers.go carries the settings-layer reading of the
// managed-integrity report (surface-gap arc decision DEC-7, lane w4-wire;
// findings CLI-5 and OBS-9 of
// docs/audits/surface-settings-precedence-gap-review-2026-10-25.md): the
// closed tool vocabulary of HookDisabledTools, the closed "tool/finding"
// vocabulary of ConfigLayerRisks, and their normalization. Tool ids and
// finding codes only: no path, project, key or value crosses.

// configLayerTools is the CLOSED tool vocabulary of HookDisabledTools and the
// tool half of ConfigLayerRisks: every tool a row of the hook-off table
// (internal/hookdisable.Switches) silences and every tool an effective-layer
// family (agentconfig.Families) belongs to. It lives here, not in those
// packages, for the same reason as driftedToolLabels: the org server
// validates against the wire vocabulary without linking the node's tables.
// diag.TestConfigLayerToolsAreWireLabels fails when either table names a
// tool this one does not.
//
// Adding a row is safe in both directions: NormalizeLabels runs on both
// sides, so an older server drops a label it does not know and an older node
// never sends one.
var configLayerTools = map[string]bool{
	"aider":        true,
	"autohand":     true,
	"claude-code":  true,
	"codebuddy":    true,
	"command-code": true,
	"copilot":      true,
	"copilot-cli":  true,
	"cortex-code":  true,
	"crush":        true,
	"cursor":       true,
	"deepseek":     true,
	"devin":        true,
	"dimcode":      true,
	"dirac":        true,
	"droid":        true,
	"gemini-cli":   true,
	"goose":        true,
	"grok":         true,
	"ibm-bob":      true,
	"junie":        true,
	"kimchi":       true,
	"opencode":     true,
	"qwen-code":    true,
	"stakpak":      true,
	"vtcode":       true,
}

// configLayerRiskCodes is the CLOSED finding half of ConfigLayerRisks: the
// agentconfig.FindingCode values that weaken capture or routing (the codes
// the doctor's config.layers row warns on). The informational codes
// (hooks_off_overridden, mcp_first_file_only, provider_unverified) are not
// risks and never cross. diag.TestConfigLayerRiskCodesMatchTheDoctor pins this
// table to the doctor's warn set, code by code.
//
// user_policy_override (FU-105, operator decision 2026-10-27) is added the
// same additive way: a tool policy key set in a user-writable source the
// tool applies as policy (IBM Bob's macOS com.ibm.bob user domain), whether
// it adds a key the administrator did not set or duplicates one they did.
// An older server drops the label it does not know (and with it the derived
// config_layer_override when it was the only one); an older node never
// sends it.
var configLayerRiskCodes = map[string]bool{
	"project_route_override": true,
	"route_shadowed":         true,
	"ide_route_override":     true,
	"project_hooks_disabled": true,
	"hooks_disabled":         true,
	"hook_array_replaced":    true,
	"layers_dropped":         true,
	"auth_pins_vendor_host":  true,
	"inactive_provider":      true,
	"user_policy_override":   true,
}

// ValidConfigLayerTool reports whether tool is in the closed
// HookDisabledTools vocabulary.
func ValidConfigLayerTool(tool string) bool { return configLayerTools[tool] }

// ConfigLayerTools returns the closed tool vocabulary, sorted.
func ConfigLayerTools() []string { return sortedSet(configLayerTools) }

// ConfigLayerRiskCodes returns the closed finding vocabulary, sorted.
func ConfigLayerRiskCodes() []string { return sortedSet(configLayerRiskCodes) }

// ConfigLayerRiskLabel renders one ConfigLayerRisks label, "tool/finding",
// and reports whether both halves are in the closed vocabulary. A label it
// refuses never crosses the wire.
func ConfigLayerRiskLabel(tool, code string) (string, bool) {
	label := tool + "/" + code
	return label, validConfigLayerRiskLabel(label)
}

// validConfigLayerRiskLabel reports whether label is a closed
// "tool/finding" pair.
func validConfigLayerRiskLabel(label string) bool {
	tool, code, ok := strings.Cut(label, "/")
	return ok && configLayerTools[tool] && configLayerRiskCodes[code]
}

// normalizeConfigLayers reduces the settings-layer reading to the wire
// vocabulary: an unsupported version (an older node's absent key, or a
// future one this binary cannot read) is not reported and carries no lists;
// a supported one keeps only closed labels.
func (r ManagedIntegrityReport) normalizeConfigLayers() ManagedIntegrityReport {
	if r.ConfigLayerVersion != ManagedConfigLayerVersion {
		r.ConfigLayerVersion = 0
		r.HookDisabledTools = nil
		r.ConfigLayerRisks = nil
		return r
	}
	r.HookDisabledTools = nilIfEmpty(normalizeManagedLabels(r.HookDisabledTools, ValidConfigLayerTool))
	r.ConfigLayerRisks = nilIfEmpty(normalizeManagedLabels(r.ConfigLayerRisks, validConfigLayerRiskLabel))
	return r
}

// nilIfEmpty returns nil for an empty list, so a normalized report carries
// the absent key rather than an empty one.
func nilIfEmpty(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	return labels
}
