package routeattest

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// Inspector reads one tool's config-lane routing surface and returns a
// verdict. ok reports whether the inspector actually recognized and read
// tool's own config surface: ok=false means this RouteKind DOES have a
// grounded reader somewhere in the table, but not for this specific tool
// identity (e.g. RouteConfigFile is shared by codex, qwen-code, and
// kimi-code in the registry, but internal/proxyroute today only ships a
// codex-specific reader) — the caller must fall back to traffic
// attestation rather than report a verdict sourced from an unrelated
// tool's config file. A false ok never carries a meaningful verdict/reason
// pair for display; callers should treat it as "no config attestation".
type Inspector func(tool, homeDir string, gateways []string) (verdict Verdict, reason string, ok bool)

// configInspectors maps each persisted RouteKind to its Inspector. Every
// RouteKind constant in internal/integration has a row here (pinned by
// TestConfigInspectorsCoverEveryRouteKind) so a future RouteKind addition
// is a build-time reminder to seed (or explicitly stub) its inspector,
// rather than a silent coverage gap.
var configInspectors = map[integration.RouteKind]Inspector{
	integration.RouteEnvSettings:    envSettingsInspector,
	integration.RouteConfigFile:     configFileInspector,
	integration.RouteProviderJSON:   stubInspector(integration.RouteProviderJSON, "provider-JSON config files (crush.json, ~/.cline/data/settings/providers.json, ~/.pi/agent/models.json, ~/.hermes/config.yaml) have no shared read-only inspector yet"),
	integration.RouteVSCodeSettings: stubInspector(integration.RouteVSCodeSettings, "VS Code globalState/state.vscdb is not a readable JSON file (Cline/Kilo Code route via manual-paste instructions, not a config write)"),
	integration.RouteLauncher:       stubInspector(integration.RouteLauncher, "launcher-injected env vars are exec-time only and leave no persisted config surface to read after the fact"),
	integration.RouteManual:         stubInspector(integration.RouteManual, "operator-pasted routes are never persisted anywhere observer can read"),
}

// envSettingsInspector is the RouteEnvSettings config reader. It is
// grounded ONLY for claude-code (the sole RouteEnvSettings row in the
// registry today, internal/proxyroute.InspectClaudeRouteWithGateways reads
// <homeDir>/.claude/settings.json). Any other tool sharing this RouteKind
// in the future gets an honest ok=false until a matching reader is added.
func envSettingsInspector(tool, homeDir string, gateways []string) (Verdict, string, bool) {
	if tool != "claude-code" {
		return VerdictUnrouted, fmt.Sprintf("no grounded env_settings config reader for tool %q (only claude-code is wired)", tool), false
	}
	status := proxyroute.InspectClaudeRouteWithGateways(homeDir, gateways)
	verdict, reason := mapRouteState(status.State)
	return verdict, reason, true
}

// configFileInspector is the RouteConfigFile config reader. It is grounded
// ONLY for codex (internal/proxyroute.InspectCodexRouteWithGateways reads
// <homeDir>/.codex/config.toml). qwen-code and kimi-code also carry
// RouteConfigFile in the registry but have no matching reader yet — they
// fall through to traffic attestation (see AttestAll), honestly, rather
// than being (mis)classified from codex's own config file.
func configFileInspector(tool, homeDir string, gateways []string) (Verdict, string, bool) {
	if tool != "codex" {
		return VerdictUnrouted, fmt.Sprintf("no grounded config_file config reader for tool %q (only codex is wired)", tool), false
	}
	status := proxyroute.InspectCodexRouteWithGateways(homeDir, gateways)
	verdict, reason := mapRouteState(status.State)
	return verdict, reason, true
}

// stubInspector builds a documented, always-ok=false Inspector for a
// RouteKind whose config surface observer cannot yet read for ANY tool.
// It exists so every RouteKind is represented in configInspectors by
// construction (§3.3's "attestations, not gaps") instead of being omitted
// from the map, while still routing every tool of that kind to traffic
// attestation honestly.
func stubInspector(kind integration.RouteKind, why string) Inspector {
	reason := fmt.Sprintf("config surface for RouteKind %q not yet readable (%s) — falls back to traffic attestation", kind, why)
	return func(_ string, _ string, _ []string) (Verdict, string, bool) {
		return VerdictUnrouted, reason, false
	}
}

// mapRouteState maps a proxyroute.RouteState (the coarse, content-free
// verdict internal/proxyroute's file inspectors already return) onto this
// package's Verdict + a display Reason.
func mapRouteState(s proxyroute.RouteState) (Verdict, string) {
	switch s {
	case proxyroute.RouteOurs:
		return VerdictRoutedLoopback, "points at an observer loopback proxy"
	case proxyroute.RouteOrgGateway:
		return VerdictRoutedOrgGateway, "points at an authorized org AI Gateway endpoint"
	case proxyroute.RouteDrifted:
		return VerdictDrifted, "points at a non-loopback host matching no authorized gateway — possible bypass"
	case proxyroute.RouteAbsent:
		return VerdictUnrouted, "no route configured (config or key missing)"
	default:
		return VerdictUnrouted, fmt.Sprintf("unrecognized proxyroute.RouteState %q", s)
	}
}
