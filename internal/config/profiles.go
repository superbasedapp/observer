package config

import (
	"fmt"
	"sort"

	"github.com/BurntSushi/toml"
)

// This file implements compression PROFILES — the Track-R replacement
// for daemon-wide `--recipe` overlays (usability arc §2.3,
// docs/plans/usability-review-2026-06-10.md).
//
// A profile is a named, immutable set of compression PARAMETERS.
// Built-ins are the embedded recipes (claude-code / codex-safe /
// codex-variant) plus "default" (the master config's own parameters,
// i.e. no overlay). Unlike the legacy --recipe flag, profiles are
// NEVER merged into the global Config during Load(): they are resolved
// per traffic class at the proxy boundary, which
//
//   - fixes the cross-tool correctness defect (one daemon serving
//     Claude Code AND Codex applies each tool's tuned parameters
//     simultaneously instead of one recipe globally), and
//   - kills the save-bakes-recipe footgun (writeConfigToml can no
//     longer persist recipe values into config.toml, because they are
//     never present in the marshaled struct).
//
// THE ENABLEMENT SPLIT (§2.3 decision 2, operator-confirmed Q6):
// `[compression.conversation] enabled` in the MASTER config remains
// the single on/off switch and is never overridden by a profile.
// Everything else in the compression tree — modes, ratios, type
// lists, shell excludes, indexing sizes, stash/rolling sub-toggles —
// is profile parameter space. "Turn compression on" is one master
// toggle that is then correct for every tool at once.
//
// Module shape: pure logic — no I/O beyond the recipes embed already
// owned by this package, no HTTP, no SQL. The proxy calls
// ResolveCompression through a single seam and receives a plain
// CompressionConfig value.

// DefaultProfileName is the no-overlay profile: master-config
// parameters pass through untouched.
const DefaultProfileName = "default"

// ProfilesConfig is the `[profiles]` TOML section: which profile each
// traffic class gets. Parameters themselves live in the embedded
// built-ins (and, from P3.4 on, user profile files) — this section
// only ASSIGNS them.
type ProfilesConfig struct {
	// Default names the profile for traffic no assignment matches.
	// Empty = DefaultProfileName (master parameters).
	Default string `toml:"default"`
	// ByProvider maps a proxy provider class ("anthropic", "openai")
	// to a profile name. R1 fidelity: provider is known per request
	// from the URL path with zero new attribution.
	ByProvider map[string]string `toml:"by_provider"`
	// ByTool maps a canonical tool name (the pidbridge Entry.Tool the
	// SessionStart hook wrote — "claude-code", "cline",
	// "kilo-code-cli", …) to a profile name. R2 fidelity: more
	// specific than ByProvider, consulted first when the proxy could
	// resolve the connection's owning tool. EMPTY by default — tools
	// inherit their provider's assignment until an operator (or the
	// P3.5 A/B evidence) says otherwise. Assign via
	// `observer profile assign tool:<name> <profile>` or
	// [profiles.by_tool] in config.toml.
	ByTool map[string]string `toml:"by_tool"`
}

// defaultProfiles returns the baked-in assignment table: Anthropic
// traffic gets the cache-aware claude-code parameters, OpenAI traffic
// the codex-safe ones. These are the pairings the A/B-measured recipes
// were tuned for — the wrong pairing breaks provider caching or
// degrades output (the defect motivating Track R).
func defaultProfiles() ProfilesConfig {
	return ProfilesConfig{
		Default: DefaultProfileName,
		ByProvider: map[string]string{
			"anthropic": "claude-code",
			"openai":    "codex-safe",
		},
	}
}

// ProfileNames returns every resolvable profile name: "default" plus
// the embedded recipes. Sorted; used by CLI help, the Settings
// Profiles panel, and assignment validation.
func ProfileNames() []string {
	names := append([]string{DefaultProfileName}, RecipeNames()...)
	sort.Strings(names)
	return names
}

// LoadProfile returns the named profile's compression parameters.
// "default" (or "") returns zeroProfile=true with master-parameter
// passthrough semantics — callers keep their base unchanged. Unknown
// names error with the available set.
func LoadProfile(name string) (params CompressionConfig, isDefault bool, err error) {
	if name == "" || name == DefaultProfileName {
		return CompressionConfig{}, true, nil
	}
	cfg, err := LoadRecipe(name)
	if err != nil {
		return CompressionConfig{}, false, fmt.Errorf("config: profile %q: %w", name, err)
	}
	return cfg.Compression, false, nil
}

// ResolveProfileName picks the profile for a traffic class from the
// assignment table: tool assignment (most specific; R2) → provider
// assignment (R1) → table default → DefaultProfileName. tool is the
// pidbridge-resolved owning tool, "" when unresolved — an empty tool
// simply skips the first tier. Pure table walk — one row per lookup
// tier so behavior is test-pinnable per row.
func ResolveProfileName(pc ProfilesConfig, provider, tool string) string {
	if tool != "" {
		if name, ok := pc.ByTool[tool]; ok && name != "" {
			return name
		}
	}
	if name, ok := pc.ByProvider[provider]; ok && name != "" {
		return name
	}
	if pc.Default != "" {
		return pc.Default
	}
	return DefaultProfileName
}

// ResolveCompression returns the compression settings for traffic
// assigned profileName: the profile's keys overlaid on the master
// config's parameters, with the master's enablement preserved (the
// §2.3 split). For the default profile the master settings pass
// through byte-identical — the compat pin P2.8 asserts a
// no-profile-config daemon behaves exactly like today's.
//
// The overlay is a PARTIAL merge: only keys the profile's TOML
// actually sets win over master (including explicit zeros — codex-
// variant pins logs max_lines=0 and compress_types=[] deliberately).
// Keys the profile doesn't mention fall through to the master config,
// consistent with how every other layer in the §2.3 precedence chain
// merges. Resolving over baked defaults instead would silently strip
// master-tuned params the recipes don't pin (rolling-summary models,
// thresholds) from profiled traffic.
func ResolveCompression(master CompressionConfig, profileName string) (CompressionConfig, error) {
	if profileName == "" || profileName == DefaultProfileName {
		return master, nil
	}
	body, err := readRecipe(profileName)
	if err != nil {
		return CompressionConfig{}, fmt.Errorf("config: profile %q: %w", profileName, err)
	}
	// Recipe TOMLs only carry [compression.*] tables, so unmarshaling
	// into a Config seeded with the master compression tree applies
	// exactly the profile's keys over it.
	overlay := Config{Compression: master}
	if err := toml.Unmarshal(body, &overlay); err != nil {
		return CompressionConfig{}, fmt.Errorf("config: profile %q: %w", profileName, err)
	}
	out := overlay.Compression
	// The master-owned switch survives the overlay: the one
	// conversation on/off gate (the product's compression switch —
	// profiles must never auto-enable compression).
	out.Conversation.Enabled = master.Conversation.Enabled
	return out, nil
}
