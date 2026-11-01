package config

// policyfamilies.go is the downgrade-safe split of [org_client.policy]
// (plans orchestrator decision P-047, the managed write hold).
//
// A RELEASED node binary (checked against v1.34.0-rc.11 and v1.36.0) loads
// config.toml with BurntSushi toml.Decode and no undecoded-key check, so it
// IGNORES a key it does not know; but its validateOrgClientPolicy REFUSES the
// whole file when accept_families or preauthorize_enforce names a family
// outside its own closed set. A family added after those releases (the
// module floor families security.scanning and terminals.isolation, and every
// later one) is therefore written into the additive keys
// accept_module_families / preauthorize_module_enforce, which this build
// reads together with the old ones and an older binary ignores: after a
// manual downgrade or an update rollback the older binary still loads the
// file, and the module family is simply not accepted there.

// releasedPolicyFamilies is the family set every released loader accepts in
// the old keys (the intersection of v1.34.0-rc.11 and v1.36.0). FROZEN:
// never add a family here; a new family goes to the module keys.
var releasedPolicyFamilies = map[string]bool{
	"admission.input":          true,
	"egress.routing_guardrail": true,
	"gateway.providers":        true,
	"node.governance":          true,
	"node.features":            true,
	"planeb.admission":         true,
	"tools.mcp_access":         true,
}

// IsReleasedPolicyFamily reports whether every released loader accepts
// family in accept_families and preauthorize_enforce.
func IsReleasedPolicyFamily(family string) bool { return releasedPolicyFamilies[family] }

// SplitPolicyFamilies splits families, order kept, into those a writer puts
// in the old keys (released) and those it puts in the module keys.
func SplitPolicyFamilies(families []string) (released, module []string) {
	for _, f := range families {
		if releasedPolicyFamilies[f] {
			released = append(released, f)
		} else {
			module = append(module, f)
		}
	}
	return released, module
}

// AcceptedFamilies is every family this node accepts: accept_families then
// accept_module_families, deduplicated, order kept. Every reader of the
// accept list reads it here, never one key alone.
func (p OrgClientPolicyConfig) AcceptedFamilies() []string {
	return unionFamilies(p.AcceptFamilies, p.AcceptModuleFamilies)
}

// PreauthorizedFamilies is every family preauthorized for enforce:
// preauthorize_enforce then preauthorize_module_enforce, deduplicated.
func (p OrgClientPolicyConfig) PreauthorizedFamilies() []string {
	return unionFamilies(p.PreauthorizeEnforce, p.PreauthorizeModuleEnforce)
}

func unionFamilies(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, f := range list {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	return out
}
