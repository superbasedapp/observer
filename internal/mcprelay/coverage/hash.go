package coverage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// PointStatus is the closed effective-state answer for one point.
type PointStatus string

const (
	// StatusEffective: every required capability is present and a compiled
	// table is running.
	StatusEffective PointStatus = "effective"
	// StatusIneffective: at least one required capability is missing - a
	// mixed-version / capability gap is a gap, not health (doc2-18).
	StatusIneffective PointStatus = "ineffective"
)

// RequiredCapabilities is the per-point required capability set (doc3
// §12.7 `point_capability_set`). Missing ANY of them makes the point report
// ineffective, never effective.
var RequiredCapabilities = map[string][]string{
	// projection.applied: at least one client config on THIS node has been
	// rewritten through the launch journal (Sol P3+P4 finding 2) - a relay
	// nothing routes through is not an effective point.
	PointRelay:            {"table.loaded", "record.store", "stdio.wrapper", "projection.applied"},
	PointProxyTools:       {"table.loaded", "proxy.inference_routed", "proxy.tools_parse", "proxy.hosted_connector_parse"},
	PointHook:             {"table.loaded", "hook.pretooluse_registered", "hook.known_tool_shapes"},
	PointConfigProjection: {"table.loaded", "projection.writer", "projection.journaled"},
}

// EffectiveInput is the R8.15 / doc2-B5 hash input.
type EffectiveInput struct {
	PolicyVersion      int64    `json:"policy_version"`
	CompiledSubsetHash string   `json:"compiled_subset_hash"`
	PointCapabilitySet []string `json:"point_capability_set"`
	ClientID           string   `json:"client_id"`
	ClientVersion      string   `json:"client_version"`
	ClientConfigState  string   `json:"client_config_state"`
}

// canonical is the JCS-shaped encoding: fixed lexicographic member order,
// no insignificant whitespace, sorted capability set.
type canonical struct {
	ClientConfigState  string   `json:"client_config_state"`
	ClientID           string   `json:"client_id"`
	ClientVersion      string   `json:"client_version"`
	CompiledSubsetHash string   `json:"compiled_subset_hash"`
	PointCapabilitySet []string `json:"point_capability_set"`
	PolicyVersion      int64    `json:"policy_version"`
}

// EffectiveHash returns the 64-hex SHA-256 over the canonical JSON of the
// input. The capability set is sorted and de-duplicated first so the hash
// is order-independent.
func EffectiveHash(in EffectiveInput) string {
	caps := append([]string(nil), in.PointCapabilitySet...)
	sort.Strings(caps)
	caps = dedup(caps)
	if caps == nil {
		caps = []string{}
	}
	raw, err := json.Marshal(canonical{
		ClientConfigState:  in.ClientConfigState,
		ClientID:           in.ClientID,
		ClientVersion:      in.ClientVersion,
		CompiledSubsetHash: in.CompiledSubsetHash,
		PointCapabilitySet: caps,
		PolicyVersion:      in.PolicyVersion,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Status resolves a point's effective status from the capabilities it
// actually has: effective only when EVERY required capability is present.
func Status(point string, have []string) (PointStatus, []string) {
	req, ok := RequiredCapabilities[point]
	if !ok {
		return StatusIneffective, nil
	}
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	var missing []string
	for _, r := range req {
		if !set[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return StatusIneffective, missing
	}
	return StatusEffective, nil
}

func dedup(sorted []string) []string {
	if len(sorted) == 0 {
		return nil
	}
	out := sorted[:1]
	for _, s := range sorted[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
