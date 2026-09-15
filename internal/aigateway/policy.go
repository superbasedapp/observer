package aigateway

import "strings"

// Principal is the member identity the model policy is resolved against: the
// roles and teams the authenticated member belongs to. Both are matched
// case-insensitively.
type Principal struct {
	Roles []string
	Teams []string
}

// ModelPolicy is the enforceable model allow-list with per-role/team tiers
// (design §2.4.2). The org routing policy body — advisory node-side — becomes
// ENFORCEABLE here. Tier keys are routing-style labels (the same normalized
// model-key vocabulary internal/routing uses), so a route's tier names line up
// with what the gateway admits.
//
// Semantics: a member may use a model if it appears in DefaultAllow OR in any
// tier of a role/team they belong to. A "*" entry in any list is a wildcard
// granting every model at that tier. When the resolved allow-set is empty, the
// verdict is DENY — the policy fails closed (Luna L11 golden), so a
// misconfigured or empty policy never silently permits arbitrary models.
type ModelPolicy struct {
	// DefaultAllow is the base tier every member gets.
	DefaultAllow []string `json:"default_allow"`
	// RoleTiers maps a role name → the models that role additionally grants.
	RoleTiers map[string][]string `json:"role_tiers,omitempty"`
	// TeamTiers maps a team name → the models that team additionally grants.
	TeamTiers map[string][]string `json:"team_tiers,omitempty"`
	// MaxOutputTokens is a per-model cap that feeds the worst-case budget
	// reservation. A model absent here uses DefaultMaxOutputTokens.
	MaxOutputTokens map[string]int `json:"max_output_tokens,omitempty"`
	// DefaultMaxOutputTokens is the fallback cap; the caller applies a hard
	// ceiling when this is zero.
	DefaultMaxOutputTokens int `json:"default_max_output_tokens"`
}

// ModelVerdict is the resolution result.
type ModelVerdict struct {
	Allowed         bool
	MaxOutputTokens int
	Reason          string
}

// wildcardModel is the allow-all sentinel usable in any tier list.
const wildcardModel = "*"

// containsModel reports whether list grants model (exact normalized match or a
// "*" wildcard).
func containsModel(list []string, model string) bool {
	for _, m := range list {
		m = strings.TrimSpace(m)
		if m == wildcardModel {
			return true
		}
		if normalizeModelKey(m) == model {
			return true
		}
	}
	return false
}

// grantsAny reports whether any of names has a tier in tiers that grants model.
func grantsAny(tiers map[string][]string, names []string, model string) bool {
	if len(tiers) == 0 {
		return false
	}
	for _, n := range names {
		if list, ok := tiers[strings.ToLower(strings.TrimSpace(n))]; ok {
			if containsModel(list, model) {
				return true
			}
		}
	}
	return false
}

// Resolve applies the allow-list + tier rules and returns whether the model is
// permitted for the principal, plus the effective max_tokens cap that feeds
// the budget reservation.
func (p ModelPolicy) Resolve(pr Principal, model string) ModelVerdict {
	key := normalizeModelKey(model)
	if key == "" {
		return ModelVerdict{Allowed: false, Reason: "no model specified"}
	}
	allowed := containsModel(p.DefaultAllow, model) ||
		grantsAny(p.RoleTiers, pr.Roles, model) ||
		grantsAny(p.TeamTiers, pr.Teams, model)
	if !allowed {
		return ModelVerdict{Allowed: false, Reason: "model not in any granted tier"}
	}
	max := p.DefaultMaxOutputTokens
	if p.MaxOutputTokens != nil {
		if m, ok := p.MaxOutputTokens[key]; ok && m > 0 {
			max = m
		}
	}
	return ModelVerdict{Allowed: true, MaxOutputTokens: max, Reason: ""}
}

// EffectiveMaxOutputTokens clamps a member-supplied max_tokens to the policy's
// cap for model. The gateway uses the clamped value both to bound the upstream
// request AND to price the worst-case reservation, so a request can never
// reserve less than it could actually spend. hardCeiling is the absolute
// backstop applied when the policy leaves the cap at zero. The cap lookup is
// principal-independent — the per-model ceiling is the same whoever asks.
func (p ModelPolicy) EffectiveMaxOutputTokens(model string, requested, hardCeiling int) int {
	key := normalizeModelKey(model)
	capTok := p.DefaultMaxOutputTokens
	if p.MaxOutputTokens != nil {
		if m, ok := p.MaxOutputTokens[key]; ok && m > 0 {
			capTok = m
		}
	}
	if capTok <= 0 {
		capTok = hardCeiling
	}
	if capTok <= 0 {
		capTok = requested
	}
	if requested > 0 && requested < capTok {
		return requested
	}
	return capTok
}
