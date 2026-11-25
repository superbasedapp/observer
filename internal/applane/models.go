package applane

import "strings"

// AllLanesKey is the [proxy.app_lanes] models key whose patterns apply to
// every lane that has no entry of its own.
const AllLanesKey = "*"

// LanePatterns returns the model allow-list that applies to lane: its own
// entry, else the AllLanesKey entry. ok=false means no list applies (every
// model is allowed).
func LanePatterns(models map[string][]string, lane string) ([]string, bool) {
	if pats, ok := models[lane]; ok {
		return pats, true
	}
	if pats, ok := models[AllLanesKey]; ok {
		return pats, true
	}
	return nil, false
}

// ModelAllowed reports whether model matches one of patterns. A pattern is
// an exact model name or a glob where '*' matches any run of characters
// ('/' included, so "openai/*" covers an OpenRouter model id). Matching is
// case-insensitive. An empty model never matches a list: a lane with a list
// forwards only a request that names an allowed model.
func ModelAllowed(patterns []string, model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	if model == "" {
		return false
	}
	for _, p := range patterns {
		if globMatch(strings.ToLower(strings.TrimSpace(p)), model) {
			return true
		}
	}
	return false
}

// globMatch matches s against pattern, where '*' is the only wildcard.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return false
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}
