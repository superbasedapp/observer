package dashboard

import "strings"

// guardLayerRows maps a guard_events.source value onto the policy layer
// that produced the verdict and the words the session feed shows for it.
// Ordered and walked top down (Module rule 5); a prefix row ends in ":".
// The vocabulary is policy.Verdict.Source's: builtin, user, project, org,
// org_budget, llm_judge, observer, and the pack:<name> rows of the
// security pillar (policy.SourcePackSecurity).
var guardLayerRows = []struct {
	source, layer, label string
}{
	{"org", "org", "organization guard bundle"},
	{"org_budget", "org", "organization budget"},
	{"user", "local", "your local rules (~/.observer/guard-policy.toml)"},
	{"project", "project", "this project's rules (.observer/guard-policy.toml)"},
	{"pack:security", "pack", "Code security pack on this node (commit and push gate, secrets, dependencies)"},
	{"pack:", "pack", "a security pack on this node"},
	{"builtin", "builtin", "built-in rules on this node"},
	{"llm_judge", "judge", "the LLM judge"},
	{"observer", "builtin", "Observer itself"},
}

// guardLayerOf returns the layer key and label for source; an unknown
// source keeps its own name as the label so nothing reads as a guess.
func guardLayerOf(source string) (layer, label string) {
	if source == "" {
		return "", ""
	}
	for _, r := range guardLayerRows {
		if source == r.source || (strings.HasSuffix(r.source, ":") && strings.HasPrefix(source, r.source)) {
			return r.layer, r.label
		}
	}
	return "other", source
}
