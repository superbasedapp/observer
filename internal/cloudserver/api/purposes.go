package api

import "github.com/marmutapp/superbased-observer/internal/cloudcontract"

// purposesValid reports whether every string is a known consent purpose.
func purposesValid(purposes []string) bool {
	for _, p := range purposes {
		if !cloudcontract.Purpose(p).Valid() {
			return false
		}
	}
	return true
}

// requiredPurposes maps the field classes an envelope actually POPULATES to the
// consent purposes that must be granted (the out-of-purpose gate, §4.2/§5.2).
// Structural content (identity/metrics/paths) requires structural insights;
// excerpts and user feedback require bounded context enrichment - with ONE
// carve-out (2026-09-16): a context that is EXACTLY the single first-prompt
// excerpt (cloudcontract.Envelope.ContextIsFirstPromptOnly) needs only the
// structural purpose. That is the narrowed first_user_prompt_excerpt field
// class the "Title only" level binds, and it is what the mandatory portal
// consent already discloses ("...action outcome categories, and your first
// prompt"). Anything wider in the context still needs the excerpt purpose.
func requiredPurposes(env cloudcontract.Envelope) []cloudcontract.Purpose {
	set := map[cloudcontract.Purpose]bool{
		// Every envelope carries the structural core.
		cloudcontract.PurposeStructuralInsights: true,
	}
	widerContext := len(env.Context) > 0 && !env.ContextIsFirstPromptOnly()
	if widerContext || env.UserFeedback != nil {
		set[cloudcontract.PurposeContextEnrichment] = true
	}
	out := make([]cloudcontract.Purpose, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	return out
}

// purposesGranted reports whether every purpose in need is present in granted.
func purposesGranted(need []cloudcontract.Purpose, granted []string) (missing cloudcontract.Purpose, ok bool) {
	have := make(map[string]bool, len(granted))
	for _, g := range granted {
		have[g] = true
	}
	for _, n := range need {
		if !have[string(n)] {
			return n, false
		}
	}
	return "", true
}
