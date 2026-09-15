package cloudcontract

import "strings"

// evidenceJargon is the closed set of envelope-internal names that must never
// appear in a NARRATIVE field. Every member is snake_case or dotted, i.e. a
// shape that does not occur in ordinary English prose, so matching one is a
// genuine leak and never a false positive on a well-written sentence.
//
// Plain English section names ("context", "metrics", "outcomes", "actions",
// "milestones") are deliberately ABSENT here: banning them mid-sentence would
// reject legitimate prose ("no tests ran in this context"). They are caught
// instead by the whole-item rule below, which is what the operator actually
// saw - an item that IS nothing but a bare section name.
var evidenceJargon = map[string]struct{}{
	"activity_mix":            {},
	"error_class":             {},
	"error_class_last":        {},
	"user_feedback":           {},
	"first_user_prompt":       {},
	"user_prompt":             {},
	"final_assistant_message": {},
	"task_excerpt":            {},
	"tests_run":               {},
	"tests_passed":            {},
	"tests_unknown":           {},
	"builds_unknown":          {},
	"model_family":            {},
	"outcome.tests":           {},
	"outcome.build":           {},
	"evidence_refs":           {},
	"taxonomy_tags":           {},
	"suggested_tags":          {},
	"schema_version":          {},
}

// bareSectionNames are the plain-English evidence section names. They are a
// leak only when an item consists of nothing else (the operator's report was a
// bullet list reading "context", "outcomes", "activity_mix").
var bareSectionNames = map[string]struct{}{
	"context":    {},
	"metrics":    {},
	"outcomes":   {},
	"actions":    {},
	"milestones": {},
}

// NarrativeRefLeak reports whether a narrative string leaks an evidence
// identifier - a bare action/milestone ref ("a136", "m5") or an envelope
// section/jargon name ("activity_mix", "outcomes") - and returns the offending
// token. Refs belong in evidence_refs; a narrative field is written FOR the
// developer and must read as plain prose.
//
// It is deliberately conservative: it matches the lowercase ref-id shape
// exactly, a closed set of non-English jargon names, and a whole item that is
// nothing but a section name. Ordinary prose that happens to contain the word
// "context" or "actions" is NOT a leak - over-rejection here would fail every
// job the way a hallucinated schema_version once did.
func NarrativeRefLeak(s string) (string, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(s), ".:;-")))
	if _, ok := bareSectionNames[trimmed]; ok {
		return trimmed, true
	}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) {
		tok = strings.Trim(tok, ".")
		if tok == "" {
			continue
		}
		if _, ok := evidenceJargon[tok]; ok {
			return tok, true
		}
		if isRefID(tok) {
			return tok, true
		}
	}
	return "", false
}

// isRefID reports whether tok has the exact action/milestone ref shape: a
// lowercase 'a' or 'm' followed by digits only ("a0", "a136", "m5").
func isRefID(tok string) bool {
	if len(tok) < 2 || (tok[0] != 'a' && tok[0] != 'm') {
		return false
	}
	for i := 1; i < len(tok); i++ {
		if tok[i] < '0' || tok[i] > '9' {
			return false
		}
	}
	return true
}

// AllowedEvidenceRefs derives the EXACT, bounded set of evidence-reference
// identifiers a result may cite for one envelope (FE3). "Cite only allowed
// evidence refs" is otherwise prompt-only: a model hallucination — or an
// injected instruction — can return refs that do not exist, and downstream
// users are shown citations that appear grounded but are fabricated. The
// executor derives this set from the uploaded envelope and rejects any result
// ref outside it.
//
// The ref grammar (documented, closed) is the union of:
//
//   - every Action.Ref present in the envelope (e.g. "a1");
//   - every Milestone.Ref present (e.g. "m1");
//   - every ContextExcerpt.Source present (e.g. "task_excerpt");
//   - a fixed vocabulary of structural section refs that ALWAYS exist:
//     "metrics", "outcomes", "outcome.tests", "outcome.build", "actions",
//     "milestones";
//   - the conditional section refs "context" (only when the envelope carries
//     context excerpts), "user_feedback" (only when it carries feedback), and
//     "activity_mix" (only when it carries a whole-session activity mix).
//
// Matching is EXACT and case-sensitive: a case-variant, whitespace-variant, or
// invented ref is not a member. The set is bounded by the envelope's own
// bounded arrays plus a small fixed vocabulary, so it cannot grow unboundedly.
func AllowedEvidenceRefs(e Envelope) map[string]struct{} {
	allowed := map[string]struct{}{
		"metrics":       {},
		"outcomes":      {},
		"outcome.tests": {},
		"outcome.build": {},
		"actions":       {},
		"milestones":    {},
	}
	for _, a := range e.Actions {
		if a.Ref != "" {
			allowed[a.Ref] = struct{}{}
		}
	}
	for _, m := range e.Milestones {
		if m.Ref != "" {
			allowed[m.Ref] = struct{}{}
		}
	}
	for _, c := range e.Context {
		if c.Source != "" {
			allowed[c.Source] = struct{}{}
		}
	}
	if len(e.Context) > 0 {
		allowed["context"] = struct{}{}
	}
	if e.UserFeedback != nil {
		allowed["user_feedback"] = struct{}{}
	}
	if len(e.ActivityMix) > 0 {
		allowed["activity_mix"] = struct{}{}
	}
	return allowed
}
