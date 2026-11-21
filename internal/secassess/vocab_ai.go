package secassess

// The AI-application frameworks a threat model uses only when the project is
// an AI application (the grounding digest sets AIApp). This file holds the
// framework ids and the shape of a category id; the full id lists and Observer's
// own descriptions are filled by the threat-model depth wave against the
// current OWASP publications, so until then a well-formed id is accepted and
// shown bare.

// Framework ids in a threat's `framework`.
const (
	FrameworkOWASPLLM     = "owasp_llm"
	FrameworkOWASPAgentic = "owasp_agentic"
)

// AIFramework is one AI-application framework.
type AIFramework struct {
	// ID is the id written in a threat's `framework`.
	ID string
	// Name is the plain-words name.
	Name string
	// SecframeworkID is the framework string internal/secframework uses for
	// the same publication; secassesssvc/drift_test.go pins the two together.
	SecframeworkID string
	// IDPrefix is the prefix of a category id (LLM01, ASI04).
	IDPrefix string
}

// AIFrameworks lists the two AI-application frameworks.
var AIFrameworks = []AIFramework{
	{FrameworkOWASPLLM, "OWASP Top 10 for LLM applications", "owasp-llm-2026", "LLM"},
	{FrameworkOWASPAgentic, "OWASP Top 10 for agentic applications", "owasp-agentic-2026", "ASI"},
}

// AIFrameworkByID returns the AI framework with the given id.
func AIFrameworkByID(id string) (AIFramework, bool) {
	for _, f := range AIFrameworks {
		if f.ID == id {
			return f, true
		}
	}
	return AIFramework{}, false
}

// ValidAICategory reports whether cat has the shape of a category id of the
// framework: the framework's prefix and the digits 01 to 10.
func ValidAICategory(framework, cat string) bool {
	f, ok := AIFrameworkByID(framework)
	if !ok {
		return false
	}
	n, ok := cutPrefix(cat, f.IDPrefix)
	if !ok || len(n) != 2 || !allDigits(n) {
		return false
	}
	v := int(n[0]-'0')*10 + int(n[1]-'0')
	return v >= 1 && v <= 10
}
