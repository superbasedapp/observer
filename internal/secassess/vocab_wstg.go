package secassess

// The penetration test's method: twelve categories whose ids follow the OWASP
// Web Security Testing Guide, and the PTES phase order for the prompt. Titles
// and one-line intents are Observer's own words; the ids are as published.

// Grounding facts a category can depend on (a closed list; the grounding
// digest of a later wave sets them). A category whose fact is false for the
// project is "not applicable" rather than "skipped".
const (
	FactAlways        = "always"
	FactLogin         = "login"
	FactSessions      = "sessions"
	FactBrowserClient = "browser_client"
	FactHTTPAPI       = "http_api"
)

// GroundingFacts lists the closed fact vocabulary.
var GroundingFacts = []string{FactAlways, FactLogin, FactSessions, FactBrowserClient, FactHTTPAPI}

// WSTGCategory is one test category.
type WSTGCategory struct {
	// ID is the four-letter category id written in a finding's `category`.
	ID string
	// Title is the plain-words title.
	Title string
	// Intent is one line on what the category tests.
	Intent string
	// AppliesWhen is the grounding fact the category needs (FactAlways when
	// it applies to every web application).
	AppliesWhen string
	// CWEFamilies are the weakness ids the category typically yields.
	CWEFamilies []string
}

// WSTGCategories lists the twelve categories in test order.
var WSTGCategories = []WSTGCategory{
	{"INFO", "Information gathering", "What the target reveals about itself: versions, routes, files and metadata a visitor can read.", FactAlways, []string{"CWE-200", "CWE-209", "CWE-497", "CWE-538"}},
	{"CONF", "Configuration and deployment", "Default settings, exposed admin or debug interfaces, missing security headers and risky methods.", FactAlways, []string{"CWE-16", "CWE-1004", "CWE-548", "CWE-942"}},
	{"IDNT", "Identity management", "How accounts are created, named and told apart, and what the target gives away about which accounts exist.", FactLogin, []string{"CWE-204", "CWE-287", "CWE-521"}},
	{"ATHN", "Authentication", "Whether signing in can be bypassed, guessed or worn down, and how credentials are reset.", FactLogin, []string{"CWE-287", "CWE-307", "CWE-521", "CWE-640", "CWE-798"}},
	{"ATHZ", "Authorization", "Whether one user can reach another user's data or a higher role's functions.", FactLogin, []string{"CWE-22", "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"}},
	{"SESS", "Session management", "How session tokens are made, kept, expired and protected, and whether cross-site requests are stopped.", FactSessions, []string{"CWE-352", "CWE-384", "CWE-613", "CWE-614"}},
	{"INPV", "Input validation", "Whether data the caller controls can change a query, a command, a file path, a template or an outbound request.", FactAlways, []string{"CWE-20", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-611", "CWE-918"}},
	{"ERRH", "Error handling", "What failures reveal: stack traces, internal names, and inconsistent behaviour on bad input.", FactAlways, []string{"CWE-209", "CWE-703", "CWE-755"}},
	{"CRYP", "Weak cryptography", "Transport protection, weak algorithms, predictable values and handling of key material.", FactAlways, []string{"CWE-319", "CWE-326", "CWE-327", "CWE-328", "CWE-330"}},
	{"BUSL", "Business logic", "Whether the workflow can be used out of order, repeated, or bent to a result its owner did not intend.", FactAlways, []string{"CWE-770", "CWE-799", "CWE-840", "CWE-841"}},
	{"CLNT", "Client side", "Script injection, unsafe redirects, framing and cross-origin settings in what the browser receives.", FactBrowserClient, []string{"CWE-79", "CWE-346", "CWE-601", "CWE-1021"}},
	{"APIT", "API", "Object and function level access, mass assignment, rate limits and schema handling on the API routes.", FactHTTPAPI, []string{"CWE-213", "CWE-285", "CWE-639", "CWE-770", "CWE-915"}},
}

// WSTGCategoryByID returns the category with the given id.
func WSTGCategoryByID(id string) (WSTGCategory, bool) {
	for _, c := range WSTGCategories {
		if c.ID == id {
			return c, true
		}
	}
	return WSTGCategory{}, false
}

// PTESPhase is one phase of the penetration testing execution standard, as
// the prompt orders the work.
type PTESPhase struct {
	ID   string
	Name string
	// Bound is what the phase is limited to inside Observer's boundary.
	Bound string
}

// PTESPhases lists the phase order for the prompt. Post-exploitation is
// bounded to staying inside the target and the run directory.
var PTESPhases = []PTESPhase{
	{"scoping", "Scoping", "The only target is the address the developer confirmed."},
	{"intelligence", "Intelligence gathering", "Read the repository and the target's own responses; no other host."},
	{"threat_modelling", "Threat modelling", "A short list of the weaknesses worth testing for this application."},
	{"vulnerability_analysis", "Vulnerability analysis", "Find where a weakness could exist, from code and from responses."},
	{"exploitation", "Exploitation", "Prove a weakness with the smallest request that shows it; nothing destructive."},
	{"post_exploitation", "Post-exploitation", "Stay inside the target and the run directory; do not move to anything else."},
	{"reporting", "Reporting", "Write the report and the assessment file in the run directory."},
}
