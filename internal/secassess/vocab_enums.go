package secassess

import "strings"

// Closed enums of the model schemas (validator row V5) and the presets the
// settings pickers name (a list-valued setting is a picker over named presets,
// never free text).

// Enum is a closed list of ids.
type Enum []string

// Has reports whether v is in the list.
func (e Enum) Has(v string) bool {
	for _, x := range e {
		if x == v {
			return true
		}
	}
	return false
}

// The enums of the threat model schema.
var (
	EnumSensitivity = Enum{"public", "internal", "confidential", "restricted"}
	EnumActorKind   = Enum{"end_user", "admin", "service", "third_party", "anonymous"}
	EnumEntryKind   = Enum{"http_route", "rpc", "cli", "message", "file", "webhook", "scheduled", "ui", "other"}
	EnumAuthn       = Enum{"none", "session", "token", "api_key", "mtls", "basic", "other", "unknown"}
	EnumExposure    = Enum{"internet", "internal_network", "local_only", "unknown"}
	EnumEncrypted   = Enum{"yes", "no", "unknown"}
	EnumThreatState = Enum{"identified", "mitigated", "partial", "accepted_by_design"}
	EnumEffort      = Enum{"s", "m", "l"}
	EnumElementKind = Enum{"component", "actor", "flow", "entry_point", "asset"}
	EnumTreeOp      = Enum{"and", "or"}
)

// The enums of the penetration test schema.
var (
	EnumCoverageStatus = Enum{"tested", "skipped", "not_applicable", "tool_unavailable"}
	EnumBasis          = Enum{"observed", "inferred"}
	EnumFindingState   = Enum{"open", "mitigated", "accepted_by_design"}
	// EnumChainResult is how one step of a red team exercise's chain went.
	EnumChainResult = Enum{"achieved", "partly", "blocked"}
)

// Band is the inherent risk band of a rating: an ordinal heuristic over
// likelihood and impact, not a probability and not a score of residual risk.
type Band string

// The bands.
const (
	BandLow      Band = "low"
	BandMedium   Band = "medium"
	BandHigh     Band = "high"
	BandCritical Band = "critical"
)

// Bands lists the bands from lowest to highest.
var Bands = []Band{BandLow, BandMedium, BandHigh, BandCritical}

// ValidRating reports whether both parts of r are in 1..5.
func ValidRating(r Rating) bool {
	return r.Likelihood >= 1 && r.Likelihood <= 5 && r.Impact >= 1 && r.Impact <= 5
}

// Score is likelihood times impact (1..25), 0 for an invalid rating.
func (r Rating) Score() int {
	if !ValidRating(r) {
		return 0
	}
	return r.Likelihood * r.Impact
}

// BandOf returns the band of a rating: low 1-6, medium 7-12, high 13-19,
// critical 20-25 (likelihood times impact). The empty band for an invalid
// rating.
func BandOf(r Rating) Band {
	switch s := r.Score(); {
	case s == 0:
		return ""
	case s <= 6:
		return BandLow
	case s <= 12:
		return BandMedium
	case s <= 19:
		return BandHigh
	default:
		return BandCritical
	}
}

// BandRank orders the bands (low 1 .. critical 4, 0 for an unknown word).
func BandRank(b Band) int {
	for i, x := range Bands {
		if x == b {
			return i + 1
		}
	}
	return 0
}

// Preset is one named choice of a list-valued setting.
type Preset struct {
	ID      string
	Name    string
	Members []string
}

// FrameworkPresets are the choices of the threat-model frameworks setting.
// STRIDE is in every one: it is the base of the analysis. LINDDUN applies to
// personal-data flows and the AI frameworks to an AI application, so a
// preset that includes them still asks for them only when the condition holds.
var FrameworkPresets = []Preset{
	{"all", "STRIDE, LINDDUN and the AI frameworks", []string{FrameworkSTRIDE, FrameworkLINDDUN, FrameworkOWASPLLM, FrameworkOWASPAgentic}},
	{"stride", "STRIDE only", []string{FrameworkSTRIDE}},
	{"stride_linddun", "STRIDE and LINDDUN", []string{FrameworkSTRIDE, FrameworkLINDDUN}},
	{"stride_ai", "STRIDE and the AI frameworks", []string{FrameworkSTRIDE, FrameworkOWASPLLM, FrameworkOWASPAgentic}},
}

// The threat-model method extras.
const (
	ExtraAbuseCases  = "abuse_cases"
	ExtraAttackTrees = "attack_trees"
)

// MethodExtraPresets are the choices of the threat-model method setting.
var MethodExtraPresets = []Preset{
	{"both", "Abuse cases and attack trees", []string{ExtraAbuseCases, ExtraAttackTrees}},
	{"abuse_cases", "Abuse cases only", []string{ExtraAbuseCases}},
	{"attack_trees", "Attack trees only", []string{ExtraAttackTrees}},
	{"neither", "Neither", nil},
}

// CategoryPresets are the choices of the penetration test categories setting.
var CategoryPresets = []Preset{
	{"all", "All twelve categories", []string{"INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS", "INPV", "ERRH", "CRYP", "BUSL", "CLNT", "APIT"}},
	{"web_no_api", "Web application without API testing", []string{"INFO", "CONF", "IDNT", "ATHN", "ATHZ", "SESS", "INPV", "ERRH", "CRYP", "BUSL", "CLNT"}},
	{"api_only", "API only", []string{"INFO", "CONF", "IDNT", "ATHN", "ATHZ", "INPV", "ERRH", "BUSL", "APIT"}},
	{"auth_access", "Authentication and access control only", []string{"IDNT", "ATHN", "ATHZ", "SESS"}},
}

// ResolvePreset returns the members of the preset with the given id in list,
// and whether the id names one. Members is a copy.
func ResolvePreset(list []Preset, id string) ([]string, bool) {
	for _, p := range list {
		if p.ID == id {
			return append([]string(nil), p.Members...), true
		}
	}
	return nil, false
}

// The enums of a reproduction request (depth plan W5b): a request a developer
// can send again, held to a closed method list, a restricted path and a header
// allow-list.
var (
	// EnumRequestMethod are the methods a reproduction request may use.
	EnumRequestMethod = Enum{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	// EnumRequestHeader are the header names (lower case) a reproduction request
	// may carry; any other is left out.
	EnumRequestHeader = Enum{
		"accept", "accept-language", "authorization", "cache-control", "content-type", "cookie",
		"if-modified-since", "if-none-match", "origin", "range", "referer", "user-agent",
		"x-api-key", "x-csrf-token", "x-forwarded-for", "x-http-method-override", "x-requested-with", "x-xsrf-token",
	}
	// EnumSecretHeader are the allowed header names whose value is a credential:
	// the name stays and the value is never kept.
	EnumSecretHeader = Enum{"authorization", "cookie", "x-api-key", "x-csrf-token", "x-xsrf-token"}
)

// ValidRequestPath reports whether s is a path and query a reproduction request
// may hold: one slash first (not two), at most capRequestPath characters, only
// the characters of a URL's path and query. A text that needs more (a space, a
// quote, an angle bracket) is written percent-encoded, as it travels.
func ValidRequestPath(s string) bool {
	if s == "" || len(s) > capRequestPath || s[0] != '/' || strings.HasPrefix(s, "//") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			strings.IndexByte("-._~:/?#[]@!$&'()*+,;=%", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

// maxHeaderName is the longest header name a reproduction request or an
// indicator may name, in bytes. Every place that shows a stored header name (the
// retest task and the plan's list of findings) cuts at this same length, so a
// name the check accepted is shown whole.
const maxHeaderName = 64

// ValidHeaderName reports whether s is an HTTP header name of the plain kind a
// reproduction request or an indicator names.
func ValidHeaderName(s string) bool {
	if s == "" || len(s) > maxHeaderName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
			return false
		}
	}
	return true
}
