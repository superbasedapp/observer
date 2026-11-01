package secdetect

import (
	"strconv"
	"strings"
)

// The templated line an agent reads in a hook deny or ask (security plan
// section 6.1, "Inside the agent"): built only from rule data, with the one
// piece of repository-controlled text (the file name) quoted, cut to 80
// characters and stripped of anything outside a safe character set. The
// agent line is at most MaxAgentLineBytes (the access-grants convention);
// a second line is addressed to the HUMAN about exceptions, so the agent is
// never told to approve or request its own exception (R-165 covers that).

const (
	// MaxAgentLineBytes caps the agent-facing line.
	MaxAgentLineBytes = 200
	// MaxLocationBytes caps the quoted location.
	MaxLocationBytes = 80
	// MaxDenyTextBytes caps the whole text (the agent line, a space and
	// the human line).
	MaxDenyTextBytes = 2*MaxAgentLineBytes + 1
)

// DenyInput is the rule data a deny text is built from.
type DenyInput struct {
	// RuleID is the guard rule id ("S-721").
	RuleID string
	// Verb is what happened ("blocked", "held").
	Verb string
	// Subject is what was stopped ("this write", "this commit").
	Subject string
	// Type is the detector type (Hit.Type); it is rendered through the
	// typeWords table, never verbatim from the content.
	Type string
	// Path is the repository-relative path (repository-controlled: it is
	// sanitized and quoted).
	Path string
	// Line is the 1-based line (0: not known).
	Line int
	// Confidence is the hit's confidence.
	Confidence Confidence
	// FixHint is the rule's one-line fix hint.
	FixHint string
	// HumanLine is the line addressed to the developer about exceptions.
	HumanLine string
}

// typeWords renders detector types in words; an unknown type renders as
// "a secret".
var typeWords = map[string]string{ //nolint:gosec // G101: detector names mapped to plain words, not credentials
	"aws_access_key":             "an AWS access key id",
	"aws_secret_key":             "an AWS secret access key",
	"github_pat":                 "a GitHub token",
	"github_pat_fine":            "a GitHub fine-grained token",
	"gcp_api_key":                "a Google API key",
	"slack_token":                "a Slack token",
	"private_key_block":          "a private key",
	"bearer_token":               "a bearer token",
	"api_key_prefixed":           "an API key",
	"api_key_named":              "an API key",
	"api_key_assignment":         "an API key",
	"json_secret_value":          "a secret value",
	"env_secret_value":           "a secret value",
	"secret_assignment":          "a secret value",
	"export_secret":              "an exported secret",
	"connection_string_password": "a password in a connection string",
	"jwt":                        "a JSON web token",
	"entropy":                    "a high-entropy string",
}

// TypeWords renders a detector type in words ("a GitHub token"); an
// unknown type renders as "a secret". It is the one owner of the words the
// deny text and the security feedback line (internal/secfeedback) use.
func TypeWords(t string) string {
	if w := typeWords[t]; w != "" {
		return w
	}
	return "a secret"
}

// DefaultSecretFixHint is S-721's fix hint.
const DefaultSecretFixHint = "Move the value to an environment variable and retry." //nolint:gosec // G101: advice wording, not a credential

// DefaultHumanLine is the exception line addressed to the developer.
const DefaultHumanLine = "If this is a test fixture, the developer can request an exception on Code security > Findings."

// DenyText renders in as the agent line followed by the human line.
func DenyText(in DenyInput) string {
	what := typeWords[in.Type]
	if what == "" {
		what = "a secret"
	}
	verb := safeWord(in.Verb, "blocked")
	subject := safeWords(in.Subject, "this write")
	var b strings.Builder
	b.WriteString("observer: ")
	b.WriteString(safeRuleID(in.RuleID))
	b.WriteString(" " + verb + " " + subject + ": it adds " + what)
	if loc := SanitizeLocation(in.Path); loc != "" {
		b.WriteString(" at " + strconv.Quote(loc))
		if in.Line > 0 {
			b.WriteString(":" + strconv.Itoa(in.Line))
		}
	}
	if in.Confidence != "" {
		b.WriteString(" (" + string(in.Confidence) + " confidence)")
	}
	b.WriteString(".")
	if hint := safeSentence(in.FixHint); hint != "" {
		b.WriteString(" " + hint)
	}
	agent := capBytes(b.String(), MaxAgentLineBytes)
	human := safeSentence(in.HumanLine)
	if human == "" {
		return agent
	}
	return capBytes(agent+" "+capBytes(human, MaxAgentLineBytes), MaxDenyTextBytes)
}

// SanitizeLocation returns p with every byte outside letters, digits, '/',
// '.', '_' and '-' removed (backslashes become '/'), cut to
// MaxLocationBytes keeping the end (the file name), with a leading "..."
// when cut.
func SanitizeLocation(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '\\':
			b.WriteByte('/')
		case safeLocationByte(c):
			b.WriteByte(c)
		}
	}
	s := b.String()
	if len(s) > MaxLocationBytes {
		s = "..." + s[len(s)-(MaxLocationBytes-3):]
	}
	return s
}

func safeLocationByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '/' || c == '.' || c == '_' || c == '-'
}

// safeRuleID keeps a rule id to [A-Z0-9-] (at most 16 bytes).
func safeRuleID(id string) string {
	var b strings.Builder
	for i := 0; i < len(id) && b.Len() < 16; i++ {
		c := id[i]
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "S-7xx"
	}
	return b.String()
}

// safeWord keeps one lowercase word, else def.
func safeWord(w, def string) string {
	for i := 0; i < len(w); i++ {
		if c := w[i]; c < 'a' || c > 'z' {
			return def
		}
	}
	if w == "" || len(w) > 16 {
		return def
	}
	return w
}

// safeWords keeps a short phrase of letters and spaces, else def.
func safeWords(w, def string) string {
	if w == "" || len(w) > 32 {
		return def
	}
	for i := 0; i < len(w); i++ {
		c := w[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != ' ' {
			return def
		}
	}
	return w
}

// safeSentence keeps printable ASCII without quotes or backticks (rule data
// is trusted, but a sentence is still bounded and single-line).
func safeSentence(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f && c != '"' && c != '`' {
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// capBytes cuts s to at most n bytes (ASCII only by construction).
func capBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
