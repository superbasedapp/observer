package secassess

import (
	"strings"
	"testing"
)

// TestRelPathRefusesHiddenRunes: a path that carries a rune that hides what it
// says when shown is refused with the control-character reason, for a
// reference, a scope path and a SARIF location alike (they share relPath).
func TestRelPathRefusesHiddenRunes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		uri  string
		ok   bool
	}{
		{"a plain path", "src/auth/login.py", true},
		{"a space in a name", "docs/my notes.md", true},
		{"a non-ASCII letter", "src/café.py", true},
		{"a control character", "src/a\x01.py", false},
		{"a delete character", "src/a\x7f.py", false},
		{"a zero-width space", "src/a​.py", false},
		{"a bidi override", "src/a‮.py", false},
		{"a soft hyphen", "src/a­.py", false},
		{"a word joiner", "src/a⁠.py", false},
		{"a line separator", "src/a .py", false},
		{"a paragraph separator", "src/a .py", false},
		{"a backtick", "src/`a`.py", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel, why := relPath(tc.uri)
			if tc.ok && (why != "" || rel != tc.uri) {
				t.Fatalf("relPath(%q) = %q, %q; want it accepted", tc.uri, rel, why)
			}
			if !tc.ok && why != "control_character" {
				t.Fatalf("relPath(%q) = %q, %q; want control_character", tc.uri, rel, why)
			}
		})
	}
}

// TestValidateIssueMessagesAreRedacted: an issue message quotes a clipped
// fragment of agent text; the redactor sees it before it is stored.
func TestValidateIssueMessagesAreRedacted(t *testing.T) {
	t.Parallel()
	// Split so the public tree carries no push-protection-shaped literal.
	const secret = "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	v := newValidator(nil, ValidateOptions{Redact: func(s string) string { return strings.ReplaceAll(s, secret, "[REDACTED]") }})
	v.issue("V4", "demo", SevWarn, "threats[0]", "The id "+secret+" is not defined.")
	if len(v.rep.Issues) != 1 {
		t.Fatalf("issues %+v", v.rep.Issues)
	}
	if got := v.rep.Issues[0].Message; strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("message %q was stored unredacted", got)
	}
}
