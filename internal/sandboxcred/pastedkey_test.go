package sandboxcred

import (
	"strings"
	"testing"
)

// TestCleanPastedKeyAndKeyProblem: keys pasted through a terminal (D9) with
// the wrappers a console adds are cleaned to the key, and a bad key names
// its one broken rule, never the key.
func TestCleanPastedKeyAndKeyProblem(t *testing.T) {
	const key = "sk-ant-api03-AbC_dEf-123"
	cases := []struct {
		name    string
		raw     string
		want    string
		problem string
	}{
		{"plain", key, key, ""},
		{"trailing LF", key + "\n", key, ""},
		{"trailing CRLF", key + "\r\n", key, ""},
		{"bracketed paste", "\x1b[200~" + key + "\x1b[201~", key, ""},
		{"bracketed paste with CRLF inside the markers", "\x1b[200~" + key + "\r\n\x1b[201~\r", key, ""},
		{"only the end marker (a split read)", key + "\x1b[201~", key, ""},
		{"surrounding spaces and tabs", "  \t" + key + " \t", key, ""},
		{"byte-order mark and zero-width space", "\uFEFF" + key + "\u200B", key, ""},
		{"NUL and DEL at the ends", "\x00" + key + "\x7f", key, ""},
		{"xai key in markers", "\x1b[200~xai-ABCdef123456\x1b[201~", "xai-ABCdef123456", ""},
		{"empty", "", "", "nothing was read"},
		{"only an Enter (empty first read)", "\r", "", "nothing was read"},
		{"only the markers", "\x1b[200~\x1b[201~", "", "nothing was read"},
		{"a CR in the middle", "sk-ant\rapi03", "sk-ant\rapi03", "line break"},
		{"a LF in the middle", "sk-ant\napi03", "sk-ant\napi03", "line break"},
		{"two keys with a space", key + " " + key, key + " " + key, "a space"},
		{"an escape inside", "sk-\x1b[Dant", "sk-\x1b[Dant", "control character"},
		{"too long", strings.Repeat("a", MaxKeyLen+1), strings.Repeat("a", MaxKeyLen+1), "longer than 4096"},
		{"a sentinel", SentinelPrefix + "anthropic-x", SentinelPrefix + "anthropic-x", "sentinel"},
	}
	for _, c := range cases {
		got := CleanPastedKey(c.raw)
		if got != c.want {
			t.Errorf("%s: cleaned %q, want %q", c.name, got, c.want)
		}
		p := KeyProblem(got)
		if c.problem == "" && p != "" {
			t.Errorf("%s: refused: %s", c.name, p)
		}
		if c.problem != "" && !strings.Contains(p, c.problem) {
			t.Errorf("%s: problem %q, want %q", c.name, p, c.problem)
		}
		if got != "" && p != "" && strings.Contains(p, got) {
			t.Errorf("%s: the problem quotes the key", c.name)
		}
	}
}
