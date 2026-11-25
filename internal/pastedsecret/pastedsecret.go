package pastedsecret

import (
	"strings"
	"unicode"
)

// The bracketed-paste markers a terminal wraps a paste in.
const (
	pasteStart = "\x1b[200~"
	pasteEnd   = "\x1b[201~"
)

// Clean removes what a paste wraps around a secret: the bracketed-paste
// markers wherever they are, then any whitespace, control character,
// byte-order mark or zero-width character at either end. A character inside
// the secret is left for the caller's own shape check to judge.
func Clean(raw string) string {
	s := strings.ReplaceAll(raw, pasteStart, "")
	s = strings.ReplaceAll(s, pasteEnd, "")
	return strings.TrimFunc(s, edgeJunk)
}

// edgeJunk is a character a paste carries around a secret.
func edgeJunk(r rune) bool {
	switch r {
	case '\uFEFF', '\u200B', '\u200C', '\u200D', '\u2060':
		return true
	}
	return unicode.IsSpace(r) || unicode.IsControl(r)
}
