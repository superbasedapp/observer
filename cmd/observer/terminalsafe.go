package main

import (
	"strings"
	"unicode"
)

// terminalSafe replaces every control character (an escape sequence a
// repository planted in a file name or a command, or a vendor API planted in
// an account field, would otherwise reach the developer's terminal) and every
// bidirectional formatting character with "?". It is untagged so every
// command that prints an untrusted string can reach it, whichever component
// set the binary was built with.
func terminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return '?'
		}
		return r
	}, s)
}
