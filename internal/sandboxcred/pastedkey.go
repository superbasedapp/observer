package sandboxcred

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/pastedsecret"
)

// pastedkey.go cleans a key pasted at `observer sandbox credentials add` and
// names the one rule a bad key breaks (live run 2026-11-19, defect D9: from
// Windows PowerShell through `wsl.exe -- observer sandbox credentials add`,
// valid anthropic and xai keys were refused two and three times with one
// message listing every rule, so nobody could tell which one failed). A
// terminal paste can carry the bracketed-paste markers (ESC[200~ before,
// ESC[201~ after) when the console has bracketed paste turned on, a CR or
// LF the clipboard held, a byte-order mark, or nothing at all when an Enter
// arrived before the paste did. Nothing here ever returns or quotes the key.

// MaxKeyLen is the longest key accepted, in bytes.
const MaxKeyLen = 4096

// CleanPastedKey removes what a terminal paste wraps around a key: the
// bracketed-paste markers wherever they are, then any whitespace, control
// character, byte-order mark or zero-width character at either end. A
// character inside the key is left for KeyProblem to judge.
// The rule's one owner is internal/pastedsecret (shared with `observer sdk
// use-key`); this is its sandbox-credential name.
func CleanPastedKey(raw string) string { return pastedsecret.Clean(raw) }

// keyRule is one row of the key check: the rule's plain words and whether
// a key breaks it.
type keyRule struct {
	problem string
	breaks  func(string) bool
}

// keyRules is the check, in order; the first broken rule is the one named.
var keyRules = []keyRule{
	{"nothing was read (the key is empty)", func(k string) bool { return k == "" }},
	{"it is longer than 4096 bytes", func(k string) bool { return len(k) > MaxKeyLen }},
	{"it holds a line break", func(k string) bool { return strings.ContainsAny(k, "\r\n") }},
	{"it holds a space", func(k string) bool { return strings.IndexFunc(k, unicode.IsSpace) >= 0 }},
	{"it holds a control character", func(k string) bool { return strings.IndexFunc(k, unicode.IsControl) >= 0 }},
	{"it is not valid UTF-8 text", func(k string) bool { return !utf8.ValidString(k) }},
	{"it is an Observer sentinel, not a provider's key", IsSentinel},
}

// KeyProblem names the first rule key breaks, or "" for a usable key. It
// never includes the key.
func KeyProblem(key string) string {
	for _, r := range keyRules {
		if r.breaks(key) {
			return r.problem
		}
	}
	return ""
}
