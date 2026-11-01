package extrun

import "strings"

// DeclaresProcess reports whether a component's Surface.Processes entries
// (internal/components) declare the program at path. The entries are short
// phrases ("git (read-only log)", "codex app-server, kiro-cli, amp, auggie
// (only for ...)"), so an entry declares a program when one of its words,
// split on anything that is not a letter, digit, dot, dash or underscore,
// equals the program's file name without a Windows ".exe" (case-insensitive).
// A class phrase with no program name in it ("vendor AI tool CLIs") declares
// no specific program.
func DeclaresProcess(declared []string, path string) bool {
	want := ProcessName(path)
	if want == "" {
		return false
	}
	for _, entry := range declared {
		for _, word := range strings.FieldsFunc(strings.ToLower(entry), notNameRune) {
			if strings.TrimRight(word, ".") == want {
				return true
			}
		}
	}
	return false
}

// ProcessName is the declaration name of the program at path: its file name,
// lower-cased, without a trailing ".exe".
func ProcessName(path string) string {
	name := strings.ToLower(baseName(path))
	return strings.TrimSuffix(name, ".exe")
}

// notNameRune reports whether r cannot be part of a program name.
func notNameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
		return false
	}
	return true
}
