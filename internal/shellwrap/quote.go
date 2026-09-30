package shellwrap

import (
	"fmt"
	"regexp"
	"strings"
)

// commandNameRE is the closed spelling a replaced command name may take. A
// name is written as a FILE name in the shim directory and spliced into shim
// scripts, so anything outside this set (a path separator, a quote, a space,
// a shell metacharacter) is refused rather than escaped.
var commandNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// segmentRE is the closed spelling of a hand-off path segment rendered into a
// shim's case / findstr pattern.
var segmentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidCommandName reports whether name can be a shim file name.
func ValidCommandName(name string) bool {
	return commandNameRE.MatchString(name) && name != "observer"
}

// checkPath refuses a path that cannot be quoted safely into every script
// language this package renders: control characters (a newline would end a
// quoted string), and a double quote (never legal in a Windows path, and the
// one character a cmd.exe "..." string cannot carry).
func checkPath(p string) error {
	if p == "" {
		return fmt.Errorf("shellwrap: empty path")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '"' {
			return fmt.Errorf("shellwrap: path %q carries a character a shell script cannot quote safely", p)
		}
	}
	return nil
}

// shQuote single-quotes s for POSIX sh: every byte is literal inside '...',
// and an embedded quote is closed, escaped and reopened.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fishQuote single-quotes s for fish, where a backslash and a single quote
// are the only characters that need escaping inside single quotes.
func fishQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

// psQuote single-quotes s for PowerShell, where a quote is doubled.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// cmdLiteral renders s for use INSIDE a cmd.exe "..." string: a percent sign
// would start a variable expansion, so it is doubled. checkPath has already
// refused a double quote.
func cmdLiteral(s string) string {
	return strings.ReplaceAll(s, "%", "%%")
}
