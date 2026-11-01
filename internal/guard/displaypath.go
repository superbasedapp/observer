package guard

import "strings"

// HomeTilde rewrites every occurrence of the home directory in text to "~",
// so a guard event reason that names a file under the developer's home reads
// "~/.observer/org-policy-bundle.json" rather than an absolute path that also
// names the developer's account (D-704 gap 5). It is a display rewrite for
// reason text only; nothing that resolves or matches a path may use it.
//
// An occurrence is rewritten only when it is a whole path component run: the
// character before it must not continue a path (so "/mnt/home/u" is left
// alone for home "/home/u") and the character after it must end the
// component (so "/home/u2" is left alone). Both separator spellings of home
// are tried, so a Windows home also matches its forward-slash form. An empty
// or root home leaves text unchanged.
func HomeTilde(text, home string) string {
	home = strings.TrimRight(home, `/\`)
	if len(home) < 2 || text == "" {
		return text
	}
	forms := []string{home}
	if slashed := strings.ReplaceAll(home, `\`, "/"); slashed != home {
		forms = append(forms, slashed)
	}
	for _, h := range forms {
		text = tildeOne(text, h)
	}
	return text
}

// tildeOne rewrites the bounded occurrences of one spelling of home.
func tildeOne(text, home string) string {
	var b strings.Builder
	rest := text
	changed := false
	for {
		i := strings.Index(rest, home)
		if i < 0 {
			break
		}
		end := i + len(home)
		before := byte(0)
		if i > 0 {
			before = rest[i-1]
		}
		after := byte(0)
		if end < len(rest) {
			after = rest[end]
		}
		if continuesPath(before) || isPathNameByte(after) {
			b.WriteString(rest[:end])
			rest = rest[end:]
			continue
		}
		b.WriteString(rest[:i])
		b.WriteString("~")
		rest = rest[end:]
		changed = true
	}
	if !changed {
		return text
	}
	b.WriteString(rest)
	return b.String()
}

// continuesPath reports whether c, the byte before an occurrence, makes the
// occurrence the tail of a longer path (a name byte or a separator).
func continuesPath(c byte) bool {
	return c == '/' || c == '\\' || isPathNameByte(c)
}

// isPathNameByte reports whether c can continue a path component name (any
// byte of a multi-byte UTF-8 character counts, so "/home/u" never matches
// the front of "/home/u" followed by a non-ASCII letter).
func isPathNameByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.' || c == '_' || c == '-' || c >= 0x80:
		return true
	}
	return false
}
