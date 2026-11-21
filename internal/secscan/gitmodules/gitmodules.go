package gitmodules

import (
	"path"
	"sort"
	"strings"
)

// FileName is the submodule declaration file's name.
const FileName = ".gitmodules"

// MaxFileBytes caps a .gitmodules file the caller reads (a real one is a
// few KB; a larger one is not read and its submodules are a gap).
const MaxFileBytes = 1 << 20

// maxEntries caps the submodules one file declares.
const maxEntries = 1024

// maxNameBytes caps a submodule's local name; a longer or unprintable name
// falls back to its path.
const maxNameBytes = 200

// Entry is one submodule a .gitmodules file declares: its section name and
// its path relative to the file's directory, forward slashes. The url is
// never read into it.
type Entry struct {
	Name string
	Path string
}

// Parse reads a .gitmodules body (git's config syntax): every
// `[submodule "<name>"]` section and its `path` key. Other sections and
// keys are skipped, the url among them; a section that names no valid
// relative path is dropped (CleanRel). Two sections with the same name are
// one submodule, the last path wins, as in git. The result is sorted by
// path, one entry per path.
func Parse(body []byte) []Entry {
	if len(body) > MaxFileBytes {
		body = body[:MaxFileBytes]
	}
	byName := map[string]string{}
	var order []string
	inSub := false
	name := ""
	for _, line := range logicalLines(string(body)) {
		s := strings.TrimSpace(line)
		if s == "" || s[0] == '#' || s[0] == ';' {
			continue
		}
		if s[0] == '[' {
			n, rest, isSub, ok := parseHeader(s)
			inSub, name = ok && isSub, n
			if inSub {
				if _, seen := byName[name]; !seen {
					if len(order) >= maxEntries {
						inSub = false
						continue
					}
					byName[name] = ""
					order = append(order, name)
				}
			}
			s = strings.TrimSpace(rest)
			if s == "" || s[0] == '#' || s[0] == ';' {
				continue
			}
		}
		if !inSub {
			continue
		}
		key, val, ok := parseKeyValue(s)
		if ok && strings.EqualFold(key, "path") {
			byName[name] = val
		}
	}
	byPath := map[string]Entry{}
	for _, n := range order {
		p, ok := CleanRel(byName[n])
		if !ok {
			continue
		}
		local := n
		if !printableName(local) {
			local = p
		}
		byPath[p] = Entry{Name: local, Path: p}
	}
	out := make([]Entry, 0, len(byPath))
	for _, e := range byPath {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// CleanRel returns p as a clean relative path with forward slashes, ok
// false for a path that is empty, absolute, holds a backslash, a drive
// letter, a NUL or a control character, or leaves its directory.
func CleanRel(p string) (string, bool) {
	if p == "" || len(p) > 4096 || strings.ContainsAny(p, "\\\x00") || strings.HasPrefix(p, "/") {
		return "", false
	}
	if len(p) >= 2 && p[1] == ':' {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return "", false
		}
	}
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

// printableName reports whether a section name is fit to show as a local
// package name: non-empty, at most maxNameBytes, no control character.
func printableName(n string) bool {
	if n == "" || len(n) > maxNameBytes {
		return false
	}
	for i := 0; i < len(n); i++ {
		if n[i] < 0x20 || n[i] == 0x7f {
			return false
		}
	}
	return true
}

// logicalLines splits a config body into lines, joining a line that ends
// in an odd number of backslashes with the next one (git's continuation)
// and dropping carriage returns.
func logicalLines(body string) []string {
	raw := strings.Split(strings.ReplaceAll(body, "\r", ""), "\n")
	var out []string
	var cur strings.Builder
	for _, l := range raw {
		n := 0
		for i := len(l) - 1; i >= 0 && l[i] == '\\'; i-- {
			n++
		}
		if n%2 == 1 {
			cur.WriteString(l[:len(l)-1])
			continue
		}
		cur.WriteString(l)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// parseHeader reads a section header at the start of s (s[0] == '['):
// `[submodule "name"]` (or git's older `[submodule.name]`). It returns the
// subsection name, the text after the closing bracket, whether the
// section is a submodule section, and ok false for a malformed header.
func parseHeader(s string) (name, rest string, isSub, ok bool) {
	i := 1
	for i < len(s) && s[i] != ']' && s[i] != '"' && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	section := s[1:i]
	if i < len(s) && s[i] == ']' {
		// [section] or the older [section.subsection].
		sec, sub, dotted := strings.Cut(section, ".")
		if !strings.EqualFold(sec, "submodule") || !dotted {
			return "", s[i+1:], false, true
		}
		return strings.ToLower(sub), s[i+1:], true, true
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) || s[i] != '"' {
		return "", "", false, false
	}
	i++
	var b strings.Builder
	for ; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if c == '"' {
			break
		}
		b.WriteByte(c)
	}
	if i >= len(s) || i+1 >= len(s) || s[i+1] != ']' {
		return "", "", false, false
	}
	return b.String(), s[i+2:], strings.EqualFold(section, "submodule"), true
}

// parseKeyValue reads `key = value` (or a bare key) from one logical line:
// the value unquoted, its escapes resolved (\n, \t, \b, \\ and \"), an
// unquoted # or ; starting a comment, and unquoted whitespace around it
// trimmed.
func parseKeyValue(s string) (key, val string, ok bool) {
	i := 0
	for i < len(s) && (isAlnum(s[i]) || s[i] == '-') {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	key = s[:i]
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) || s[i] == '#' || s[i] == ';' {
		return key, "", true
	}
	if s[i] != '=' {
		return "", "", false
	}
	i++
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	var b strings.Builder
	quoted := false
	space := 0
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			flushSpace(&b, &space)
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'b':
				b.WriteByte('\b')
			default:
				b.WriteByte(s[i])
			}
		case c == '"':
			flushSpace(&b, &space)
			quoted = !quoted
		case !quoted && (c == '#' || c == ';'):
			return key, b.String(), true
		case !quoted && (c == ' ' || c == '\t'):
			space++
		default:
			flushSpace(&b, &space)
			b.WriteByte(c)
		}
	}
	return key, b.String(), true
}

// flushSpace writes the unquoted whitespace held back so far (trailing
// whitespace is never written).
func flushSpace(b *strings.Builder, n *int) {
	for ; *n > 0; *n-- {
		b.WriteByte(' ')
	}
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
