package codexpatch

import (
	"path"
	"strings"
)

// header.go resolves an apply_patch envelope's file headers (`*** Update
// File: pkg/a.go`), which Codex writes relative to the session's working
// directory (lane LEFT2-SEC item R-024, the L-106 residual). Two owners
// share it: the Codex adapter resolves the header it stores as an action's
// target against the turn's working directory (so the post-write scan reads
// the file the patch wrote, not a same-named file at the project root), and
// the lines-of-code key (internal/store) anchors the envelope's other
// relative headers with the directory that resolution reveals. Pure string
// work in either OS's spelling, never a filesystem lookup.

// IsAbsAnyOS reports whether p is absolute in either convention: a POSIX
// root, a Windows drive letter (`C:\`, `c:/`) or a UNC path (`\\host\share`).
// filepath.IsAbs alone answers for the host only, so a Linux daemon reading
// a Windows rollout (or the other way round) would misread one.
func IsAbsAnyOS(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0]
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	}
	return false
}

// windowsShaped reports whether a working directory is a Windows spelling.
func windowsShaped(dir string) bool {
	return strings.HasPrefix(dir, `\\`) || (len(dir) >= 2 && dir[1] == ':') || (strings.Contains(dir, `\`) && !strings.Contains(dir, "/"))
}

// headerRules is the resolution table, walked top-down (CLAUDE.md module
// rule 5); the first row whose test holds decides.
var headerRules = []struct {
	name    string
	when    func(header, cwd string) bool
	resolve func(header, cwd string) string
}{
	{"an empty header stays empty", func(h, _ string) bool { return strings.TrimSpace(h) == "" }, func(string, string) string { return "" }},
	{"an absolute header stays as written", func(h, _ string) bool { return IsAbsAnyOS(strings.TrimSpace(h)) }, func(h, _ string) string { return strings.TrimSpace(h) }},
	{"with no working directory a header stays as written", func(_, c string) bool { return strings.TrimSpace(c) == "" }, func(h, _ string) string { return strings.TrimSpace(h) }},
	{"a Windows working directory joins with backslashes", func(_, c string) bool { return windowsShaped(strings.TrimSpace(c)) }, func(h, c string) string {
		return strings.TrimRight(strings.TrimSpace(c), `\/`) + `\` + strings.ReplaceAll(strings.TrimSpace(h), "/", `\`)
	}},
	{"a POSIX working directory joins and cleans", func(string, string) bool { return true }, func(h, c string) string {
		return path.Join(strings.TrimSpace(c), strings.TrimSpace(h))
	}},
}

// ResolveHeader resolves one patch header against the session's working
// directory: an absolute header, or one with no working directory to
// resolve against, stays as written.
func ResolveHeader(header, cwd string) string {
	for _, r := range headerRules {
		if r.when(header, cwd) {
			return r.resolve(header, cwd)
		}
	}
	return header
}

// HeaderRuleNames lists the resolution table's rows in order (one test per
// row).
func HeaderRuleNames() []string {
	out := make([]string, 0, len(headerRules))
	for _, r := range headerRules {
		out = append(out, r.name)
	}
	return out
}

// slash turns a path into forward-slash form.
func slash(p string) string { return strings.ReplaceAll(strings.TrimSpace(p), `\`, "/") }

// HeaderBase returns the directory a relative header was resolved from,
// given the stored target it became (absolute or project-relative, either
// slash): the target with the header's own path cut from its end, ending
// in a slash, or "" when they are equal (the working directory was the
// root the target is relative to). ok is false when the header is absolute
// or the target does not end with it.
func HeaderBase(target, header string) (base string, ok bool) {
	t, h := slash(target), slash(header)
	if t == "" || h == "" || IsAbsAnyOS(h) {
		return "", false
	}
	h = strings.TrimPrefix(path.Clean("/"+h), "/")
	switch {
	case t == h:
		return "", true
	case strings.HasSuffix(t, "/"+h):
		return t[:len(t)-len(h)], true
	}
	return "", false
}

// AnchorHeader places a relative header under base (from HeaderBase); an
// absolute header, or an empty base, leaves it as written.
func AnchorHeader(base, header string) string {
	if base == "" || IsAbsAnyOS(strings.TrimSpace(header)) {
		return header
	}
	return base + strings.TrimPrefix(path.Clean("/"+slash(header)), "/")
}
