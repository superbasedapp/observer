package policy

import "strings"

// Path handling in this package is deliberately OS-AGNOSTIC: it never
// uses path/filepath (whose semantics depend on the daemon's runtime
// GOOS) because the daemon's OS and the analyzed client's OS can
// differ (Linux daemon + Windows client via the WSL bridge, and vice
// versa). The same Event must produce the same Verdict everywhere, so
// flavor detection is derived from the path STRING itself: drive
// letters / backslashes / UNC prefixes mean Windows shape, everything
// else POSIX shape. Resolution is purely lexical — no symlink or
// case-folding filesystem truth is consulted (no I/O); that residual
// gap is the documented F1-class caveat.

// isWindowsPath reports whether p is Windows-shaped: a drive-letter
// prefix ("C:"), a backslash separator anywhere, or a UNC prefix.
func isWindowsPath(p string) bool {
	if len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0]) {
		return true
	}
	return strings.Contains(p, `\`) || strings.HasPrefix(p, `\\`)
}

// isASCIILetter reports whether c is an ASCII letter.
func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isAbsPath reports whether p is absolute in either flavor: a leading
// "/" (POSIX), a drive-letter prefix, or a UNC prefix.
func isAbsPath(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0])
}

// normPath converts p to the canonical comparable form used
// throughout this package: forward slashes only, repeated separators
// collapsed, "." segments dropped, ".." resolved lexically (clamped
// at the root for absolute paths, preserved when they would escape a
// relative path), drive letters lowercased, and trailing separators
// trimmed (except on a bare root). A preserved leading "~" segment
// passes through so unexpanded home-relative forms remain matchable.
//
// A UNC path (`\\server\share\x`, WINNODE item 2) keeps its leading `\\`
// and has forward slashes after it (`\\server/share/x`): folding it to
// `/server/share/x`, as this function once did, made a network share look
// like a POSIX path, so it never compared against a Windows project root and
// a recursive delete of a share was allowed. The share (`\\server/share`) is
// its root: ".." clamps there. An extended-length prefix (`\\?\`) is
// dropped, so `\\?\C:\x` is `c:/x` and `\\?\UNC\server\share` is the UNC
// path. Only the backslash spelling is UNC: a POSIX `//x` stays `/x`.
func normPath(p string) string {
	if p == "" {
		return ""
	}
	if rest, ok := strings.CutPrefix(p, `\\?\`); ok {
		p = rest
		if hasFoldPrefix(p, `UNC\`) {
			p = `\\` + p[4:]
		}
	}
	if rest, ok := strings.CutPrefix(p, uncPrefix); ok {
		return normUNC(rest)
	}
	s := strings.ReplaceAll(p, `\`, "/")
	drive := ""
	if len(s) >= 2 && s[1] == ':' && isASCIILetter(s[0]) {
		drive = strings.ToLower(s[:2])
		s = s[2:]
	}
	rooted := strings.HasPrefix(s, "/")
	segs := strings.Split(s, "/")
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		switch seg {
		case "", ".":
			continue
		case "..":
			if n := len(out); n > 0 && out[n-1] != ".." {
				out = out[:n-1]
			} else if !rooted && drive == "" {
				out = append(out, "..")
			}
			// ".." at an absolute root clamps (deleting above /
			// is still deleting /).
		default:
			out = append(out, seg)
		}
	}
	joined := strings.Join(out, "/")
	switch {
	case drive != "" && rooted:
		return drive + "/" + joined
	case drive != "":
		if joined == "" {
			return drive
		}
		return drive + "/" + joined // treat drive-relative as drive-rooted (lexical best effort)
	case rooted:
		return "/" + joined
	default:
		return joined
	}
}

// uncPrefix is the leading `\\` a normalized UNC path keeps (normPath).
const uncPrefix = `\\`

// normUNC normalizes the part of a UNC path after its `\\`: forward
// slashes, "." and empty segments dropped, ".." resolved lexically and
// clamped at the share (the first two segments are the server and share).
func normUNC(rest string) string {
	segs := strings.Split(strings.ReplaceAll(rest, `\`, "/"), "/")
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(out) > 2 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	return uncPrefix + strings.Join(out, "/")
}

// isUNCPath reports whether p names a UNC location (normalized or raw).
func isUNCPath(p string) bool {
	return strings.HasPrefix(normPath(p), uncPrefix)
}

// expandHome rewrites a leading home reference — "~", "~/", "$HOME",
// "%USERPROFILE%" (any case) — to the injected home directory. When
// home is empty the reference is left in place, which still matches
// the "~/"-anchored pattern tables (graceful degradation, documented
// in engine.go).
func expandHome(p, home string) string {
	if home == "" {
		return p
	}
	rest, ok := splitHomePrefix(p)
	if !ok {
		return p
	}
	if rest == "" {
		return home
	}
	return home + "/" + rest
}

// homePrefixes are the home-directory spellings a path may start with:
// the POSIX shells' ~, $HOME and ${HOME} (quoting is already stripped by
// the lexer, so "${HOME}" arrives as ${HOME}), cmd's %USERPROFILE% and
// PowerShell's $env:USERPROFILE / ${env:USERPROFILE} (PowerShell's own
// $HOME is the same spelling as the POSIX one). Matching is
// case-insensitive (hasFoldPrefix).
var homePrefixes = [...]string{
	"~", "${HOME}", "$HOME", "%USERPROFILE%",
	"${env:USERPROFILE}", "$env:USERPROFILE",
}

// splitHomePrefix strips a recognized home-reference prefix from p and
// returns the remainder (without its leading separator). ok is false
// when p carries no home prefix.
func splitHomePrefix(p string) (rest string, ok bool) {
	for _, pre := range homePrefixes {
		if !hasFoldPrefix(p, pre) {
			continue
		}
		tail := p[len(pre):]
		if tail == "" {
			return "", true
		}
		if tail[0] == '/' || tail[0] == '\\' {
			return tail[1:], true
		}
	}
	return "", false
}

// shellExpansions returns the [start, end) byte spans of the expansions
// in word that the shell performs and this pure package cannot: POSIX and
// PowerShell `$NAME`, `${...}` (PowerShell scope form `$env:NAME` too),
// positional `$1`; cmd `%NAME%`. A leading home spelling (homePrefixes) is
// resolved, not unresolved, and a character in lit (read from a
// single-quoted or escaped region, Command.ArgvLiterals) is literal text.
// Command substitutions never reach here: the parser strips them before
// lexing, which already reads them as empty.
func shellExpansions(word string, lit []int, d Dialect) [][2]int {
	start := 0
	if rest, ok := splitHomePrefix(word); ok {
		start = len(word) - len(rest)
	}
	isLit := func(i int) bool {
		for _, o := range lit {
			if o == i {
				return true
			}
		}
		return false
	}
	var spans [][2]int
	for i := start; i < len(word); i++ {
		if isLit(i) {
			continue
		}
		end := 0
		switch {
		case d == DialectCmd && word[i] == '%':
			if j := strings.IndexByte(word[i+1:], '%'); j > 0 && isEnvName(word[i+1:i+1+j]) {
				end = i + j + 2
			}
		case d != DialectCmd && word[i] == '$':
			end = dollarExpansionEnd(word, i, d)
		}
		if end > i {
			spans = append(spans, [2]int{i, end})
			i = end - 1
		}
	}
	return spans
}

// dollarExpansionEnd returns the end of the `$` expansion starting at i,
// or 0 when the `$` starts none.
func dollarExpansionEnd(word string, i int, d Dialect) int {
	if i+1 >= len(word) {
		return 0
	}
	c := word[i+1]
	switch {
	case c == '{':
		if j := strings.IndexByte(word[i+2:], '}'); j >= 0 {
			return i + 2 + j + 1
		}
		return len(word)
	case c >= '0' && c <= '9':
		return i + 2
	case c == '_' || isASCIILetter(c):
		j := i + 1
		for j < len(word) && isNameByte(word[j]) {
			j++
		}
		// PowerShell scope-qualified variable: $env:NAME, $global:x.
		if d == DialectPowerShell && j+1 < len(word) && word[j] == ':' && isNameByte(word[j+1]) {
			j++
			for j < len(word) && isNameByte(word[j]) {
				j++
			}
		}
		return j
	}
	return 0
}

func isNameByte(c byte) bool {
	return c == '_' || isASCIILetter(c) || (c >= '0' && c <= '9')
}

// withoutSpans returns word with every span removed: what the shell
// produces when each unresolved expansion is empty.
func withoutSpans(word string, spans [][2]int) string {
	var b strings.Builder
	prev := 0
	for _, sp := range spans {
		b.WriteString(word[prev:sp[0]])
		prev = sp[1]
	}
	b.WriteString(word[prev:])
	return b.String()
}

// isEnvName reports whether s is a plausible environment variable name.
func isEnvName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && !isASCIILetter(c) && (c < '0' || c > '9' || i == 0) {
			return false
		}
	}
	return s != ""
}

// hasFoldPrefix is a case-insensitive strings.HasPrefix (ASCII fold —
// path prefixes here are ASCII).
func hasFoldPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// resolvePath resolves target into the canonical comparable form:
// home references expanded, relative paths joined against cwd (or
// projectRoot when cwd is empty), then normalized. Returns "" when
// the path cannot be resolved (relative target with no anchor) —
// callers must treat "" as not-a-hit, never as a hit.
func resolvePath(target, home, cwd, projectRoot string) string {
	if target == "" {
		return ""
	}
	p := expandHome(target, home)
	if !isAbsPath(p) && !strings.HasPrefix(p, "~") {
		anchor := cwd
		if anchor == "" {
			anchor = projectRoot
		}
		if anchor == "" {
			return ""
		}
		p = strings.TrimRight(anchor, "/\\") + "/" + p
	}
	return normPath(p)
}

// comparableFlavors reports whether two normalized paths can be
// meaningfully compared: both Windows-shaped, both POSIX-shaped, or
// one Windows-shaped and the other the WSL drvfs mount of a drive
// (see alignFlavors). Any other mix means a missing crossmount
// translation at the boundary; rules treat that as unknown (no hit)
// rather than guessing.
func comparableFlavors(a, b string) bool {
	_, _, ok := alignFlavors(a, b)
	return ok
}

// drvfsFold rewrites a WSL drvfs mount path (`/mnt/c`, `/mnt/c/...`)
// to the drive form the same directory has on the Windows side
// (`c:/`, `c:/...`). Purely lexical, like everything in this file: the
// daemon stores a Windows tool's project root translated (`/mnt/c/x`)
// while the tool's own payload names files natively (`C:\x\f.go`), and
// both must compare as one location on any host.
func drvfsFold(p string) (string, bool) {
	if len(p) < 6 || !strings.HasPrefix(p, "/mnt/") || !isASCIILetter(p[5]) {
		return p, false
	}
	rest := p[6:]
	if rest != "" && rest[0] != '/' {
		return p, false // `/mnt/cache`: a directory, not a drive mount
	}
	if rest == "" {
		rest = "/"
	}
	return strings.ToLower(p[5:6]) + ":" + rest, true
}

// alignFlavors returns a and b in one comparable flavor: unchanged
// when they already share one, or with the POSIX side folded to its
// drive form when it is a drvfs mount and the other is Windows-shaped.
// ok is false when the two have no common flavor.
//
// A UNC path is comparable with every path: with another UNC path it is a
// Windows path like any other, and with a drive or POSIX path it never
// shares a location (isUnder and pathsEqual answer false), so the
// outside-the-project arms see a share as outside a drive or POSIX project,
// as they always saw it outside a POSIX one.
func alignFlavors(a, b string) (string, string, bool) {
	if isUNCPath(a) || isUNCPath(b) {
		return a, b, true
	}
	wa, wb := isWindowsPath(a), isWindowsPath(b)
	switch {
	case wa == wb:
		return a, b, true
	case wa:
		f, ok := drvfsFold(b)
		return a, f, ok
	default:
		f, ok := drvfsFold(a)
		return f, b, ok
	}
}

// pathsEqual reports whether two normalized paths refer to the same
// location, comparing case-insensitively when either is
// Windows-shaped.
func pathsEqual(a, b string) bool {
	a, b = normPath(a), normPath(b)
	var ok bool
	if a, b, ok = alignFlavors(a, b); !ok {
		return false
	}
	if foldCase(a, b) {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// foldCase reports whether two aligned paths compare case-insensitively:
// either is Windows-shaped and neither is UNC. UNC paths keep the
// case-sensitive comparison they had while normPath folded them to POSIX
// look-alikes, so no outside-the-project verdict on a share loosens
// (WINNODE item 2; a share named in two cases reads as two places).
func foldCase(a, b string) bool {
	return (isWindowsPath(a) || isWindowsPath(b)) && !isUNCPath(a) && !isUNCPath(b)
}

// isUnder reports whether child is root itself or lexically beneath
// it. Both arguments are normalized first; comparison is
// case-insensitive when either side is Windows-shaped. Mixed flavors
// are never under each other unless alignFlavors can fold them onto
// one (a drvfs mount against its drive).
func isUnder(child, root string) bool {
	c, r := normPath(child), normPath(root)
	if c == "" || r == "" {
		return false
	}
	var ok bool
	if c, r, ok = alignFlavors(c, r); !ok {
		return false
	}
	if foldCase(c, r) {
		c, r = strings.ToLower(c), strings.ToLower(r)
	}
	if c == r {
		return true
	}
	if !strings.HasSuffix(r, "/") {
		r += "/"
	}
	return strings.HasPrefix(c, r)
}

// isFilesystemRoot reports whether the normalized path is a
// filesystem root: "/", a bare drive ("c:", "c:/") or a bare UNC share
// (`\\server/share`, or the server alone).
func isFilesystemRoot(p string) bool {
	p = normPath(p)
	if p == "/" {
		return true
	}
	if rest, ok := strings.CutPrefix(p, uncPrefix); ok {
		return strings.Count(rest, "/") <= 1
	}
	return len(p) >= 2 && len(p) <= 3 && p[1] == ':' && isASCIILetter(p[0]) &&
		(len(p) == 2 || p[2] == '/')
}

// isRootDepthGlob reports whether the normalized path is a
// root-depth wildcard ("/*", "c:/*", `\\server/share/*` or "<home>/*"), the
// everything-at-once delete shapes R-101 treats as catastrophic.
func isRootDepthGlob(p, home string) bool {
	p = normPath(p)
	if p == "/*" || p == "~/*" {
		return true
	}
	if len(p) == 4 && p[1] == ':' && isASCIILetter(p[0]) && p[2] == '/' && p[3] == '*' {
		return true
	}
	if share, ok := strings.CutSuffix(p, "/*"); ok && strings.HasPrefix(share, uncPrefix) && isFilesystemRoot(share) {
		return true
	}
	return home != "" && pathsEqual(strings.TrimSuffix(p, "/*"), home) && strings.HasSuffix(p, "/*")
}

// baseName returns the final segment of a normalized path ("" for a
// bare root).
func baseName(p string) string {
	p = normPath(p)
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// hasComponent reports whether any path segment of the normalized
// path equals comp (case-insensitive on Windows-shaped paths). Used
// for ".git"-targeting detection.
func hasComponent(p, comp string) bool {
	n := normPath(p)
	ci := isWindowsPath(n)
	for _, seg := range strings.Split(n, "/") {
		if seg == comp || (ci && strings.EqualFold(seg, comp)) {
			return true
		}
	}
	return false
}

// matchGlob matches a normalized forward-slash path against a glob
// pattern supporting "*" and "?" within a segment and "**" as a
// zero-or-more-segments wildcard. Character classes ("[a-z]") are NOT
// supported — the policy pattern tables don't need them and keeping
// the matcher small keeps it auditable. ci selects ASCII
// case-insensitive matching (used for the sensitive-path tables: see
// rules_boundary.go for why that is always-on there).
func matchGlob(pattern, path string, ci bool) bool {
	pat, p := normPath(pattern), normPath(path)
	if ci {
		pat, p = strings.ToLower(pat), strings.ToLower(p)
	}
	return matchSegs(strings.Split(pat, "/"), strings.Split(p, "/"))
}

// matchSegs matches pattern segments against path segments,
// implementing the "**" zero-or-more-segments semantics recursively
// (pattern depth is small and bounded by the rule tables).
func matchSegs(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		if matchSegs(pat[1:], segs) {
			return true
		}
		if len(segs) > 0 {
			return matchSegs(pat, segs[1:])
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if !matchSeg(pat[0], segs[0]) {
		return false
	}
	return matchSegs(pat[1:], segs[1:])
}

// matchSeg matches one path segment against one pattern segment with
// "*" (any run) and "?" (any single byte) wildcards, using greedy
// star matching with backtracking. Byte-wise: non-ASCII segments
// compare by exact bytes, which is correct for the ASCII pattern
// tables this package ships.
func matchSeg(p, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// matchAnyGlob reports whether path matches any pattern in patterns.
func matchAnyGlob(patterns []string, path string, ci bool) bool {
	for _, pat := range patterns {
		if matchGlob(pat, path, ci) {
			return true
		}
	}
	return false
}

// looksPathish reports whether a shell token plausibly names a
// filesystem path worth resolving against the path rule tables: it
// contains a separator, or starts with a home/env home reference, or
// a dot-segment. Bare words ("config") are deliberately NOT pathish —
// resolving every word against the sensitive tables would be FP soup.
func looksPathish(tok string) bool {
	if tok == "" || strings.HasPrefix(tok, "-") {
		return false
	}
	if strings.ContainsAny(tok, `/\`) {
		return true
	}
	if _, ok := splitHomePrefix(tok); ok || strings.HasPrefix(tok, "~") {
		return true
	}
	return tok == "." || tok == ".." || strings.HasPrefix(tok, "./") || strings.HasPrefix(tok, "../")
}
