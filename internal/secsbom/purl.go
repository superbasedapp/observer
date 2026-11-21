package secsbom

import (
	"regexp"
	"sort"
	"strings"
)

// purlRow is one ecosystem <-> purl type mapping with its name encoding.
type purlRow struct {
	// Ecosystem is the OSV ecosystem name as internal/secscan/depscan
	// spells it.
	Ecosystem string
	// Type is the purl type (lower case).
	Type string
	// normalize canonicalises a package name for this type in both
	// directions; nil keeps the name as is.
	normalize func(string) string
	// split turns an ecosystem package name into purl path segments
	// (namespace segments then the name) and an optional subpath; ok is
	// false when the name has no valid purl shape for this type.
	split func(name string) (segments []string, subpath string, ok bool)
	// join is split's reverse.
	join func(segments []string, subpath string) (string, bool)
}

// purlTable is THE one ecosystem <-> purl type table (plan section 3 "One
// purl table"). One row per ecosystem, one row per type.
//
// It is a superset of the build-tagged scalibrfacade.purlTypes table
// (facade.go, canary packages only), which agrees on every row it has: npm
// npm, PyPI pypi, crates.io cargo, Go golang, RubyGems gem, Packagist
// composer, NuGet nuget, Maven maven, Pub pub, SwiftURL swift, Hex hex,
// Hackage hackage, Julia julia, CRAN cran. The one difference: GitHub
// Actions has a row here (`pkg:githubactions`, the purl-spec type for an
// action) and none in purlTypes; the facade's own actions extractor
// (actions.go) builds its packages with SCALIBR's purl.TypeGithub
// ("github"), which names a GitHub repository rather than an action, so
// "github" is deliberately NOT read back as GitHub Actions here.
var purlTable = []purlRow{
	{Ecosystem: "npm", Type: "npm", split: splitPath, join: joinPath},
	{Ecosystem: "PyPI", Type: "pypi", normalize: normalizePyPI, split: splitPath, join: joinPath},
	{Ecosystem: "Go", Type: "golang", split: splitPath, join: joinPath},
	{Ecosystem: "crates.io", Type: "cargo", split: splitPath, join: joinPath},
	{Ecosystem: "RubyGems", Type: "gem", split: splitPath, join: joinPath},
	{Ecosystem: "Packagist", Type: "composer", normalize: strings.ToLower, split: splitPath, join: joinPath},
	{Ecosystem: "NuGet", Type: "nuget", split: splitPath, join: joinPath},
	{Ecosystem: "Maven", Type: "maven", split: splitMaven, join: joinMaven},
	{Ecosystem: "Pub", Type: "pub", normalize: strings.ToLower, split: splitPath, join: joinPath},
	{Ecosystem: "Hex", Type: "hex", normalize: strings.ToLower, split: splitPath, join: joinPath},
	{Ecosystem: "Hackage", Type: "hackage", split: splitPath, join: joinPath},
	{Ecosystem: "SwiftURL", Type: "swift", split: splitPath, join: joinPath},
	{Ecosystem: "Julia", Type: "julia", split: splitPath, join: joinPath},
	{Ecosystem: "CRAN", Type: "cran", split: splitPath, join: joinPath},
	{Ecosystem: "GitHub Actions", Type: "githubactions", split: splitAction, join: joinAction},
}

var (
	byEcosystem = map[string]*purlRow{}
	byType      = map[string]*purlRow{}
)

func init() {
	for i := range purlTable {
		r := &purlTable[i]
		byEcosystem[r.Ecosystem] = r
		byType[r.Type] = r
	}
}

// Ecosystems returns every ecosystem the purl table maps, sorted.
func Ecosystems() []string {
	out := make([]string, 0, len(purlTable))
	for _, r := range purlTable {
		out = append(out, r.Ecosystem)
	}
	sort.Strings(out)
	return out
}

// PurlType returns the purl type of an OSV ecosystem; ok is false when the
// ecosystem has no row.
func PurlType(ecosystem string) (string, bool) {
	r, ok := byEcosystem[ecosystem]
	if !ok {
		return "", false
	}
	return r.Type, true
}

// EcosystemForType returns the OSV ecosystem of a purl type (matched case
// insensitively); ok is false when the type has no row.
func EcosystemForType(purlType string) (string, bool) {
	r, ok := byType[strings.ToLower(purlType)]
	if !ok {
		return "", false
	}
	return r.Ecosystem, true
}

// PurlFor returns the package URL of one package version: the ecosystem's
// purl type, the name split into namespace and name the way the type
// spells it (npm "@scope/name" -> "pkg:npm/%40scope/name", Maven
// "group:artifact" -> "pkg:maven/group/artifact", a Go module path as
// namespace/name, GitHub Actions "owner/repo[/path]" ->
// "pkg:githubactions/owner/repo[#path]"), each segment percent-encoded, and
// "@version" when the version is not empty. ok is false for an ecosystem
// with no row, an empty name, or a name with no valid shape for the type
// (a Maven name without exactly one colon).
func PurlFor(ecosystem, name, version string) (string, bool) {
	r, ok := byEcosystem[ecosystem]
	if !ok || name == "" {
		return "", false
	}
	if r.normalize != nil {
		name = r.normalize(name)
	}
	segs, sub, ok := r.split(name)
	if !ok {
		return "", false
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(r.Type)
	for _, s := range segs {
		b.WriteByte('/')
		b.WriteString(escape(s))
	}
	if version != "" {
		b.WriteByte('@')
		b.WriteString(escape(version))
	}
	if sub != "" {
		b.WriteByte('#')
		parts := strings.Split(sub, "/")
		for i, p := range parts {
			parts[i] = escape(p)
		}
		b.WriteString(strings.Join(parts, "/"))
	}
	return b.String(), true
}

// ParsePurl reads a package URL back to the OSV ecosystem, package name and
// version (PurlFor's reverse). Qualifiers are ignored; a subpath is kept
// only where the type carries one in the name (GitHub Actions). ok is false
// for text that is not a purl, a type with no row, or a malformed
// percent-encoding.
func ParsePurl(p string) (ecosystem, name, version string, ok bool) {
	if len(p) < 4 || !strings.EqualFold(p[:4], "pkg:") {
		return "", "", "", false
	}
	rest := strings.TrimLeft(p[4:], "/")
	var sub string
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest, sub = rest[:i], strings.Trim(rest[i+1:], "/")
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	// The version separator is the last "@" after the last "/", so an
	// unencoded npm scope ("pkg:npm/@scope/name@1") still reads.
	if i := strings.LastIndexByte(rest, '@'); i >= 0 && i > strings.LastIndexByte(rest, '/') {
		v, good := unescape(rest[i+1:])
		if !good {
			return "", "", "", false
		}
		rest, version = rest[:i], v
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", "", "", false
	}
	r, found := byType[strings.ToLower(rest[:slash])]
	if !found {
		return "", "", "", false
	}
	var segs []string
	for _, s := range strings.Split(rest[slash+1:], "/") {
		if s == "" {
			continue
		}
		d, good := unescape(s)
		if !good {
			return "", "", "", false
		}
		segs = append(segs, d)
	}
	if len(segs) == 0 {
		return "", "", "", false
	}
	var subParts []string
	for _, s := range strings.Split(sub, "/") {
		if s == "" || s == "." || s == ".." {
			continue
		}
		d, good := unescape(s)
		if !good {
			return "", "", "", false
		}
		subParts = append(subParts, d)
	}
	name, ok = r.join(segs, strings.Join(subParts, "/"))
	if !ok || name == "" {
		return "", "", "", false
	}
	if r.normalize != nil {
		name = r.normalize(name)
	}
	return r.Ecosystem, name, version, true
}

// splitPath splits a name on "/" (npm scopes, Go module paths, Packagist
// vendor/name, SwiftURL host/owner/repo; a flat name is one segment).
func splitPath(name string) ([]string, string, bool) {
	segs := strings.Split(name, "/")
	for _, s := range segs {
		if s == "" {
			return nil, "", false
		}
	}
	return segs, "", true
}

// joinPath is splitPath's reverse; a subpath is not part of these names.
func joinPath(segs []string, _ string) (string, bool) {
	return strings.Join(segs, "/"), true
}

// splitMaven turns "group:artifact" into the namespace group and the name
// artifact.
func splitMaven(name string) ([]string, string, bool) {
	group, artifact, ok := strings.Cut(name, ":")
	if !ok || group == "" || artifact == "" || strings.Contains(artifact, ":") {
		return nil, "", false
	}
	return []string{group, artifact}, "", true
}

// joinMaven is splitMaven's reverse; a namespace written in several path
// segments is read as one dotted group id.
func joinMaven(segs []string, _ string) (string, bool) {
	if len(segs) < 2 {
		return "", false
	}
	return strings.Join(segs[:len(segs)-1], ".") + ":" + segs[len(segs)-1], true
}

// splitAction turns "owner/repo[/path...]" into the namespace owner, the
// name repo and the subpath path.
func splitAction(name string) ([]string, string, bool) {
	parts := strings.Split(name, "/")
	if len(parts) < 2 {
		return nil, "", false
	}
	for _, p := range parts {
		if p == "" {
			return nil, "", false
		}
	}
	return parts[:2], strings.Join(parts[2:], "/"), true
}

// joinAction is splitAction's reverse.
func joinAction(segs []string, sub string) (string, bool) {
	if len(segs) != 2 {
		return "", false
	}
	name := segs[0] + "/" + segs[1]
	if sub != "" {
		name += "/" + sub
	}
	return name, true
}

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// normalizePyPI is the PEP 503 name normalisation the pypi purl type
// requires: lower case, runs of "-", "_" and "." become one "-".
func normalizePyPI(name string) string {
	return pypiSeparators.ReplaceAllString(strings.ToLower(name), "-")
}

const upperHex = "0123456789ABCDEF"

// escape percent-encodes one purl component: everything but the unreserved
// characters and ":" (which the purl spec leaves unencoded).
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&15])
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~' || c == ':'
}

// unescape decodes %XX sequences; ok is false for a malformed one.
func unescape(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		hi, ok1 := fromHex(s[i+1])
		lo, ok2 := fromHex(s[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), true
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
