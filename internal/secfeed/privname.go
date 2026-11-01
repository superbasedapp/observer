package secfeed

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/mod/module"
)

// privname.go is the private-name classifier (security plan section 8.3,
// ported from the JSP-11 prototype, which gave the expected verdict on all
// 44 names and 27 registry addresses): before any online lookup each name
// is classified from the project's package-manager configuration, read by
// the caller from fixed paths and from the daemon's own environment (never
// the agent's). A name is public-routable only when its effective registry
// is that ecosystem's public default and it matches no private scope;
// everything else is private (offline checks only) or invalid (a URL, a
// path or a git spec; never sent anywhere). The stated costs: a corporate
// mirror configured as the default registry makes every name private, pip's
// extra-index-url makes every name private, NuGet with several sources
// needs packageSourceMapping. Ecosystems without a row are private.

// classifyTable is the per-ecosystem classifier table.
var classifyTable = []struct {
	eco Ecosystem
	fn  func(string, PrivConfig) PrivResult
}{
	{EcoNpm, classifyNpm},
	{EcoPyPI, classifyPyPI},
	{EcoGo, classifyGo},
	{EcoCargo, classifyCargo},
	{EcoNuGet, classifyNuGet},
}

// PrivVerdict is the classifier's answer.
type PrivVerdict string

// The classifier verdicts.
const (
	// PrivPublic: may be sent to the public source.
	PrivPublic PrivVerdict = "public"
	// PrivPrivate: never sent; offline index only.
	PrivPrivate PrivVerdict = "private"
	// PrivInvalid: not a registry name at all (a URL, a path, a git spec);
	// never sent.
	PrivInvalid PrivVerdict = "invalid"
)

// PrivResult carries the verdict and the reason a person sees.
type PrivResult struct {
	Verdict PrivVerdict
	Reason  string
	Name    string // the normalized name that would be sent (Public only)
}

// PrivConfig is what the daemon read from fixed paths and its OWN environment
// (never the agent's), plus the org's private scopes on a managed node.
type PrivConfig struct {
	// npm: the effective .npmrc (project over user over global, then the
	// npm_config_ variables): default registry and per-scope registries
	// ("@corp" -> url). NpmExtraRegistries are other default registries a
	// name may resolve on (a .yarnrc.yml's npmRegistryServer).
	NpmRegistry        string
	NpmScopeRegistries map[string]string
	NpmExtraRegistries []string
	// PyPI: index-url and extra-index-url (pip.conf, PIP_INDEX_URL,
	// PIP_EXTRA_INDEX_URL, Poetry sources folded in).
	PipIndexURL       string
	PipExtraIndexURLs []string
	// Go: the go env values.
	GoPrivate, GoNoProxy, GoNoSumDB, GoProxy string
	// Cargo: whether crates-io is source-replaced, and the named registries.
	CargoReplaceCratesIO string
	// NuGet: sources and packageSourceMapping (pattern -> source key).
	NuGetSources map[string]string // key -> url
	NuGetMapping map[string]string // pattern ("Corp.*", "*") -> key
	// Org private scopes per ecosystem (managed nodes): prefixes or globs.
	OrgPrivate map[Ecosystem][]string
	// Unplaced lists ecosystems whose configuration could not be read or
	// parsed (the role that failed): every name there is private.
	Unplaced map[Ecosystem]string
}

// IsPublicDefault reports whether a registry address is exactly the
// ecosystem's public default: https, the exact host (case-insensitive, a
// trailing dot dropped), default port, no credentials. A lookalike, a
// private address or plain http is not.
func IsPublicDefault(eco Ecosystem, addr string) bool {
	spec, ok := EcosystemOf(eco)
	want := spec.PublicHost
	if !ok || strings.TrimSpace(addr) == "" {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(addr))
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host != want {
		if !(eco == EcoPyPI && host == "files.pythonhosted.org") && !(eco == EcoNpm && host == "registry.yarnpkg.com") {
			return false
		}
	}
	if p := u.Port(); p != "" && p != "443" {
		return false
	}
	switch eco {
	case EcoPyPI:
		path := strings.TrimSuffix(u.Path, "/")
		return path == "/simple" || path == "/pypi" || path == ""
	case EcoNuGet:
		return strings.HasPrefix(u.Path, "/v3/index.json")
	}
	return true
}

var (
	npmNameRe  = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)
	pypiNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	crateRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	nugetRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)
)

// Classify decides one name. spec is what an install command named (it may
// carry a version or be a URL or path); eco is the ecosystem.
func Classify(eco Ecosystem, spec string, c PrivConfig) PrivResult {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.ContainsAny(spec, "\n\r\t ") {
		return PrivResult{Verdict: PrivInvalid, Reason: "empty or contains whitespace"}
	}
	for _, r := range classifyTable {
		if r.eco == eco {
			res := r.fn(spec, c)
			if res.Verdict == PrivPublic && c.Unplaced[eco] != "" {
				// A configuration that could not be read cannot vouch.
				return PrivResult{Verdict: PrivPrivate, Reason: "configuration could not be read: " + c.Unplaced[eco]}
			}
			return res
		}
	}
	return PrivResult{Verdict: PrivPrivate, Reason: "ecosystem not in the table"}
}

func classifierLocation(spec string) bool {
	l := strings.ToLower(spec)
	for _, p := range []string{"http://", "https://", "git+", "git:", "github:", "gitlab:", "bitbucket:", "file:", "link:", "./", "../", "/", "~/", "workspace:", "portal:", "patch:"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return strings.HasSuffix(l, ".tgz") || strings.HasSuffix(l, ".tar.gz") || strings.HasSuffix(l, ".whl") || strings.Contains(l, "\\")
}

func orgPrivate(eco Ecosystem, name string, c PrivConfig) (string, bool) {
	for _, p := range c.OrgPrivate[eco] {
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(name, strings.TrimSuffix(p, "*")) {
				return p, true
			}
		} else if name == p || strings.HasPrefix(name, p+"/") || strings.HasPrefix(name, p+".") {
			return p, true
		}
	}
	return "", false
}

func classifyNpm(spec string, c PrivConfig) PrivResult {
	if strings.HasPrefix(spec, "npm:") { // an alias target: npm:real@1
		spec = strings.TrimPrefix(spec, "npm:")
	}
	if classifierLocation(spec) {
		return PrivResult{Verdict: PrivInvalid, Reason: "a URL, path or git spec, not a registry name"}
	}
	name := spec
	if i := strings.LastIndex(spec, "@"); i > 0 { // strip @version, keep @scope
		name = spec[:i]
	}
	if strings.Count(name, "/") > 1 || (strings.Contains(name, "/") && !strings.HasPrefix(name, "@")) {
		return PrivResult{Verdict: PrivInvalid, Reason: "user/repo shorthand is a GitHub spec"}
	}
	if !npmNameRe.MatchString(name) {
		return PrivResult{Verdict: PrivInvalid, Reason: "not a valid npm name"}
	}
	if p, ok := orgPrivate(EcoNpm, name, c); ok {
		return PrivResult{Verdict: PrivPrivate, Reason: "org private scope " + p}
	}
	reg := c.NpmRegistry
	if reg == "" {
		reg = "https://registry.npmjs.org/"
	}
	if strings.HasPrefix(name, "@") {
		scope, _, _ := strings.Cut(name, "/")
		if r, ok := c.NpmScopeRegistries[scope]; ok {
			reg = r
		}
	}
	if !IsPublicDefault(EcoNpm, reg) {
		return PrivResult{Verdict: PrivPrivate, Reason: "effective registry is not the public default: " + redact(reg)}
	}
	if _, scoped := c.NpmScopeRegistries[scopeOf(name)]; !scoped {
		for _, x := range c.NpmExtraRegistries {
			if !IsPublicDefault(EcoNpm, x) {
				return PrivResult{Verdict: PrivPrivate, Reason: "another default registry is configured: " + redact(x)}
			}
		}
	}
	return PrivResult{Verdict: PrivPublic, Reason: "public default registry", Name: name}
}

// scopeOf returns an npm name's scope ("@corp"), or "".
func scopeOf(name string) string {
	if !strings.HasPrefix(name, "@") {
		return ""
	}
	scope, _, _ := strings.Cut(name, "/")
	return scope
}

func classifyPyPI(spec string, c PrivConfig) PrivResult {
	if classifierLocation(spec) || strings.Contains(spec, "@") {
		return PrivResult{Verdict: PrivInvalid, Reason: "a URL, path or direct reference, not an index name"}
	}
	name := spec
	for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<", "[", ";"} {
		if i := strings.Index(name, sep); i > 0 {
			name = name[:i]
		}
	}
	if !pypiNameRe.MatchString(name) {
		return PrivResult{Verdict: PrivInvalid, Reason: "not a valid PyPI name"}
	}
	norm := strings.ToLower(pep503.ReplaceAllString(name, "-"))
	if p, ok := orgPrivate(EcoPyPI, norm, c); ok {
		return PrivResult{Verdict: PrivPrivate, Reason: "org private scope " + p}
	}
	if c.PipIndexURL != "" && !IsPublicDefault(EcoPyPI, c.PipIndexURL) {
		return PrivResult{Verdict: PrivPrivate, Reason: "index-url is not the public default: " + redact(c.PipIndexURL)}
	}
	for _, x := range c.PipExtraIndexURLs {
		if !IsPublicDefault(EcoPyPI, x) {
			// pip searches every index and takes the best version, so a name
			// on the private index may resolve there: dependency confusion
			// territory. Without a per-name source map the name is not
			// known to be public.
			return PrivResult{Verdict: PrivPrivate, Reason: "an extra index is configured (" + redact(x) + "), so the name may resolve privately"}
		}
	}
	return PrivResult{Verdict: PrivPublic, Reason: "public default index", Name: norm}
}

func classifyGo(spec string, c PrivConfig) PrivResult {
	path := spec
	if i := strings.Index(path, "@"); i > 0 {
		path = path[:i]
	}
	if classifierLocation(spec) || module.CheckPath(path) != nil {
		return PrivResult{Verdict: PrivInvalid, Reason: "not a valid module path"}
	}
	for _, env := range []struct{ name, val string }{{"GOPRIVATE", c.GoPrivate}, {"GONOPROXY", c.GoNoProxy}, {"GONOSUMDB", c.GoNoSumDB}} {
		if env.val != "" && module.MatchPrefixPatterns(env.val, path) {
			return PrivResult{Verdict: PrivPrivate, Reason: env.name + " matches"}
		}
	}
	if p, ok := orgPrivate(EcoGo, path, c); ok {
		return PrivResult{Verdict: PrivPrivate, Reason: "org private scope " + p}
	}
	proxy := c.GoProxy
	if proxy == "" {
		proxy = "https://proxy.golang.org,direct"
	}
	first := strings.Split(strings.Split(proxy, ",")[0], "|")[0]
	if first == "off" || first == "direct" || !IsPublicDefault(EcoGo, first) {
		return PrivResult{Verdict: PrivPrivate, Reason: "GOPROXY's first entry is not the public proxy: " + redact(first)}
	}
	return PrivResult{Verdict: PrivPublic, Reason: "public module proxy", Name: path}
}

func classifyCargo(spec string, c PrivConfig) PrivResult {
	name := spec
	if i := strings.Index(name, "@"); i > 0 {
		name = name[:i]
	}
	if classifierLocation(spec) || !crateRe.MatchString(name) {
		return PrivResult{Verdict: PrivInvalid, Reason: "not a valid crate name"}
	}
	if p, ok := orgPrivate(EcoCargo, name, c); ok {
		return PrivResult{Verdict: PrivPrivate, Reason: "org private scope " + p}
	}
	if c.CargoReplaceCratesIO != "" {
		return PrivResult{Verdict: PrivPrivate, Reason: "crates-io is source-replaced by " + c.CargoReplaceCratesIO}
	}
	return PrivResult{Verdict: PrivPublic, Reason: "crates.io", Name: strings.ToLower(name)}
}

func classifyNuGet(spec string, c PrivConfig) PrivResult {
	name := spec
	if i := strings.IndexAny(name, "@ "); i > 0 {
		name = name[:i]
	}
	if classifierLocation(spec) || !nugetRe.MatchString(name) {
		return PrivResult{Verdict: PrivInvalid, Reason: "not a valid package id"}
	}
	if p, ok := orgPrivate(EcoNuGet, name, c); ok {
		return PrivResult{Verdict: PrivPrivate, Reason: "org private scope " + p}
	}
	sources := c.NuGetSources
	if len(sources) == 0 {
		sources = map[string]string{"nuget.org": "https://api.nuget.org/v3/index.json"}
	}
	key := ""
	switch {
	case len(c.NuGetMapping) > 0:
		best := -1
		for pat, k := range c.NuGetMapping {
			ok := pat == "*" || strings.EqualFold(pat, name) || (strings.HasSuffix(pat, "*") && strings.HasPrefix(strings.ToLower(name), strings.ToLower(strings.TrimSuffix(pat, "*"))))
			if ok && len(pat) > best {
				best, key = len(pat), k
			}
		}
		if key == "" {
			return PrivResult{Verdict: PrivPrivate, Reason: "no packageSourceMapping pattern matches"}
		}
	case len(sources) > 1:
		return PrivResult{Verdict: PrivPrivate, Reason: "several sources and no packageSourceMapping, so the source is ambiguous"}
	default:
		for k := range sources {
			key = k
		}
	}
	if !IsPublicDefault(EcoNuGet, sources[key]) {
		return PrivResult{Verdict: PrivPrivate, Reason: "mapped source is not nuget.org: " + redact(sources[key])}
	}
	return PrivResult{Verdict: PrivPublic, Reason: "nuget.org", Name: strings.ToLower(name)}
}

// redact drops credentials from a registry URL before it reaches a reason.
func redact(addr string) string {
	u, err := url.Parse(addr)
	if err != nil {
		return "(unparseable)"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}
