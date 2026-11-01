package secfeed

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// privconfig.go turns the package-manager configuration the caller read
// from fixed paths into the classifier's PrivConfig (security plan section
// 8.3 "Private names are never sent to a public source"). Every parser is
// lenient about shape and conservative about meaning: a file it cannot read
// adds nothing, and a registry it cannot place makes names private, never
// public.

// ConfigFile names one file the caller reads, by role.
type ConfigFile string

// The config file roles, in precedence order within an ecosystem (the
// project file over the user file over the global file).
const (
	ConfNpmrcProject  ConfigFile = "npmrc.project"
	ConfNpmrcUser     ConfigFile = "npmrc.user"
	ConfNpmrcGlobal   ConfigFile = "npmrc.global"
	ConfYarnrcProject ConfigFile = "yarnrc.project"
	ConfYarnrcUser    ConfigFile = "yarnrc.user"
	// Yarn 1's .yarnrc (registry and "@scope:registry" lines) and Bun's
	// bunfig.toml ([install] registry and scopes).
	ConfYarn1Project  ConfigFile = "yarn1rc.project"
	ConfYarn1User     ConfigFile = "yarn1rc.user"
	ConfBunfigProject ConfigFile = "bunfig.project"
	ConfBunfigUser    ConfigFile = "bunfig.user"
	ConfPipProject    ConfigFile = "pip.project"
	ConfPipUser       ConfigFile = "pip.user"
	// ConfPipGlobal is the machine-wide pip file(s), ConfPipVenv the
	// active virtual environment's ($VIRTUAL_ENV/pip.conf).
	ConfPipGlobal ConfigFile = "pip.global"
	ConfPipVenv   ConfigFile = "pip.venv"
	ConfPyproject ConfigFile = "pyproject"
	ConfUVProject ConfigFile = "uv.project"
	ConfUVUser    ConfigFile = "uv.user"
	// ConfUVUserXDG is ~/.config/uv/uv.toml, which uv reads on every OS
	// (on Windows and macOS beside the platform config directory).
	ConfUVUserXDG ConfigFile = "uv.user.xdg"
	// ConfRequirements is the project's requirements files, concatenated
	// (their --index-url and --extra-index-url lines).
	ConfRequirements ConfigFile = "requirements"
	ConfCargoProject ConfigFile = "cargo.project"
	ConfCargoUser    ConfigFile = "cargo.user"
	ConfNuGetProject ConfigFile = "nuget.project"
	ConfNuGetUser    ConfigFile = "nuget.user"
	// ConfGoEnv is the go env file (`go env GOENV`: $GOENV, else the
	// user config dir's go/env), the values `go env -w` writes.
	ConfGoEnv          ConfigFile = "goenv"
	maxConfigFileBytes            = 256 << 10
)

// configEcosystem maps a role to the ecosystem whose names it decides.
var configEcosystem = map[ConfigFile]Ecosystem{
	ConfNpmrcProject: EcoNpm, ConfNpmrcUser: EcoNpm, ConfNpmrcGlobal: EcoNpm, ConfYarnrcProject: EcoNpm, ConfYarnrcUser: EcoNpm,
	ConfYarn1Project: EcoNpm, ConfYarn1User: EcoNpm, ConfBunfigProject: EcoNpm, ConfBunfigUser: EcoNpm,
	ConfPipProject: EcoPyPI, ConfPipUser: EcoPyPI, ConfPipGlobal: EcoPyPI, ConfPipVenv: EcoPyPI, ConfPyproject: EcoPyPI,
	ConfUVProject: EcoPyPI, ConfUVUser: EcoPyPI, ConfUVUserXDG: EcoPyPI, ConfRequirements: EcoPyPI,
	ConfCargoProject: EcoCargo, ConfCargoUser: EcoCargo, ConfNuGetProject: EcoNuGet, ConfNuGetUser: EcoNuGet, ConfGoEnv: EcoGo,
}

// PrivConfigInput is what the caller read.
type PrivConfigInput struct {
	Files map[ConfigFile][]byte
	// Unreadable lists roles whose file exists but could not be read
	// (permissions, over the size cap, not a regular file): every name of
	// that ecosystem is then private, never public.
	Unreadable map[ConfigFile]bool
	// Env reads the DAEMON's own environment, never the agent's; nil reads
	// nothing (the hook's side).
	Env func(string) string
	// Environ lists the daemon's NAME=value pairs, for the variables only
	// a prefix names (npm_config_@scope:registry); nil lists none.
	Environ func() []string
	// OrgPrivate are the org's private scopes on a managed node.
	OrgPrivate map[Ecosystem][]string
}

// privBuilder carries one BuildPrivConfig run.
type privBuilder struct {
	in PrivConfigInput
	c  PrivConfig
}

// unplaced marks role's ecosystem private.
func (p *privBuilder) unplaced(role ConfigFile) {
	if eco, ok := configEcosystem[role]; ok && p.c.Unplaced[eco] == "" {
		p.c.Unplaced[eco] = string(role)
	}
}

// file returns a role's bytes; one over the cap is unplaced.
func (p *privBuilder) file(role ConfigFile) []byte {
	b := p.in.Files[role]
	if len(b) > maxConfigFileBytes {
		p.unplaced(role)
		return nil
	}
	return b
}

// env reads the daemon's environment ("" with none).
func (p *privBuilder) env(k string) string {
	if p.in.Env == nil {
		return ""
	}
	return strings.TrimSpace(p.in.Env(k))
}

// privSteps is the per-ecosystem build table, run in order.
var privSteps = []func(*privBuilder){(*privBuilder).npm, (*privBuilder).pypi, (*privBuilder).golang, (*privBuilder).cargo, (*privBuilder).nuget}

// BuildPrivConfig assembles the classifier configuration. A file it cannot
// read or parse marks its ecosystem unplaced (PrivConfig.Unplaced): every
// name there is private.
func BuildPrivConfig(in PrivConfigInput) PrivConfig {
	p := &privBuilder{in: in, c: PrivConfig{NpmScopeRegistries: map[string]string{}, OrgPrivate: in.OrgPrivate, Unplaced: map[Ecosystem]string{}}}
	for role, bad := range in.Unreadable {
		if bad {
			p.unplaced(role)
		}
	}
	for _, step := range privSteps {
		step(p)
	}
	return p.c
}

// npm: global, then user, then project (npm's own precedence), then the
// npm_config_ variables; a .yarnrc.yml counts as one more layer.
func (p *privBuilder) npm() {
	for _, role := range []ConfigFile{ConfNpmrcGlobal, ConfNpmrcUser, ConfNpmrcProject} {
		reg, scopes := ParseNpmrc(p.file(role))
		if reg != "" {
			p.c.NpmRegistry = reg
		}
		for k, v := range scopes {
			p.c.NpmScopeRegistries[k] = v
		}
	}
	for _, role := range []ConfigFile{ConfYarnrcUser, ConfYarnrcProject} {
		reg, scopes, ok := ParseYarnrc(p.file(role))
		if !ok {
			p.unplaced(role)
			continue
		}
		if reg != "" {
			p.c.NpmExtraRegistries = append(p.c.NpmExtraRegistries, reg)
		}
		for k, v := range scopes {
			p.c.NpmScopeRegistries[k] = v
		}
	}
	for _, role := range []ConfigFile{ConfYarn1User, ConfYarn1Project} {
		reg, scopes := ParseYarn1rc(p.file(role))
		if reg != "" {
			p.c.NpmExtraRegistries = append(p.c.NpmExtraRegistries, reg)
		}
		p.addScopes(scopes)
	}
	for _, role := range []ConfigFile{ConfBunfigUser, ConfBunfigProject} {
		reg, scopes, ok := ParseBunfig(p.file(role))
		if !ok {
			p.unplaced(role)
			continue
		}
		if reg != "" {
			p.c.NpmExtraRegistries = append(p.c.NpmExtraRegistries, reg)
		}
		p.addScopes(scopes)
	}
	if v := p.env("BUN_CONFIG_REGISTRY"); v != "" {
		p.c.NpmExtraRegistries = append(p.c.NpmExtraRegistries, v)
	}
	if v := firstEnv(p.env, "NPM_CONFIG_REGISTRY", "npm_config_registry"); v != "" {
		p.c.NpmRegistry = v
	}
	if v := p.env("YARN_NPM_REGISTRY_SERVER"); v != "" {
		p.c.NpmExtraRegistries = append(p.c.NpmExtraRegistries, v)
	}
	if p.in.Environ == nil {
		return
	}
	for _, kv := range p.in.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "npm_config_@") && strings.HasSuffix(lk, ":registry") {
			p.c.NpmScopeRegistries[strings.TrimSuffix(strings.TrimPrefix(lk, "npm_config_"), ":registry")] = strings.TrimSpace(v)
		}
	}
}

// addScopes adds scoped registries; a scope a second source also names
// keeps a non-public address over a public one (more private, never less).
func (p *privBuilder) addScopes(scopes map[string]string) {
	for k, v := range scopes {
		if old, ok := p.c.NpmScopeRegistries[k]; ok && !IsPublicDefault(EcoNpm, old) && IsPublicDefault(EcoNpm, v) {
			continue
		}
		p.c.NpmScopeRegistries[k] = v
	}
}

// pypi: pip files (global, user, project, the virtual environment's), then
// the daemon's environment (pip's own precedence); an index-url an earlier
// layer names counts as one more index (conservatively: it only ever makes
// a name more private). Poetry sources, uv indexes and requirements-file
// index lines count as extra indexes (pip-like search order).
func (p *privBuilder) pypi() {
	for _, role := range []ConfigFile{ConfPipGlobal, ConfPipUser, ConfPipProject, ConfPipVenv} {
		idx, extra := ParsePipConf(p.file(role))
		if idx != "" {
			if p.c.PipIndexURL != "" {
				p.c.PipExtraIndexURLs = append(p.c.PipExtraIndexURLs, p.c.PipIndexURL)
			}
			p.c.PipIndexURL = idx
		}
		p.c.PipExtraIndexURLs = append(p.c.PipExtraIndexURLs, extra...)
	}
	if v := p.env("PIP_INDEX_URL"); v != "" {
		p.c.PipIndexURL = v
	}
	p.c.PipExtraIndexURLs = append(p.c.PipExtraIndexURLs, strings.Fields(p.env("PIP_EXTRA_INDEX_URL"))...)
	p.c.PipExtraIndexURLs = append(p.c.PipExtraIndexURLs, strings.Fields(p.env("PIP_FIND_LINKS"))...)
	if b := p.file(ConfPyproject); len(b) > 0 {
		urls, ok := ParsePoetrySources(b)
		if !ok {
			p.unplaced(ConfPyproject)
		}
		p.c.PipExtraIndexURLs = append(p.c.PipExtraIndexURLs, urls...)
	}
	for _, role := range []ConfigFile{ConfUVUser, ConfUVUserXDG, ConfUVProject} {
		urls, ok := ParseUVConfig(p.file(role))
		if !ok {
			p.unplaced(role)
		}
		p.c.PipExtraIndexURLs = append(p.c.PipExtraIndexURLs, urls...)
	}
	for _, k := range []string{"UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_FIND_LINKS"} {
		for _, u := range strings.Fields(p.env(k)) {
			p.c.PipExtraIndexURLs = append(p.c.PipExtraIndexURLs, uvIndexURL(u))
		}
	}
	p.c.PipExtraIndexURLs = append(p.c.PipExtraIndexURLs, ParseRequirementsIndexes(p.file(ConfRequirements))...)
}

// uvIndexURL strips a uv "name=url" index entry to its URL.
func uvIndexURL(u string) string {
	name, url, ok := strings.Cut(u, "=")
	if ok && !strings.Contains(name, "/") {
		return url
	}
	return u
}

// golang: the go env file, then the daemon's environment (the variable
// wins, as in the go command).
func (p *privBuilder) golang() {
	goenv := ParseGoEnv(p.file(ConfGoEnv))
	pick := func(k string) string {
		if v := p.env(k); v != "" {
			return v
		}
		return goenv[k]
	}
	p.c.GoPrivate, p.c.GoNoProxy, p.c.GoNoSumDB, p.c.GoProxy = pick("GOPRIVATE"), pick("GONOPROXY"), pick("GONOSUMDB"), pick("GOPROXY")
}

// cargo: source replacement or another default registry.
func (p *privBuilder) cargo() {
	for _, role := range []ConfigFile{ConfCargoUser, ConfCargoProject} {
		if r := ParseCargoReplace(p.file(role)); r != "" {
			p.c.CargoReplaceCratesIO = r
		}
	}
	if v := p.env("CARGO_REGISTRY_DEFAULT"); v != "" && v != "crates-io" {
		p.c.CargoReplaceCratesIO = "CARGO_REGISTRY_DEFAULT=" + v
	}
}

// nuget: the machine default nuget.org source, unless a file clears it.
func (p *privBuilder) nuget() {
	p.c.NuGetSources = map[string]string{"nuget.org": "https://api.nuget.org/v3/index.json"}
	for _, role := range []ConfigFile{ConfNuGetUser, ConfNuGetProject} {
		src, mapping, cleared := ParseNuGetConfig(p.file(role))
		if cleared {
			p.c.NuGetSources = map[string]string{}
		}
		for k, v := range src {
			p.c.NuGetSources[k] = v
		}
		if len(mapping) > 0 {
			p.c.NuGetMapping = mapping
		}
	}
}

// firstEnv returns the first non-empty of the named variables.
func firstEnv(env func(string) string, keys ...string) string {
	for _, k := range keys {
		if v := env(k); v != "" {
			return v
		}
	}
	return ""
}

// ParseGoEnv reads the go env file: KEY=VALUE lines, as `go env -w`
// writes them.
func ParseGoEnv(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// ParseYarnrc reads a Yarn Berry .yarnrc.yml: npmRegistryServer and the
// npmScopes' registries ("corp" -> "@corp"). ok is false for a file that
// does not parse.
func ParseYarnrc(b []byte) (registry string, scopes map[string]string, ok bool) {
	scopes = map[string]string{}
	if len(bytes.TrimSpace(b)) == 0 {
		return "", scopes, true
	}
	var doc struct {
		NpmRegistryServer string `yaml:"npmRegistryServer"`
		NpmScopes         map[string]struct {
			NpmRegistryServer string `yaml:"npmRegistryServer"`
		} `yaml:"npmScopes"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return "", nil, false
	}
	for scope, v := range doc.NpmScopes {
		if v.NpmRegistryServer == "" {
			continue
		}
		scopes["@"+strings.TrimPrefix(scope, "@")] = v.NpmRegistryServer
	}
	return strings.TrimSpace(doc.NpmRegistryServer), scopes, true
}

// ParseYarn1rc reads a Yarn 1 .yarnrc: `registry "url"` and
// `"@scope:registry" "url"` lines (quotes optional).
func ParseYarn1rc(b []byte) (registry string, scopes map[string]string) {
	scopes = map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		k = strings.Trim(strings.TrimSpace(k), `"'`)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		k = strings.TrimPrefix(k, "--")
		switch {
		case k == "registry":
			registry = v
		case strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry"):
			scopes[strings.TrimSuffix(k, ":registry")] = v
		}
	}
	return registry, scopes
}

// ParseBunfig reads a bunfig.toml's [install] registry and
// [install.scopes] (a value is a URL string or a table with a url). ok is
// false for a file that does not parse.
func ParseBunfig(b []byte) (registry string, scopes map[string]string, ok bool) {
	scopes = map[string]string{}
	if len(bytes.TrimSpace(b)) == 0 {
		return "", scopes, true
	}
	var doc struct {
		Install struct {
			Registry any            `toml:"registry"`
			Scopes   map[string]any `toml:"scopes"`
		} `toml:"install"`
	}
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return "", nil, false
	}
	url := func(v any) string {
		switch t := v.(type) {
		case string:
			return strings.TrimSpace(t)
		case map[string]any:
			if s, ok := t["url"].(string); ok {
				return strings.TrimSpace(s)
			}
			// A table with no url names a source this reader cannot place.
			return "(a registry table with no url)"
		}
		return ""
	}
	for k, v := range doc.Install.Scopes {
		if u := url(v); u != "" {
			scopes["@"+strings.TrimPrefix(k, "@")] = u
		}
	}
	return url(doc.Install.Registry), scopes, true
}

// ParseUVConfig reads a uv.toml's indexes: index-url, extra-index-url,
// find-links, [[index]] urls and the same keys under [pip]. ok is false
// for a file that does not parse.
func ParseUVConfig(b []byte) ([]string, bool) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, true
	}
	var doc uvSettings
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return nil, false
	}
	return doc.urls(), true
}

// uvSettings is the subset of uv's settings that names an index, the same
// shape at a uv.toml's top level and under pyproject's [tool.uv].
type uvSettings struct {
	IndexURL      string   `toml:"index-url"`
	ExtraIndexURL []string `toml:"extra-index-url"`
	FindLinks     []string `toml:"find-links"`
	Index         []struct {
		URL string `toml:"url"`
	} `toml:"index"`
	Pip struct {
		IndexURL      string   `toml:"index-url"`
		ExtraIndexURL []string `toml:"extra-index-url"`
		FindLinks     []string `toml:"find-links"`
	} `toml:"pip"`
}

func (u uvSettings) urls() []string {
	var out []string
	add := func(ss ...string) {
		for _, s := range ss {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	add(u.IndexURL, u.Pip.IndexURL)
	add(u.ExtraIndexURL...)
	add(u.FindLinks...)
	add(u.Pip.ExtraIndexURL...)
	add(u.Pip.FindLinks...)
	for _, i := range u.Index {
		add(i.URL)
	}
	return out
}

// ParseRequirementsIndexes reads the index lines of requirements files:
// -i, --index-url, --extra-index-url, -f and --find-links (with a space or
// an equals sign).
func ParseRequirementsIndexes(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxConfigFileBytes)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		for i := 0; i < len(f); i++ {
			name, value, hasValue := strings.Cut(f[i], "=")
			switch name {
			case "-i", "--index-url", "--extra-index-url", "-f", "--find-links":
			default:
				if strings.HasPrefix(f[i], "-i") && len(f[i]) > 2 && name == f[i] {
					out = append(out, f[i][2:])
				}
				continue
			}
			if !hasValue {
				if i+1 >= len(f) {
					out = append(out, "(an index line with no value)")
					continue
				}
				i++
				value = f[i]
			}
			out = append(out, value)
		}
	}
	return out
}

// ParseNpmrc reads `registry=` and `@scope:registry=` lines.
func ParseNpmrc(b []byte) (registry string, scopes map[string]string) {
	scopes = map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		switch {
		case k == "registry":
			registry = v
		case strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry"):
			scopes[strings.TrimSuffix(k, ":registry")] = v
		}
	}
	return registry, scopes
}

// ParsePipConf reads index-url and extra-index-url from pip's ini file
// ([global] and [install]); extra-index-url may span continuation lines.
func ParsePipConf(b []byte) (index string, extra []string) {
	section, key := "", ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section, key = strings.ToLower(strings.Trim(line, "[]")), ""
			continue
		}
		if section != "global" && section != "install" {
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			if key == "extra-index-url" {
				extra = append(extra, strings.Fields(line)...)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch key {
		case "index-url", "index_url":
			index = v
		case "extra-index-url", "extra_index_url":
			key = "extra-index-url"
			extra = append(extra, strings.Fields(v)...)
		}
	}
	return index, extra
}

// ParsePoetrySources reads [[tool.poetry.source]] urls and uv's settings
// under [tool.uv] ([[tool.uv.index]], index-url, extra-index-url,
// find-links) from pyproject.toml. ok is false for a file that does not
// parse.
func ParsePoetrySources(b []byte) ([]string, bool) {
	if len(b) == 0 {
		return nil, true
	}
	var doc struct {
		Tool struct {
			Poetry struct {
				Source []struct {
					URL string `toml:"url"`
				} `toml:"source"`
			} `toml:"poetry"`
			UV uvSettings `toml:"uv"`
		} `toml:"tool"`
	}
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return nil, false
	}
	var out []string
	for _, s := range doc.Tool.Poetry.Source {
		if s.URL != "" {
			out = append(out, s.URL)
		}
	}
	return append(out, doc.Tool.UV.urls()...), true
}

// ParseCargoReplace reads [source.crates-io] replace-with and a
// [registry] default other than crates-io.
func ParseCargoReplace(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var doc struct {
		Source map[string]struct {
			ReplaceWith string `toml:"replace-with"`
		} `toml:"source"`
		Registry struct {
			Default string `toml:"default"`
		} `toml:"registry"`
	}
	if _, err := toml.Decode(string(b), &doc); err != nil {
		// An unreadable cargo config cannot be placed: assume replaced.
		return "(unreadable cargo config)"
	}
	if r := doc.Source["crates-io"].ReplaceWith; r != "" {
		return r
	}
	if d := doc.Registry.Default; d != "" && d != "crates-io" {
		return "registry.default " + d
	}
	return ""
}

// ParseNuGetConfig reads packageSources (with <clear/>) and
// packageSourceMapping.
func ParseNuGetConfig(b []byte) (sources, mapping map[string]string, cleared bool) {
	if len(b) == 0 {
		return nil, nil, false
	}
	var doc struct {
		Sources struct {
			Clear []struct{} `xml:"clear"`
			Add   []struct {
				Key   string `xml:"key,attr"`
				Value string `xml:"value,attr"`
			} `xml:"add"`
		} `xml:"packageSources"`
		Mapping struct {
			Source []struct {
				Key     string `xml:"key,attr"`
				Package []struct {
					Pattern string `xml:"pattern,attr"`
				} `xml:"package"`
			} `xml:"packageSource"`
		} `xml:"packageSourceMapping"`
	}
	if err := xml.Unmarshal(b, &doc); err != nil {
		return map[string]string{"(unreadable)": "unreadable nuget.config"}, nil, false
	}
	sources = map[string]string{}
	for _, a := range doc.Sources.Add {
		sources[a.Key] = a.Value
	}
	if len(doc.Mapping.Source) > 0 {
		mapping = map[string]string{}
		for _, s := range doc.Mapping.Source {
			for _, p := range s.Package {
				mapping[p.Pattern] = s.Key
			}
		}
	}
	return sources, mapping, len(doc.Sources.Clear) > 0
}

// NewClassifier returns the gate's classifier over cfg: true only for a
// public-routable name.
func NewClassifier(cfg PrivConfig) Classifier {
	return func(s InstallSpec) bool {
		if s.Invalid {
			return false
		}
		if s.Private {
			return false
		}
		return Classify(s.Eco, s.Spec, cfg).Verdict == PrivPublic
	}
}
